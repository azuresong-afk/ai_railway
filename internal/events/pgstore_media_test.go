package events_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Изображения запроса в содержимом full (задача 6.13, ADR-0039): таблица
// event_media, шифрование ключом данных, срок содержимого.

var (
	pgImageA = []byte("\x89PNG\r\n\x1a\nПаспорт 4510 123456 на снимке")
	pgImageB = []byte("\xff\xd8\xffвторое изображение")
)

// imageEvent — событие full с двумя сохранёнными изображениями.
func (e *pgEnv) imageEvent(t *testing.T) events.Event {
	t.Helper()
	ev := e.event(t, events.StorageFull, &events.Content{Request: "Что на картинке?", Images: []events.ContentImage{
		{Location: "messages[0].content[1]", Format: "png", Data: pgImageA},
		{Location: "messages[0].content[2]", Format: "jpeg", Sanitized: true, Data: pgImageB},
	}})
	ev.Media = []events.MediaCheck{
		{Location: "messages[0].content[1]", Mode: events.MediaModeSync, Checked: true, Format: "png", Width: 64, Height: 32, Stored: true},
		{Location: "messages[0].content[2]", Mode: events.MediaModeSync, Checked: true, Format: "webp", Width: 64, Height: 32, Stored: true, Sanitized: true},
	}
	return ev
}

func TestPGEventsImagesStoredEncrypted(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	ev := e.imageEvent(t)
	plain := e.event(t, events.StorageFull, &events.Content{Request: "без изображений"})
	if res, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev, plain}}); err != nil ||
		res.Accepted != 2 {
		t.Fatalf("запись: %+v %v", res, err)
	}
	// Повтор пакета не дублирует изображения.
	if _, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev}}); err != nil {
		t.Fatal(err)
	}
	rows, err := e.owner.Query(ctx, "SELECT idx, location, format, sanitized, key_id::text, sealed FROM event_media WHERE event_id = $1 ORDER BY idx", ev.ID)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var idx int
		var loc, format, key string
		var sanitized bool
		var sealed []byte
		if err := rows.Scan(&idx, &loc, &format, &sanitized, &key, &sealed); err != nil {
			t.Fatal(err)
		}
		want := ev.Content.Images[idx]
		if loc != want.Location || format != want.Format || sanitized != want.Sanitized || key != e.keyID ||
			bytes.Contains(sealed, want.Data[4:]) || bytes.Contains(sealed, []byte("4510")) {
			t.Fatalf("строка %d: %s %s %v %s", idx, loc, format, sanitized, key)
		}
		n++
	}
	rows.Close()
	if n != 2 {
		t.Fatalf("строк изображений %d", n)
	}
	// Ни в метаданных, ни в шифротексте текста содержимого байтов нет.
	var details []byte
	var sealed []byte
	if err := e.owner.QueryRow(ctx, "SELECT e.details::text, c.sealed FROM events e JOIN event_content c ON c.event_id = e.id WHERE e.id = $1", ev.ID).
		Scan(&details, &sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(details, []byte("4510")) || bytes.Contains(details, []byte(`"images"`)) || len(sealed) > 1024 {
		t.Fatalf("details %s, шифротекст текста %d байт", details, len(sealed))
	}
	// Чтение: текст без изображений, изображения отдельно и по порядку.
	got, err := e.st.Content(ctx, ev.ID)
	if err != nil || got.Content.Request != "Что на картинке?" || len(got.Content.Images) != 0 {
		t.Fatalf("содержимое: %+v %v", got, err)
	}
	imgs, err := e.st.Images(ctx, ev.ID)
	if err != nil || len(imgs) != 2 || !bytes.Equal(imgs[0].Data, pgImageA) || !bytes.Equal(imgs[1].Data, pgImageB) ||
		imgs[1].Format != "jpeg" || !imgs[1].Sanitized {
		t.Fatalf("изображения: %d %v", len(imgs), err)
	}
	if imgs, err := e.st.Images(ctx, plain.ID); err != nil || len(imgs) != 0 {
		t.Fatalf("у события без изображений: %d %v", len(imgs), err)
	}
	if imgs, err := e.st.Images(ctx, "not-an-id"); err != nil || len(imgs) != 0 {
		t.Fatalf("неверный ID: %d %v", len(imgs), err)
	}
}

// Шифротекст изображения, переставленный на другое место, не
// расшифровывается (AAD — ID события и номер).
func TestPGEventsImageSwapped(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	ev := e.imageEvent(t)
	if _, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO event_media (event_id, ts, idx, org_id, location, format, sanitized, key_id, key_day, alg, sealed)
		SELECT event_id, ts, 5, org_id, location, format, sanitized, key_id, key_day, alg, sealed FROM event_media WHERE event_id = $1 AND idx = 0`,
		ev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Images(ctx, ev.ID); !errors.Is(err, aisecCrypto.ErrDecrypt) {
		t.Fatalf("переставленный шифротекст: %v", err)
	}
}

// Права роли сервера: изображения только добавляются и читаются; строку не
// меняет и не удаляет и владелец (кроме перешифрования).
func TestPGEventsImageRights(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	ev := e.imageEvent(t)
	if _, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev}}); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		"UPDATE event_media SET format = 'gif'",
		"DELETE FROM event_media",
		"TRUNCATE event_media",
		"DROP TABLE event_media_p" + time.Now().UTC().Format("20060102"),
	} {
		if _, err := e.app.Exec(ctx, sql); sqlState(err) != "42501" {
			t.Errorf("сервер: %s: %v", sql, err)
		}
	}
	for _, sql := range []string{
		"UPDATE event_media SET location = 'images[0]'",
		"UPDATE event_media SET sealed = sealed || '\\x00'::bytea",
		"DELETE FROM event_media",
	} {
		if _, err := e.owner.Exec(ctx, sql); sqlState(err) != "23514" {
			t.Errorf("владелец: %s: %v", sql, err)
		}
	}
	// Предел шифротекста и номера — ограничения таблицы.
	for _, sql := range []string{
		fmt.Sprintf(`INSERT INTO event_media (event_id, ts, idx, org_id, location, format, key_id, key_day, alg, sealed)
			SELECT event_id, ts, 16, org_id, location, format, key_id, key_day, alg, sealed FROM event_media WHERE event_id = '%s' AND idx = 0`, ev.ID),
		fmt.Sprintf(`INSERT INTO event_media (event_id, ts, idx, org_id, location, format, key_id, key_day, alg, sealed)
			SELECT event_id, ts, 7, org_id, location, format, key_id, key_day, alg, sealed || repeat('x', %d)::bytea FROM event_media WHERE event_id = '%s' AND idx = 0`,
			events.MaxStoredImageBytes+2048, ev.ID),
		fmt.Sprintf(`INSERT INTO event_media (event_id, ts, idx, org_id, location, format, sanitized, key_id, key_day, alg, sealed)
			SELECT event_id, ts, 8, org_id, location, 'gif', true, key_id, key_day, alg, sealed FROM event_media WHERE event_id = '%s' AND idx = 0`, ev.ID),
	} {
		if _, err := e.owner.Exec(ctx, sql); sqlState(err) != "23514" {
			t.Errorf("ограничение: %v", err)
		}
	}
}

// Срок: изображения удаляются вместе с секцией содержимого тех же суток.
func TestPGEventsImageRetention(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	ev := e.imageEvent(t)
	if _, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev}}); err != nil {
		t.Fatal(err)
	}
	// Секции изображений старше срока содержимого (90 суток) удаляются, а
	// метаданные тех же суток (срок 365) остаются.
	old := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -100)
	for _, parent := range []string{"events", "event_content", "event_media"} {
		name := fmt.Sprintf("%s_p%s", parent, old.Format("20060102"))
		if _, err := e.owner.Exec(ctx, fmt.Sprintf("CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
			name, parent, old.Format(time.RFC3339), old.AddDate(0, 0, 1).Format(time.RFC3339))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO event_media (event_id, ts, idx, org_id, location, format, key_id, key_day, alg, sealed)
		SELECT event_id, $1, 0, org_id, location, format, key_id, ($1::timestamptz AT TIME ZONE 'UTC')::date, alg, sealed
		FROM event_media WHERE event_id = $2 AND idx = 0`, old.Add(time.Hour), ev.ID); err != nil {
		t.Fatal(err)
	}
	dropped, err := e.st.DropExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := "event_media_p" + old.Format("20060102")
	found := false
	for _, d := range dropped {
		found = found || d == want
		if d == "events_p"+old.Format("20060102") {
			t.Fatal("метаданные удалены по сроку содержимого")
		}
	}
	var left int
	if err := e.owner.QueryRow(ctx, "SELECT count(*) FROM event_media WHERE ts < now() - interval '90 days'").Scan(&left); err != nil ||
		!found || left != 0 {
		t.Fatalf("удалены %v, осталось старых %d, %v", dropped, left, err)
	}
	if imgs, err := e.st.Images(ctx, ev.ID); err != nil || len(imgs) != 2 {
		t.Fatalf("свежие изображения: %d %v", len(imgs), err)
	}
}
