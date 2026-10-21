package events_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Чтение событий для консоли (задача 2.16) на PostgreSQL: фильтры в SQL,
// страницы, подсчёт для выгрузки, сроки хранения с аудитом, сохранённые
// фильтры, агрегаты. В CI без PostgreSQL пропускаются.

const testUser = "01900000-0000-7000-8000-0000000000b1"

// seed — события последних минут: n штук, у чётных — app crm и находка
// pii.inn, у нечётных — app bot и поток.
func seed(t *testing.T, e *pgEnv, n int) []events.Event {
	t.Helper()
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	evs := make([]events.Event, 0, n)
	for i := range n {
		ev := e.event(t, events.StorageMasked, &events.Content{Request: "секрет"})
		ev.Tokens = &events.Tokens{Prompt: 10, Completion: 3}
		if i%2 == 0 {
			ev.App = "crm"
			ev.Findings = []events.Finding{{Detector: "pii.inn", Category: "pii", Threat: "DM-05"}}
			ev.Threats = []string{"DM-05", "DM-13"}
		} else {
			ev.App, ev.Stream = "bot", true
		}
		evs = append(evs, ev)
		time.Sleep(2 * time.Millisecond) // разные миллисекунды UUIDv7
	}
	if _, _, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: evs}); err != nil {
		t.Fatal(err)
	}
	return evs
}

func lastHour() events.Query {
	now := time.Now().UTC()
	return events.Query{From: now.Add(-time.Hour), To: now.Add(time.Minute)}
}

func TestPGEventsListFilterPages(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	evs := seed(t, e, 5)
	q := lastHour()
	all, err := e.st.List(ctx, q)
	if err != nil || len(all) != 5 || all[0].ID != evs[4].ID || all[4].ID != evs[0].ID {
		t.Fatalf("список: %d %v", len(all), err)
	}
	if all[0].Details != nil || all[0].HasContent != true || all[0].GatewayID != testGateway {
		t.Fatalf("запись: %+v", all[0])
	}
	// Страница и курсор.
	q.Limit = 2
	p1, err := e.st.List(ctx, q)
	if err != nil || len(p1) != 2 {
		t.Fatalf("страница: %v", err)
	}
	q.After = &events.Position{TS: p1[1].TS, ID: p1[1].ID}
	p2, err := e.st.List(ctx, q)
	if err != nil || len(p2) != 2 || p2[0].ID != evs[2].ID {
		t.Fatalf("вторая страница: %+v %v", p2, err)
	}
	for in, want := range map[string]int{
		`app = "crm"`:                             3,
		`app != "crm" and stream = true`:          2,
		`detector = "pii.inn"`:                    3,
		`detector != "pii.inn"`:                   2,
		`threat in ("DM-13", "DM-99")`:            3,
		`threat not in ("DM-13")`:                 2,
		`gateway = "` + testGateway + `"`:         5,
		`env != "prod"`:                           0,
		`user = "a1b2c3" and model = "mock-echo"`: 5,
		`app = "x'); DROP TABLE events; --"`:      0,
	} {
		f, err := events.ParseFilter(in)
		if err != nil {
			t.Fatal(in, err)
		}
		q := lastHour()
		q.Filter = f
		got, err := e.st.List(ctx, q)
		if err != nil || len(got) != want {
			t.Errorf("%s: %d (%v), ожидалось %d", in, len(got), err, want)
		}
		if n, err := e.st.Count(ctx, q, 100); err != nil || n != want {
			t.Errorf("%s: подсчёт %d (%v)", in, n, err)
		}
	}
	// Подсчёт останавливается на limit+1.
	if n, err := e.st.Count(ctx, lastHour(), 2); err != nil || n != 3 {
		t.Fatalf("подсчёт с пределом: %d %v", n, err)
	}
	// Снимок по времени приёма.
	q = lastHour()
	q.ReceivedBefore = time.Now().Add(-time.Hour)
	if n, err := e.st.Count(ctx, q, 100); err != nil || n != 0 {
		t.Fatalf("снимок: %d %v", n, err)
	}
	// Выгрузка с подробностями, без содержимого.
	q = lastHour()
	q.WithDetails = true
	var rows int
	if err := e.st.Each(ctx, q, func(r *events.Record) error {
		rows++
		if r.Details == nil || r.Details.Decision == nil {
			t.Fatalf("нет подробностей: %+v", r)
		}
		return nil
	}); err != nil || rows != 5 {
		t.Fatalf("выгрузка: %d %v", rows, err)
	}
	stop := errors.New("стоп")
	if err := e.st.Each(ctx, q, func(*events.Record) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("ошибка обработчика: %v", err)
	}
	card, err := e.st.Card(ctx, evs[0].ID)
	if err != nil || card.Details == nil || len(card.Details.Findings) != 1 || card.App != "crm" {
		t.Fatalf("карточка: %+v %v", card, err)
	}
	if _, err := e.st.Card(ctx, "01900000-0000-7000-8000-000000000099"); !errors.Is(err, events.ErrNotFound) {
		t.Fatalf("нет события: %v", err)
	}
	// Период длиннее предела — отказ до запроса к БД.
	q = lastHour()
	q.From = q.To.Add(-events.MaxQueryRange - time.Second)
	if _, err := e.st.List(ctx, q); !errors.Is(err, events.ErrBadRange) {
		t.Fatalf("период: %v", err)
	}
}

func TestPGEventsRetentionSettings(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	r, err := e.st.Retention(ctx)
	if err != nil || r.MetadataDays != 365 || r.ContentDays != 90 {
		t.Fatalf("умолчания: %+v %v", r, err)
	}
	by := audit.Actor{Type: audit.ActorUser, ID: testUser, Name: "admin"}
	ip := netip.MustParseAddr("192.0.2.10")
	if _, err := e.st.SetRetention(ctx, events.Retention{MetadataDays: 30, ContentDays: 60}, by, ip); !errors.Is(err, events.ErrBadRetention) {
		t.Fatalf("содержимое дольше метаданных: %v", err)
	}
	old, err := e.st.SetRetention(ctx, events.Retention{MetadataDays: 180, ContentDays: 14}, by, ip)
	if err != nil || old.MetadataDays != 365 {
		t.Fatalf("изменение: %+v %v", old, err)
	}
	if r, err := e.st.Retention(ctx); err != nil || r.MetadataDays != 180 || r.ContentDays != 14 {
		t.Fatalf("после изменения: %+v %v", r, err)
	}
	var details string
	if err := e.owner.QueryRow(ctx, `SELECT details::text FROM audit_log WHERE action = 'events.settings_changed'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if details != `{"after":{"content_days":14,"metadata_days":180},"before":{"content_days":90,"metadata_days":365},"reduced":true}` {
		t.Fatalf("запись аудита: %s", details)
	}
	// Ограничение таблицы — вторая линия защиты.
	if _, err := e.app.Exec(ctx, "UPDATE event_settings SET content_days = 3"); err == nil {
		t.Fatal("срок содержимого 3 суток принят БД")
	}
}

func TestPGEventsSavedFilters(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.owner.Exec(ctx, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash,
		password_changed_at, must_change_password, created_at, created_by)
		VALUES ($1, $2, 'analyst1', 'Аналитик', 'analyst', 'active', 'x', now(), false, now(), 'test')`, testUser, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	f, err := events.ParseFilter(`app in ("crm") and stream = true`)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := e.st.SaveFilter(ctx, testUser, "Поток CRM", f)
	if err != nil || sf.Filter != `app = "crm" and stream = true` {
		t.Fatalf("сохранение: %+v %v", sf, err)
	}
	if _, err := e.st.SaveFilter(ctx, testUser, "Поток CRM", f); !errors.Is(err, events.ErrFilterExists) {
		t.Fatalf("повтор имени: %v", err)
	}
	list, err := e.st.Filters(ctx, testUser)
	if err != nil || len(list) != 1 || list[0].ID != sf.ID {
		t.Fatalf("список: %+v %v", list, err)
	}
	if list, err := e.st.Filters(ctx, "01900000-0000-7000-8000-0000000000b2"); err != nil || len(list) != 0 {
		t.Fatalf("чужой список: %+v %v", list, err)
	}
	if err := e.st.DeleteFilter(ctx, "01900000-0000-7000-8000-0000000000b2", sf.ID); !errors.Is(err, events.ErrNotFound) {
		t.Fatalf("удаление чужого: %v", err)
	}
	if err := e.st.DeleteFilter(ctx, testUser, sf.ID); err != nil {
		t.Fatal(err)
	}
	for i := range events.MaxSavedFilters {
		if _, err := e.st.SaveFilter(ctx, testUser, "f"+string(rune('a'+i%26))+string(rune('a'+i/26)), events.Filter{}); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := e.st.SaveFilter(ctx, testUser, "лишний", events.Filter{}); !errors.Is(err, events.ErrTooManyFilters) {
		t.Fatalf("предел: %v", err)
	}
}

// bypassImmutable выполняет sql в обход триггера неизменяемости (только
// тесты, суперпользователь): так моделируется время приёма в прошлом.
func bypassImmutable(t *testing.T, e *pgEnv, sql string, args ...any) {
	t.Helper()
	ctx := pgCtx(t)
	tx, err := e.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() //nolint:gosec // G104: откат после фиксации безвреден
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// Пересчёт агрегатов идемпотентен; позднее событие учитывается.
func TestPGEventsAggregates(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	seed(t, e, 4)
	// Отметка — в прошлом, а задание учитывает события старше минуты:
	// сдвигаем время приёма назад.
	bypassImmutable(t, e, "UPDATE events SET received_at = received_at - interval '5 minutes'")
	run := func() {
		t.Helper()
		for range 64 {
			res, err := e.st.Aggregate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(res.Upto) < 2*time.Minute {
				return
			}
		}
		t.Fatal("задание не догнало текущее время")
	}
	run()
	sum := func(interval string) (n, tokens, dm05 int64) {
		t.Helper()
		now := time.Now().UTC()
		rows, err := e.st.Aggregates(ctx, events.StatsQuery{Interval: interval, From: now.Add(-3 * time.Hour), To: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range rows {
			n += a.Events
			tokens += a.TokensPrompt
			dm05 += a.Threats["DM-05"]
		}
		return n, tokens, dm05
	}
	if n, tok, dm := sum(events.IntervalMinute); n != 4 || tok != 40 || dm != 2 {
		t.Fatalf("минуты: %d %d %d", n, tok, dm)
	}
	if n, _, dm := sum(events.IntervalHour); n != 4 || dm != 2 {
		t.Fatalf("часы: %d %d", n, dm)
	}
	// Повторный пересчёт тех же минут не удваивает счётчики.
	if _, err := e.owner.Exec(ctx, "UPDATE event_aggregate_state SET received_upto = now() - interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	run()
	if n, _, _ := sum(events.IntervalMinute); n != 4 {
		t.Fatalf("повторный пересчёт: %d", n)
	}
	// Событие, принятое после прошлого запуска (шлюз досылал очередь), —
	// его минута пересчитывается заново.
	late := seed(t, e, 1)
	if _, err := e.owner.Exec(ctx, "UPDATE event_aggregate_state SET received_upto = now() - interval '2 minutes'"); err != nil {
		t.Fatal(err)
	}
	bypassImmutable(t, e, "UPDATE events SET received_at = now() - interval '90 seconds' WHERE id = $1", late[0].ID)
	run()
	if n, _, _ := sum(events.IntervalHour); n != 5 {
		t.Fatalf("позднее событие: %d", n)
	}
	// Два одновременных пересчёта не мешают друг другу.
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := e.st.Aggregate(context.WithoutCancel(ctx))
			errs <- err
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
