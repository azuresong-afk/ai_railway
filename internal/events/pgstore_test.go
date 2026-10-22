package events_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/keyring/keyringtest"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются
// (в CI PostgreSQL нет). Каждый тест — в своей схеме; сервер работает под
// ролью aisec_app, как в установке.

const testGateway = "01900000-0000-7000-8000-0000000000a1"

type pgEnv struct {
	owner, app *pgxpool.Pool
	dsn        string
	schema     string
	box        *keyring.Box
	log        *audit.Log
	st         *events.PGStore
	ids        *ids.Generator
	keyID      string
}

func pgCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func newPool(t *testing.T, dsn, schema, role string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 8
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	if role != "" {
		cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, "SELECT set_config('role', $1, false)", role)
			return err
		}
	}
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

type poolExec struct{ p *pgxpool.Pool }

func (e poolExec) InTx(ctx context.Context, fn func(store.Tx) error) error {
	tx, err := e.p.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() //nolint:gosec // G104: откат после фиксации безвреден
	if err := fn(poolTx{tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type poolTx struct{ tx pgx.Tx }

func (t poolTx) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := t.tx.Exec(ctx, sql, args...)
	return err
}

func (t poolTx) Applied(ctx context.Context) ([]store.Applied, error) {
	rows, err := t.tx.Query(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.Applied, error) {
		var a store.Applied
		err := r.Scan(&a.Version, &a.Name, &a.Checksum)
		return a, err
	})
}

func setupPG(t *testing.T) *pgEnv {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgCtx(t)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "ev_test_" + hex.EncodeToString(b)
	admin := newPool(t, dsn, "public", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE") //nolint:gosec // G104: уборка тестовой схемы
	})
	owner := newPool(t, dsn, schema, "")
	ms, err := store.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&store.Migrator{Exec: poolExec{owner}, Hasher: h, Migrations: ms}).Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO aisec_app"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO gateways (id, org_id, name, status, created_at, created_by)
		VALUES ($1, $2, 'gw-1', 'pending', now(), 'cli:test')`, testGateway, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	dir, keyID := keyringtest.Install(t, ctx, owner, p, audit.DefaultOrgID)
	app := newPool(t, dsn, schema, "aisec_app")
	box, err := keyring.Load(ctx, app, p, dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := events.NewPGStore(app, box, l, "", events.WithRandom(r))
	if err != nil {
		t.Fatal(err)
	}
	return &pgEnv{owner: owner, app: app, dsn: dsn, schema: schema, box: box, log: l, st: st, ids: ids.NewGenerator(r), keyID: keyID}
}

func (e *pgEnv) event(t *testing.T, storage string, c *events.Content) events.Event {
	t.Helper()
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	return events.Event{
		ID: u.String(), Time: u.Time().Add(-time.Millisecond), Type: events.TypeGatewayRequest, App: "support-bot", Env: "prod",
		User: "a1b2c3", Provider: "mock", Model: "mock-echo", PolicyMode: events.ModeEnforce, Storage: storage,
		Decision: &events.Decision{Action: "block", Applied: []string{"block"}, Rule: "injection", Severity: "high"},
		Findings: []events.Finding{{Detector: "injection.ru", Category: "injection", Score: 0.9, Threat: "DM-01"}},
		Threats:  []string{"DM-01"}, LatencyMS: map[string]int64{"total": 12}, Content: c,
	}
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestPGEventsInsertContent(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	n, err := e.st.EnsurePartitions(ctx)
	if err != nil || n != 2*(events.PartitionsBack+events.PartitionsAhead+1) {
		t.Fatalf("секции: %d %v", n, err)
	}
	if n, err := e.st.EnsurePartitions(ctx); err != nil || n != 0 {
		t.Fatalf("повторное создание секций: %d %v", n, err)
	}
	promptText := "Паспорт 4510 123456, СНИЛС 112-233-445 95"
	none := e.event(t, events.StorageNone, nil)
	masked := e.event(t, events.StorageMasked, &events.Content{Request: "Паспорт [passport]"})
	full := e.event(t, events.StorageFull, &events.Content{Request: promptText, Response: "Готово"})
	started := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	in := events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{none, masked, full},
		Stats: &events.SenderStats{StartedAt: started, Dropped: 5, Rejected: 1}}
	res, err := e.st.Insert(ctx, in)
	if err != nil || res.Accepted != 3 || res.Duplicates != 0 || res.Truncated != 0 || len(res.Rejected) != 0 {
		t.Fatalf("запись: %+v %v", res, err)
	}
	// Повтор пакета — дубли пропускаются, содержимое не перезаписывается.
	in.Stats = &events.SenderStats{StartedAt: started, Dropped: 3, Rejected: 1}
	if res, err := e.st.Insert(ctx, in); err != nil || res.Accepted != 0 || res.Duplicates != 3 {
		t.Fatalf("повтор: %+v %v", res, err)
	}
	var count, contents int
	if err := e.owner.QueryRow(ctx, "SELECT (SELECT count(*) FROM events), (SELECT count(*) FROM event_content)").Scan(&count, &contents); err != nil {
		t.Fatal(err)
	}
	if count != 3 || contents != 2 {
		t.Fatalf("событий %d, содержимого %d", count, contents)
	}
	// Счётчики шлюза не уменьшаются от старого пакета того же запуска.
	var dropped int64
	if err := e.owner.QueryRow(ctx, "SELECT dropped FROM gateway_event_stats WHERE gateway_id = $1", testGateway).Scan(&dropped); err != nil || dropped != 5 {
		t.Fatalf("счётчик отброшенных: %d %v", dropped, err)
	}
	// Метаданные: шлюз из Ingest, действие и угрозы — в столбцах, без содержимого.
	var gw, action string
	var threats []string
	var details []byte
	if err := e.owner.QueryRow(ctx, "SELECT gateway_id::text, action, threats, details::text FROM events WHERE id = $1", full.ID).
		Scan(&gw, &action, &threats, &details); err != nil {
		t.Fatal(err)
	}
	if gw != testGateway || action != "block" || !slices.Equal(threats, []string{"DM-01"}) || bytes.Contains(details, []byte("4510")) {
		t.Fatalf("строка события: %s %s %v %s", gw, action, threats, details)
	}
	// full: в БД только шифротекст производного ключа суток.
	var sealed []byte
	var keyID, keyDay string
	var req *string
	if err := e.owner.QueryRow(ctx, "SELECT sealed, key_id::text, key_day::text, request FROM event_content WHERE event_id = $1", full.ID).
		Scan(&sealed, &keyID, &keyDay, &req); err != nil {
		t.Fatal(err)
	}
	ts, err := events.PartitionTime(full.ID)
	if err != nil {
		t.Fatal(err)
	}
	if req != nil || bytes.Contains(sealed, []byte("4510")) || keyID != e.keyID || keyDay != ts.UTC().Format(time.DateOnly) {
		t.Fatalf("шифротекст: открытый текст %v, ключ %s, сутки %s", req, keyID, keyDay)
	}
	got, err := e.st.Content(ctx, full.ID)
	if err != nil || got.Storage != events.StorageFull || got.Content.Request != promptText || got.Content.Response != "Готово" {
		t.Fatalf("расшифровка: %+v %v", got, err)
	}
	if got, err := e.st.Content(ctx, masked.ID); err != nil || got.Content.Request != "Паспорт [passport]" {
		t.Fatalf("masked: %+v %v", got, err)
	}
	if _, err := e.st.Content(ctx, none.ID); !errors.Is(err, events.ErrNotFound) {
		t.Fatalf("none: %v", err)
	}
	var used int64
	if err := e.owner.QueryRow(ctx, "SELECT sealed FROM derived_key_usage WHERE purpose = 'event-content'").Scan(&used); err != nil || used != 4096 {
		t.Fatalf("счётчик производного ключа: %d %v", used, err)
	}
}

// Шифротекст, переставленный в строку другого события, не расшифровывается
// (AAD — таблица, столбец и ID строки, Р4).
func TestPGEventsSwappedCiphertext(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	a := e.event(t, events.StorageFull, &events.Content{Request: "секрет A"})
	b := e.event(t, events.StorageNone, nil)
	if _, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{a, b}}); err != nil {
		t.Fatal(err)
	}
	tb, err := events.PartitionTime(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Владелец схемы копирует шифротекст A в строку B (в обход продукта).
	if _, err := e.owner.Exec(ctx, `INSERT INTO event_content (event_id, ts, org_id, storage, key_id, key_day, alg, sealed)
		SELECT $1, $2, org_id, storage, key_id, ($2::timestamptz AT TIME ZONE 'UTC')::date, alg, sealed
		FROM event_content WHERE event_id = $3`, b.ID, tb, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Content(ctx, b.ID); !errors.Is(err, aisecCrypto.ErrDecrypt) {
		t.Fatalf("переставленный шифротекст: %v", err)
	}
}

// Права роли сервера: только добавление и чтение; секции — только функциями.
func TestPGEventsAppRights(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	ev := e.event(t, events.StorageMasked, &events.Content{Request: "x"})
	if _, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev}}); err != nil {
		t.Fatal(err)
	}
	part := "events_p" + time.Now().UTC().Format("20060102")
	for sql, want := range map[string]string{
		"UPDATE events SET app = 'x'": "42501",
		"DELETE FROM events":          "42501",
		"DELETE FROM event_content":   "42501",
		"TRUNCATE events":             "42501",
		"DROP TABLE " + part:          "42501",
		// Сроки хранения сервер меняет (2.16), но только эти столбцы.
		"UPDATE event_settings SET id = false":        "42501",
		"DELETE FROM event_settings":                  "42501",
		"UPDATE event_filters SET filter = ''":        "42501",
		"DELETE FROM event_aggregate_state":           "42501",
		"UPDATE event_aggregate_state SET id = false": "42501",
		"CREATE TABLE events_p20990101 PARTITION OF events FOR VALUES FROM ('2099-01-01') TO ('2099-01-02')": "42501",
		"SELECT events_ensure_partitions(100, 0)":                                                            "22023",
	} {
		if _, err := e.app.Exec(ctx, sql); sqlState(err) != want {
			t.Errorf("%s: %v (ожидался %s)", sql, err, want)
		}
	}
	// Даже владелец не меняет и не удаляет события построчно.
	for _, sql := range []string{"UPDATE events SET app = 'x'", "DELETE FROM event_content"} {
		if _, err := e.owner.Exec(ctx, sql); sqlState(err) != "23514" {
			t.Errorf("владелец, %s: %v", sql, err)
		}
	}
}

// Событие вне существующих секций не записывается: нужен повтор после
// создания секций.
func TestPGEventsNoPartition(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	ev := e.event(t, events.StorageNone, nil)
	_, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev}})
	if !errors.Is(err, events.ErrNoPartition) {
		t.Fatalf("без секций: %v", err)
	}
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	if res, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev}}); err != nil || res.Accepted != 1 {
		t.Fatalf("после создания секций: %+v %v", res, err)
	}
}

// Событие, которое СУБД отвергла (Check в обход), не губит пакет: пакет
// записывается по одному событию, отказ — только у отвергнутых (В10 ревью
// 2.r3a). Проверяются NUL в тексте и чужой policy_mode у auth_failure.
func TestPGEventsRejectOneOfBatch(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	nul := e.event(t, events.StorageNone, nil)
	nul.App = "a\x00b"
	mode := e.event(t, events.StorageNone, nil)
	mode.Type, mode.App, mode.Decision = events.TypeAuthFailure, "", nil
	mode.AuthFailure = &events.AuthFailure{RemoteAddr: "192.0.2.1", Reason: "invalid_key"}
	mode.PolicyMode = "audit"
	good := e.event(t, events.StorageFull, &events.Content{Request: "запрос", Response: "ответ"})
	plain := e.event(t, events.StorageMasked, &events.Content{Request: "x"})
	stats := &events.SenderStats{StartedAt: time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond), Dropped: 2}
	res, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(),
		Events: []events.Event{nul, good, mode, plain}, Stats: stats})
	if err != nil || res.Accepted != 2 || res.Duplicates != 0 || !slices.Equal(res.Rejected, []int{0, 2}) {
		t.Fatalf("пакет с отвергнутыми событиями: %+v %v", res, err)
	}
	if got, err := e.st.Content(ctx, good.ID); err != nil || got.Content.Request != "запрос" {
		t.Fatalf("содержимое принятого события: %+v %v", got, err)
	}
	var count int
	var dropped int64
	if err := e.owner.QueryRow(ctx, "SELECT (SELECT count(*) FROM events), (SELECT dropped FROM gateway_event_stats)").
		Scan(&count, &dropped); err != nil || count != 2 || dropped != 2 {
		t.Fatalf("строк событий %d, счётчик %d: %v", count, dropped, err)
	}
	// Повтор пакета: принятые — дубли, отвергнутые — снова отказ.
	res, err = e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(),
		Events: []events.Event{nul, good, mode, plain}})
	if err != nil || res.Accepted != 0 || res.Duplicates != 2 || !slices.Equal(res.Rejected, []int{0, 2}) {
		t.Fatalf("повтор: %+v %v", res, err)
	}
}

// Содержимое full из 64 КиБ «<» и управляющих символов не помещалось в
// предел шифротекста и губило пакет (В10 ревью 2.r3a). Теперь оно
// обрезается, событие записывается с отметкой content_truncated, соседние
// события пакета — как обычно.
func TestPGEventsTruncateLargeContent(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	lt := strings.Repeat("<", events.MaxContentBytes)
	ctl := strings.Repeat("\x01", events.MaxContentBytes)
	html := e.event(t, events.StorageFull, &events.Content{Request: lt, Response: lt})
	ctrl := e.event(t, events.StorageFull, &events.Content{Request: ctl, Response: ctl})
	small := e.event(t, events.StorageFull, &events.Content{Request: "обычный запрос"})
	none := e.event(t, events.StorageNone, nil)
	for _, ev := range []events.Event{html, ctrl, small, none} {
		if code := events.Check(&ev, time.Now()); code != "" {
			t.Fatalf("Check: %s", code)
		}
	}
	res, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(),
		Events: []events.Event{html, ctrl, small, none}})
	if err != nil || res.Accepted != 4 || res.Truncated != 1 || len(res.Rejected) != 0 {
		t.Fatalf("запись: %+v %v", res, err)
	}
	// «<» без HTML-экранирования помещается целиком.
	if got, err := e.st.Content(ctx, html.ID); err != nil || got.Content.Request != lt || got.Content.Response != lt {
		t.Fatalf("«<»: %v", err)
	}
	got, err := e.st.Content(ctx, ctrl.ID)
	if err != nil || !strings.HasSuffix(got.Content.Request, "…") || !strings.HasPrefix(ctl, strings.TrimSuffix(got.Content.Request, "…")) ||
		len(got.Content.Request) < 20000 {
		t.Fatalf("обрезанное содержимое: %d байт, %v", len(got.Content.Request), err)
	}
	for id, want := range map[string]bool{html.ID: false, ctrl.ID: true, small.ID: false} {
		rec, err := e.st.Card(ctx, id)
		if err != nil || rec.Details == nil || rec.Details.ContentTruncated != want {
			t.Fatalf("отметка обрезки %s: %+v %v", id, rec.Details, err)
		}
	}
	var size int
	if err := e.owner.QueryRow(ctx, "SELECT octet_length(sealed) FROM event_content WHERE event_id = $1", ctrl.ID).Scan(&size); err != nil ||
		size > events.MaxSealedBytes {
		t.Fatalf("размер шифротекста %d: %v", size, err)
	}
}

// Сроки хранения: удаляются только секции старше настроек, с записью в аудит.
func TestPGEventsRetention(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	day := func(d int) time.Time { return today.AddDate(0, 0, d) }
	// Старые секции создаёт владелец (как будто события копились давно).
	for _, d := range []int{-400, -100, -40} {
		for _, parent := range []string{"events", "event_content"} {
			name := fmt.Sprintf("%s_p%s", parent, day(d).Format("20060102"))
			if _, err := e.owner.Exec(ctx, fmt.Sprintf("CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
				name, parent, day(d).Format(time.RFC3339), day(d+1).Format(time.RFC3339))); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Секция с чужим именем не трогается.
	if _, err := e.owner.Exec(ctx, fmt.Sprintf("CREATE TABLE events_manual PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')",
		day(-500).Format(time.RFC3339), day(-499).Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	dropped, err := e.st.DropExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// По умолчанию: метаданные 365 суток, содержимое 90.
	want := []string{
		"event_content_p" + day(-400).Format("20060102"), "event_content_p" + day(-100).Format("20060102"),
		"events_p" + day(-400).Format("20060102"),
	}
	if !slices.Equal(dropped, want) {
		t.Fatalf("удалены %v, ожидались %v", dropped, want)
	}
	var n int
	if err := e.owner.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action = 'events.retention'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("записей аудита %d %v", n, err)
	}
	if again, err := e.st.DropExpired(ctx); err != nil || len(again) != 0 {
		t.Fatalf("повтор: %v %v", again, err)
	}
	if err := e.owner.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action = 'events.retention'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("пустое удаление записано в аудит: %d %v", n, err)
	}
	// Сокращение срока — только через настройки (у сервера права нет).
	if _, err := e.owner.Exec(ctx, "UPDATE event_settings SET metadata_days = 30, content_days = 7"); err != nil {
		t.Fatal(err)
	}
	dropped, err = e.st.DropExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{
		"event_content_p" + day(-40).Format("20060102"), "events_p" + day(-100).Format("20060102"), "events_p" + day(-40).Format("20060102"),
	}
	if !slices.Equal(dropped, want) {
		t.Fatalf("удалены %v, ожидались %v", dropped, want)
	}
	// Секции окна приёма (7 суток назад) на месте при минимальных сроках.
	for _, parent := range []string{"events", "event_content"} {
		var ok bool
		name := parent + "_p" + day(-events.PartitionsBack).Format("20060102")
		if err := e.owner.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", name).Scan(&ok); err != nil || !ok {
			t.Fatalf("%s удалена: %v", name, err)
		}
	}
	if _, err := e.owner.Exec(ctx, "UPDATE event_settings SET content_days = 6"); sqlState(err) != "23514" {
		t.Fatalf("содержимое меньше 7 суток: %v", err)
	}
}

// received_at ставят часы СУБД, а не приложения (Н22 ревью 2.r3a): при
// отставании часов сервера приложения событие не попадает в уже пройденное
// окно агрегатов.
func TestPGEventsReceivedAtFromDB(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	ev := e.event(t, events.StorageNone, nil)
	if _, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now().Add(-time.Hour), Events: []events.Event{ev}}); err != nil {
		t.Fatal(err)
	}
	var lag time.Duration
	if err := e.owner.QueryRow(ctx, "SELECT now() - received_at FROM events WHERE id = $1", ev.ID).Scan(&lag); err != nil {
		t.Fatal(err)
	}
	if lag > time.Minute || lag < -time.Minute {
		t.Fatalf("received_at отстаёт от часов СУБД на %v", lag)
	}
}

// hookFunc — IngestHook из функции.
type hookFunc func(ctx context.Context, tx pgx.Tx, gatewayID string, accepted []*events.Event) error

func (f hookFunc) OnIngest(ctx context.Context, tx pgx.Tx, gatewayID string, accepted []*events.Event) error {
	return f(ctx, tx, gatewayID, accepted)
}

// Точка вызова движка оповещений (ADR-0020): в транзакцию приёма приходят
// только впервые записанные события; ошибка движка откатывает весь пакет.
func TestPGIngestHook(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	var got []string
	fail := false
	errHook := errors.New("движок оповещений недоступен")
	st, err := events.NewPGStore(e.app, e.box, e.log, "", events.WithIngestHook(hookFunc(
		func(_ context.Context, _ pgx.Tx, gw string, acc []*events.Event) error {
			if gw != testGateway {
				t.Errorf("шлюз %s", gw)
			}
			if fail {
				return errHook
			}
			for _, ev := range acc {
				got = append(got, ev.ID)
			}
			return nil
		})))
	if err != nil {
		t.Fatal(err)
	}
	a, b := e.event(t, events.StorageNone, nil), e.event(t, events.StorageNone, nil)
	if _, err := st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{a}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{a, b}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{a.ID, b.ID}) {
		t.Fatalf("в движок переданы %v", got)
	}
	fail = true
	c := e.event(t, events.StorageNone, nil)
	if _, err := st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{c}}); !errors.Is(err, errHook) {
		t.Fatalf("ошибка движка: %v", err)
	}
	var n int
	if err := e.owner.QueryRow(ctx, "SELECT count(*) FROM events WHERE id = $1", c.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("пакет не откатился: %d %v", n, err)
	}
}
