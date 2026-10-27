package reports_test

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/keyring/keyringtest"
	"github.com/azuresong-afk/ai_railway/internal/reports"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

const (
	pgGateway = "01900000-0000-7000-8000-0000000000a1"
	pgChannel = "01900000-0000-7000-8000-0000000000c1"
)

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

type pgEnv struct {
	owner, app *pgxpool.Pool
	log        *audit.Log
	events     *events.PGStore
	store      *reports.PGStore
	ids        *ids.Generator
}

func setupPG(t *testing.T) (context.Context, *pgEnv) {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
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
	schema := "rp_test_" + hex.EncodeToString(b)
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
		VALUES ($1, $2, 'gw-1', 'pending', now(), 'cli:test')`, pgGateway, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO notify_channels (id, org_id, name, type, enabled, min_severity, settings, secret_fields, version,
		created_at, created_by, updated_at, updated_by) VALUES ($1, $2, 'smtp', 'email', true, 'info', '{}', '{}', 1, now(), 'cli:test', now(), 'cli:test')`,
		pgChannel, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	dir, _ := keyringtest.Install(t, ctx, owner, p, audit.DefaultOrgID)
	app := newPool(t, dsn, schema, "aisec_app")
	box, err := keyring.Load(ctx, app, p, dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := events.NewPGStore(app, box, l, "", events.WithRandom(r))
	if err != nil {
		t.Fatal(err)
	}
	st, err := reports.NewPGStore(app, l, "")
	if err != nil {
		t.Fatal(err)
	}
	return ctx, &pgEnv{owner: owner, app: app, log: l, events: ev, store: st, ids: ids.NewGenerator(r)}
}

func (e *pgEnv) schedule(t *testing.T, name string) reports.Schedule {
	t.Helper()
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return reports.Schedule{ID: u.String(), Name: name, Report: reports.KindPilot, Frequency: reports.FreqWeekly, Weekday: 1, At: "08:00",
		Format: reports.FormatXLSX, ChannelID: pgChannel, Enabled: true, NextRunAt: now.Add(-time.Minute), Version: 1,
		CreatedAt: now, CreatedBy: "user:u1", UpdatedAt: now, UpdatedBy: "user:u1"}
}

func entry(action, id string) audit.Entry {
	return audit.Entry{Actor: audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "admin"}, Action: action, Result: audit.ResultSuccess,
		Object: audit.Object{Type: "report_schedule", ID: id}, Details: map[string]any{"k": "v"}}
}

func (e *pgEnv) auditCount(t *testing.T, ctx context.Context, action string) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Расписания и журнал рассылки на PostgreSQL: запись и аудит — одной
// транзакцией, очередь выбирается без повторов, удаление снимает журнал.
func TestPGReportSchedules(t *testing.T) {
	ctx, e := setupPG(t)
	s := e.schedule(t, "Еженедельный")
	if err := e.store.CreateSchedule(ctx, s, entry("report_schedule.create", s.ID)); err != nil {
		t.Fatal(err)
	}
	if e.auditCount(t, ctx, "report_schedule.create") != 1 {
		t.Fatal("нет записи аудита создания")
	}
	dup := e.schedule(t, "Еженедельный")
	var ie *reports.InputError
	if err := e.store.CreateSchedule(ctx, dup, entry("report_schedule.create", dup.ID)); !errors.As(err, &ie) || ie.Fields["name"] == "" {
		t.Fatalf("повтор названия: %v", err)
	}
	// Отказ транзакции не оставляет записи аудита.
	if e.auditCount(t, ctx, "report_schedule.create") != 1 {
		t.Error("запись аудита осталась после отката")
	}
	got, err := e.store.Schedule(ctx, s.ID)
	if err != nil || got.Weekday != 1 || got.Day != 0 || got.At != "08:00" || !got.LastRunAt.IsZero() {
		t.Fatalf("чтение: %+v %v", got, err)
	}
	if _, err := e.store.Schedule(ctx, "01900000-0000-7000-8000-0000000000ff"); !errors.Is(err, reports.ErrNotFound) {
		t.Fatalf("нет расписания: %v", err)
	}
	upd, err := e.store.UpdateSchedule(ctx, s.ID, func(old reports.Schedule) (reports.Schedule, audit.Entry, error) {
		old.Frequency, old.Weekday, old.Day, old.Version = reports.FreqMonthly, 0, 5, old.Version+1
		return old, entry("report_schedule.update", s.ID), nil
	})
	if err != nil || upd.Day != 5 || upd.Weekday != 0 {
		t.Fatalf("изменение: %+v %v", upd, err)
	}

	// Очередь: расписание со сроком ставится один раз, срок сдвигается.
	now := time.Now().UTC().Truncate(time.Microsecond)
	plan := func(sc reports.Schedule) (reports.Run, time.Time, error) {
		u, err := e.ids.New()
		if err != nil {
			return reports.Run{}, time.Time{}, err
		}
		return reports.Run{ID: u.String(), DueAt: sc.NextRunAt, PeriodFirst: "2026-09-01", PeriodLast: "2026-09-30", Status: reports.RunPending,
			NextAt: now, CreatedAt: now, UpdatedAt: now}, now.Add(24 * time.Hour), nil
	}
	if n, err := e.store.EnqueueDue(ctx, now, 10, plan); err != nil || n != 1 {
		t.Fatalf("постановка: %d %v", n, err)
	}
	if n, err := e.store.EnqueueDue(ctx, now, 10, plan); err != nil || n != 0 {
		t.Fatalf("повторная постановка: %d %v", n, err)
	}
	r, sc, ok, err := e.store.ClaimRun(ctx, now, 10*time.Minute)
	if err != nil || !ok || r.ScheduleID != s.ID || sc.ID != s.ID || r.PeriodFirst != "2026-09-01" || r.PeriodLast != "2026-09-30" {
		t.Fatalf("выборка: %+v %v %v", r, ok, err)
	}
	if _, _, ok, _ := e.store.ClaimRun(ctx, now, 10*time.Minute); ok { //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
		t.Fatal("запуск выдан дважды")
	}
	r.Attempts, r.Status, r.SentAt, r.UpdatedAt = 1, reports.RunSent, now, now
	rec := entry("data.export", s.ID)
	if err := e.store.FinishRun(ctx, r, &rec); err != nil {
		t.Fatal(err)
	}
	runs, err := e.store.Runs(ctx, s.ID, 10)
	if err != nil || len(runs) != 1 || runs[0].Status != reports.RunSent || runs[0].Error != "" || runs[0].SentAt.IsZero() {
		t.Fatalf("журнал: %+v %v", runs, err)
	}
	if e.auditCount(t, ctx, "data.export") != 1 {
		t.Error("нет записи data.export")
	}
	// Код ошибки — только латиница и подчёркивание (ограничение схемы).
	r.Status, r.Error = reports.RunFailed, "Ошибка: текст ответа"
	r.SentAt = time.Time{}
	if err := e.store.FinishRun(ctx, r, nil); err == nil {
		t.Error("текст ошибки принят в журнал")
	}
	// 3Н47 ревью 3.r4: роль сервера удаляет завершённые запуски старше срока.
	if n, err := e.store.PruneRuns(ctx, now); err != nil || n != 0 {
		t.Fatalf("очистка свежего журнала: %d %v", n, err)
	}
	if n, err := e.store.PruneRuns(ctx, now.Add(time.Second)); err != nil || n != 1 {
		t.Fatalf("очистка старого запуска: %d %v", n, err)
	}
	// Приложение не удаляет журнал доставки напрямую, только вместе с расписанием.
	if err := e.store.DeleteSchedule(ctx, s.ID, func(old reports.Schedule) audit.Entry { return entry("report_schedule.delete", old.ID) }); err != nil {
		t.Fatal(err)
	}
	if runs, _ := e.store.Runs(ctx, s.ID, 10); len(runs) != 0 { //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
		t.Error("журнал остался после удаления")
	}
	if e.auditCount(t, ctx, "report_schedule.delete") != 1 {
		t.Error("нет записи аудита удаления")
	}
}

func TestPGReportScheduleLimit(t *testing.T) {
	ctx, e := setupPG(t)
	for i := 0; i < reports.MaxSchedules; i++ {
		s := e.schedule(t, "Расписание "+string(rune('a'+i%26))+strings.Repeat("x", i/26))
		if err := e.store.CreateSchedule(ctx, s, entry("report_schedule.create", s.ID)); err != nil {
			t.Fatal(i, err)
		}
	}
	s := e.schedule(t, "Лишнее")
	if err := e.store.CreateSchedule(ctx, s, entry("report_schedule.create", s.ID)); !errors.Is(err, reports.ErrTooMany) {
		t.Fatalf("предел: %v", err)
	}
}

// Отметки аналитиков за период: счётчики и ложные срабатывания по строкам матрицы.
func TestPGReportMarks(t *testing.T) {
	ctx, e := setupPG(t)
	if _, err := e.events.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	var evs []events.Event
	for i, app := range []string{"crm", "crm", "hr"} {
		u, err := e.ids.New()
		if err != nil {
			t.Fatal(err)
		}
		evs = append(evs, events.Event{ID: u.String(), Time: u.Time().Add(-time.Millisecond), Type: events.TypeGatewayRequest, App: app, Env: "prod",
			User: "a1b2c3", Provider: "mock", Model: "mock-echo", PolicyMode: events.ModeEnforce, Storage: events.StorageNone,
			Decision: &events.Decision{Action: "block", Applied: []string{"block"}, Rule: "injection", Severity: "high"},
			Findings: []events.Finding{{Detector: "injection.ru", Category: "injection", Score: 0.9, Threat: "DM-0" + string(rune('1'+i%2))}},
			Threats:  []string{"DM-0" + string(rune('1'+i%2))}, LatencyMS: map[string]int64{"total": 12}})
	}
	if _, err := e.events.Insert(ctx, events.Ingest{GatewayID: pgGateway, ReceivedAt: time.Now(), Events: evs}); err != nil {
		t.Fatal(err)
	}
	by := audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "analyst"}
	ip := netip.MustParseAddr("192.0.2.1")
	for i, m := range []string{events.MarkFalsePositive, events.MarkFalsePositive, events.MarkConfirmed} {
		if _, err := e.events.SetMark(ctx, evs[i].ID, events.Mark{Mark: m}, by, ip); err != nil {
			t.Fatal(err)
		}
	}
	f := &reports.PGFacts{DB: e.app, OrgID: audit.DefaultOrgID}
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	ms, err := f.Marks(ctx, from, to, "")
	if err != nil || ms.FalsePositive != 2 || ms.Confirmed != 1 || len(ms.FalseByThreat) != 2 {
		t.Fatalf("все приложения: %+v %v", ms, err)
	}
	if ms, err = f.Marks(ctx, from, to, "crm"); err != nil || ms.FalsePositive != 2 || ms.Confirmed != 0 {
		t.Fatalf("crm: %+v %v", ms, err)
	}
	if ms, err = f.Marks(ctx, from, to, "hr"); err != nil || ms.FalsePositive != 0 || ms.Confirmed != 1 {
		t.Fatalf("hr: %+v %v", ms, err)
	}
	if ms, err = f.Marks(ctx, to, to.Add(time.Hour), ""); err != nil || ms.FalsePositive != 0 || ms.Confirmed != 0 {
		t.Fatalf("другой период: %+v %v", ms, err)
	}
}
