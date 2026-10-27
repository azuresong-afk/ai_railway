package sysstatus_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются
// (в CI PostgreSQL нет). Каждый тест — в своей схеме; сервер работает под
// ролью aisec_app, как в установке. Тестам не дан префикс TestDMxx_: в CI
// их пропуск не должен считаться провалом строки матрицы обнаружения.

type pgEnv struct {
	owner, app *pgxpool.Pool
	store      *sysstatus.PGStore
	log        *audit.Log
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
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() //nolint:gosec // G104: откат после коммита безвреден
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

func setupPG(t *testing.T) (*pgEnv, context.Context) {
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
	schema := "st_test_" + hex.EncodeToString(b)
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
	app := newPool(t, dsn, schema, "aisec_app")
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := sysstatus.NewPGStore(app, l, "")
	if err != nil {
		t.Fatal(err)
	}
	return &pgEnv{owner: owner, app: app, store: st, log: l}, ctx
}

func (e *pgEnv) alerts(t *testing.T, ctx context.Context) []string {
	t.Helper()
	rows, err := e.owner.Query(ctx, "SELECT object_id || '/' || (details->>'state') FROM audit_log WHERE action = 'system.alert' ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPGTransitionWritesAuditOnlyOnChange(t *testing.T) {
	e, ctx := setupPG(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := func(active bool) audit.Entry {
		return audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, ID: "system-status"}, Action: "system.alert",
			Object: audit.Object{Type: "system", ID: sysstatus.ConditionTime}, Result: audit.ResultFailure,
			Details: map[string]any{"state": map[bool]string{true: "raised", false: "cleared"}[active]}}
	}
	step := func(active bool, wantChanged bool) {
		t.Helper()
		ch, err := e.store.Transition(ctx, sysstatus.ConditionTime, active, now, rec)
		if err != nil || ch != wantChanged {
			t.Fatalf("active=%v: changed=%v err=%v", active, ch, err)
		}
	}
	step(false, false) // первое наблюдение без нарушения — без записи
	step(false, false)
	step(true, true)
	step(true, false)
	step(true, false)
	step(false, true)
	step(false, false)
	got := e.alerts(t, ctx)
	if len(got) != 2 || got[0] != "time_sync/raised" || got[1] != "time_sync/cleared" {
		t.Fatalf("записи аудита: %v", got)
	}
	states, err := e.store.AlertStates(ctx)
	if err != nil || len(states) != 1 || states[sysstatus.ConditionTime].Active {
		t.Fatalf("%+v %v", states, err)
	}
	// Состояние неизвестного условия БД не принимает (CHECK).
	if _, err := e.store.Transition(ctx, "bogus", true, now, rec); err == nil {
		t.Fatal("неизвестное условие принято")
	}
	if n := len(e.alerts(t, ctx)); n != 2 {
		t.Fatalf("запись аудита осталась при откате: %d", n)
	}
	// Условия по компоненту (В18, Н28 ревью 2.r3b): коды с UUID шлюза;
	// условия DM-44 по шлюзу (задача 3.11), корня УЦ (3В5 ревью 3.r1) и
	// сертификата заказчика (задача 3.27).
	gw := "0192a000-0000-7000-8000-000000000001"
	for _, code := range []string{"integrity:server", "integrity:gateway:" + gw, "config_bundle", "config_bundle_lag:" + gw,
		"events_dropped:" + gw, "gateway_offline:" + gw, "cert_expiry:" + gw, "reports_stale:" + gw,
		"ca_expiry", "ca_expiry:critical", "customer_cert_expiry", "customer_cert_expiry:critical"} {
		if _, err := e.store.Transition(ctx, code, true, now, rec); err != nil {
			t.Fatalf("%s: %v", code, err)
		}
	}
	for _, code := range []string{"integrity:gateway:", "integrity:gateway:G1'--", "integrity:other", "config_bundle_lag:x y",
		"ca_expiry:other", "cert_expiry", "customer_cert_expiry:warn"} {
		if _, err := e.store.Transition(ctx, code, true, now, rec); err == nil {
			t.Fatalf("неверный код %q принят", code)
		}
	}
}

func TestPGProbes(t *testing.T) {
	e, ctx := setupPG(t)
	size, err := e.store.AuditSize(ctx)
	if err != nil || size <= 0 {
		t.Fatalf("размер журнала: %d %v", size, err)
	}
	for _, a := range []string{"auth.locked", "access.denied", "access.denied", "auth.login"} {
		if err := e.log.Record(ctx, audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, ID: "t"}, Action: a,
			Object: audit.Object{Type: "x", ID: "1"}, Result: audit.ResultDenied}); err != nil {
			t.Fatal(err)
		}
	}
	locked, denied, err := e.store.AuditCounts(ctx, time.Now().Add(-time.Hour))
	if err != nil || locked != 1 || denied != 2 {
		t.Fatalf("%d %d %v", locked, denied, err)
	}
	if l, d, err := e.store.AuditCounts(ctx, time.Now().Add(time.Hour)); err != nil || l != 0 || d != 0 {
		t.Fatalf("окно в будущем: %d %d %v", l, d, err)
	}
	stats, err := e.store.EventStats(ctx)
	if err != nil || len(stats) != 0 {
		t.Fatalf("%v %v", stats, err)
	}
	// Цепочка аудита: без проверок — nil, затем итог последней проверки.
	if ch, err := e.store.AuditChain(ctx); err != nil || ch != nil {
		t.Fatalf("без проверок: %+v %v", ch, err)
	}
	if _, err := audit.NewVerifier(e.log).Verify(ctx); err != nil {
		t.Fatal(err)
	}
	ch, err := e.store.AuditChain(ctx)
	if err != nil || ch == nil || !ch.OK || ch.Reason != "ok" || ch.LastSeq < 4 || ch.BrokenSeq != nil {
		t.Fatalf("после проверки: %+v %v", ch, err)
	}
	// Условие audit_chain принимается ограничением таблицы (миграция 0015).
	if _, err := e.store.Transition(ctx, sysstatus.ConditionAuditLog, true, time.Now(), func(bool) audit.Entry {
		return audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, ID: "t"}, Action: "system.alert",
			Object: audit.Object{Type: "system", ID: sysstatus.ConditionAuditLog}, Result: audit.ResultFailure}
	}); err != nil {
		t.Fatal(err)
	}
}

// 3В17 ревью 3.r2: отметка прохода фоновой задачи правил читается ролью
// сервера, возраст считает PostgreSQL; условие alert_job_stale проходит
// CHECK таблицы состояний.
func TestPGAlertJob(t *testing.T) {
	e, ctx := setupPG(t)
	job, err := e.store.AlertJob(ctx, time.Now())
	if err != nil || !job.Tracked || !job.LastRunAt.IsZero() {
		t.Fatalf("без проходов: %+v %v", job, err)
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO alert_job_runs (org_id, job, ran_at) VALUES ($1, 'periodic', now() - interval '7 minutes')`,
		audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	job, err = e.store.AlertJob(ctx, time.Now())
	if err != nil || job.LastRunAt.IsZero() || job.Age < 6*time.Minute || job.Age > 8*time.Minute {
		t.Fatalf("проход 7 минут назад: %+v %v", job, err)
	}
	if job.FailingRules != 0 {
		t.Fatalf("правил со сбоем без состояний: %+v", job)
	}
	// 3Н48 ревью 3.r4: правило, падающее дольше AlertJobStaleAfter, считается;
	// свежая серия сбоев и отключённое правило — нет.
	for i, r := range []struct {
		enabled bool
		ago     string
	}{{true, "7 minutes"}, {true, "1 minute"}, {false, "9 minutes"}} {
		id := fmt.Sprintf("01900000-0000-7000-8000-0000000004%02d", i)
		if _, err := e.owner.Exec(ctx, `INSERT INTO alert_rules (id, org_id, kind, name, description, enabled, severity, condition,
				group_by, suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, 'anomaly', $4, '', $3, 'high', '{}', '{}', 0, 0, '{}', 1, now(), 'test', now(), 'test')`,
			id, audit.DefaultOrgID, r.enabled, "правило "+r.ago); err != nil {
			t.Fatal(err)
		}
		if _, err := e.owner.Exec(ctx, `INSERT INTO alert_rule_state (rule_id, evaluated_at, state)
			VALUES ($1, now(), jsonb_build_object('warning', 'evaluation_failed', 'failing_since', now() - $2::interval))`,
			id, r.ago); err != nil {
			t.Fatal(err)
		}
	}
	job, err = e.store.AlertJob(ctx, time.Now())
	if err != nil || job.FailingRules != 1 || time.Since(job.FailingSince) < 6*time.Minute || time.Since(job.FailingSince) > 8*time.Minute {
		t.Fatalf("правила со сбоем: %+v %v", job, err)
	}
	if _, err := e.store.Transition(ctx, sysstatus.ConditionAlertJob, true, time.Now(), func(bool) audit.Entry {
		return audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, ID: "system-status"}, Action: "system.alert",
			Object: audit.Object{Type: "system", ID: sysstatus.ConditionAlertJob}, Result: audit.ResultFailure,
			Details: map[string]any{"condition": sysstatus.ConditionAlertJob, "state": "raised"}}
	}); err != nil {
		t.Fatal(err)
	}
}
