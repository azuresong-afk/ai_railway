package integrity

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются
// (в CI нет PostgreSQL). Поэтому в именах нет префикса TestDM42_: строку
// DM-42 покрывают тесты без БД. Каждый тест — в своей схеме, приложение
// работает под ролью aisec_app.

type pgEnv struct {
	owner *pgxpool.Pool
	app   *pgxpool.Pool
	log   *audit.Log
	store *PGStore
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
	cfg.MaxConns = 4
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

func setupPG(t *testing.T) *pgEnv {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgCtx(t)
	p := provider(t)
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "integrity_test_" + hex.EncodeToString(b)
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
	s, err := NewPGStore(app, l, p)
	if err != nil {
		t.Fatal(err)
	}
	return &pgEnv{owner: owner, app: app, log: l, store: s}
}

func TestPGStoreRecordAndLatestPostgres(t *testing.T) {
	env := setupPG(t)
	ctx := pgCtx(t)
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	ok := Result{Component: "server", Trigger: TriggerStartup, At: at, Reason: ReasonOK, ManifestVersion: "1.0", Checked: 3, TestSigned: true}
	bad := Result{Component: "server", Trigger: TriggerManual, At: at.Add(time.Minute), Reason: ReasonFilesMismatch, ManifestVersion: "1.0",
		Checked: 3, Failures: []Failure{{Path: "bin/aisec-server", Problem: ProblemModified}}}
	cli := Result{Component: "cli", Trigger: TriggerManual, At: at, Reason: ReasonSignatureInvalid}
	user := audit.Actor{Type: audit.ActorUser, ID: "00000000-0000-7000-8000-0000000000aa", Name: "admin"}
	for _, rc := range []struct {
		res Result
		by  audit.Actor
	}{{ok, systemActor("server")}, {bad, user}, {cli, audit.Actor{Type: audit.ActorCLI, ID: "uid:0"}}} {
		if err := env.store.Record(ctx, rc.res, rc.by, netip.MustParseAddr("192.0.2.1")); err != nil {
			t.Fatal(err)
		}
	}
	latest, err := env.store.Latest(ctx)
	if err != nil || len(latest) != 2 {
		t.Fatalf("%+v %v", latest, err)
	}
	// По компоненту по алфавиту: cli, server; у server — последняя проверка.
	if latest[0].Component != "cli" || latest[0].Reason != ReasonSignatureInvalid || len(latest[0].Failures) != 0 {
		t.Fatalf("%+v", latest[0])
	}
	if latest[1].Reason != ReasonFilesMismatch || latest[1].Trigger != TriggerManual || len(latest[1].Failures) != 1 ||
		latest[1].Failures[0] != bad.Failures[0] || !latest[1].At.Equal(bad.At) {
		t.Fatalf("%+v", latest[1])
	}
	// Каждый итог — запись integrity.check; нарушение — ещё tech_log integrity.
	var success, failure, tech int
	if err := env.owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE result = 'success'), count(*) FILTER (WHERE result = 'failure')
		FROM audit_log WHERE action = 'integrity.check'`).Scan(&success, &failure); err != nil {
		t.Fatal(err)
	}
	if err := env.owner.QueryRow(ctx, `SELECT count(*) FROM tech_log WHERE class = 'integrity' AND level = 'critical'`).Scan(&tech); err != nil {
		t.Fatal(err)
	}
	if success != 1 || failure != 2 || tech != 2 {
		t.Fatalf("аудит %d/%d, тех. журнал %d", success, failure, tech)
	}
	var actorID string
	if err := env.owner.QueryRow(ctx, `SELECT actor_id FROM audit_log WHERE action = 'integrity.check' AND actor_type = 'user'`).Scan(&actorID); err != nil || actorID != user.ID {
		t.Fatalf("%q %v", actorID, err)
	}
	// Цепочка аудита цела после записей.
	v, err := audit.NewVerifier(env.log).Verify(ctx)
	if err != nil || !v.OK() {
		t.Fatalf("%+v %v", v, err)
	}
}

// История проверок только дополняется — и для роли приложения, и для владельца.
func TestIntegrityChecksAppendOnlyPostgres(t *testing.T) {
	env := setupPG(t)
	ctx := pgCtx(t)
	if err := env.store.Record(ctx, Result{Component: "server", Trigger: TriggerStartup, At: time.Now().UTC(), Reason: ReasonOK},
		systemActor("server"), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	for _, pool := range []*pgxpool.Pool{env.app, env.owner} {
		for _, q := range []string{
			"UPDATE integrity_checks SET ok = false, reason = 'files_mismatch'",
			"DELETE FROM integrity_checks",
			"TRUNCATE integrity_checks",
		} {
			_, err := pool.Exec(ctx, q)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || (pe.Code != "42501") {
				t.Fatalf("%s: %v", q, err)
			}
		}
	}
	// Несогласованная строка (ok при нарушении) отклоняется CHECK.
	_, err := env.app.Exec(ctx, `INSERT INTO integrity_checks (id, org_id, ts, component, trigger_kind, ok, reason,
		manifest_version, test_signed, checked, failures, omitted, actor_type, actor_id)
		VALUES ('00000000-0000-7000-8000-0000000000bb', $1, now(), 'server', 'manual', true, 'files_mismatch', '', false, 0, '[]', 0, 'system', 'x')`,
		audit.DefaultOrgID)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" {
		t.Fatalf("CHECK: %v", err)
	}
}
