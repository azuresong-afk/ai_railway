package build_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются
// (в CI PostgreSQL нет). Схема своя на тест, сервер — под ролью aisec_app.

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

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// migrated — схема теста с миграциями: пул владельца схемы и пул роли
// сервера; без AISEC_TEST_DATABASE_URL тест пропускается.
func migrated(t *testing.T) (aisecCrypto.Provider, *pgxpool.Pool, *pgxpool.Pool) {
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
	schema := "bundles_test_" + hex.EncodeToString(b)
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
	return p, owner, newPool(t, dsn, schema, "aisec_app")
}

func TestPGConfigBundles(t *testing.T) {
	ctx := pgCtx(t)
	p, owner, app := migrated(t)
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := build.NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	org := audit.DefaultOrgID
	if _, err := st.Latest(ctx, org); !errors.Is(err, build.ErrNotFound) {
		t.Fatalf("пусто: %v", err)
	}
	entry := func(v string) audit.Entry {
		return audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, ID: "bundle-builder"}, Action: "bundle.build",
			Object: audit.Object{Type: "config_bundle", ID: v}, Result: audit.ResultSuccess, Details: map[string]any{"version": v}}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := build.Record{OrgID: org, Version: 100, Content: []byte(`{"a":1}`), Hash: h.Sum([]byte(`{"a":1}`)), HashAlg: h.Name(), CreatedAt: now}
	if err := st.Create(ctx, rec, entry("100")); err != nil {
		t.Fatal(err)
	}
	got, err := st.Latest(ctx, org)
	if err != nil || got.Version != 100 || string(got.Content) != `{"a":1}` || !got.CreatedAt.Equal(now) {
		t.Fatalf("последняя версия: %+v, %v", got, err)
	}
	for _, v := range []int64{100, 99} {
		rec.Version = v
		if err := st.Create(ctx, rec, entry("x")); !errors.Is(err, build.ErrConflict) {
			t.Errorf("версия %d после 100: %v", v, err)
		}
	}
	rec.Version = 101
	if err := st.Create(ctx, rec, entry("101")); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := owner.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action = 'bundle.build'").Scan(&n); err != nil || n != 2 {
		t.Fatalf("записей аудита: %d, %v", n, err)
	}
	// Версии неизменяемы и не удаляются никем, включая владельца схемы.
	for _, q := range []string{
		"UPDATE config_bundles SET content = '\\x7b7d'::bytea WHERE version = 100",
		"DELETE FROM config_bundles WHERE version = 100",
		"TRUNCATE config_bundles",
	} {
		if _, err := owner.Exec(ctx, q); sqlState(err) != "42501" {
			t.Errorf("%s владельцем: %v", q, err)
		}
	}
	if _, err := app.Exec(ctx, "DELETE FROM config_bundles WHERE version = 100"); sqlState(err) != "42501" {
		t.Errorf("удаление ролью сервера: %v", err)
	}
}
