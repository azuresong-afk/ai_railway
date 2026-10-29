package license

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
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются.
// Каждый тест — в своей схеме; сервер работает под ролью aisec_app.

type pgEnv struct {
	owner, app *pgxpool.Pool
	st         *PGStore
}

func pgTestCtx(t *testing.T) context.Context {
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
	ctx := pgTestCtx(t)
	p := provider(t)
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "license_test_" + hex.EncodeToString(b)
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
	st, err := NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	return &pgEnv{owner: owner, app: app, st: st}
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// Лицензии на PostgreSQL: загрузка, повторная проверка новым сервисом,
// таблица только дополняется, отметка часов только растёт, коды условий
// проходят CHECK system_alert_state.
func TestPGLicenseStore(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	clock := &fakeClock{t: day(2026, 11, 1)}
	newSvc := func() *Service {
		s, err := New(Options{Store: e.st, Provider: provider(t), Clock: clock.now})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := newSvc()
	if st, err := s.State(ctx); err != nil || st.Phase != PhaseNone {
		t.Fatalf("пустая установка: %+v %v", st, err)
	}
	if _, err := s.Upload(ctx, confirmed, signTest(t, baseLicense(3))); err != nil {
		t.Fatal(err)
	}
	var rej *Rejected
	if _, err := s.Upload(ctx, confirmed, signTest(t, baseLicense(2))); !errors.As(err, &rej) || rej.Reason != ReasonStaleNumber {
		t.Fatalf("номер старше: %v", err)
	}
	// Гонка: кэш сервиса не видит номер 3 — отказ в транзакции хранилища.
	if err := e.st.Save(ctx, audit.DefaultOrgID, Stored{Number: 3, File: []byte("{}"), LoadedAt: clock.t, LoadedBy: "user:u1"},
		audit.Entry{}); !errors.Is(err, ErrStale) {
		t.Fatalf("тот же номер: %v", err)
	}
	// Новый сервис читает лицензию из БД и проверяет подпись заново.
	if st, err := newSvc().State(ctx); err != nil || st.Phase != PhaseActive || st.Number != 3 {
		t.Fatalf("из БД: %+v %v", st, err)
	}
	var n int
	if err := e.owner.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action IN ('license.loaded', 'license.rejected')").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("записей аудита: %d", n)
	}
	// Таблица только дополняется — и для роли приложения, и для владельца.
	if _, err := e.app.Exec(ctx, "DELETE FROM licenses"); sqlState(err) != "42501" {
		t.Fatalf("удаление ролью приложения: %v", err)
	}
	if _, err := e.app.Exec(ctx, "UPDATE licenses SET number = 9"); sqlState(err) != "42501" {
		t.Fatalf("изменение ролью приложения: %v", err)
	}
	for _, q := range []string{"DELETE FROM licenses", "TRUNCATE licenses", "TRUNCATE license_clock"} {
		if _, err := e.owner.Exec(ctx, q); sqlState(err) != "23514" {
			t.Fatalf("%s владельцем: %v", q, err)
		}
	}
	// Отметка часов только растёт.
	clock.t = day(2027, 1, 1)
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if hw, err := e.st.AdvanceClock(ctx, audit.DefaultOrgID, day(2026, 1, 1)); err != nil || !hw.Equal(day(2027, 1, 1)) {
		t.Fatalf("отметка часов: %s %v", hw, err)
	}
	if _, err := e.app.Exec(ctx, "UPDATE license_clock SET high_water = $1", day(2026, 1, 1)); sqlState(err) != "23514" {
		t.Fatalf("отметка часов вниз: %v", err)
	}
	if _, err := e.app.Exec(ctx, "DELETE FROM license_clock"); sqlState(err) != "42501" {
		t.Fatalf("удаление отметки: %v", err)
	}
	// Пределы считают только действующие шлюзы и приложения не в архиве.
	if u, err := e.st.Usage(ctx, audit.DefaultOrgID); err != nil || u != (Usage{}) {
		t.Fatalf("пустая установка: %+v %v", u, err)
	}
	for i, status := range []string{"active", "pending", "active"} {
		if _, err := e.owner.Exec(ctx, `INSERT INTO gateways (id, org_id, name, status, created_at, created_by, registered_at, cert_serial,
			cert_not_after) VALUES ($1, $2, $3, $4, now(), 'test', CASE WHEN $4 = 'active' THEN now() END,
			CASE WHEN $4 = 'active' THEN $5 END, CASE WHEN $4 = 'active' THEN now() + interval '1 day' END)`,
			"01900000-0000-7000-8000-0000000f000"+string(rune('1'+i)), audit.DefaultOrgID, "gw-"+string(rune('a'+i)), status,
			"0"+string(rune('1'+i))); err != nil {
			t.Fatalf("шлюз %d: %v", i, err)
		}
	}
	if u, err := e.st.Usage(ctx, audit.DefaultOrgID); err != nil || u.Gateways != 2 || u.Applications != 0 {
		t.Fatalf("шлюзы: %+v %v", u, err)
	}
	for _, code := range []string{"license_expiry", "license_expiry:critical", "license_grace", "license_restricted",
		"license_invalid", "license_clock"} {
		if _, err := e.owner.Exec(ctx, "INSERT INTO system_alert_state (org_id, condition, active, since, updated_at) VALUES ($1, $2, true, now(), now())", audit.DefaultOrgID, code); err != nil {
			t.Fatalf("условие %s: %v", code, err)
		}
	}
}
