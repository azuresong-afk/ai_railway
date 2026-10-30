package servicedb

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются.
// Каждый тест — в своей схеме; сервер работает под ролью aisec_app.

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

type pgEnv struct {
	owner, app *pgxpool.Pool
	ms         []store.Migration
	migrator   func(upTo int) error
}

// setupSchema создаёт схему; миграции применяет migrator(до версии).
func setupSchema(t *testing.T) *pgEnv {
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
	schema := "servicedb_test_" + hex.EncodeToString(b)
	admin := newPool(t, dsn, "public", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE") //nolint:gosec // G104: уборка тестовой схемы
	})
	e := &pgEnv{owner: newPool(t, dsn, schema, "")}
	if e.ms, err = store.LoadMigrations(migrations.FS); err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	e.migrator = func(upTo int) error {
		var ms []store.Migration
		for _, m := range e.ms {
			if upTo == 0 || m.Version <= upTo {
				ms = append(ms, m)
			}
		}
		_, err := (&store.Migrator{Exec: poolExec{e.owner}, Hasher: h, Migrations: ms}).Up(ctx)
		return err
	}
	return e
}

func (e *pgEnv) store(t *testing.T) (*PGStore, *audit.Log) {
	t.Helper()
	ctx := pgTestCtx(t)
	var schema string
	if err := e.owner.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO aisec_app"); err != nil {
		t.Fatal(err)
	}
	e.app = newPool(t, e.owner.Config().ConnConfig.ConnString(), schema, "aisec_app")
	l, err := audit.New(e.app, provider(t))
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewPGStore(e.app, l)
	if err != nil {
		t.Fatal(err)
	}
	return st, l
}

func (e *pgEnv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(pgTestCtx(t), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Загрузка, откат, повреждённая сохранённая база на PostgreSQL: правила те
// же, что у Memory; запись и аудит — одной транзакцией.
func TestPGServiceDBs(t *testing.T) {
	e := setupSchema(t)
	if err := e.migrator(0); err != nil {
		t.Fatal(err)
	}
	st, _ := e.store(t)
	ctx := pgTestCtx(t)
	m := newManager(t, st, 0)
	for v := 1; v <= 2; v++ {
		if _, err := m.Upload(ctx, testBy, sign(t, testKindName, payload(v, "2026-10-28"), nil)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := m.Upload(ctx, testBy, sign(t, testKindName, payload(2, "2026-10-28"), nil))
	var re *RejectError
	if !errors.As(err, &re) || re.Reason != ReasonStale {
		t.Fatalf("та же версия: %v", err)
	}
	if n := e.count(t, `SELECT count(*) FROM service_dbs WHERE kind = $1`, testKindName); n != 2 {
		t.Fatalf("строк: %d", n)
	}
	// Новый менеджер читает обе версии и проверяет подпись заново.
	if s, err := newManager(t, st, 0).State(ctx); err != nil || s.Current.Version != 2 || !s.Current.Valid || s.Previous.Version != 1 {
		t.Fatalf("из БД: %+v %v", s, err)
	}
	if _, err := m.Rollback(ctx, testBy); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rollback(ctx, testBy); !errors.As(err, &re) || re.Reason != ReasonNoPrevious {
		t.Fatalf("второй откат: %v", err)
	}
	if n := e.count(t, `SELECT count(*) FROM service_dbs WHERE kind = $1 AND slot = 'current' AND version = 1`, testKindName); n != 1 {
		t.Fatalf("после отката: %d", n)
	}
	// Подмена файла в БД: текущая не используется, запись аудита.
	if _, err := e.owner.Exec(ctx, `UPDATE service_dbs SET file = convert_to('{}', 'UTF8') WHERE kind = $1`, testKindName); err != nil {
		t.Fatal(err)
	}
	m2 := newManager(t, st, 0)
	if a, err := m2.Active(ctx); err != nil || a != nil {
		t.Fatalf("подменённая база используется: %+v %v", a, err)
	}
	for action, want := range map[string]int{ActionLoaded: 2, ActionRejected: 1, ActionRolledBack: 2, ActionStoredInvalid: 1} {
		if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = $1 AND details->>'kind' = $2`, action, testKindName); n != want {
			t.Fatalf("%s: %d записей", action, n)
		}
	}
	// Роль сервера не может нарушить ограничения таблицы.
	if _, err := e.app.Exec(ctx, `UPDATE service_dbs SET slot = 'other'`); err == nil {
		t.Fatal("слот вне перечня принят")
	}
}

// Миграция 0068 на БД с данными: строки каталога и базы требований
// переходят в service_dbs текущими версиями, прежние таблицы удалены.
func TestPGMigration0068MovesRows(t *testing.T) {
	e := setupSchema(t)
	if err := e.migrator(67); err != nil {
		t.Fatal(err)
	}
	ctx := pgTestCtx(t)
	catalog := readFile(t, "../../testdata/shadowai/catalog-test.aisecdb")
	at := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	if _, err := e.owner.Exec(ctx, `INSERT INTO shadow_ai_catalog (org_id, version, catalog_date, subkey_serial, fingerprint, services, file, uploaded_at, uploaded_by)
		VALUES ($1, 1, '2026-10-28', 1, 'fp-c', 28, $2, $3, 'user:a')`, audit.DefaultOrgID, catalog, at); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO compliance_base (org_id, version, base_date, subkey_serial, fingerprint, requirements, file, uploaded_at, uploaded_by)
		VALUES ($1, 7, '2026-10-27', 1, 'fp-b', 12, '\x7b7d'::bytea, $2, 'user:b')`, audit.DefaultOrgID, at); err != nil {
		t.Fatal(err)
	}
	if err := e.migrator(0); err != nil {
		t.Fatal(err)
	}
	type row struct {
		kind, slot, fp, by string
		version            int64
		date               time.Time
		records            int
		file               []byte
	}
	rows, err := e.owner.Query(ctx, `SELECT kind, slot, fingerprint, uploaded_by, version, db_date, records, file FROM service_dbs ORDER BY kind`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.kind, &x.slot, &x.fp, &x.by, &x.version, &x.date, &x.records, &x.file)
		return x, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 ||
		got[0].kind != "compliance_requirements" || got[0].slot != SlotCurrent || got[0].version != 7 || got[0].records != 12 || got[0].fp != "fp-b" ||
		got[0].date.Format(time.DateOnly) != "2026-10-27" || string(got[0].file) != "{}" ||
		got[1].kind != "shadow_ai_catalog" || got[1].version != 1 || got[1].records != 28 || got[1].by != "user:a" || string(got[1].file) != string(catalog) {
		t.Fatalf("перенесено: %+v", got)
	}
	for _, table := range []string{"shadow_ai_catalog", "compliance_base"} {
		if n := e.count(t, `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1`, table); n != 0 {
			t.Fatalf("таблица %s осталась", table)
		}
	}
}
