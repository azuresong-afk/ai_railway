package shadowai

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
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
	schema := "shadow_test_" + hex.EncodeToString(b)
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

func (e *pgEnv) service(t *testing.T) *Service {
	t.Helper()
	s, err := New(Options{Store: e.st, Provider: provider(t), OrgID: audit.DefaultOrgID, UserMAC: testMAC(t),
		Clock:    func() time.Time { return testNow },
		Location: func(context.Context) (*time.Location, error) { return time.LoadLocation("Europe/Moscow") }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *pgEnv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(pgTestCtx(t), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestPGShadowAICatalogAndImport(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	s := e.service(t)
	if v, err := s.Catalog(ctx); err != nil || v.Loaded {
		t.Fatalf("пустой каталог: %+v %v", v, err)
	}
	if _, err := s.UploadCatalog(ctx, testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	var ce *CatalogError
	if _, err := s.UploadCatalog(ctx, testBy, readFile(t, testCatalogSigned)); !errors.As(err, &ce) || ce.Reason != "stale_version" {
		t.Fatalf("та же версия: %v", err)
	}
	// Новый сервис читает каталог из БД и проверяет подпись заново.
	s = e.service(t)
	if v, err := s.Catalog(ctx); err != nil || !v.Valid || v.Version != 1 || len(v.Services) != 28 {
		t.Fatalf("каталог из БД: %+v %v", v, err)
	}
	squid := readFile(t, "../../testdata/shadowai/access-squid.log")
	imp, err := s.Import(ctx, testBy, FormatSquid, bytes.NewReader(squid))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, bytes.NewReader(squid)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("повтор: %v", err)
	}
	if _, err := s.Import(ctx, testBy, FormatCEF, bytes.NewReader(readFile(t, "../../testdata/shadowai/usergate-cef.log"))); err != nil {
		t.Fatal(err)
	}
	imps, err := s.Imports(ctx)
	if err != nil || len(imps) != 2 || imps[1].ID != imp.ID || imps[1].Matched != 5 ||
		len(imps[1].ErrorLines) != 2 || imps[1].ErrorLines[0] != 7 {
		t.Fatalf("журнал импорта: %+v %v", imps, err)
	}
	q := Query{From: testNow.AddDate(0, 0, -7), To: testNow}
	svcs, err := s.Services(ctx, q)
	if err != nil || len(svcs) != 5 || svcs[0].ID != "chatgpt" || svcs[0].Requests != 3 || svcs[0].Name != "ChatGPT" {
		t.Fatalf("сервисы: %+v %v", svcs, err)
	}
	users, err := s.Users(ctx, q)
	if err != nil || len(users) == 0 || users[0].Alias != pseudonym(testMAC(t), "ivanov.ia") || users[0].Requests != 3 {
		t.Fatalf("пользователи: %+v %v", users, err)
	}
	q.Step = StepHour
	if pts, err := s.Timeline(ctx, q); err != nil || len(pts) != 3 || pts[1].Requests != 4 {
		t.Fatalf("динамика по часам: %+v %v", pts, err)
	}
	q.Step = StepDay
	pts, err := s.Timeline(ctx, q)
	if err != nil || len(pts) != 1 || pts[0].Requests != 7 || pts[0].Services != 5 ||
		!pts[0].Bucket.Equal(time.Date(2026, 10, 26, 21, 0, 0, 0, time.UTC)) {
		t.Fatalf("динамика по суткам: %+v %v", pts, err)
	}
	// В БД нет логинов, адресов и узлов из журналов — только псевдонимы.
	for _, bad := range []string{"ivanov", "petrova", "10.0.12", "10.0.20", "example.ru", "chatgpt.com"} {
		for _, sql := range []string{
			`SELECT count(*) FROM shadow_ai_hour WHERE user_alias LIKE '%' || $1 || '%' OR service LIKE '%' || $1 || '%'`,
			`SELECT count(*) FROM audit_log WHERE action LIKE 'shadow_ai.%' AND details::text LIKE '%' || $1 || '%'`,
		} {
			if n := e.count(t, sql, bad); n != 0 {
				t.Fatalf("%q в БД: %d", bad, n)
			}
		}
	}
	for action, want := range map[string]int{"shadow_ai.catalog_loaded": 1, "shadow_ai.catalog_rejected": 1, "shadow_ai.import": 2} {
		if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = $1`, action); n != want {
			t.Fatalf("%s: %d записей", action, n)
		}
	}
	// Роль сервера не может удалять или править журнал импорта.
	if _, err := e.app.Exec(ctx, `DELETE FROM shadow_ai_imports`); sqlState(err) != "42501" {
		t.Fatalf("удаление журнала импорта: %v", err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE shadow_ai_hour SET user_alias = 'ivanov'`); sqlState(err) != "23514" {
		t.Fatalf("псевдоним вне формата: %v", err)
	}
}

func TestPGShadowAIRetention(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	s := e.service(t)
	by := testBy
	by.Confirm = func(context.Context) error { return nil }
	if _, err := s.SetRetention(ctx, by, 400); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("без первичной настройки: %v", err)
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO install_settings (org_id, timezone, retention_mode, updated_at)
		VALUES ($1, 'Europe/Moscow', 'masked', now())`, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	if st, err := s.Settings(ctx); err != nil || st.RetentionDays != DefaultRetentionDays {
		t.Fatalf("по умолчанию: %+v %v", st, err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE install_settings SET shadow_ai_retention_days = 10`); sqlState(err) != "23514" {
		t.Fatalf("срок 10 суток: %v", err)
	}
	if _, err := s.SetRetention(ctx, by, 400); err != nil {
		t.Fatal(err)
	}
	// Старая сводка удаляется, свежая остаётся; запись аудита — одна.
	alias := strings.Repeat("ab", 16)
	if _, err := e.owner.Exec(ctx, `INSERT INTO shadow_ai_hour (org_id, bucket, service, user_alias, user_kind, requests, bytes) VALUES
		($1, date_trunc('hour', now()) - interval '500 days', 'chatgpt', $2, 'user', 1, 10),
		($1, date_trunc('hour', now()) - interval '1 hour', 'chatgpt', $2, 'user', 1, 10)`, audit.DefaultOrgID, alias); err != nil {
		t.Fatal(err)
	}
	n, err := e.st.PurgeExpired(ctx, audit.DefaultOrgID)
	if err != nil || n != 1 {
		t.Fatalf("очистка: %d %v", n, err)
	}
	if n := e.count(t, `SELECT count(*) FROM shadow_ai_hour`); n != 1 {
		t.Fatalf("осталось %d сводок", n)
	}
	if n, err := e.st.PurgeExpired(ctx, audit.DefaultOrgID); err != nil || n != 0 {
		t.Fatalf("повторная очистка: %d %v", n, err)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'shadow_ai.retention'`); n != 1 {
		t.Fatalf("записей об очистке: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'shadow_ai.settings_changed'`); n != 1 {
		t.Fatalf("записей о настройке: %d", n)
	}
}

// 4В27: число разных и новых для организации псевдонимов импорта и сумма
// новых в организации за сутки — в журнале импорта и в аудите
// shadow_ai.import; первый импорт с пользователями — исходный состав, его
// псевдонимы тоже новые (4В28), сумма — по организации (4Н28). Логины
// синтетические.
func TestPGShadowAIImportUsers(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	s := e.service(t)
	if _, err := s.UploadCatalog(ctx, testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	probe := func(prefix string, n int) *strings.Reader {
		var b strings.Builder
		for i := range n {
			b.WriteString(strings.Join([]string{strconv.FormatInt(at.Add(time.Duration(i%24)*time.Hour).Unix(), 10) + ".000", "10",
				"10.0.0.1", "TCP_TUNNEL/200", "100", "CONNECT", "chatgpt.com:443", prefix + strconv.Itoa(i), "HIER_DIRECT/203.0.113.1", "-"}, " ") + "\n")
		}
		return strings.NewReader(b.String())
	}
	last := func() map[string]any {
		var d map[string]any
		if err := e.owner.QueryRow(ctx, `SELECT details FROM audit_log WHERE action = 'shadow_ai.import' ORDER BY seq DESC LIMIT 1`).Scan(&d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, probe("staff.", 30)); err != nil {
		t.Fatal(err)
	}
	if d := last(); d["users"] != float64(30) || d["new_users"] != float64(30) || d["new_users_day"] != float64(30) || d["baseline"] != true {
		t.Fatalf("исходный состав: %v", d)
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, io.MultiReader(probe("probe.", 20), probe("staff.", 10))); err != nil {
		t.Fatal(err)
	}
	if d := last(); d["users"] != float64(30) || d["new_users"] != float64(20) || d["new_users_day"] != float64(50) || d["baseline"] != nil {
		t.Fatalf("второй импорт: %v", d)
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, probe("more.", 5)); err != nil {
		t.Fatal(err)
	}
	if d := last(); d["new_users"] != float64(5) || d["new_users_day"] != float64(55) {
		t.Fatalf("третий импорт: %v", d)
	}
	other := By{Actor: audit.Actor{Type: audit.ActorUser, ID: "u-other"}}
	if _, err := s.Import(ctx, other, FormatSquid, probe("other.", 3)); err != nil {
		t.Fatal(err)
	}
	if d := last(); d["new_users"] != float64(3) || d["new_users_day"] != float64(58) {
		t.Fatalf("другой субъект: %v", d)
	}
	if n := e.count(t, `SELECT count(*) FROM shadow_ai_imports WHERE baseline AND users = 30 AND new_users = 30`); n != 1 {
		t.Fatalf("исходный состав в журнале импорта: %d", n)
	}
	if n := e.count(t, `SELECT sum(new_users) FROM shadow_ai_imports`); n != 58 {
		t.Fatalf("новых в журнале импорта: %d", n)
	}
}
