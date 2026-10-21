package audit

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL (make dev, postgres на
// 127.0.0.1:5432; пользователь стенда — владелец БД). Без переменной
// пропускаются. Каждый тест работает в своей схеме, поэтому не мешает
// тестам internal/store в той же БД.

type testEnv struct {
	owner  *pgxpool.Pool // владелец схемы (как aisec-cli migrate)
	app    *pgxpool.Pool // те же соединения под ролью aisec_app
	log    *Log          // журнал под ролью приложения
	schema string
}

func ctxT(t *testing.T) context.Context {
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

// poolExec — store.Executor поверх пула, чтобы применить миграции.
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
	defer rows.Close()
	var out []store.Applied
	for rows.Next() {
		var a store.Applied
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func setupDB(t *testing.T) *testEnv {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := ctxT(t)
	r, err := provider(t).Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "audit_test_" + hex.EncodeToString(b)
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
	m := &store.Migrator{Exec: poolExec{owner}, Hasher: hasher(t), Migrations: ms}
	if _, err := m.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO aisec_app"); err != nil {
		t.Fatal(err)
	}
	app := newPool(t, dsn, schema, "aisec_app")
	l, err := New(app, provider(t))
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{owner: owner, app: app, log: l, schema: schema}
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func record(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		e := validEntry()
		e.Details = map[string]any{"i": i, "method": "password"}
		if err := l.Record(ctxT(t), e); err != nil {
			t.Fatal(err)
		}
	}
}

func verify(t *testing.T, v *Verifier) Verification {
	t.Helper()
	res, err := v.Verify(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Р5, РСБ.4: роль приложения только читает и добавляет.
func TestAppendOnlyForAppRole(t *testing.T) {
	env := setupDB(t)
	ctx := ctxT(t)
	record(t, env.log, 3)
	var n int
	if err := env.app.QueryRow(ctx, "SELECT count(*) FROM audit_log").Scan(&n); err != nil || n != 3 {
		t.Fatalf("SELECT: %d, %v", n, err)
	}
	for _, tbl := range []string{"audit_log", "audit_verifications", "tech_log"} {
		for _, q := range []string{
			"UPDATE " + tbl + " SET ts = now()",
			"DELETE FROM " + tbl,
			"TRUNCATE " + tbl,
		} {
			_, err := env.app.Exec(ctx, q)
			if sqlState(err) != "42501" {
				t.Errorf("%s под aisec_app: %v (ожидался отказ в правах 42501)", q, err)
			}
		}
	}
	if err := env.log.Tech(ctx, TechEntry{Component: "server", Kind: TechStart, Level: LevelInfo, Message: "запущен"}); err != nil {
		t.Fatalf("техжурнал под aisec_app: %v", err)
	}
}

// Триггеры запрещают UPDATE и TRUNCATE даже владельцу таблицы; DELETE —
// только процедуре архивации под aisec_audit_archiver и только записей,
// покрытых контрольной точкой (задача 2.5).
func TestTriggersBlockOwner(t *testing.T) {
	env := setupDB(t)
	ctx := ctxT(t)
	record(t, env.log, 2)
	verify(t, NewVerifier(env.log))
	for _, q := range []string{
		"UPDATE audit_log SET actor_name = 'x' WHERE seq = 1",
		"DELETE FROM audit_log WHERE seq = 1",
		"TRUNCATE audit_log",
		"UPDATE audit_verifications SET ok = false",
		"DELETE FROM audit_verifications",
		"TRUNCATE audit_verifications",
	} {
		if _, err := env.owner.Exec(ctx, q); sqlState(err) != "42501" {
			t.Errorf("%s владельцем: %v", q, err)
		}
	}
	// Даже роль aisec_audit_archiver не удаляет запись, не покрытую
	// контрольной точкой (0005_audit_archive); путь с точкой — archive_pg_test.go.
	tx, err := env.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // G104: тест откатывает всё
	for _, q := range []string{
		"GRANT USAGE ON SCHEMA " + pgx.Identifier{env.schema}.Sanitize() + " TO aisec_audit_archiver",
		"SET LOCAL ROLE aisec_audit_archiver",
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := tx.Exec(ctx, "DELETE FROM audit_log WHERE seq = 1"); sqlState(err) != "42501" {
		t.Fatalf("удаление без контрольной точки: %v", err)
	}
}

// Вставка в обход internal/audit не встраивается в середину цепочки.
func TestLinkTriggerRejectsForeignInsert(t *testing.T) {
	env := setupDB(t)
	ctx := ctxT(t)
	record(t, env.log, 2)
	insert := `INSERT INTO audit_log (seq, id, org_id, ts, actor_type, actor_id, actor_name, action,
		object_type, object_id, result, details, hash_alg, prev_hash, hash)
		VALUES ($1, '0192f3a0-0000-7000-8000-0000000000ff', $2, now(), 'user', 'u', 'u', 'auth.login',
		'', '', 'success', '{}', 'SHA-256', $3, $3)`
	for name, args := range map[string][]any{
		"не тот prev": {int64(3), DefaultOrgID, make([]byte, 32)},
		"пропуск":     {int64(5), DefaultOrgID, make([]byte, 32)},
	} {
		if _, err := env.app.Exec(ctx, insert, args...); err == nil {
			t.Errorf("%s: вставка принята", name)
		}
	}
}

// Временная таблица audit_log в сессии роли приложения не обманывает
// триггер связности: он читает таблицу по схеме триггера.
func TestLinkTriggerIgnoresTempTable(t *testing.T) {
	env := setupDB(t)
	ctx := ctxT(t)
	record(t, env.log, 2)
	tx, err := env.app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // G104: тест откатывает всё
	fake := make([]byte, 32)
	for _, q := range []string{
		"CREATE TEMP TABLE audit_log (seq bigint, hash bytea)",
		"INSERT INTO pg_temp.audit_log VALUES (2, $1)",
	} {
		args := []any{}
		if strings.Contains(q, "$1") {
			args = append(args, fake)
		}
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			t.Skipf("временные таблицы недоступны: %v", err)
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO `+pgx.Identifier{env.schema, "audit_log"}.Sanitize()+` (seq, id, org_id, ts, actor_type,
		actor_id, actor_name, action, object_type, object_id, result, details, hash_alg, prev_hash, hash)
		VALUES (3, '0192f3a0-0000-7000-8000-0000000000fe', $1, now(), 'user', 'u', 'u', 'auth.login',
		'', '', 'success', '{}', 'SHA-256', $2, $2)`, DefaultOrgID, fake)
	if err == nil {
		t.Fatal("вставка с подменой через временную таблицу принята")
	}
}

// DM-43 на настоящем PostgreSQL: правка и удаление в обход триггеров
// (суперпользователь, session_replication_role = replica) обнаруживаются.
// В имени нет префикса TestDM43_: без AISEC_TEST_DATABASE_URL (в CI) тест
// пропускается, а dm-coverage считает пропуск непройденным тестом строки.
// Строку DM-43 покрывает TestDM43_ChainBroken.
func TestChainBrokenPostgres(t *testing.T) {
	cases := []struct {
		name      string
		sql       string
		verifyFst bool // проверить до вмешательства (нужно для хвоста)
		reason    Reason
		seq       int64
	}{
		{"правка", "UPDATE audit_log SET actor_name = 'другой' WHERE seq = 3", false, ReasonHashMismatch, 3},
		{"правка подробностей", `UPDATE audit_log SET details = '{"i":0,"method":"none"}' WHERE seq = 2`, false, ReasonHashMismatch, 2},
		{"удаление из середины", "DELETE FROM audit_log WHERE seq = 3", false, ReasonGap, 4},
		{"удаление начала", "DELETE FROM audit_log WHERE seq <= 2", false, ReasonHeadMissing, 3},
		{"удаление хвоста", "DELETE FROM audit_log WHERE seq >= 4", true, ReasonTailTruncated, 0},
		{"бесконечное время в обход CHECK", "ALTER TABLE audit_log DROP CONSTRAINT audit_log_ts_check; " +
			"UPDATE audit_log SET ts = 'infinity' WHERE seq = 2", false, ReasonInvalid, 2},
		{"пробелы в подробностях", `UPDATE audit_log SET details = '{"i": 0, "method": "password"}' WHERE seq = 1`, false, ReasonInvalid, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := setupDB(t)
			ctx := ctxT(t)
			record(t, env.log, 5)
			if tc.verifyFst {
				if res := verify(t, NewVerifier(env.log)); !res.OK() {
					t.Fatalf("до вмешательства: %v", res.Break)
				}
			}
			tx, err := env.owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
				t.Skipf("нужен суперпользователь: %v", err)
			}
			for _, q := range strings.Split(tc.sql, "; ") {
				if _, err := tx.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			// Новый процесс: проверка опирается на audit_verifications.
			res := verify(t, NewVerifier(env.log))
			if res.OK() || res.Break.Reason != tc.reason || (tc.seq != 0 && res.Break.Seq != tc.seq) {
				t.Fatalf("итог %+v, ожидалось %s на %d", res.Break, tc.reason, tc.seq)
			}
			var action string
			if err := env.owner.QueryRow(ctx,
				"SELECT action FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&action); err != nil || action != "audit.chain_broken" {
				t.Fatalf("в журнале нет записи о нарушении: %q, %v", action, err)
			}
			var class string
			if err := env.owner.QueryRow(ctx,
				"SELECT class FROM tech_log WHERE kind = 'error' ORDER BY ts DESC LIMIT 1").Scan(&class); err != nil || class != "integrity" {
				t.Fatalf("в техжурнале нет записи о нарушении: %q, %v", class, err)
			}
		})
	}
}

func TestVerifyValidAndRecorded(t *testing.T) {
	env := setupDB(t)
	ctx := ctxT(t)
	v := NewVerifier(env.log)
	if res := verify(t, v); !res.OK() || res.Checked != 0 {
		t.Fatalf("пустой журнал: %+v", res)
	}
	record(t, env.log, 3)
	// Первая проверка добавила запись audit.chain_verified: 1 + 3.
	res := verify(t, v)
	if !res.OK() || res.Checked != 4 || res.Head.Seq != 4 {
		t.Fatalf("%+v", res)
	}
	var ok int
	if err := env.owner.QueryRow(ctx, "SELECT count(*) FROM audit_verifications WHERE ok").Scan(&ok); err != nil || ok != 2 {
		t.Fatalf("итогов проверки: %d, %v", ok, err)
	}
	// Адрес и подробности переживают круг через БД без изменения хеша.
	e := validEntry()
	e.SourceIP = netip.MustParseAddr("2001:db8::1")
	e.Details = map[string]any{"html": "<b>&</b>", "n": 1.25, "u": " "}
	if err := env.log.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	e.SourceIP = netip.MustParseAddr("::ffff:192.0.2.7")
	if err := env.log.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	if res := verify(t, v); !res.OK() {
		t.Fatalf("после круга через БД: %v", res.Break)
	}
}

func TestConcurrentRecord(t *testing.T) {
	env := setupDB(t)
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- env.log.Record(context.Background(), validEntry())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	res := verify(t, NewVerifier(env.log))
	if !res.OK() || res.Checked != n {
		t.Fatalf("%+v", res)
	}
}

// РСБ.3: необязательное событие отключается, обязательное — нет, даже если
// подменить настройки в БД.
func TestSettingsAndMandatory(t *testing.T) {
	env := setupDB(t)
	ctx := ctxT(t)
	by := Entry{Actor: Actor{Type: ActorUser, ID: "u-1", Name: "admin"}, SourceIP: netip.MustParseAddr("192.0.2.1")}
	s, err := env.log.Settings(ctx, "")
	if err != nil || s.RetentionDays != DefaultRetentionDays || len(s.DisabledActions) != 0 {
		t.Fatalf("по умолчанию: %+v, %v", s, err)
	}
	if err := env.log.SetSettings(ctx, by, Settings{DisabledActions: []string{"auth.login"}, RetentionDays: 365}); err == nil {
		t.Fatal("обязательное событие отключено")
	}
	if err := env.log.SetSettings(ctx, by, Settings{DisabledActions: []string{"events.list"}, RetentionDays: 90}); err != nil {
		t.Fatal(err)
	}
	if s, err := env.log.Settings(ctx, ""); err != nil || s.RetentionDays != 90 || len(s.DisabledActions) != 1 {
		t.Fatalf("после изменения: %+v, %v", s, err)
	}
	var details string
	if err := env.owner.QueryRow(ctx,
		"SELECT details::text FROM audit_log WHERE action = 'audit.settings_changed'").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if want := `{"after":{"disabled_actions":["events.list"],"retention_days":90},"before":{"disabled_actions":[],"retention_days":365}}`; details != want {
		t.Fatalf("до и после: %s", details)
	}
	e := validEntry()
	e.Action = "events.list"
	if err := env.log.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	// Подмена настроек в обход проверки: обязательное событие в списке.
	if _, err := env.owner.Exec(ctx, "UPDATE audit_settings SET disabled_actions = '{auth.login,events.list}'"); err != nil {
		t.Fatal(err)
	}
	if err := env.log.Record(ctx, validEntry()); err != nil {
		t.Fatal(err)
	}
	var list, login int
	if err := env.owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action = 'events.list'),
		count(*) FILTER (WHERE action = 'auth.login') FROM audit_log`).Scan(&list, &login); err != nil {
		t.Fatal(err)
	}
	if list != 0 || login != 1 {
		t.Fatalf("events.list: %d (ожидалось 0), auth.login: %d (ожидалось 1)", list, login)
	}
}

func TestRecordRejectsSecrets(t *testing.T) {
	env := setupDB(t)
	e := validEntry()
	e.Details = map[string]any{"after": map[string]any{"api_key": "sk-test"}}
	if err := env.log.Record(ctxT(t), e); err == nil {
		t.Fatal("секрет записан")
	}
}
