package redteam

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тестирование устойчивости на живой БД (задача 5.32, миграция 0075):
// цели и запуски с записями аудита в той же транзакции, ключ запуска в
// счётчике изменений конфигурации, прерывание при запуске сервера,
// сроки хранения, удаление цели без потери запусков. Переменная
// AISEC_TEST_DATABASE_URL; без неё тесты пропускаются. Каждый тест — в
// своей схеме, сервер работает под ролью aisec_app.

func pgTestCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	owner *pgxpool.Pool
	st    *PGStore
}

func setupPG(t *testing.T) *pgEnv {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgTestCtx(t)
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
	schema := "redteam_test_" + hex.EncodeToString(b)
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
	return &pgEnv{owner: owner, st: st}
}

func (e *pgEnv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(pgTestCtx(t), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *pgEnv) audits(t *testing.T, action string) int {
	t.Helper()
	return e.count(t, "SELECT count(*) FROM audit_log WHERE action = $1", action)
}

func (e *pgEnv) revision(t *testing.T) int {
	t.Helper()
	return e.count(t, "SELECT COALESCE(max(revision), 0)::int FROM config_revisions WHERE org_id = $1", audit.DefaultOrgID)
}

// Запуск цели endpoint на мок-LLM с хранилищем PostgreSQL: итоги и аудит
// в БД, промптов и значения секретного заголовка в БД нет; удаление цели
// оставляет запуск с её именем.
func TestPGRedTeamEndpointRun(t *testing.T) {
	pg := setupPG(t)
	e := newEnv(t, func(o *Options) { o.Store = pg.st })
	tg := e.target(func(in *TargetInput) { in.AuthHeader = "X-Api-Key" })
	const secret = "pg-auth-value-31c2" //nolint:gosec // G101: синтетическое значение заголовка для проверки, что оно не сохраняется
	run, err := e.s.StartRun(context.Background(), admin, StartInput{TargetID: tg.ID, AuthValue: secret,
		Scenarios: []string{"RT-DM01-001", "RT-DM06-001", "RT-DM08-001"}})
	if err != nil {
		t.Fatal(err)
	}
	r, res := e.wait(run.ID)
	if r.Status != RunDone || len(res) != 3 || r.Counts[VerdictSucceeded] == 0 {
		t.Fatalf("запуск: %+v %+v", r, res)
	}
	if n := pg.count(t, "SELECT count(*) FROM redteam_results WHERE run_id = $1", run.ID); n != 3 {
		t.Fatalf("итогов в БД: %d", n)
	}
	for _, a := range []string{ActionTargetCreated, ActionRunStarted, ActionRunFinished} {
		if pg.audits(t, a) != 1 {
			t.Errorf("записей %s: %d", a, pg.audits(t, a))
		}
	}
	// Значения секретного заголовка нет ни в итогах, ни в целях, ни в
	// аудите; промптов атак — в целях и аудите (выдержка masked — ответ
	// цели, мок повторяет вопрос).
	for _, q := range []string{
		"SELECT count(*) FROM redteam_targets WHERE row_to_json(redteam_targets)::text LIKE '%' || $1 || '%'",
		"SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'",
	} {
		for _, s := range []string{secret, "Забудь все предыдущие", "without any rules"} {
			if n := pg.count(t, q, s); n != 0 {
				t.Errorf("%q найдено: %s", s, q)
			}
		}
	}
	if n := pg.count(t, "SELECT count(*) FROM redteam_results WHERE row_to_json(redteam_results)::text LIKE '%' || $1 || '%'", secret); n != 0 {
		t.Error("значение секретного заголовка в итогах")
	}
	if err := e.s.DeleteTarget(context.Background(), admin, tg.ID); err != nil {
		t.Fatal(err)
	}
	got, err := pg.st.Run(context.Background(), audit.DefaultOrgID, run.ID)
	if err != nil || got.TargetID != "" || got.TargetName != tg.Name {
		t.Fatalf("запуск удалённой цели: %+v %v", got, err)
	}
}

// Ключ запуска цели gateway: начало и конец растят счётчик конфигурации,
// запуск без ключа — нет; прерывание при запуске сервера и сроки хранения.
func TestPGRedTeamKeysInterruptPurge(t *testing.T) {
	pg := setupPG(t)
	ctx := pgTestCtx(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	tg := Target{ID: "01900000-0000-7000-8000-0000000000e1", OrgID: audit.DefaultOrgID, Name: "Бот", Kind: KindEndpoint,
		URL: testTarget, RequestTemplate: `{"q":"{{prompt}}"}`, ResponsePath: "a", AuthorizationNote: "Договор о пилоте № 17",
		Storage: StorageNone, Limits: Limits{30, 2, 30, 30}, CreatedAt: now, CreatedBy: "t", UpdatedAt: now, UpdatedBy: "t"}
	if err := pg.st.CreateTarget(ctx, tg, admin.entry(ActionTargetCreated, objectTarget, tg.ID, map[string]any{})); err != nil {
		t.Fatal(err)
	}
	rev := pg.revision(t)
	base := Run{OrgID: audit.DefaultOrgID, TargetID: tg.ID, TargetName: tg.Name, TargetKind: KindGateway, Status: RunRunning,
		Scenarios: 1, Counts: Counts{}, StartedAt: now, StartedBy: "t", Deadline: now.Add(time.Hour)}
	keyed := base
	keyed.ID, keyed.AppID, keyed.KeyPrefix, keyed.KeyHash = "01900000-0000-7000-8000-0000000000e2", "01900000-0000-7000-8000-0000000000a1",
		"rtkey001", []byte(strings.Repeat("k", 32))
	if err := pg.st.CreateRun(ctx, keyed, admin.entry(ActionRunStarted, objectRun, keyed.ID, map[string]any{})); err != nil {
		t.Fatal(err)
	}
	if got := pg.revision(t); got != rev+1 {
		t.Fatalf("счётчик после ключа запуска: %d, было %d", got, rev)
	}
	plain := base
	plain.ID, plain.TargetKind = "01900000-0000-7000-8000-0000000000e3", KindEndpoint
	if err := pg.st.CreateRun(ctx, plain, admin.entry(ActionRunStarted, objectRun, plain.ID, map[string]any{})); err != nil {
		t.Fatal(err)
	}
	if got := pg.revision(t); got != rev+1 {
		t.Fatalf("запуск без ключа изменил счётчик: %d", got)
	}
	keys, err := pg.st.ActiveKeys(ctx, audit.DefaultOrgID, now)
	if err != nil || len(keys) != 1 || keys[0].KeyPrefix != "rtkey001" || len(keys[0].KeyHash) != 32 {
		t.Fatalf("ключи: %+v %v", keys, err)
	}
	if keys, _ := pg.st.ActiveKeys(ctx, audit.DefaultOrgID, now.Add(2*time.Hour)); len(keys) != 0 { //nolint:gosec // G104: при ошибке значение пустое и проверка ниже падает
		t.Fatal("ключ после срока запуска выдан")
	}
	if err := pg.st.SaveResult(ctx, audit.DefaultOrgID, Result{RunID: plain.ID, ScenarioID: "RT-DM01-001", Lang: LangRU,
		Threat: "DM-01", Category: "injection", Verdict: VerdictBlocked, Step: 1}); err != nil {
		t.Fatal(err)
	}
	// Запуск сервера: идущие запуски — failed/interrupted с аудитом, ключ
	// уходит из пакета (счётчик растёт).
	n, err := pg.st.Interrupt(ctx, audit.DefaultOrgID, now, func(r Run) audit.Entry {
		return systemEntry(ActionRunFinished, r, map[string]any{"status": r.Status, "reason": r.Reason})
	})
	if err != nil || n != 2 || pg.audits(t, ActionRunFinished) != 2 || pg.revision(t) != rev+2 {
		t.Fatalf("прерывание: %d %v, счётчик %d", n, err, pg.revision(t))
	}
	if r, _ := pg.st.Run(ctx, audit.DefaultOrgID, keyed.ID); r.Status != RunFailed || r.Reason != ReasonInterrupted || r.FinishedAt == nil { //nolint:gosec // G104: при ошибке значение пустое и проверка ниже падает
		t.Fatalf("прерванный запуск: %+v", r)
	}
	if keys, _ := pg.st.ActiveKeys(ctx, audit.DefaultOrgID, now); len(keys) != 0 { //nolint:gosec // G104: при ошибке значение пустое и проверка ниже падает
		t.Fatal("ключ прерванного запуска выдан")
	}
	if err := pg.st.FinishRun(ctx, keyed, audit.Entry{}); err == nil {
		t.Fatal("завершение уже завершённого запуска")
	}
	// Сроки хранения: итоги удаляются раньше запусков.
	if err := pg.st.Purge(ctx, audit.DefaultOrgID, time.Now().Add(time.Minute), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if pg.count(t, "SELECT count(*) FROM redteam_results") != 0 || pg.count(t, "SELECT count(*) FROM redteam_runs") != 2 {
		t.Fatal("очистка итогов")
	}
	if err := pg.st.Purge(ctx, audit.DefaultOrgID, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if pg.count(t, "SELECT count(*) FROM redteam_runs") != 0 {
		t.Fatal("очистка запусков")
	}
	// Ограничения таблиц: значение вне перечня отвергает сама БД.
	bad := base
	bad.ID, bad.Status = "01900000-0000-7000-8000-0000000000e4", "paused"
	if err := pg.st.CreateRun(ctx, bad, admin.entry(ActionRunStarted, objectRun, bad.ID, map[string]any{})); err == nil {
		t.Fatal("неизвестное состояние запуска принято")
	}
}
