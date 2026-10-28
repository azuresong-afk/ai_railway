package quotalease

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются.
// Каждый тест — в своей схеме; сервер работает под ролью aisec_app.

const (
	tUser     = "01900000-0000-7000-8000-00000000e001"
	tProvider = "01900000-0000-7000-8000-00000000e002"
	tAppCRM   = "01900000-0000-7000-8000-00000000e003"
	tAppHelp  = "01900000-0000-7000-8000-00000000e004"
	gwA       = "01900000-0000-7000-8000-00000000e0a1"
	gwB       = "01900000-0000-7000-8000-00000000e0a2"
	gwC       = "01900000-0000-7000-8000-00000000e0a3"
)

// pgNow — 28.10.2026 12:00 МСК.
var pgNow = time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

type pgEnv struct {
	owner, app *pgxpool.Pool
	st         *PGStore
	ids        *ids.Generator
	prov       aisecCrypto.Provider
}

func pgTestCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func newPool(t *testing.T, dsn, schema, role string, conns int32) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = conns
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

// setupPG — схема с миграциями, установка в поясе Europe/Moscow в режиме
// leased, три действующих шлюза на связи и два приложения: crm (квоты и
// жёсткий бюджет 100 ₽) и helpdesk (без лимитов).
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
	schema := "quota_test_" + hex.EncodeToString(b)
	admin := newPool(t, dsn, "public", "", 2)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE") //nolint:gosec // G104: уборка тестовой схемы
	})
	owner := newPool(t, dsn, schema, "", 4)
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
	org := audit.DefaultOrgID
	for _, q := range []string{
		"GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO aisec_app",
		`INSERT INTO install_settings (org_id, timezone, retention_mode, updated_at, quota_mode, quota_mode_changed_at)
			VALUES ('` + org + `', 'Europe/Moscow', 'masked', now(), 'leased', '2026-10-01T00:00:00Z')`,
		`INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at, must_change_password,
			created_at, created_by) VALUES ('` + tUser + `', '` + org + `', 'owner', 'Владелец', 'app_owner', 'active', 'x', now(), false, now(), 'test')`,
		`INSERT INTO providers (id, org_id, slug, name, type, base_url, ca_pem, created_at, created_by, updated_at, updated_by)
			VALUES ('` + tProvider + `', '` + org + `', 'mock', 'Mock', 'openai', 'https://mock.example', 'pem', now(), 't', now(), 't')`,
	} {
		if _, err := owner.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, a := range []struct{ id, slug, quotas string }{
		{tAppCRM, "crm", `{"requests_per_minute":100,"tokens_per_minute":1000,"tokens_per_day":10000}`},
		{tAppHelp, "helpdesk", `{}`},
	} {
		if _, err := owner.Exec(ctx, `INSERT INTO applications (id, org_id, slug, name, owner_id, env, provider_id, models, policy,
			policy_mode, storage, fail_mode, user_from, quotas, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $3, $4, 'prod', $5, '{m1}', 'default', 'enforce', 'masked', 'fail_open', 'none', $6, now(), 't', now(), 't')`,
			a.id, org, a.slug, tUser, tProvider, a.quotas); err != nil {
			t.Fatal(err)
		}
	}
	// Жёсткий бюджет crm — 100 ₽ (10 000 копеек).
	if _, err := owner.Exec(ctx, `INSERT INTO app_budgets (app_id, org_id, mode, monthly_limit, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'hard', 10000, now(), 't', now(), 't')`, tAppCRM, org); err != nil {
		t.Fatal(err)
	}
	for i, gw := range []string{gwA, gwB, gwC} {
		if _, err := owner.Exec(ctx, `INSERT INTO gateways (id, org_id, name, status, created_at, created_by, registered_at, cert_serial,
			cert_not_after, last_seen_at) VALUES ($1, $2, $3, 'active', now(), 'cli:test', now(), $4, now() + interval '1 year', $5)`,
			gw, org, fmt.Sprintf("gw-%d", i+1), fmt.Sprintf("%x", i+1), pgNow); err != nil {
			t.Fatal(err)
		}
	}
	app := newPool(t, dsn, schema, "aisec_app", 16)
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	return &pgEnv{owner: owner, app: app, st: st, ids: ids.NewGenerator(r), prov: p}
}

func (e *pgEnv) newID() (string, error) {
	id, err := e.ids.New()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (e *pgEnv) uuid(t testing.TB) string {
	t.Helper()
	id, err := e.newID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// lease — запрос одной квоты одного приложения от шлюза gw.
func (e *pgEnv) lease(ctx context.Context, gw string, now time.Time, app string, q QuotaRequest) (Grant, error) {
	resp, err := e.st.Lease(ctx, LeaseInput{OrgID: audit.DefaultOrgID, GatewayID: gw, Now: now, NewID: e.newID,
		Request: Request{Apps: []AppRequest{{App: app, Quotas: []QuotaRequest{q}}}}})
	if err != nil {
		return Grant{}, err
	}
	if q.Want == 0 {
		return Grant{}, nil
	}
	if len(resp.Apps) != 1 || len(resp.Apps[0].Quotas) != 1 {
		return Grant{}, fmt.Errorf("ответ: %+v", resp)
	}
	return resp.Apps[0].Quotas[0], nil
}

func (e *pgEnv) mustLease(t *testing.T, gw string, now time.Time, app string, q QuotaRequest) Grant {
	t.Helper()
	if q.RequestID == "" {
		q.RequestID = e.uuid(t)
	}
	g, err := e.lease(pgTestCtx(t), gw, now, app, q)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (e *pgEnv) count(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := e.owner.QueryRow(pgTestCtx(t), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Несколько шлюзов против одного сервера (ADR-0021, п. 3): параллельные
// запросы аренды трёх шлюзов не выдают больше минутной квоты, суточной
// квоты и жёсткого бюджета; доля шлюза — лимит на число шлюзов на связи.
func TestPGLeaseGatewaysNeverExceedLimits(t *testing.T) {
	e := setupPG(t)
	cases := []struct {
		quota string
		limit int64
		want  int64
	}{
		{QuotaRPM, 100, 1},
		{QuotaTPM, 1000, 7},
		{QuotaTPD, 10000, 13},
		{QuotaBudget, 10000 * 100_000, 333_333},
	}
	for _, c := range cases {
		t.Run(c.quota, func(t *testing.T) {
			var mu sync.Mutex
			var total int64
			var wg sync.WaitGroup
			errs := make(chan error, 64)
			for _, gw := range []string{gwA, gwB, gwC} {
				for range 8 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						ctx := context.Background()
						for {
							id, err := e.newID()
							if err != nil {
								errs <- err
								return
							}
							g, err := e.lease(ctx, gw, pgNow, "crm", QuotaRequest{Quota: c.quota, RequestID: id, Want: c.want})
							if err != nil {
								errs <- err
								return
							}
							mu.Lock()
							total += g.Granted
							mu.Unlock()
							if g.Granted == 0 {
								if g.RetryAfterMS <= 0 || g.Remaining != 0 {
									errs <- fmt.Errorf("отказ без срока: %+v", g)
								}
								return
							}
						}
					}()
				}
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatal(err)
			}
			if total != c.limit {
				t.Fatalf("выдано %d при лимите %d", total, c.limit)
			}
			if n := e.count(t, `SELECT COALESCE(SUM(granted), 0) FROM quota_grants WHERE quota = $1 AND kind = 'lease'`, c.quota); n != c.limit {
				t.Fatalf("в БД %d при лимите %d", n, c.limit)
			}
		})
	}
	// Доля первой аренды при трёх шлюзах: ⌈100/3⌉ минутной квоты.
	e2 := setupPG(t)
	if g := e2.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaRPM, Want: 1}); g.Granted != 34 || g.TTLMS != 10000 || g.Limit != 100 {
		t.Fatalf("начальная доля: %+v", g)
	}
	// Суточная квота: 1 % лимита (доля на 5 минут меньше).
	if g := e2.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaTPD, Want: 1}); g.Granted != 100 || g.TTLMS != 300000 {
		t.Fatalf("доля суточной квоты: %+v", g)
	}
	// Нагруженный шлюз (прошлая аренда ещё не закрыта) — удвоенная доля.
	if g := e2.mustLease(t, gwA, pgNow.Add(time.Second), "crm", QuotaRequest{Quota: QuotaRPM, Want: 1}); g.Granted != 66 || g.Remaining != 0 {
		t.Fatalf("удвоенная доля: %+v", g)
	}
}

// Минутное окно скользящее: выданное освобождается через минуту после срока
// аренды; неизрасходованный остаток возвращается отчётом.
func TestPGLeaseMinuteWindowAndReturn(t *testing.T) {
	e := setupPG(t)
	g1 := e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaRPM, Want: 100})
	if g1.Granted != 100 {
		t.Fatalf("выдача: %+v", g1)
	}
	g2 := e.mustLease(t, gwB, pgNow, "crm", QuotaRequest{Quota: QuotaRPM, Want: 1})
	if g2.Granted != 0 || g2.RetryAfterMS != (MinuteTTL+MinuteWindow).Milliseconds() {
		t.Fatalf("исчерпано: %+v", g2)
	}
	// Шлюз A израсходовал 30 и вернул остаток: B получает долю.
	e.mustLease(t, gwA, pgNow.Add(time.Second), "crm", QuotaRequest{Quota: QuotaRPM, Reports: []LeaseReport{{Lease: g1.Lease, Used: 30}}})
	if g := e.mustLease(t, gwB, pgNow.Add(2*time.Second), "crm", QuotaRequest{Quota: QuotaRPM, Want: 70}); g.Granted != 70 {
		t.Fatalf("после возврата: %+v", g)
	}
	if g := e.mustLease(t, gwC, pgNow.Add(3*time.Second), "crm", QuotaRequest{Quota: QuotaRPM, Want: 1}); g.Granted != 0 {
		t.Fatalf("сверх лимита: %+v", g)
	}
	// Через минуту после срока аренды A (10 с) её 30 освобождаются.
	at := pgNow.Add(MinuteTTL + MinuteWindow + time.Millisecond)
	if g := e.mustLease(t, gwC, at, "crm", QuotaRequest{Quota: QuotaRPM, Want: 30}); g.Granted < 30 || g.Granted > 30 {
		t.Fatalf("после окна: %+v", g)
	}
	// Неотчитанная аренда учитывается полностью до конца окна.
	if g := e.mustLease(t, gwA, at, "crm", QuotaRequest{Quota: QuotaRPM, Want: 1}); g.Granted != 0 {
		t.Fatalf("неотчитанная аренда B освобождена раньше окна: %+v", g)
	}
}

// Аренда суточной квоты и бюджета не переходит границу суток и месяца в
// поясе установки; в новом окне лимит снова полный.
func TestPGLeaseDayAndMonthBoundary(t *testing.T) {
	e := setupPG(t)
	// 23:58 МСК 31.10.2026 — до конца суток и месяца 2 минуты.
	late := time.Date(2026, 10, 31, 20, 58, 0, 0, time.UTC)
	for _, gw := range []string{gwA, gwB, gwC} {
		if _, err := e.owner.Exec(pgTestCtx(t), `UPDATE gateways SET last_seen_at = $2 WHERE id = $1`, gw, late); err != nil {
			t.Fatal(err)
		}
	}
	// Каждый шлюз получает не больше равной доли суток (4В19 ревью 4.r2):
	// ⌈10 000/3⌉, при остатке — повтор через секунду, а не в конце суток.
	d := e.mustLease(t, gwA, late, "crm", QuotaRequest{Quota: QuotaTPD, Want: 10000})
	m := e.mustLease(t, gwA, late, "crm", QuotaRequest{Quota: QuotaBudget, Want: 1})
	if d.Granted != 3334 || d.RetryAfterMS != time.Second.Milliseconds() || d.TTLMS != (2*time.Minute).Milliseconds() ||
		m.TTLMS != (2*time.Minute).Milliseconds() {
		t.Fatalf("срок у границы: %+v %+v", d, m)
	}
	e.mustLease(t, gwB, late, "crm", QuotaRequest{Quota: QuotaTPD, Want: 10000})
	if g := e.mustLease(t, gwC, late, "crm", QuotaRequest{Quota: QuotaTPD, Want: 10000}); g.Granted != 3332 || g.Remaining != 0 {
		t.Fatalf("остаток суток: %+v", g)
	}
	if g := e.mustLease(t, gwB, late, "crm", QuotaRequest{Quota: QuotaTPD, Want: 1}); g.Granted != 0 ||
		g.RetryAfterMS != (2*time.Minute).Milliseconds() {
		t.Fatalf("до конца суток: %+v", g)
	}
	keys := e.count(t, `SELECT count(*) FROM quota_grants WHERE kind = 'lease' AND window_key IN ('2026-10-31', '2026-10')`)
	if keys != 4 {
		t.Fatalf("ключи окон: %d", keys)
	}
	next := late.Add(2 * time.Minute)
	if g := e.mustLease(t, gwB, next, "crm", QuotaRequest{Quota: QuotaTPD, Want: 1}); g.Granted == 0 {
		t.Fatalf("новые сутки: %+v", g)
	}
	if n := e.count(t, `SELECT count(*) FROM quota_grants WHERE window_key = '2026-11-01'`); n != 1 {
		t.Fatalf("окно новых суток: %d", n)
	}
	if g := e.mustLease(t, gwB, next, "crm", QuotaRequest{Quota: QuotaBudget, Want: 1}); g.Granted == 0 {
		t.Fatalf("новый месяц: %+v", g)
	}
	if n := e.count(t, `SELECT count(*) FROM quota_grants WHERE window_key = '2026-11' AND kind = 'lease'`); n != 1 {
		t.Fatalf("окно нового месяца: %d", n)
	}
}

// Повтор запроса с тем же request_id возвращает ту же выдачу и не учитывает
// автономный расход дважды.
func TestPGLeaseRetryIsIdempotent(t *testing.T) {
	e := setupPG(t)
	q := QuotaRequest{Quota: QuotaTPD, RequestID: e.uuid(t), Want: 50, Offline: 500}
	g1 := e.mustLease(t, gwA, pgNow, "crm", q)
	g2 := e.mustLease(t, gwA, pgNow.Add(time.Second), "crm", q)
	if g1.Lease == "" || g1.Lease != g2.Lease || g1.Granted != g2.Granted {
		t.Fatalf("повтор: %+v %+v", g1, g2)
	}
	if n := e.count(t, `SELECT count(*) FROM quota_grants WHERE quota = 'tokens_per_day'`); n != 2 {
		t.Fatalf("выдач после повтора: %d", n)
	}
	if n := e.count(t, `SELECT SUM(granted) FROM quota_grants WHERE kind = 'offline'`); n != 500 {
		t.Fatalf("автономный расход: %d", n)
	}
	// Автономный расход минутных квот не учитывается — окно прошло.
	e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaRPM, Offline: 50})
	if n := e.count(t, `SELECT count(*) FROM quota_grants WHERE quota = 'requests_per_minute'`); n != 0 {
		t.Fatalf("минутный автономный расход: %d", n)
	}
	// Остаток суток: 10 000 − 500 офлайн − выданное; шлюзу — не больше
	// равной доли ⌈10 000/3⌉.
	if g := e.mustLease(t, gwB, pgNow, "crm", QuotaRequest{Quota: QuotaTPD, Want: 10000}); g.Granted != 3334 ||
		g.Remaining != 10000-500-g1.Granted-3334 {
		t.Fatalf("остаток суток: %+v", g)
	}
}

// Нарушения в отчёте шлюза (ADR-0021, п. 6): чужая аренда, другая квота,
// больше выданного, повтор с другим числом, ID запроса другой квоты —
// запрос отклоняется целиком и ничего не выдаётся.
func TestPGLeaseViolations(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	a := e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaRPM, Want: 10})
	reqID := e.uuid(t)
	e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaTPM, RequestID: reqID, Want: 10})
	free := func() int64 {
		return e.count(t, `SELECT COALESCE(SUM(COALESCE(used, granted)), 0) FROM quota_grants WHERE quota = 'requests_per_minute'`)
	}
	before := free()
	for name, c := range map[string]struct {
		gw     string
		app    string
		q      QuotaRequest
		reason string
	}{
		"чужая аренда":      {gwB, "crm", QuotaRequest{Quota: QuotaRPM, Want: 5, Reports: []LeaseReport{{Lease: a.Lease, Used: 0}}}, ReasonUnknownLease},
		"другая квота":      {gwA, "crm", QuotaRequest{Quota: QuotaTPD, Want: 5, Reports: []LeaseReport{{Lease: a.Lease, Used: 0}}}, ReasonUnknownLease},
		"другое приложение": {gwA, "helpdesk", QuotaRequest{Quota: QuotaRPM, Reports: []LeaseReport{{Lease: a.Lease, Used: 0}}}, ReasonUnknownLease},
		"больше выданного":  {gwA, "crm", QuotaRequest{Quota: QuotaRPM, Reports: []LeaseReport{{Lease: a.Lease, Used: a.Granted + 1}}}, ReasonOverused},
		"ID другой квоты":   {gwA, "crm", QuotaRequest{Quota: QuotaRPM, RequestID: reqID, Want: 5}, ReasonReusedRequest},
	} {
		if c.q.RequestID == "" {
			c.q.RequestID = e.uuid(t)
		}
		_, err := e.lease(ctx, c.gw, pgNow, c.app, c.q)
		var v *Violation
		if !errors.As(err, &v) || v.Reason != c.reason {
			t.Errorf("%s: %v", name, err)
		}
	}
	if after := free(); after != before {
		t.Fatalf("нарушение изменило учёт: %d → %d", before, after)
	}
	// Отчёт с тем же числом повторять можно, с другим — нет.
	rep := QuotaRequest{Quota: QuotaRPM, Reports: []LeaseReport{{Lease: a.Lease, Used: 4}}}
	e.mustLease(t, gwA, pgNow, "crm", rep)
	e.mustLease(t, gwA, pgNow, "crm", rep)
	rep.Reports[0].Used = 3
	rep.RequestID = e.uuid(t)
	var v *Violation
	if _, err := e.lease(ctx, gwA, pgNow, "crm", rep); !errors.As(err, &v) || v.Reason != ReasonRereported {
		t.Fatalf("повтор с другим числом: %v", err)
	}
	// Отчёт об удалённой аренде ни на что не влияет.
	e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaRPM, Reports: []LeaseReport{{Lease: e.uuid(t), Used: 1}}})
	// Неизвестное приложение и приложение без лимита.
	if g := e.mustLease(t, gwA, pgNow, "nope", QuotaRequest{Quota: QuotaRPM, Want: 1}); !g.Unknown || g.Granted != 0 {
		t.Fatalf("неизвестное приложение: %+v", g)
	}
	if g := e.mustLease(t, gwA, pgNow, "helpdesk", QuotaRequest{Quota: QuotaRPM, Want: 1}); !g.Unlimited {
		t.Fatalf("без лимита: %+v", g)
	}
}

// Сервис: нарушение пишется в аудит quota.lease_violation; режим local —
// ErrModeLocal; переход на local при нескольких шлюзах — с повторной
// проверкой и weakening; признак автономной доли — в Health.
func TestPGServiceModeAuditAndHealth(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	now := pgNow
	svc, err := New(Options{Store: e.st, IDs: e.ids, OrgID: audit.DefaultOrgID, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	a := e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaRPM, Want: 1})
	_, err = svc.Lease(ctx, gwB, netip.MustParseAddr("10.0.0.1"), Request{Apps: []AppRequest{{App: "crm", Quotas: []QuotaRequest{{Quota: QuotaRPM,
		RequestID: e.uuid(t), Reports: []LeaseReport{{Lease: a.Lease, Used: 0}}}}}}})
	var v *Violation
	if !errors.As(err, &v) {
		t.Fatalf("нарушение: %v", err)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'quota.lease_violation' AND actor_id = $1 AND result = 'failure'`, gwB); n != 1 {
		t.Fatalf("аудит нарушения: %d", n)
	}
	st, err := svc.Settings(ctx)
	if err != nil || st.Mode != ModeLeased || st.GatewaysOnline != 3 {
		t.Fatalf("настройки: %+v %v", st, err)
	}
	by := By{Actor: audit.Actor{Type: audit.ActorUser, ID: tUser}}
	if _, err := svc.SetMode(ctx, by, ModeLocal); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("без повторной проверки: %v", err)
	}
	by.Confirm = func(context.Context) error { return nil }
	if st, err := svc.SetMode(ctx, by, ModeLocal); err != nil || st.Mode != ModeLocal || st.ChangedAt == nil {
		t.Fatalf("переход на local: %+v %v", st, err)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'install.quota_mode_changed'
		AND (details->>'weakening')::boolean AND details::jsonb->'weakening_reasons' ? 'quota_local_multi_gateway'`); n != 1 {
		t.Fatalf("аудит ослабления: %d", n)
	}
	if _, err := svc.Lease(ctx, gwA, netip.MustParseAddr("10.0.0.1"), Request{Apps: []AppRequest{{App: "crm",
		Quotas: []QuotaRequest{{Quota: QuotaRPM, RequestID: e.uuid(t), Want: 1}}}}}); !errors.Is(err, ErrModeLocal) {
		t.Fatalf("режим local: %v", err)
	}
	if _, err := svc.SetMode(ctx, By{Actor: by.Actor}, ModeLeased); err != nil {
		t.Fatal(err)
	}
	// Признак автономной доли — у действующего шлюза, 3 минуты.
	if err := svc.Observe(ctx, gwC, true); err != nil {
		t.Fatal(err)
	}
	if h, err := svc.Health(ctx); err != nil || h.Mode != ModeLeased || len(h.Autonomous) != 1 || h.Autonomous[0] != gwC {
		t.Fatalf("Health: %+v %v", h, err)
	}
	now = now.Add(AutonomousFresh + time.Second)
	if h, err := svc.Health(ctx); err != nil || len(h.Autonomous) != 0 {
		t.Fatalf("признак устарел: %+v %v", h, err)
	}
	// До первичной настройки — ErrNotSetUp.
	if _, err := e.owner.Exec(ctx, `DELETE FROM install_settings`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetMode(ctx, by, ModeLocal); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("без настройки: %v", err)
	}
	if _, err := e.lease(ctx, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaRPM, RequestID: e.uuid(t), Want: 1}); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("аренда без настройки: %v", err)
	}
}

// Бюджет: расход месяца до включения аренды (budget_usage из heartbeat)
// учитывается строкой base один раз.
func TestPGLeaseBudgetBaseFromHeartbeat(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	// 90 ₽ из 100 уже израсходовано по heartbeat двух шлюзов.
	for _, gw := range []string{gwA, gwB} {
		if _, err := e.owner.Exec(ctx, `INSERT INTO budget_usage (org_id, gateway_id, started_at, app_slug, month, cost, priced_tokens,
			unpriced_tokens, requests, unpriced_requests, updated_at) VALUES ($1, $2, $3, 'crm', '2026-10', 450000000, 0, 0, 1, 0, $3)`,
			audit.DefaultOrgID, gw, pgNow); err != nil {
			t.Fatal(err)
		}
	}
	// Первым пришёл автономный расход 5 ₽ (первая выдача не удалась):
	// строка base всё равно создаётся при первой выдаче.
	e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaBudget, Offline: 50_000_000})
	g := e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaBudget, Want: 1})
	if g.Granted+g.Remaining != 50_000_000 {
		t.Fatalf("остаток бюджета: %+v", g)
	}
	e.mustLease(t, gwB, pgNow, "crm", QuotaRequest{Quota: QuotaBudget, Want: 1})
	if n := e.count(t, `SELECT count(*) FROM quota_grants WHERE kind = 'base'`); n != 1 {
		t.Fatalf("строк base: %d", n)
	}
}

// Очистка: выдачи старше двух окон удаляются, текущие остаются.
func TestPGPurgeOldGrants(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaRPM, Want: 1})
	e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaTPD, Want: 1})
	if err := e.st.Observe(ctx, audit.DefaultOrgID, gwA, true, pgNow); err != nil {
		t.Fatal(err)
	}
	if n, err := e.st.Purge(ctx, audit.DefaultOrgID, pgNow.Add(time.Minute)); err != nil || n != 0 {
		t.Fatalf("рано: %d %v", n, err)
	}
	if n, err := e.st.Purge(ctx, audit.DefaultOrgID, pgNow.Add(3*time.Minute)); err != nil || n != 1 {
		t.Fatalf("минутная выдача: %d %v", n, err)
	}
	if n, err := e.st.Purge(ctx, audit.DefaultOrgID, pgNow.Add(50*time.Hour)); err != nil || n != 1 {
		t.Fatalf("суточная выдача: %d %v", n, err)
	}
	if n := e.count(t, `SELECT count(*) FROM quota_gateway_state`); n != 0 {
		t.Fatalf("признаки шлюзов: %d", n)
	}
}

// 4В19 ревью 4.r2: скомпрометированный шлюз одним запросом не выбирает
// весь суточный лимит или месячный бюджет — ни огромным want, ни огромным
// автономным расходом, ни удвоением доли без отчётов; отзыв шлюза
// освобождает его неотчитанные аренды и автономный расход.
func TestPGLeaseOverclaimBounded(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	budget := int64(10000 * 100_000)
	// Огромный want — не больше равной доли (три шлюза на связи).
	if g := e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaTPD, Want: MaxUnits}); g.Granted != 3334 {
		t.Fatalf("суточная квота, огромный want: %+v", g)
	}
	if g := e.mustLease(t, gwA, pgNow, "crm", QuotaRequest{Quota: QuotaBudget, Want: MaxUnits}); g.Granted != ceilDiv(budget, 3) {
		t.Fatalf("бюджет, огромный want: %+v", g)
	}
	// Огромный автономный расход учитывается не больше доли шлюза за окно;
	// лишнее — в аудит, запрос не отклоняется.
	off := QuotaRequest{Quota: QuotaBudget, RequestID: e.uuid(t), Offline: MaxUnits}
	e.mustLease(t, gwB, pgNow, "crm", off)
	e.mustLease(t, gwB, pgNow, "crm", off) // повтор того же запроса — без второй записи
	e.mustLease(t, gwB, pgNow, "crm", QuotaRequest{Quota: QuotaBudget, Offline: MaxUnits})
	if n := e.count(t, `SELECT SUM(granted) FROM quota_grants WHERE kind = 'offline' AND gateway_id = $1`, gwB); n != ceilDiv(budget, 3) {
		t.Fatalf("автономный расход шлюза B: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'quota.lease_violation'
		AND details->>'reason' = 'offline_overclaim'`); n != 2 {
		t.Fatalf("записей offline_overclaim: %d", n)
	}
	// Шлюз C получает свою долю бюджета.
	if g := e.mustLease(t, gwC, pgNow, "crm", QuotaRequest{Quota: QuotaBudget, Want: 1}); g.Granted == 0 || g.Remaining == 0 {
		t.Fatalf("бюджет после завышенного расхода: %+v", g)
	}
	// Без отчётов удвоение — не больше двух раз подряд: 100, 200, 400, затем
	// снова начальная доля — 1 % суточной квоты.
	got := []int64{}
	for i := range 5 {
		g := e.mustLease(t, gwC, pgNow.Add(time.Duration(i+1)*time.Second), "crm", QuotaRequest{Quota: QuotaTPD, Want: 1})
		got = append(got, g.Granted)
	}
	if fmt.Sprint(got) != "[100 200 400 100 100]" {
		t.Fatalf("выдачи без отчётов: %v", got)
	}
	// Отзыв шлюза B освобождает его автономный расход, A — неотчитанные
	// аренды; отчитанное остаётся.
	l, err := audit.New(e.owner, e.prov)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := gwregistry.NewPGStore(e.owner, l)
	if err != nil {
		t.Fatal(err)
	}
	var released any
	for _, name := range []string{"gw-1", "gw-2"} {
		if _, err := reg.Revoke(ctx, audit.DefaultOrgID, name, pgNow, func(gw gwregistry.Gateway) audit.Entry {
			return audit.Entry{OrgID: audit.DefaultOrgID, Actor: audit.Actor{Type: audit.ActorCLI, ID: "test"}, Action: "gateway.revoke",
				Object: audit.Object{Type: "gateway", ID: gw.ID}, Result: audit.ResultSuccess}
		}); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM quota_grants WHERE gateway_id IN ($1, $2)`, gwA, gwB); n != 0 {
		t.Fatalf("после отзыва у A и B осталось выдач: %d", n)
	}
	if err := e.owner.QueryRow(ctx, `SELECT details->'quota_grants_released' FROM audit_log WHERE action = 'gateway.revoke'
		AND object_id = $1`, gwA).Scan(&released); err != nil || fmt.Sprint(released) != "2" {
		t.Fatalf("аудит отзыва A: %v %v", released, err)
	}
	if n := e.count(t, `SELECT count(*) FROM quota_grants WHERE gateway_id = $1`, gwC); n != 6 {
		t.Fatalf("выдачи шлюза C: %d", n)
	}
}
