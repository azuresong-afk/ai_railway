package gwregistry_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются
// (в CI PostgreSQL нет). Каждый тест — в своей схеме. aisec-cli работает
// под владельцем схемы, сервер — под ролью aisec_app, как в установке.

type pgEnv struct {
	owner, app *pgxpool.Pool
	cli, srv   *gwregistry.Service
	clock      *clock
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
	cfg.MaxConns = 16
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
	schema := "gw_test_" + hex.EncodeToString(b)
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
	ca, err := aisecCrypto.NewCA("AISec test CA", 400*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e := &pgEnv{owner: owner, app: newPool(t, dsn, schema, "aisec_app"), clock: &clock{t: time.Now().UTC().Truncate(time.Microsecond)}}
	mk := func(pool *pgxpool.Pool, withCA *aisecCrypto.CA) *gwregistry.Service {
		l, err := audit.New(pool, p)
		if err != nil {
			t.Fatal(err)
		}
		st, err := gwregistry.NewPGStore(pool, l)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := gwregistry.New(gwregistry.Options{Store: st, Provider: p, CA: withCA, Audit: l, Clock: e.clock.now})
		if err != nil {
			t.Fatal(err)
		}
		return svc
	}
	e.cli, e.srv = mk(owner, nil), mk(e.app, ca)
	return e
}

func (e *pgEnv) issue(t *testing.T, name string, rereg bool) string {
	t.Helper()
	tok, _, err := e.cli.IssueToken(pgCtx(t), gwregistry.TokenInput{Name: name, Reregister: rereg, Actor: cliActor})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *pgEnv) register(t *testing.T, tok string) gwregistry.Registration {
	t.Helper()
	_, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := e.srv.Register(pgCtx(t), gwregistry.RegisterInput{Token: tok, CSR: csr, SourceIP: testIP})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func (e *pgEnv) actions(t *testing.T) map[string]int {
	t.Helper()
	rows, err := e.owner.Query(pgCtx(t), "SELECT action, result FROM audit_log")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for rows.Next() {
		var a, r string
		if err := rows.Scan(&a, &r); err != nil {
			t.Fatal(err)
		}
		out[a+"/"+r]++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPGRegistryLifecycle(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	reg := e.register(t, e.issue(t, "gw-1", false))
	peer, err := aisecCrypto.ParseCertInfo(reg.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Authenticate(ctx, peer, testIP); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := e.srv.Heartbeat(ctx, reg.Gateway.ID, gwregistry.HeartbeatInput{Version: "2.0.0", BundleETag: `"e1"`}, testIP); err != nil {
		t.Fatal(err)
	}
	list, err := e.cli.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("список: %+v %v", list, err)
	}
	g := list[0]
	if g.Status != gwregistry.StatusActive || g.Version != "2.0.0" || g.BundleETag != `"e1"` || g.LastAddr != testIP ||
		g.LastSeenAt.IsZero() || g.CertSerial != peer.Serial {
		t.Fatalf("строка шлюза: %+v", g)
	}
	// Повторная регистрация заменяет сертификат: прежний не принимается.
	reg2 := e.register(t, e.issue(t, "gw-1", true))
	if reg2.Gateway.ID != reg.Gateway.ID {
		t.Fatal("перерегистрация создала новый шлюз")
	}
	if _, err := e.srv.Authenticate(ctx, peer, testIP); !errors.Is(err, gwregistry.ErrUnknownCert) {
		t.Fatalf("прежний сертификат: %v", err)
	}
	if _, err := e.cli.Revoke(ctx, "gw-1", cliActor); err != nil {
		t.Fatal(err)
	}
	peer2, err := aisecCrypto.ParseCertInfo(reg2.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Authenticate(ctx, peer2, testIP); !errors.Is(err, gwregistry.ErrRevoked) {
		t.Fatalf("отозванный шлюз: %v", err)
	}
	got := e.actions(t)
	for k, n := range map[string]int{
		"gateway.token_issue/success": 2, "gateway.register/success": 2, "gateway.revoke/success": 1, "gateway.mtls_denied/denied": 2,
	} {
		if got[k] != n {
			t.Errorf("аудит %s: %d, ожидается %d (все: %v)", k, got[k], n, got)
		}
	}
}

func TestPGRegisterTokenOnce(t *testing.T) {
	e := setupPG(t)
	tok := e.issue(t, "gw-1", false)
	_, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	ok, denied := 0, 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.srv.Register(context.Background(), gwregistry.RegisterInput{Token: tok, CSR: csr})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, gwregistry.ErrTokenInvalid):
				denied++
			default:
				t.Errorf("регистрация: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || denied != 7 {
		t.Fatalf("успешных %d, отказов %d", ok, denied)
	}
	// Истёкший токен.
	tok2 := e.issue(t, "gw-2", false)
	e.clock.add(gwregistry.DefaultTokenTTL)
	if _, err := e.srv.Register(pgCtx(t), gwregistry.RegisterInput{Token: tok2, CSR: csr}); !errors.Is(err, gwregistry.ErrTokenInvalid) {
		t.Fatalf("истёкший токен: %v", err)
	}
}

// Права роли сервера и триггеры: шлюзы создаёт и отзывает только владелец,
// отзыв окончательный, токен гасится один раз, строки не удаляются.
func TestPGRegistryGuards(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	reg := e.register(t, e.issue(t, "gw-1", false))
	id := reg.Gateway.ID
	for name, q := range map[string]string{
		"вставка шлюза":     "INSERT INTO gateways (id, org_id, name, status, created_at, created_by) VALUES ('0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', '" + audit.DefaultOrgID + "', 'x', 'pending', now(), 'x')",
		"отзыв сервером":    "UPDATE gateways SET revoked_at = now() WHERE id = '" + id + "'",
		"переименование":    "UPDATE gateways SET name = 'other' WHERE id = '" + id + "'",
		"вставка токена":    "INSERT INTO gateway_tokens (id, gateway_id, hash_alg, token_hash, created_at, expires_at) VALUES ('0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c', '" + id + "', 'SHA-256', '\\x00112233445566778899aabbccddeeff', now(), now() + interval '1 hour')",
		"снятие погашения":  "UPDATE gateway_tokens SET used_at = NULL",
		"удаление шлюза":    "DELETE FROM gateways",
		"удаление токенов":  "DELETE FROM gateway_tokens",
		"смена хеша токена": "UPDATE gateway_tokens SET token_hash = '\\x00112233445566778899aabbccddeeff'",
	} {
		if _, err := e.app.Exec(ctx, q); err == nil {
			t.Errorf("aisec_app: %s выполнено", name)
		}
	}
	if _, err := e.cli.Revoke(ctx, "gw-1", cliActor); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"возврат отозванного": "UPDATE gateways SET status = 'active', revoked_at = NULL WHERE id = '" + id + "'",
		"повторное погашение": "UPDATE gateway_tokens SET used_at = now()",
		"удаление шлюза":      "DELETE FROM gateways WHERE id = '" + id + "'",
		"очистка":             "TRUNCATE gateways CASCADE",
	} {
		if _, err := e.owner.Exec(ctx, q); err == nil {
			t.Errorf("владелец: %s выполнено", name)
		}
	}
	if _, err := e.srv.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1"}, testIP); !errors.Is(err, gwregistry.ErrNotFound) {
		t.Fatalf("heartbeat отозванного: %v", err)
	}
}

// Н38 ревью 2.r4 на PostgreSQL под aisec_app: запрос проверки, передача в
// heartbeat, снятие ответом с записью итога в журнал одной транзакцией.
func TestPGGatewayVerifyRequest(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	reg := e.register(t, e.issue(t, "gw-1", false))
	id := reg.Gateway.ID
	if n, err := e.srv.RequestVerify(ctx, cliActor, testIP); err != nil || n != 1 {
		t.Fatalf("запрос: %d %v", n, err)
	}
	res, err := e.srv.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1"}, testIP)
	if err != nil || res.VerifyRequestedAt.IsZero() {
		t.Fatalf("запрос в heartbeat: %+v %v", res, err)
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	in := gwregistry.HeartbeatInput{Version: "1", VerifyRequest: res.VerifyRequestedAt,
		Integrity: &gwregistry.CheckReport{OK: true, At: e.clock.now(), Reason: "ok"}}
	if res, err := e.srv.Heartbeat(ctx, id, in, testIP); err != nil || !res.VerifyRequestedAt.IsZero() {
		t.Fatalf("ответ на запрос: %+v %v", res, err)
	}
	list, err := e.cli.List(ctx)
	if err != nil || len(list) != 1 || !list[0].VerifyRequestedAt.IsZero() {
		t.Fatalf("запрос не снят: %+v %v", list, err)
	}
	if a := e.actions(t); a["integrity.verify_requested/success"] != 1 || a["integrity.check/success"] != 1 {
		t.Fatalf("журнал: %v", a)
	}
}

// Запуск и остановка шлюза на PostgreSQL (В27 ревью 2.r5): время с
// наносекундами сравнивается после округления, записи — в одной
// транзакции с heartbeat.
func TestPGGatewayStartStop(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	reg := e.register(t, e.issue(t, "gw-1", false))
	id := reg.Gateway.ID
	started := e.clock.now().Add(-time.Minute).Add(789 * time.Nanosecond)
	for i, in := range []gwregistry.HeartbeatInput{
		{Version: "1", StartedAt: started},
		{Version: "1", StartedAt: started},
		{Version: "1", StartedAt: started, Stopping: true},
		{Version: "1", StartedAt: started.Add(time.Second)},
	} {
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
		if _, err := e.srv.Heartbeat(ctx, id, in, testIP); err != nil {
			t.Fatalf("heartbeat %d: %v", i, err)
		}
		if i == 2 {
			list, err := e.cli.List(ctx)
			if err != nil || len(list) != 1 || !list[0].StartedAt.IsZero() {
				t.Fatalf("время запуска не стёрто: %+v %v", list, err)
			}
		}
	}
	if a := e.actions(t); a["component.start/success"] != 2 || a["component.stop/success"] != 1 {
		t.Fatalf("журнал: %v", a)
	}
	list, err := e.cli.List(ctx)
	if err != nil || len(list) != 1 || !list[0].StartedAt.Equal(started.Add(time.Second).Truncate(time.Microsecond)) {
		t.Fatalf("время запуска: %+v %v", list, err)
	}
}
