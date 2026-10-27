package approvals_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/approvals"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/keyring/keyringtest"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются.
// Каждый тест — в своей схеме; сервер работает под ролью aisec_app.

const (
	pgGatewayA = "01900000-0000-7000-8000-0000000000a1"
	pgGatewayB = "01900000-0000-7000-8000-0000000000b1"
	pgUser     = "01900000-0000-7000-8000-0000000000c1"
)

var pgArgsHash = strings.Repeat("ab", 32)

type pgEnv struct {
	owner, app *pgxpool.Pool
	provider   aisecCrypto.Provider
	dir        string
	box        *keyring.Box
	svc        *approvals.Service
	by         approvals.By
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

func setupPG(t *testing.T, clock func() time.Time) *pgEnv {
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
	schema := "appr_test_" + hex.EncodeToString(b)
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
	for i, id := range []string{pgGatewayA, pgGatewayB} {
		if _, err := owner.Exec(ctx, `INSERT INTO gateways (id, org_id, name, status, created_at, created_by)
			VALUES ($1, $2, $3, 'pending', now(), 'cli:test')`, id, audit.DefaultOrgID, "gw-"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	dir, _ := keyringtest.Install(t, ctx, owner, p, audit.DefaultOrgID)
	app := newPool(t, dsn, schema, "aisec_app")
	box, err := keyring.Load(ctx, app, p, dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := approvals.NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := approvals.New(approvals.Options{Store: st, Provider: p, Box: box, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	by := approvals.By{Actor: audit.Actor{Type: audit.ActorUser, ID: pgUser, Name: "duty"},
		Confirm: func(context.Context) error { return nil }}
	return &pgEnv{owner: owner, app: app, provider: p, dir: dir, box: box, svc: svc, by: by}
}

func pgInput(agent string) approvals.CreateInput {
	return approvals.CreateInput{Path: approvals.PathMCP, App: "crm", Agent: agent, Server: "files", Tool: "delete_file",
		Risk: policy.RiskHigh, Rule: "tools-approve", Severity: policy.High, ArgsHash: pgArgsHash,
		Args: `{"path":"/tmp/report.txt"}`, Timeout: 10 * time.Minute}
}

func (e *pgEnv) create(t *testing.T, gw, agent string) approvals.Request {
	t.Helper()
	r, err := e.svc.Create(pgCtx(t), gw, pgInput(agent))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *pgEnv) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(pgCtx(t), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPGApprovalLifecycle(t *testing.T) {
	e := setupPG(t, nil)
	ctx := pgCtx(t)
	r := e.create(t, pgGatewayA, "support-bot")
	var raw []byte
	if err := e.owner.QueryRow(ctx, `SELECT args FROM approval_requests WHERE id = $1`, r.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "report.txt") {
		t.Fatal("аргументы в БД открыты")
	}
	got, err := e.svc.Get(ctx, r.ID)
	if err != nil || got.State != approvals.Pending || got.App != "crm" || got.Deadline.Sub(got.CreatedAt) != 10*time.Minute {
		t.Fatalf("чтение: %+v %v", got, err)
	}
	if args, err := e.svc.Args(ctx, got); err != nil || string(args) != `{"path":"/tmp/report.txt"}` {
		t.Fatalf("аргументы: %q %v", args, err)
	}
	if _, err := e.svc.Wait(ctx, pgGatewayB, r.ID, 0); !errors.Is(err, approvals.ErrNotFound) {
		t.Fatalf("чужой шлюз: %v", err)
	}
	dec, err := e.svc.Decide(ctx, e.by, r.ID, approvals.DecideInput{Approve: true, ArgsHash: pgArgsHash, Comment: "ок"})
	if err != nil || dec.State != approvals.Approved || dec.DecidedBy != pgUser {
		t.Fatalf("решение: %+v %v", dec, err)
	}
	if _, err := e.svc.Decide(ctx, e.by, r.ID, approvals.DecideInput{}); !errors.Is(err, approvals.ErrClosed) {
		t.Fatalf("повторное решение: %v", err)
	}
	w, err := e.svc.Wait(ctx, pgGatewayA, r.ID, 0)
	if err != nil || w.State != approvals.Approved || w.DecidedByName != "duty" || w.Comment != "ок" {
		t.Fatalf("опрос: %+v %v", w, err)
	}
	if e.auditCount(t, "agent.approval.requested") != 1 || e.auditCount(t, "agent.approval.approve") != 1 {
		t.Fatal("записи аудита")
	}
	list, err := e.svc.List(ctx, approvals.Filter{State: approvals.Approved, App: "crm", Agent: "support-bot", Limit: 10})
	if err != nil || len(list) != 1 || list[0].ID != r.ID {
		t.Fatalf("список: %d %v", len(list), err)
	}
	next, err := e.svc.List(ctx, approvals.Filter{AfterTime: list[0].CreatedAt, AfterID: list[0].ID, Limit: 10})
	if err != nil || len(next) != 0 {
		t.Fatalf("следующая страница: %d %v", len(next), err)
	}
}

// Пределы очереди соблюдаются при параллельном создании (блокировка шлюза).
func TestPGApprovalQueueLimitConcurrent(t *testing.T) {
	e := setupPG(t, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	created, full := 0, 0
	for range approvals.MaxPerAgent + 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.Create(context.Background(), pgGatewayA, pgInput("support-bot"))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				created++
			case errors.Is(err, approvals.ErrQueueFull):
				full++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if created != approvals.MaxPerAgent || full != 8 {
		t.Fatalf("создано %d, отклонено %d", created, full)
	}
	if n := e.auditCount(t, "agent.approval.queue_full"); n != 1 {
		t.Fatalf("записей о переполнении: %d", n)
	}
}

// Закрытый запрос не меняется даже напрямую ролью приложения; поля запроса
// не меняются никогда.
func TestPGApprovalClosedImmutable(t *testing.T) {
	e := setupPG(t, nil)
	ctx := pgCtx(t)
	r := e.create(t, pgGatewayA, "support-bot")
	if _, err := e.app.Exec(ctx, `UPDATE approval_requests SET args_hash = $2 WHERE id = $1`, r.ID, strings.Repeat("cd", 32)); err == nil {
		t.Fatal("роль приложения изменила хеш аргументов")
	}
	if _, err := e.svc.Decide(ctx, e.by, r.ID, approvals.DecideInput{}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE approval_requests SET state = 'approved' WHERE id = $1`,
		`UPDATE approval_requests SET comment = 'другое' WHERE id = $1`,
		`UPDATE approval_requests SET deadline = deadline + interval '1 minute' WHERE id = $1`,
	} {
		if _, err := e.owner.Exec(ctx, q, r.ID); err == nil {
			t.Errorf("закрытый запрос изменён: %s", q)
		}
	}
	// Аргументы закрытого удаляются, но не возвращаются.
	if _, err := e.app.Exec(ctx, `UPDATE approval_requests SET args = NULL, args_key_id = NULL, args_alg = NULL WHERE id = $1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `UPDATE approval_requests SET args = '\x00112233445566778899aabbccddeeff', args_key_id = (SELECT id FROM data_keys LIMIT 1), args_alg = 'x' WHERE id = $1`, r.ID); err == nil {
		t.Fatal("удалённые аргументы вернулись")
	}
	// У ожидающего аргументы не удаляются (CHECK).
	p := e.create(t, pgGatewayA, "support-bot")
	if _, err := e.app.Exec(ctx, `UPDATE approval_requests SET args = NULL, args_key_id = NULL, args_alg = NULL WHERE id = $1`, p.ID); err == nil {
		t.Fatal("аргументы ожидающего удалены")
	}
}

func TestPGApprovalExpireInterruptPurge(t *testing.T) {
	now := time.Now().UTC()
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); defer mu.Unlock(); now = now.Add(d) }
	e := setupPG(t, clock)
	ctx := pgCtx(t)
	expiring := e.create(t, pgGatewayA, "support-bot")
	lost := e.create(t, pgGatewayB, "support-bot")
	kept := e.create(t, pgGatewayB, "support-bot")
	advance(approvals.InterruptGrace + time.Second)
	if err := e.svc.Sync(ctx, pgGatewayB, []string{kept.ID}, false); err != nil {
		t.Fatal(err)
	}
	advance(10 * time.Minute)
	if err := e.svc.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]approvals.State{expiring.ID: approvals.Timeout, lost.ID: approvals.Interrupted, kept.ID: approvals.Timeout} {
		if got, err := e.svc.Get(ctx, id); err != nil || got.State != want {
			t.Errorf("%s: %s %v, ожидалось %s", id, got.State, err, want)
		}
	}
	if _, err := e.svc.Decide(ctx, e.by, expiring.ID, approvals.DecideInput{Approve: true, ArgsHash: pgArgsHash}); !errors.Is(err, approvals.ErrExpired) {
		t.Fatalf("решение после срока: %v", err)
	}
	advance(approvals.ArgsRetention + time.Minute)
	if err := e.svc.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Get(ctx, expiring.ID)
	if err != nil || got.Args != nil {
		t.Fatalf("аргументы не удалены: %+v %v", got, err)
	}
	advance(approvals.DefaultMetadataDays * 24 * time.Hour)
	if err := e.svc.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Get(ctx, expiring.ID); !errors.Is(err, approvals.ErrNotFound) {
		t.Fatalf("запрос не удалён: %v", err)
	}
}

// Ротация ключа данных: аргументы ожидающего запроса перешифрованы и
// читаются после вывода прежней версии (ADR-0018).
func TestPGApprovalArgsRewrap(t *testing.T) {
	e := setupPG(t, nil)
	ctx := pgCtx(t)
	r := e.create(t, pgGatewayA, "support-bot")
	ownerLog, err := audit.New(e.owner, e.provider)
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.Actor{Type: audit.ActorCLI, ID: "uid:0", Name: "root"}
	if _, err := keyring.RotateData(ctx, e.owner, ownerLog, e.provider, e.dir, audit.DefaultOrgID, actor, time.Now()); err != nil {
		t.Fatal(err)
	}
	full, err := keyring.Load(ctx, e.owner, e.provider, e.dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := keyring.Rewrap(ctx, e.owner, full, keyring.RewrapOptions{ContentPurpose: "event-content"})
	if err != nil || n.Approvals != 1 {
		t.Fatalf("перешифрование: %+v %v", n, err)
	}
	if res, err := keyring.DestroyRetired(ctx, e.owner, ownerLog, audit.DefaultOrgID, actor); err != nil || len(res.Destroyed) != 1 {
		t.Fatalf("вывод прежней версии: %+v %v", res, err)
	}
	if err := e.box.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Get(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if args, err := e.svc.Args(ctx, got); err != nil || string(args) != `{"path":"/tmp/report.txt"}` {
		t.Fatalf("аргументы после ротации: %q %v", args, err)
	}
}
