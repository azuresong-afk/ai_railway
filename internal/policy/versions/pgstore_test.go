package versions_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются
// (в CI PostgreSQL нет). Каждый тест — в своей схеме; сервер работает под
// ролью aisec_app, как в установке.

type pgEnv struct {
	owner, app *pgxpool.Pool
	svc        *versions.Service
	by         versions.By
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
	schema := "policies_test_" + hex.EncodeToString(b)
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
	e := &pgEnv{owner: owner, app: newPool(t, dsn, schema, "aisec_app"),
		by: versions.By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-00000000a001", Name: "admin"}}}
	l, err := audit.New(e.app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := versions.NewPGStore(e.app, l)
	if err != nil {
		t.Fatal(err)
	}
	if e.svc, err = versions.New(versions.Options{Store: st, Provider: p, Catalog: registry(t)}); err != nil {
		t.Fatal(err)
	}
	return e
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func (e *pgEnv) count(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(pgCtx(t), "SELECT count(*) FROM audit_log WHERE action = $1", action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPGPolicyVersions(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	d, err := e.svc.Create(ctx, e.by, spec("crm", policy.Enforce, ruleInjection, rulePII), versions.SourceAPI, "первая", versions.ConsoleDefaults)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Create(ctx, e.by, spec("crm", policy.Monitor), versions.SourceAPI, "", versions.ConsoleDefaults); !errors.Is(err, versions.ErrExists) {
		t.Fatalf("повторный ID: %v", err)
	}
	d2, err := e.svc.Update(ctx, e.by, "crm", 1, spec("crm", policy.Monitor, rulePII), versions.SourceAPI, "", versions.ConsoleDefaults)
	if err != nil || d2.Policy.Current != 2 || d2.Policy.Mode != "monitor" {
		t.Fatalf("версия 2: %+v %v", d2.Policy, err)
	}
	if _, err := e.svc.Update(ctx, e.by, "crm", 1, spec("crm", policy.Enforce), versions.SourceAPI, "", versions.ConsoleDefaults); !errors.Is(err, versions.ErrConflict) {
		t.Fatalf("устаревшая base_version: %v", err)
	}
	d3, err := e.svc.Rollback(ctx, e.by, "crm", 1, 2, "назад")
	if err != nil || d3.Version.Version != 3 || d3.Version.RolledBackFrom != 1 {
		t.Fatalf("откат: %+v %v", d3.Version, err)
	}
	got, err := e.svc.Get(ctx, "crm", 0)
	if err != nil || got.Version.Version != 3 || string(got.Version.YAML) != string(d3.Version.YAML) ||
		string(got.Version.Hash) != string(d3.Version.Hash) || got.Spec.Mode != policy.Enforce {
		t.Fatalf("текущая версия: %+v %v", got.Version, err)
	}
	v1, err := e.svc.Get(ctx, "crm", 1)
	if err != nil || string(v1.Version.YAML) != string(d.Version.YAML) {
		t.Fatalf("версия 1: %v", err)
	}
	vs, err := e.svc.Versions(ctx, "crm", 3, 10)
	if err != nil || len(vs) != 2 || vs[0].Version != 2 || vs[0].YAML != nil {
		t.Fatalf("список версий: %+v %v", vs, err)
	}
	list, err := e.svc.List(ctx)
	if err != nil || len(list) != len(policy.TemplateIDs())+1 {
		t.Fatalf("список: %+v %v", list, err)
	}
	if mode, ok, err := e.svc.PolicyMode(ctx, audit.DefaultOrgID, "crm"); err != nil || !ok || mode != "enforce" {
		t.Fatalf("PolicyMode: %s %v %v", mode, ok, err)
	}
	for action, want := range map[string]int{"policy.create": 1, "policy.update": 1, "policy.rollback": 1} {
		if n := e.count(t, action); n != want {
			t.Errorf("%s в аудите: %d", action, n)
		}
	}
}

// Два сохранения поверх одной версии: проходит одно, второе — конфликт.
func TestPGPolicyConcurrentUpdate(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.svc.Create(ctx, e.by, spec("p", policy.Enforce, ruleInjection), versions.SourceAPI, "", versions.ConsoleDefaults); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		ok, confl int
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.Update(ctx, e.by, "p", 1, spec("p", policy.Monitor), versions.SourceAPI, "", versions.ConsoleDefaults)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, versions.ErrConflict):
				confl++
			default:
				t.Errorf("сохранение: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || confl != n-1 {
		t.Fatalf("успешных %d, конфликтов %d", ok, confl)
	}
}

func TestPGPolicyGuards(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	d, err := e.svc.Create(ctx, e.by, spec("p", policy.Enforce, ruleInjection), versions.SourceAPI, "", versions.ConsoleDefaults)
	if err != nil {
		t.Fatal(err)
	}
	id := d.Policy.ID
	ins := func(version int) string {
		return "INSERT INTO policy_versions (policy_id, version, spec_yaml, spec_hash, hash_alg, source, created_at, created_by) VALUES ('" +
			id + "', " + strconv.Itoa(version) + ", 'x', '\\x00112233445566778899aabbccddeeff', 'SHA-256', 'api', now(), 'test')"
	}
	for name, q := range map[string]string{
		"правка версии":      "UPDATE policy_versions SET spec_yaml = 'x'",
		"удаление версии":    "DELETE FROM policy_versions",
		"удаление политики":  "DELETE FROM policies",
		"смена slug":         "UPDATE policies SET slug = 'q'",
		"возврат версии":     "UPDATE policies SET current_version = 0",
		"пропуск номера":     ins(3),
		"очистка версий":     "TRUNCATE policy_versions CASCADE",
		"текущая без версии": "UPDATE policies SET current_version = 2",
		"slug шаблона":       "INSERT INTO policies (id, org_id, slug, name, mode, current_version, created_at, created_by, updated_at, updated_by) VALUES ('0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', '" + audit.DefaultOrgID + "', 'base', 'x', 'monitor', 1, now(), 'x', now(), 'x')",
	} {
		if _, err := e.app.Exec(ctx, q); err == nil {
			t.Errorf("aisec_app: %s выполнено", name)
		}
	}
	for name, q := range map[string]string{
		"правка версии":     "UPDATE policy_versions SET comment = 'x'",
		"удаление версии":   "DELETE FROM policy_versions",
		"удаление политики": "DELETE FROM policies",
		"смена slug":        "UPDATE policies SET slug = 'q'",
		"пропуск номера":    ins(5),
	} {
		if _, err := e.owner.Exec(ctx, q); err == nil {
			t.Errorf("владелец: %s выполнено", name)
		}
	}
	if _, err := e.app.Exec(ctx, "DELETE FROM policy_versions"); sqlState(err) != "42501" {
		t.Errorf("DELETE под aisec_app: %v", err)
	}
	if v, err := e.svc.Get(ctx, "p", 0); err != nil || v.Version.Version != 1 {
		t.Fatalf("политика после попыток: %+v %v", v.Version, err)
	}
}
