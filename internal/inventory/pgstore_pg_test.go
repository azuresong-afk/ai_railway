package inventory

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/cyclonedx"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Реестр ИИ на живой БД (задача 5.17, миграция 0069): PGStore, пополнение
// по агрегатам dash_req_hour, пределы и ограничения таблиц. Переменная
// AISEC_TEST_DATABASE_URL; без неё тесты пропускаются. Каждый тест — в своей
// схеме; сервер работает под ролью aisec_app.

const (
	pgOwner    = "01900000-0000-7000-8000-00000000a001"
	pgProvider = "01900000-0000-7000-8000-00000000b001"
	pgApp      = "01900000-0000-7000-8000-00000000c001"
)

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

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

type pgEnv struct {
	owner *pgxpool.Pool
	svc   *Service
	st    *PGStore
	clock *testClock
	by    By
}

func profile(t *testing.T) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// setupPG — схема со всеми миграциями, провайдер, владелец и приложение.
func setupPG(t *testing.T) *pgEnv {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgTestCtx(t)
	p := profile(t)
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "inventory_test_" + hex.EncodeToString(b)
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
	mustExec(t, owner, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by) VALUES ($1, $2, 'owner', 'Владелец', 'app_owner', 'active', 'x', now(), false, now(), 'test')`,
		pgOwner, audit.DefaultOrgID)
	mustExec(t, owner, `INSERT INTO providers (id, org_id, slug, name, type, base_url, ca_pem, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'gigachat', 'GigaChat', 'gigachat', 'https://gigachat.example.ru', 'x', now(), 'test', now(), 'test')`,
		pgProvider, audit.DefaultOrgID)
	mustExec(t, owner, `INSERT INTO applications (id, org_id, slug, name, owner_id, env, provider_id, models, policy, policy_mode, storage,
			fail_mode, user_from, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'billing', 'Биллинг', $3, 'prod', $4, '{GigaChat-Pro}', 'base', 'monitor', 'masked', 'fail_open', 'none',
			now(), 'test', now(), 'test')`, pgApp, audit.DefaultOrgID, pgOwner, pgProvider)
	app := newPool(t, dsn, schema, "aisec_app")
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	e := &pgEnv{owner: owner, st: st, clock: &testClock{t: time.Date(2026, 10, 30, 12, 34, 0, 0, time.UTC)},
		by: By{Actor: audit.Actor{Type: audit.ActorUser, ID: pgOwner, Name: "admin"}}}
	if e.svc, err = New(Options{Store: st, Provider: p, Clock: e.clock.now}); err != nil {
		t.Fatal(err)
	}
	return e
}

func mustExec(t *testing.T, p *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := p.Exec(pgTestCtx(t), sql, args...); err != nil {
		t.Fatal(err)
	}
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
	return e.count(t, `SELECT count(*) FROM audit_log WHERE action = $1`, action)
}

// aggregate — строка почасового агрегата дашбордов.
func (e *pgEnv) aggregate(t *testing.T, bucket time.Time, app, provider, model string) {
	t.Helper()
	mustExec(t, e.owner, `INSERT INTO dash_req_hour (org_id, bucket, app, provider, model, action, mode, requests, with_findings,
			non_text_unchecked, tokens_prompt, tokens_completion, cost, unpriced_requests)
		VALUES ($1, $2, $3, $4, $5, 'allow', 'monitor', 3, 0, 0, 10, 20, 0, 3)`, audit.DefaultOrgID, bucket, app, provider, model)
}

func customerInput(t *testing.T, name string, files ...string) ModelInput {
	t.Helper()
	fs := make([]string, len(files))
	for i, f := range files {
		fs[i] = fileJSON(f)
	}
	in, err := ParseModelInput([]byte(`{"kind":"customer","name":"` + name + `","version":"1","owner":"Отдел ИИ","files":[` + strings.Join(fs, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestPGInventoryModels(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	m, err := e.svc.CreateModel(ctx, e.by, customerInput(t, "llama-ft", "model.safetensors", "adapters/lora.safetensors"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateModel(ctx, e.by, customerInput(t, "llama-ft")); !errors.Is(err, ErrExists) {
		t.Fatalf("повтор: %v", err)
	}
	in := customerInput(t, "other")
	in.Provider = "nope"
	if _, err := e.svc.CreateModel(ctx, e.by, in); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("неизвестный провайдер: %v", err)
	}
	in.Provider = "gigachat"
	served, err := e.svc.CreateModel(ctx, e.by, in)
	if err != nil {
		t.Fatal(err)
	}
	got, usage, err := e.svc.Model(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != OriginManual || len(got.Files) != 2 || got.Files[0].Path != "adapters/lora.safetensors" || hex.EncodeToString(got.Files[1].Hash) != testHash ||
		len(usage) != 0 || got.FirstSeen != nil {
		t.Fatalf("карточка: %+v, %+v", got, usage)
	}
	if n := e.audits(t, "inventory.model_created"); n != 2 {
		t.Fatalf("записей inventory.model_created: %d", n)
	}
	// Список: отбор и курсор.
	page, err := e.svc.Models(ctx, Filter{Limit: 1})
	if err != nil || len(page) != 1 || page[0].ID != m.ID || page[0].FileCount != 2 || page[0].Files != nil {
		t.Fatalf("первая страница: %+v, %v", page, err)
	}
	page, err = e.svc.Models(ctx, Filter{After: &Cursor{CreatedAt: page[0].CreatedAt, ID: page[0].ID}, Limit: 10})
	if err != nil || len(page) != 1 || page[0].ID != served.ID {
		t.Fatalf("вторая страница: %+v, %v", page, err)
	}
	for f, want := range map[string]int{"LLAMA": 1, "нет": 0} {
		if page, err := e.svc.Models(ctx, Filter{Query: f}); err != nil || len(page) != want {
			t.Errorf("q=%s: %d, %v", f, len(page), err)
		}
	}
	if page, err := e.svc.Models(ctx, Filter{Provider: "gigachat", Kind: KindCustomer, Origin: OriginManual}); err != nil || len(page) != 1 {
		t.Errorf("отбор по провайдеру: %d, %v", len(page), err)
	}
	// Изменение: замена файлов и вид; без отличий — без аудита.
	p, err := ParseModelPatch([]byte(`{"title":"Кредиты","files":[` + fileJSON("model.gguf") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	upd, err := e.svc.UpdateModel(ctx, e.by, m.ID, p)
	if err != nil || upd.Title != "Кредиты" || len(upd.Files) != 1 {
		t.Fatalf("изменение: %+v, %v", upd, err)
	}
	if _, err := e.svc.UpdateModel(ctx, e.by, m.ID, p); err != nil {
		t.Fatal(err)
	}
	if n := e.audits(t, "inventory.model_updated"); n != 1 {
		t.Fatalf("записей inventory.model_updated: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM inventory_model_files WHERE model_id = $1`, m.ID); n != 1 {
		t.Fatalf("файлов после замены: %d", n)
	}
	kind := KindProvider
	if _, err := e.svc.UpdateModel(ctx, e.by, m.ID, ModelPatch{Kind: &kind}); err == nil {
		t.Fatal("модель без провайдера стала моделью провайдера")
	}
	if _, err := e.svc.UpdateModel(ctx, e.by, "01900000-0000-7000-8000-0000000000ff", p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет модели: %v", err)
	}
	// Подробности аудита без хешей.
	var details string
	if err := e.owner.QueryRow(ctx, `SELECT details::text FROM audit_log WHERE action = 'inventory.model_updated'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, testHash) || !strings.Contains(details, `"files"`) {
		t.Fatalf("подробности: %s", details)
	}
	// Удаление каскадом.
	if err := e.svc.DeleteModel(ctx, e.by, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteModel(ctx, e.by, m.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("повторное удаление: %v", err)
	}
	if n := e.count(t, `SELECT count(*) FROM inventory_model_files WHERE model_id = $1`, m.ID); n != 0 || e.audits(t, "inventory.model_deleted") != 1 {
		t.Fatalf("файлов после удаления: %d", n)
	}
}

func TestPGInventoryDiscoverAndOverview(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	hour := e.clock.t.Truncate(time.Hour)
	e.aggregate(t, hour.Add(-30*24*time.Hour), "billing", "gigachat", "GigaChat-Pro")
	e.aggregate(t, hour.Add(-time.Hour), "billing", "gigachat", "GigaChat-Pro")
	e.aggregate(t, hour, "billing", "gigachat", "GigaChat-Max")
	e.aggregate(t, hour, "support", "gigachat", "GigaChat-Pro")
	// Check API без провайдера и модели и провайдер с неверным ID — пропускаются.
	e.aggregate(t, hour, "billing", "", "")
	e.aggregate(t, hour, "billing", "Bad Provider", "m")
	// Модель заказчика, которую обслуживает провайдер продукта: связывается с трафиком.
	in := customerInput(t, "llama-ft", "model.safetensors")
	in.Provider = "gigachat"
	cm, err := e.svc.CreateModel(ctx, e.by, in)
	if err != nil {
		t.Fatal(err)
	}
	e.aggregate(t, hour, "billing", "gigachat", "llama-ft")

	res, err := e.svc.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Models != 2 || res.Links != 4 || res.Skipped != 0 || len(res.Names) != 2 {
		t.Fatalf("первый запуск: %+v", res)
	}
	if n := e.audits(t, "inventory.discovered"); n != 1 {
		t.Fatalf("записей inventory.discovered: %d", n)
	}
	got, usage, err := e.svc.Model(ctx, cm.ID)
	if err != nil || got.Origin != OriginManual || got.FirstSeen == nil || !got.FirstSeen.Equal(hour) || len(usage) != 1 {
		t.Fatalf("модель заказчика после пополнения: %+v, %+v, %v", got, usage, err)
	}
	pro, err := e.svc.Models(ctx, Filter{Origin: OriginTraffic, Query: "GigaChat-Pro"})
	if err != nil || len(pro) != 1 || pro[0].Kind != KindProvider || !pro[0].FirstSeen.Equal(hour.Add(-30*24*time.Hour)) || !pro[0].LastSeen.Equal(hour) {
		t.Fatalf("модель из трафика: %+v, %v", pro, err)
	}
	us, err := e.svc.Usage(ctx, UsageFilter{App: "billing"})
	if err != nil || len(us) != 3 {
		t.Fatalf("использование billing: %+v, %v", us, err)
	}
	// Повтор окна ничего не меняет и аудит не пишет.
	e.clock.t = e.clock.t.Add(10 * time.Minute)
	if res, err := e.svc.Discover(ctx); err != nil || res.Models != 0 || res.Links != 0 {
		t.Fatalf("повтор: %+v, %v", res, err)
	}
	if n := e.audits(t, "inventory.discovered"); n != 1 {
		t.Fatalf("повтор записал аудит: %d", n)
	}
	// Строка прошлого часа внутри окна (шлюз дослал накопленное) — учитывается;
	// старше окна — нет: окно от отметки минус SyncOverlap.
	e.clock.t = e.clock.t.Add(24 * time.Hour)
	e.aggregate(t, hour.Add(-5*24*time.Hour), "late", "gigachat", "GigaChat-Pro")
	e.aggregate(t, hour.Add(-20*24*time.Hour), "ancient", "gigachat", "GigaChat-Pro")
	if res, err := e.svc.Discover(ctx); err != nil || res.Links != 1 {
		t.Fatalf("досланные часы: %+v, %v", res, err)
	}
	// Удалённая модель из трафика появляется снова при новом трафике.
	if err := e.svc.DeleteModel(ctx, e.by, pro[0].ID); err != nil {
		t.Fatal(err)
	}
	if res, err := e.svc.Discover(ctx); err != nil || res.Models != 1 {
		t.Fatalf("после удаления: %+v, %v", res, err)
	}

	// Сводка: ключи без отозванных, состояние истёкшего, провайдер без учётных данных.
	now := e.clock.t
	mustExec(t, e.owner, `INSERT INTO app_keys (id, org_id, app_id, name, prefix, key_hash, hash_alg, expires_at, created_at, created_by)
		VALUES ('01900000-0000-7000-8000-00000000d001', $1, $2, 'Основной', 'aisec_aaaaaaaa', '\x00112233445566778899aabbccddeeff', 'SHA-256', $3, $4, 'test'),
			('01900000-0000-7000-8000-00000000d002', $1, $2, 'Старый', 'aisec_bbbbbbbb', '\x00112233445566778899aabbccddeeff', 'SHA-256', $5, $6, 'test')`,
		audit.DefaultOrgID, pgApp, now.Add(24*time.Hour), now.Add(-time.Hour), now.Add(-time.Minute), now.Add(-48*time.Hour))
	mustExec(t, e.owner, `INSERT INTO app_keys (id, org_id, app_id, name, prefix, key_hash, hash_alg, expires_at, created_at, created_by, revoked_at, revoked_by)
		VALUES ('01900000-0000-7000-8000-00000000d003', $1, $2, 'Отозван', 'aisec_cccccccc', '\x00112233445566778899aabbccddeeff', 'SHA-256', $3, $4, 'test', $4, 'test')`,
		audit.DefaultOrgID, pgApp, now.Add(24*time.Hour), now.Add(-2*time.Hour))
	o, err := e.svc.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Apps) != 1 || len(o.Apps[0].Keys) != 2 || o.Apps[0].Keys[0].State != KeyActive || o.Apps[0].Keys[1].State != KeyExpired ||
		o.Apps[0].Provider != "gigachat" || o.Apps[0].Models[0] != "GigaChat-Pro" {
		t.Fatalf("приложения: %+v", o.Apps)
	}
	if len(o.Providers) != 1 || o.Providers[0].CredentialSet || o.Providers[0].External != true {
		t.Fatalf("провайдеры: %+v", o.Providers)
	}
	if o.Models != 3 || o.Usage != 5 || o.Sync.SyncedUpto == nil || !o.Sync.SyncedUpto.Equal(now.Truncate(time.Hour)) || o.Sync.LimitReached {
		t.Fatalf("сводка: %+v", o)
	}
}

func TestPGInventoryLimits(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	mustExec(t, e.owner, `INSERT INTO inventory_models (id, org_id, kind, provider, name, origin, created_at, created_by, updated_at, updated_by)
		SELECT ('01900000-0000-7000-8000-' || lpad(to_hex(g), 12, '0'))::uuid, $1, 'customer', '', 'm' || g, 'manual', now(), 'test', now(), 'test'
		FROM generate_series(1, $2::int) g`, audit.DefaultOrgID, MaxModels)
	if _, err := e.svc.CreateModel(ctx, e.by, customerInput(t, "one-more")); !errors.Is(err, ErrTooMany) {
		t.Fatalf("сверх предела моделей: %v", err)
	}
	e.aggregate(t, e.clock.t.Truncate(time.Hour), "billing", "gigachat", "GigaChat-Pro")
	res, err := e.svc.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Связь добавлена (предел использования не достигнут), модель — нет.
	if res.Links != 1 || res.Models != 0 || res.Skipped != 1 {
		t.Fatalf("пополнение у предела: %+v", res)
	}
	o, err := e.svc.Overview(ctx)
	if err != nil || !o.Sync.LimitReached || o.Sync.Skipped != 1 {
		t.Fatalf("состояние: %+v, %v", o.Sync, err)
	}
	// Повтор окна без новых данных строку не переписывает (ревью 5.17).
	xmin := func() string {
		t.Helper()
		var x string
		if err := e.owner.QueryRow(ctx, `SELECT xmin::text FROM inventory_usage WHERE app = 'billing'`).Scan(&x); err != nil {
			t.Fatal(err)
		}
		return x
	}
	before := xmin()
	if res, err := e.svc.Discover(ctx); err != nil || res.Links != 0 || xmin() != before {
		t.Fatalf("повтор окна: %+v, %v, xmin %s → %s", res, err, before, xmin())
	}
	// Предел связей: новая тройка пропускается, известная — нет.
	mustExec(t, e.owner, `INSERT INTO inventory_usage (org_id, app, provider, model, first_seen, last_seen)
		SELECT $1, 'app-' || g, 'gigachat', 'GigaChat-Pro', now(), now() FROM generate_series(1, $2::int) g`, audit.DefaultOrgID, MaxUsage-1)
	e.aggregate(t, e.clock.t.Truncate(time.Hour), "crm", "gigachat", "GigaChat-Pro")
	if res, err := e.svc.Discover(ctx); err != nil || res.Links != 0 || res.Skipped != 2 {
		t.Fatalf("пополнение у предела связей: %+v, %v", res, err)
	}
	// Ограничения таблиц: путь, хеш, вид без провайдера, роль.
	id := "01900000-0000-7000-8000-000000000001"
	for _, sql := range []string{
		`INSERT INTO inventory_model_files (model_id, path, size, role, hash_alg, hash) VALUES ($1, '', 1, 'weights', 'SHA-256', '\x00')`,
		`INSERT INTO inventory_model_files (model_id, path, size, role, hash_alg, hash) VALUES ($1, 'a', -1, 'weights', 'SHA-256', decode(repeat('00', 32), 'hex'))`,
		`INSERT INTO inventory_model_files (model_id, path, size, role, hash_alg, hash) VALUES ($1, 'a', 1, 'pickle', 'SHA-256', decode(repeat('00', 32), 'hex'))`,
		`INSERT INTO inventory_model_files (model_id, path, size, role, hash_alg, hash) VALUES ($1, 'a', 1, 'weights', 'MD5', decode(repeat('00', 32), 'hex'))`,
		`UPDATE inventory_models SET kind = 'provider' WHERE id = $1`,
		`UPDATE inventory_models SET first_seen = now() WHERE id = $1`,
	} {
		if _, err := e.owner.Exec(ctx, sql, id); err == nil {
			t.Errorf("ограничение не сработало: %s", sql)
		}
	}
}

// Выгрузка AI-BOM на живой БД (задача 5.18): снимок реестра, адрес
// провайдера без пути, запись data.export той же транзакцией.
func TestPGInventoryAIBOM(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	in := customerInput(t, "llama-ft", "model.safetensors")
	in.Provider = "gigachat"
	m, err := e.svc.CreateModel(ctx, e.by, in)
	if err != nil {
		t.Fatal(err)
	}
	before := e.audits(t, "data.export")
	bom, err := e.svc.ExportAIBOM(ctx, e.by, "1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := cyclonedx.Validate(bom); err != nil {
		t.Fatalf("документ не по схеме: %v", err)
	}
	if len(bom.Services) != 1 || bom.Services[0].TrustZone != "external" || bom.Services[0].Endpoints[0] != "https://gigachat.example.ru:443" {
		t.Fatalf("сервисы: %+v", bom.Services)
	}
	var model *cyclonedx.Component
	for i := range bom.Components {
		if bom.Components[i].BOMRef == "model:"+m.ID {
			model = &bom.Components[i]
		}
	}
	if model == nil || len(model.Components) != 1 || len(model.Components[0].Hashes) != 1 {
		t.Fatalf("модель: %+v", bom.Components)
	}
	if e.audits(t, "data.export") != before+1 {
		t.Fatal("нет записи data.export")
	}
	var kind string
	var comps int
	if err := e.owner.QueryRow(ctx, `SELECT details->>'kind', (details->>'components')::int FROM audit_log
		WHERE action = 'data.export' ORDER BY seq DESC LIMIT 1`).Scan(&kind, &comps); err != nil {
		t.Fatal(err)
	}
	if kind != ExportKindAIBOM || comps != 3 {
		t.Errorf("запись: вид %q, компонентов %d", kind, comps)
	}
}
