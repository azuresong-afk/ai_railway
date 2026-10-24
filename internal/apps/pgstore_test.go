package apps_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/keyring/keyringtest"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются
// (в CI PostgreSQL нет). Каждый тест — в своей схеме; сервер работает под
// ролью aisec_app, как в установке.

type pgEnv struct {
	owner, app *pgxpool.Pool
	svc        *apps.Service
	box        *keyring.Box
	keyID      string
	clock      *clock
	caPEM      string
	by         apps.By
	// dir — каталог ключей установки (ротация ключа данных).
	dir string
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
	schema := "apps_test_" + hex.EncodeToString(b)
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
	// Синтетические владельцы приложений.
	for i, id := range []string{ownerA, ownerB} {
		if _, err := owner.Exec(ctx, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash,
			password_changed_at, must_change_password, created_at, created_by)
			VALUES ($1, $2, $3, 'Владелец', 'app_owner', 'active', 'x', now(), false, now(), 'test')`,
			id, audit.DefaultOrgID, "owner"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	e := &pgEnv{owner: owner, app: newPool(t, dsn, schema, "aisec_app"),
		clock: &clock{t: time.Now().UTC().Truncate(time.Microsecond)},
		by:    apps.By{Actor: audit.Actor{Type: audit.ActorUser, ID: ownerA, Name: "admin"}, Policy: true, Confirm: confirmed}}
	var dir string
	dir, e.keyID = keyringtest.Install(t, ctx, owner, p, audit.DefaultOrgID)
	e.dir = dir
	if e.box, err = keyring.Load(ctx, e.app, p, dir, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("AISec test provider CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.caPEM = string(ca.CertPEM())
	l, err := audit.New(e.app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := apps.NewPGStore(e.app, l)
	if err != nil {
		t.Fatal(err)
	}
	e.svc, err = apps.New(apps.Options{Store: st, Provider: p, Box: e.box, Clock: e.clock.now,
		OwnerCheck: func(context.Context, string) error { return nil }})
	if err != nil {
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

func (e *pgEnv) actions(t *testing.T) map[string]int {
	t.Helper()
	rows, err := e.owner.Query(pgCtx(t), "SELECT action FROM audit_log")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out[a]++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *pgEnv) fixture(t *testing.T) (apps.Provider, apps.Application) {
	t.Helper()
	ctx := pgCtx(t)
	in := apps.ProviderInput{Slug: "openai-main", Name: "Основной", Type: "openai", BaseURL: "https://llm.example/v1", CAPEM: e.caPEM}
	p, err := e.svc.CreateProvider(ctx, e.by, in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := e.svc.CreateApplication(ctx, e.by, appInput("helpdesk", p.ID, ownerA), nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, a
}

func TestPGApplicationsLifecycle(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	p, a := e.fixture(t)
	if _, err := e.svc.CreateApplication(ctx, e.by, appInput("helpdesk", p.ID, ownerA), nil); !errors.Is(err, apps.ErrSlugTaken) {
		t.Fatalf("повторный slug: %v", err)
	}
	if _, err := e.svc.CreateApplication(ctx, e.by, appInput("other", "01900000-0000-7000-8000-0000000000ff", ownerA), nil); !errors.Is(err, apps.ErrProviderNotFound) {
		t.Fatalf("неизвестный провайдер: %v", err)
	}
	got, err := e.svc.Application(ctx, a.ID, "")
	if err != nil || got.Slug != "helpdesk" || got.Policy != a.Policy || got.Aliases["default"] != "gpt-4o-mini" {
		t.Fatalf("чтение: %+v %v", got, err)
	}
	if _, err := e.svc.Application(ctx, a.ID, ownerB); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("чужое приложение: %v", err)
	}
	in := appInput("helpdesk", p.ID, ownerB)
	in.Quotas.RequestsPerMinutePerKey = 300
	upd, err := e.svc.UpdateApplication(ctx, e.by, a.ID, in)
	if err != nil || upd.OwnerID != ownerB || upd.Quotas.RequestsPerMinutePerKey != 300 {
		t.Fatalf("изменение: %+v %v", upd, err)
	}
	dom := []string{"corp.example"}
	prot, err := e.svc.SetProtection(ctx, e.by, a.ID, apps.ProtectionInput{FailMode: "fail_open", ExfilAllowDomains: &dom})
	if err != nil || prot.FailMode != "fail_open" || len(prot.ExfilAllowDomains) != 1 {
		t.Fatalf("поля защиты: %+v %v", prot, err)
	}
	if got, err := e.svc.Application(ctx, a.ID, ""); err != nil || got.FailMode != "fail_open" || got.ExfilAllowDomains[0] != "corp.example" {
		t.Fatalf("поля защиты после чтения: %+v %v", got, err)
	}
	list, err := e.svc.Applications(ctx, ownerB, nil, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("список владельца: %d %v", len(list), err)
	}
	if _, err := e.svc.DeleteProvider(ctx, e.by, p.ID); !errors.Is(err, apps.ErrProviderInUse) {
		t.Fatalf("удаление используемого провайдера: %v", err)
	}
	k, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "prod", AllowedCIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}})
	if err != nil || len(k.AllowedCIDRs) != 2 {
		t.Fatalf("ключ: %+v %v", k, err)
	}
	arch, err := e.svc.ArchiveApplication(ctx, e.by, a.ID)
	if err != nil || !arch.Archived() {
		t.Fatalf("архив: %v", err)
	}
	keys, err := e.svc.Keys(ctx, a.ID, "")
	if err != nil || len(keys) != 1 || keys[0].RevokedAt.IsZero() {
		t.Fatalf("ключи после архивации: %+v %v", keys, err)
	}
	if _, err := e.svc.UpdateApplication(ctx, e.by, a.ID, in); !errors.Is(err, apps.ErrArchived) {
		t.Fatalf("изменение архивного: %v", err)
	}
	acts := e.actions(t)
	for _, want := range []string{"provider.create", "application.create", "application.update", "app_key.issue", "application.archive"} {
		if acts[want] != 1 {
			t.Errorf("%s в аудите: %d", want, acts[want])
		}
	}
}

func TestPGKeysRotateRevoke(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	_, a := e.fixture(t)
	k, raw, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	var hash []byte
	if err := e.owner.QueryRow(ctx, "SELECT key_hash FROM app_keys WHERE id = $1", k.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(hash, []byte(raw)) || len(hash) == 0 {
		t.Fatal("в БД должен быть только хеш ключа")
	}
	overlap := time.Hour
	nk, _, old, err := e.svc.RotateKey(ctx, e.by, k.ID, "", apps.RotateInput{Overlap: &overlap})
	if err != nil || nk.RotatedFrom != k.ID || !old.ExpiresAt.Equal(e.clock.t.Add(time.Hour)) {
		t.Fatalf("ротация: %+v %+v %v", nk, old, err)
	}
	if _, err := e.svc.RevokeKey(ctx, e.by, nk.ID, ownerB); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("отзыв чужим владельцем: %v", err)
	}
	if _, err := e.svc.RevokeKey(ctx, e.by, nk.ID, ownerA); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RevokeKey(ctx, e.by, nk.ID, ""); !errors.Is(err, apps.ErrKeyInactive) {
		t.Fatalf("повторный отзыв: %v", err)
	}
	acts := e.actions(t)
	if acts["app_key.issue"] != 1 || acts["app_key.rotate"] != 1 || acts["app_key.revoke"] != 1 {
		t.Fatalf("аудит: %v", acts)
	}
}

func TestPGProviderCredential(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	p, _ := e.fixture(t)
	secret := []byte("sk-synthetic-0123456789")
	if _, err := e.svc.SetCredential(ctx, e.by, p.ID, secret); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	var keyID, alg string
	if err := e.owner.QueryRow(ctx, "SELECT credential, credential_key_id, credential_alg FROM providers WHERE id = $1", p.ID).Scan(&stored, &keyID, &alg); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, secret) || keyID != e.keyID || alg == "" {
		t.Fatalf("учётные данные хранятся открыто или без ключа: %q %s", keyID, alg)
	}
	got, err := e.svc.OpenCredential(ctx, p.ID)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("расшифровка: %v", err)
	}
	// Шифртекст другой строки не расшифровывается: AAD привязан к ID (Р4).
	in := apps.ProviderInput{Slug: "second", Name: "Второй", Type: "openai", BaseURL: "https://llm2.example/v1", CAPEM: e.caPEM}
	p2, err := e.svc.CreateProvider(ctx, e.by, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `UPDATE providers SET credential = $1, credential_key_id = $2, credential_alg = $3,
		credential_set_at = now() WHERE id = $4`, stored, keyID, alg, p2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.OpenCredential(ctx, p2.ID); err == nil {
		t.Fatal("чужой шифртекст расшифрован")
	}
	if _, err := e.svc.SetExternal(ctx, e.by, p.ID, false, "Провайдер развёрнут в контуре заказчика"); err != nil {
		t.Fatal(err)
	}
	acts := e.actions(t)
	if acts["provider.credentials_set"] != 1 || acts["provider.external_changed"] != 1 {
		t.Fatalf("аудит: %v", acts)
	}
	var details string
	if err := e.owner.QueryRow(ctx, "SELECT string_agg(details::text, ' ') FROM audit_log").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(details), secret) {
		t.Fatal("учётные данные попали в журнал аудита")
	}
}

func TestPGGuards(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	p, a := e.fixture(t)
	k, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	// Права aisec_app: ключи не удаляются и не меняются, кроме срока и отзыва.
	for name, q := range map[string]string{
		"удаление ключа":    "DELETE FROM app_keys",
		"смена хеша":        "UPDATE app_keys SET key_hash = '\\x00112233445566778899aabbccddeeff'",
		"смена подсетей":    "UPDATE app_keys SET allowed_cidrs = '{}'",
		"удаление прил.":    "DELETE FROM applications",
		"очистка ключей":    "TRUNCATE app_keys CASCADE",
		"очистка прил.":     "TRUNCATE applications CASCADE",
		"очистка провайд.":  "TRUNCATE providers CASCADE",
		"смена slug прил.":  "UPDATE applications SET slug = 'other'",
		"смена slug пров.":  "UPDATE providers SET slug = 'other'",
		"продление ключа":   "UPDATE app_keys SET expires_at = expires_at + interval '1 day'",
		"удаление провайд.": "DELETE FROM providers WHERE id = '" + p.ID + "'",
	} {
		if _, err := e.app.Exec(ctx, q); err == nil {
			t.Errorf("aisec_app: %s выполнено", name)
		}
	}
	// Даже владелец схемы не обходит триггеры.
	for name, q := range map[string]string{
		"удаление ключа":  "DELETE FROM app_keys",
		"удаление прил.":  "DELETE FROM applications",
		"продление ключа": "UPDATE app_keys SET expires_at = expires_at + interval '1 day'",
		"смена хеша":      "UPDATE app_keys SET key_hash = '\\x00112233445566778899aabbccddeeff'",
	} {
		if _, err := e.owner.Exec(ctx, q); err == nil {
			t.Errorf("владелец: %s выполнено", name)
		}
	}
	if _, err := e.svc.RevokeKey(ctx, e.by, k.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, "UPDATE app_keys SET revoked_at = NULL, revoked_by = NULL"); err == nil {
		t.Error("отзыв ключа снят")
	}
	if _, err := e.svc.ArchiveApplication(ctx, e.by, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, "UPDATE applications SET archived_at = NULL"); err == nil {
		t.Error("приложение возвращено из архива")
	}
	if _, err := e.app.Exec(ctx, "DELETE FROM app_keys"); sqlState(err) != "42501" {
		t.Errorf("DELETE FROM app_keys под aisec_app: %v", err)
	}
}
