package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/backup"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/notify"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

const testBackupPhrase = "синтетическая фраза копии 2026"

// writePhraseFile — файл фразы с правами perm.
func writePhraseFile(t *testing.T, phrase string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "phrase")
	if err := os.WriteFile(path, []byte(phrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

// Проверки аргументов и фразы — до обращения к БД.
func TestBackupArgs(t *testing.T) {
	var out, errb bytes.Buffer
	dsn := "postgres://u@127.0.0.1:1/db"
	good := writePhraseFile(t, testBackupPhrase, 0o400)
	short := writePhraseFile(t, "короткая", 0o400)
	wide := writePhraseFile(t, testBackupPhrase, 0o600)
	twoLines := filepath.Join(t.TempDir(), "two")
	if err := os.WriteFile(twoLines, []byte(testBackupPhrase+"\nещё строка\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		args []string
		dsn  string
		want string
	}{
		"нет подкоманды":  {nil, dsn, "подкоманда"},
		"чужая":           {[]string{"list"}, dsn, "неизвестная подкоманда"},
		"без -keys":       {[]string{"create", "-out", "x", "-no-user-hmac-key"}, dsn, "-keys"},
		"без ключа HMAC":  {[]string{"create", "-keys", "k", "-out", "x"}, dsn, "-no-user-hmac-key"},
		"оба про HMAC":    {[]string{"create", "-keys", "k", "-out", "x", "-user-hmac-key", "f", "-no-user-hmac-key"}, dsn, "-no-user-hmac-key"},
		"фраза в args":    {[]string{"create", "-keys", "k", "-out", "x", "-no-user-hmac-key", testBackupPhrase}, dsn, "в аргументах не принимается"},
		"без БД":          {[]string{"create", "-keys", "k", "-out", "x", "-no-user-hmac-key"}, "", "AISEC_DATABASE_URL"},
		"короткая фраза":  {[]string{"create", "-keys", "k", "-out", "x", "-no-user-hmac-key", "-passphrase-file", short}, dsn, "короче 16"},
		"права 0600":      {[]string{"create", "-keys", "k", "-out", "x", "-no-user-hmac-key", "-passphrase-file", wide}, dsn, "нужно 0400"},
		"две строки":      {[]string{"create", "-keys", "k", "-out", "x", "-no-user-hmac-key", "-passphrase-file", twoLines}, dsn, "одна строка"},
		"restore без -in": {[]string{"restore", "-keys", "k"}, dsn, "-in"},
		"restore args":    {[]string{"restore", "-keys", "k", "-in", "f", "-passphrase-file", good, "лишнее"}, dsn, "в аргументах не принимается"},
	} {
		err := backupCmd(c.args, c.dsn, &out, &errb, time.Now())
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Терминала у теста нет: без файла фразы — отказ, из канала не читается.
	_, err := readPassphrase("", true, &errb)
	if err == nil || !strings.Contains(err.Error(), "-passphrase-file") {
		t.Errorf("без терминала: %v", err)
	}
	phrase, err := readPassphraseFile(good)
	if err != nil || string(phrase) != testBackupPhrase {
		t.Fatalf("фраза из файла: %q %v", phrase, err)
	}
}

// Файл копии не перезаписывается и пишется с правами 0600.
func TestWriteFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "copy.aisec-backup")
	if err := writeFileAtomic(path, []byte("данные")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("права: %v %v", info, err)
	}
	if err := writeFileAtomic(path, []byte("другие")); err == nil {
		t.Fatal("файл перезаписан")
	}
	if got, _ := os.ReadFile(path); string(got) != "данные" { //nolint:gosec // G304: путь из t.TempDir
		t.Fatalf("содержимое: %q", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("временный файл остался: %v", entries)
	}
}

// installation — схема БД после migrate и init с каталогом ключей.
type installation struct {
	dsn  string
	keys string
	db   *store.DB
	box  *keyring.Box
}

func newInstallation(t *testing.T, admin *store.DB, base, schema string) *installation {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{"DROP SCHEMA IF EXISTS " + schema + " CASCADE", "CREATE SCHEMA " + schema} {
		if _, err := admin.Pool().Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = admin.Pool().Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE") //nolint:gosec // G104: уборка теста
	})
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	in := &installation{dsn: base + sep + "search_path=" + schema, keys: keyDir(t)}
	var out, errb bytes.Buffer
	if err := migrate(nil, in.dsn, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if err := initCmd([]string{"-dir", in.keys}, in.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	db, err := store.Open(ctx, in.dsn, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	in.db = db
	if in.box, err = keyring.Load(ctx, db.Pool(), standardProvider(t), in.keys, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	return in
}

func (in *installation) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := in.db.Pool().Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func (in *installation) seal(t *testing.T, plain []byte, table, column, id string) []byte {
	t.Helper()
	out, err := in.box.Seal(context.Background(), plain, table, column, id)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (in *installation) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := in.db.Pool().QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// Синтетическая конфигурация всех видов, с секретами под ключом данных.
const (
	tUser     = "0192a000-0000-7000-8000-000000000001"
	tUser2    = "0192a000-0000-7000-8000-000000000002"
	tUserExt  = "0192a000-0000-7000-8000-000000000003"
	tProvider = "0192a000-0000-7000-8000-000000000101"
	tApp      = "0192a000-0000-7000-8000-000000000201"
	tKey1     = "0192a000-0000-7000-8000-000000000301"
	tKey2     = "0192a000-0000-7000-8000-000000000302"
	tPolicy   = "0192a000-0000-7000-8000-000000000401"
	tToken    = "0192a000-0000-7000-8000-000000000501"
)

var (
	tTOTP       = bytes.Repeat([]byte{0x5a}, aisecCrypto.TOTPSecretSize)
	tCredential = []byte("synthetic-provider-credential")
	// tTokenRaw — синтетический токен API (секрет — 32 байта 0x11).
	tTokenRaw = "aisec_pat_abcd1234_" + strings.Repeat("ERER", 10) + "ERE"
)

func populate(t *testing.T, in *installation) {
	t.Helper()
	h, err := standardProvider(t).Hasher()
	if err != nil {
		t.Fatal(err)
	}
	org := audit.DefaultOrgID
	pw := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U"
	in.exec(t, `INSERT INTO roles (org_id, id, display_name, description, mfa_required, created_at, created_by, updated_at)
		VALUES ($1, 'duty_analyst', 'Дежурный аналитик', 'синтетическая', false, now(), 'user:x', now())`, org)
	in.exec(t, "INSERT INTO role_permissions (org_id, role_id, permission, scope) VALUES ($1, 'duty_analyst', 'events.read', 'all')", org)
	in.exec(t, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by, last_login_at) VALUES
		($1, $3, 'sec.admin', 'Синтетический администратор', 'security_admin', 'active', $4, now(), false, now(), 'setup', now()),
		($2, $3, 'duty', 'Синтетический дежурный', 'duty_analyst', 'deactivated', $4, now(), true, now(), 'user:x', NULL)`,
		tUser, tUser2, org, pw)
	in.exec(t, "UPDATE users SET failed_attempts = 5, locked_at = now(), locked_until = now() + interval '15 minutes' WHERE id = $1", tUser2)
	in.exec(t, `INSERT INTO user_mfa (user_id, state, secret, data_key_id, alg, created_at)
		VALUES ($1, 'pending', $2, $3, $4, now())`,
		tUser2, in.seal(t, tTOTP, "user_mfa", "secret", tUser2), in.box.KeyID(), in.box.Alg())
	in.exec(t, "INSERT INTO password_history (user_id, password_hash, created_at) VALUES ($1, $2, now() - interval '1 day')", tUser, pw)
	in.exec(t, `INSERT INTO user_mfa (user_id, state, secret, data_key_id, alg, last_step, created_at, enabled_at)
		VALUES ($1, 'enabled', $2, $3, $4, 1234, now(), now())`,
		tUser, in.seal(t, tTOTP, "user_mfa", "secret", tUser), in.box.KeyID(), in.box.Alg())
	in.exec(t, "INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES ($1, $2, now())", tUser, h.Sum([]byte("rc-1")))
	in.exec(t, `INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, hash_alg, permissions, expires_at,
		created_at, last_used_ip) VALUES ($1, $2, $3, 'ci', 'aisec_pat_abcd1234', $4, 'SHA-256', '{events.read:all}',
		now() + interval '10 days', now(), '10.0.0.7')`, tToken, org, tUser, h.Sum([]byte(tTokenRaw)))
	in.exec(t, `INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, hash_alg, permissions, expires_at,
		created_at, revoked_at, revoked_by, revoke_reason) VALUES ('0192a000-0000-7000-8000-000000000502', $1, $2, 'old',
		'aisec_pat_zzzz9999', $3, 'SHA-256', '{events.read:all}', now() + interval '10 days', now() - interval '1 day', now(),
		$2, 'admin')`, org, tUser, h.Sum([]byte("token-old")))
	in.exec(t, `INSERT INTO providers (id, org_id, slug, name, type, base_url, ca_pem, external, credential,
		credential_key_id, credential_alg, credential_set_at, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'mock-llm', 'Синтетический провайдер', 'openai', 'https://llm.example.test', 'PEM', true, $3, $4, $5,
		now(), now(), 'user:x', now(), 'user:x')`,
		tProvider, org, in.seal(t, tCredential, "providers", "credential", tProvider), in.box.KeyID(), in.box.Alg())
	in.exec(t, `INSERT INTO applications (id, org_id, slug, name, owner_id, env, provider_id, models, aliases, policy,
		policy_mode, storage, fail_mode, user_from, quotas, lists, exfil_allow_domains, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'support-bot', 'Синтетический бот', $3, 'test', $4, '{gpt-x}', '{"fast":"gpt-x"}', 'corp',
		'monitor', 'masked', 'fail_open', 'header', '{"requests_per_minute": 60}', '[{"id":"stop","category":"stop_words","words":["стоп-слово"]}]', '{example.test}',
		now(), 'user:x', now(), 'user:x')`, tApp, org, tUser, tProvider)
	in.exec(t, `INSERT INTO app_keys (id, org_id, app_id, name, prefix, key_hash, hash_alg, allowed_cidrs, expires_at,
		created_at, created_by, revoked_at, revoked_by) VALUES ($1, $2, $3, 'первый', 'aisec_aaaa1111', $4, 'SHA-256',
		'{10.0.0.0/8}', now() + interval '1 day', now() - interval '1 hour', 'user:x', now(), 'user:x')`,
		tKey1, org, tApp, h.Sum([]byte("k1")))
	in.exec(t, `INSERT INTO app_keys (id, org_id, app_id, name, prefix, key_hash, hash_alg, expires_at, created_at,
		created_by, rotated_from) VALUES ($1, $2, $3, 'второй', 'aisec_bbbb2222', $4, 'SHA-256', now() + interval '30 days',
		now(), 'user:x', $5)`, tKey2, org, tApp, h.Sum([]byte("k2")), tKey1)
	v1, v2 := "id: corp\nversion: 1\nname: Синтетическая\nmode: monitor\n", "id: corp\nversion: 2\nname: Синтетическая\nmode: enforce\n"
	v3 := "id: corp\nversion: 3\nname: Синтетическая\nmode: monitor\n"
	ctx := context.Background()
	tx, err := in.db.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO policies (id, org_id, slug, name, mode, current_version, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, 'corp', 'Синтетическая', 'monitor', 3, now(), 'user:x', now(), 'user:x')`, []any{tPolicy, org}},
		{`INSERT INTO policy_versions (policy_id, version, spec_yaml, spec_hash, hash_alg, source, created_at, created_by)
			VALUES ($1, 1, $2, $3, 'SHA-256', 'api', now(), 'user:x')`, []any{tPolicy, v1, h.Sum([]byte(v1))}},
		{`INSERT INTO policy_versions (policy_id, version, spec_yaml, spec_hash, hash_alg, source, comment, created_at, created_by)
			VALUES ($1, 2, $2, $3, 'SHA-256', 'api', 'строже', now(), 'user:x')`, []any{tPolicy, v2, h.Sum([]byte(v2))}},
		{`INSERT INTO policy_versions (policy_id, version, spec_yaml, spec_hash, hash_alg, source, rolled_back_from, created_at, created_by)
			VALUES ($1, 3, $2, $3, 'SHA-256', 'rollback', 1, now(), 'user:x')`, []any{tPolicy, v3, h.Sum([]byte(v3))}},
	} {
		if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	in.exec(t, `INSERT INTO auth_settings (org_id, password_min_length, password_min_classes, password_history,
		password_max_age_days, password_warn_days, lockout_threshold, lockout_minutes, session_idle_minutes,
		session_max_per_user, temp_password_hours, mfa_required_all, updated_at) VALUES ($1, 14, 3, 5, 90, 7, 5, 30, 15, 3, 24, true, now())`, org)
	in.exec(t, `INSERT INTO audit_settings (org_id, disabled_actions, retention_days, updated_at) VALUES ($1, '{events.list}', 400, now())
		ON CONFLICT (org_id) DO UPDATE SET disabled_actions = EXCLUDED.disabled_actions, retention_days = EXCLUDED.retention_days`, org)
	in.exec(t, "UPDATE event_settings SET metadata_days = 200, content_days = 30")
	in.exec(t, "INSERT INTO install_settings (org_id, timezone, retention_mode, updated_at) VALUES ($1, 'Asia/Yekaterinburg', 'none', now())", org)
	in.exec(t, "UPDATE organizations SET name = 'ООО «Синтетика»' WHERE id = $1", org)
}

// view — сравнимое содержимое установки: снимок с секретами, открытыми
// обратно (шифротексты разных ключей данных не сравниваются).
func view(t *testing.T, in *installation, w *backup.Writer) string {
	t.Helper()
	ctx := context.Background()
	tx, err := in.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // G104: транзакция только для чтения
	s, err := backup.Read(ctx, tx, in.box, w.Keys(), audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	s.TakenAt = time.Time{}
	// Отзыв при восстановлении (В21) сравнивается отдельно.
	for i := range s.APITokens {
		if r := s.APITokens[i].RevokeReason; r != nil && *r == auth.APITokenRevokedByBackupRestore {
			s.APITokens[i].RevokedAt, s.APITokens[i].RevokedBy, s.APITokens[i].RevokeReason = nil, nil, nil
		}
	}
	for i := range s.Users {
		if m := s.Users[i].MFA; m != nil {
			if m.Secret, err = w.Keys().OpenSecret(m.Secret, "user_mfa.secret", s.Users[i].ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := range s.Providers {
		if c := s.Providers[i].Credential; c != nil {
			if s.Providers[i].Credential, err = w.Keys().OpenSecret(c, "providers.credential", s.Providers[i].ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	openSectionSecrets(t, s, w)
	out, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// authToken предъявляет токен API сервису входа установки.
func authToken(t *testing.T, in *installation, raw string) error {
	t.Helper()
	ctx := context.Background()
	p := standardProvider(t)
	l, err := openAuditLog(in.db, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := auth.NewPGStore(in.db.Pool(), l)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.NewPGAPITokens(in.db.Pool(), l)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewService(ctx, st, l, p, auth.WithAPITokenStore(tokens))
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.AuthenticateAPIToken(ctx, raw, netip.MustParseAddr("10.0.0.9"))
	return err
}

func auditCount(t *testing.T, in *installation, action, result, stage string) int {
	t.Helper()
	return in.count(t, `SELECT count(*) FROM audit_log WHERE action = $1 AND result = $2
		AND ($3 = '' OR details->>'stage' = $3)`, action, result, stage)
}

// Круговой тест на живой БД (AISEC_TEST_DATABASE_URL): копия установки →
// новая установка после init → восстановление → данные совпадают,
// секреты расшифровываются ключом данных новой установки, ключ HMAC
// записан, токен первичной настройки погашен, цепочка аудита цела.
// Затем отказы: повторное восстановление без флага (непустая установка),
// с флагом — совпадения, неверная фраза и подменённый байт (код 3).
func TestBackupRoundTripOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src")
	dst := newInstallation(t, admin, base, "cli_backup_dst")
	populate(t, src)
	populateStage34(t, src)
	// Сервер новой установки уже запускался: встроенное правило создано со
	// своим ID, отметка часов лицензии — позже, чем в копии.
	dst.exec(t, `INSERT INTO alert_rules (id, org_id, builtin_key, kind, name, description, enabled, severity, condition, group_by,
		suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
		VALUES ('0192a000-0000-7000-8000-0000000007ff', $1, $2, 'threshold', 'Заблокированные инъекции', 'встроенное', true,
		'high', '{"count":1}', '{}', 0, 10, '{"roles":[],"users":[]}', 1, now(), 'system', now(), 'system')`,
		audit.DefaultOrgID, builtinRuleKey)
	dst.exec(t, "INSERT INTO license_clock (org_id, high_water) VALUES ($1, now() + interval '2 days')", audit.DefaultOrgID)
	// Внешняя учётная запись IdP (ADR-0025): без пароля, привязана к издателю и sub.
	src.exec(t, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by, auth_source, idp_issuer, idp_subject) VALUES
		($1, $2, 'ivanov.ext', 'Синтетический внешний', 'analyst', 'active', '!external', now(), false, now(), 'oidc',
		'oidc', 'https://idp.example.test/realms/aisec', 'idp-user-1')`, tUserExt, audit.DefaultOrgID)

	dir := t.TempDir()
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	hmacIn := filepath.Join(dir, "user-hmac.key")
	hmacKey := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(hmacIn, hmacKey, 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "config.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"create", "-keys", src.keys, "-out", file, "-passphrase-file", phrase,
		"-user-hmac-key", hmacIn}, src.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("create: %v %s", err, errb.String())
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("файл копии: %v %v", info, err)
	}
	data, err := os.ReadFile(file) //nolint:gosec // G304: путь из t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range append([][]byte{tCredential, tTOTP, hmacKey, []byte("sec.admin"), []byte("argon2id")}, stage34Secrets(t)...) {
		if bytes.Contains(data, leak) {
			t.Errorf("в файле копии открытым текстом: %q", leak)
		}
	}
	if n := auditCount(t, src, "backup.create", "success", ""); n != 1 {
		t.Fatalf("записей backup.create: %d", n)
	}

	hmacOut := filepath.Join(dir, "restored-hmac.key")
	out.Reset()
	if err := backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase,
		"-user-hmac-key-out", hmacOut}, dst.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("restore: %v %s", err, errb.String())
	}
	if !strings.Contains(out.String(), "Конфигурация восстановлена") || strings.Contains(out.String(), "Пропущены") ||
		strings.Contains(out.String(), "версии 1") || !strings.Contains(out.String(), "каналов 3, правил оповещений 1 (+ встроенных 1)") {
		t.Fatalf("вывод: %s", out.String())
	}
	for _, leak := range stage34Secrets(t) {
		if bytes.Contains(out.Bytes(), leak) || bytes.Contains(errb.Bytes(), leak) {
			t.Errorf("в выводе команд открытым текстом: %q", leak)
		}
	}
	w, err := backup.NewWriter(ctx, standardProvider(t), []byte(testBackupPhrase), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a, b := view(t, src, w), view(t, dst, w); a != b {
		t.Fatalf("данные после восстановления отличаются:\n--- исходная\n%s\n--- восстановленная\n%s", a, b)
	}
	if n := dst.count(t, `SELECT count(*) FROM users WHERE id = $1 AND auth_source = 'oidc' AND idp_subject = 'idp-user-1'
		AND password_hash = '!external'`, tUserExt); n != 1 {
		t.Fatal("внешняя учётная запись не восстановлена")
	}
	// Этапы 3–4: встроенное правило обновлено значениями копии и сохранило
	// ID установки; отметка часов лицензии назад не поставлена; ключ агента
	// восстановлен с привязкой; секреты — под ключом данных новой установки.
	if n := dst.count(t, `SELECT count(*) FROM alert_rules WHERE builtin_key = $1 AND id = '0192a000-0000-7000-8000-0000000007ff'
		AND NOT enabled AND severity = 'critical' AND version = 3`, builtinRuleKey); n != 1 {
		t.Fatal("встроенное правило не обновлено из копии")
	}
	if n := dst.count(t, "SELECT count(*) FROM license_clock WHERE high_water > now() + interval '1 day'"); n != 1 {
		t.Fatal("отметка часов лицензии поставлена назад")
	}
	if n := dst.count(t, "SELECT count(*) FROM app_keys WHERE id = $1 AND agent_id = $2 AND revoked_at IS NULL", tAgentKey, tAgent); n != 1 {
		t.Fatal("привязка ключа к агенту не восстановлена")
	}
	for _, q := range []string{
		"SELECT count(*) FROM notify_channels WHERE secret IS NOT NULL AND secret_key_id = $1",
		"SELECT count(*) FROM prompt_baselines WHERE text_key_id = $1",
		"SELECT count(*) FROM mcp_servers WHERE credential_key_id = $1",
		"SELECT count(*) FROM gateway_tls WHERE key_key_id = $1",
		"SELECT count(*) FROM oidc_settings WHERE client_secret_key_id = $1",
		"SELECT count(*) FROM ldap_settings WHERE bind_password_key_id = $1",
	} {
		if n := dst.count(t, q, dst.box.KeyID()); n == 0 {
			t.Errorf("секрет не под ключом данных новой установки: %s", q)
		}
	}
	var hookSealed []byte
	if err := dst.db.Pool().QueryRow(ctx, "SELECT secret FROM notify_channels WHERE id = $1", tChannelHook).Scan(&hookSealed); err != nil {
		t.Fatal(err)
	}
	if got, err := dst.box.Open(dst.box.KeyID(), hookSealed, "notify_channels", "secret", tChannelHook); err != nil ||
		string(got) != tWebhookSecret {
		t.Fatalf("секрет webhook: %v", err)
	}
	// В21: действующий токен копии восстановлен отозванным и не принимается;
	// отозванный до копии сохранил свою причину.
	if err := authToken(t, src, tTokenRaw); err != nil {
		t.Fatalf("токен в исходной установке: %v", err)
	}
	if err := authToken(t, dst, tTokenRaw); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("токен из копии после восстановления: %v", err)
	}
	if n := dst.count(t, `SELECT count(*) FROM api_tokens WHERE id = $1 AND revoke_reason = 'backup_restore'
		AND revoked_by IS NULL AND revoked_at IS NOT NULL`, tToken); n != 1 {
		t.Fatal("токен не отозван при восстановлении")
	}
	if n := dst.count(t, "SELECT count(*) FROM api_tokens WHERE revoke_reason = 'admin'"); n != 1 {
		t.Fatal("причина прежнего отзыва потеряна")
	}
	if !strings.Contains(out.String(), "восстановлены отозванными") || !strings.Contains(out.String(), "aisec-cli audit export") {
		t.Fatalf("вывод без шагов после восстановления: %s", out.String())
	}
	// Секреты в новой установке — под её ключом данных.
	var sealed []byte
	var keyID string
	if err := dst.db.Pool().QueryRow(ctx, "SELECT secret, data_key_id::text FROM user_mfa WHERE user_id = $1", tUser).
		Scan(&sealed, &keyID); err != nil {
		t.Fatal(err)
	}
	if keyID != dst.box.KeyID() || keyID == src.box.KeyID() {
		t.Fatalf("ключ данных секрета TOTP: %s", keyID)
	}
	if got, err := dst.box.Open(keyID, sealed, "user_mfa", "secret", tUser); err != nil || !bytes.Equal(got, tTOTP) {
		t.Fatalf("секрет TOTP: %v", err)
	}
	got, err := os.ReadFile(hmacOut) //nolint:gosec // G304: путь из t.TempDir
	if err != nil || !bytes.Equal(got, hmacKey) {
		t.Fatalf("ключ HMAC: %v", err)
	}
	if info, err := os.Stat(hmacOut); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("права ключа HMAC: %v", err)
	}
	if n := dst.count(t, "SELECT count(*) FROM setup_tokens WHERE used_at IS NULL"); n != 0 {
		t.Errorf("токен первичной настройки не погашен: %d", n)
	}
	if auditCount(t, dst, "backup.restore", "success", "started") != 1 || auditCount(t, dst, "backup.restore", "success", "done") != 1 {
		t.Fatal("нет записей аудита до и после восстановления")
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND details->>'stage' = 'done'
		AND details->>'copy_age_hours' = '0' AND details->>'api_tokens_revoked' = '1'`); n != 1 {
		t.Fatal("в записи «после» нет возраста копии и числа отозванных токенов")
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND details->>'stage' = 'done'
		AND details->>'settings_restored' = 'true' AND details->'settings'->'events'->>'content_days' = '30'
		AND details->'settings'->'install'->>'timezone' = 'Asia/Yekaterinburg'
		AND details->'settings'->'install'->>'quota_mode' = 'leased' AND details->'settings'->'oidc'->>'client_id' = 'aisec-console'
		AND details->'settings'->>'license_number' = '1' AND details->>'format_version' = '2'
		AND details->>'skipped_objects' = '0' AND details->>'notify_channels' = '3'`); n != 1 {
		t.Fatal("в записи «после» нет новых значений настроек")
	}
	for _, leak := range stage34Secrets(t) {
		if n := dst.count(t, "SELECT count(*) FROM audit_log WHERE strpos(details::text, $1) > 0", string(leak)); n != 0 {
			t.Errorf("секрет в журнале аудита: %q", leak)
		}
	}
	out.Reset()
	if err := auditCmd([]string{"verify"}, dst.dsn, &out, &errb); err != nil || !strings.Contains(out.String(), "Цепочка цела") {
		t.Fatalf("цепочка после восстановления: %v %s", err, out.String())
	}

	// Повторное восстановление: установка уже не пустая.
	restore := func(extra ...string) error {
		args := append([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase,
			"-user-hmac-key-out", filepath.Join(t.TempDir(), "hmac.key")}, extra...)
		return backupCmd(args, dst.dsn, &out, &errb, time.Now())
	}
	if err := restore(); err == nil || !strings.Contains(err.Error(), "не пустая") {
		t.Fatalf("непустая установка без флага: %v", err)
	}
	if n := auditCount(t, dst, "backup.restore", "denied", "refused"); n != 1 {
		t.Fatalf("отказ не записан в аудит: %d", n)
	}
	var ce *backup.ConflictError
	leftover := filepath.Join(t.TempDir(), "hmac-conflict.key")
	err = backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase,
		"-user-hmac-key-out", leftover, "-allow-nonempty"}, dst.dsn, &out, &errb, time.Now())
	if !errors.As(err, &ce) || len(ce.Items) == 0 {
		t.Fatalf("совпадения с флагом: %v", err)
	}
	if _, err := os.Stat(leftover); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("после отказа остался файл ключа псевдонимов: %v", err)
	}
	if n := auditCount(t, dst, "backup.restore", "denied", "refused"); n != 2 {
		t.Fatalf("отказ по совпадениям не записан: %d", n)
	}

	// Неверная фраза и подменённый байт: код 3, запись об отказе, БД не тронута.
	t.Setenv("AISEC_DATABASE_URL", dst.dsn)
	before := dst.count(t, "SELECT count(*) FROM users")
	wrong := writePhraseFile(t, testBackupPhrase+"!", 0o400)
	if code := run([]string{"backup", "restore", "-keys", dst.keys, "-in", file, "-passphrase-file", wrong,
		"-allow-nonempty"}, &out, &errb, time.Now()); code != 3 {
		t.Fatalf("неверная фраза: код %d, %s", code, errb.String())
	}
	tampered := filepath.Join(dir, "tampered.aisec-backup")
	bad := bytes.Clone(data)
	bad[len(bad)/2] ^= 0x10
	if err := os.WriteFile(tampered, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"backup", "restore", "-keys", dst.keys, "-in", tampered, "-passphrase-file", phrase,
		"-allow-nonempty"}, &out, &errb, time.Now()); code != 3 {
		t.Fatalf("подменённый байт: код %d, %s", code, errb.String())
	}
	if n := auditCount(t, dst, "backup.restore", "failure", "refused"); n != 2 {
		t.Fatalf("отказы по неверной копии в аудите: %d", n)
	}
	if dst.count(t, "SELECT count(*) FROM users") != before {
		t.Fatal("отказ изменил БД")
	}
}

// С флагом -allow-nonempty объекты копии добавляются к существующим без
// совпадений; без флага — отказ.
func TestBackupRestoreNonEmptyOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src2")
	dst := newInstallation(t, admin, base, "cli_backup_dst2")
	populate(t, src)
	populateStage34(t, src)
	dst.exec(t, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by) VALUES ('0192a000-0000-7000-8000-00000000aaaa', $1, 'first.admin',
		'Синтетический первый', 'security_admin', 'active', 'x', now(), false, now(), 'setup')`, audit.DefaultOrgID)

	dir := t.TempDir()
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join(dir, "config.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"create", "-keys", src.keys, "-out", file, "-passphrase-file", phrase, "-no-user-hmac-key"},
		src.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("create: %v", err)
	}
	args := []string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase}
	if err := backupCmd(args, dst.dsn, &out, &errb, time.Now()); err == nil || !strings.Contains(err.Error(), "users: 1") {
		t.Fatalf("без флага: %v", err)
	}
	if err := backupCmd(append(args, "-allow-nonempty", "-user-hmac-key-out", filepath.Join(dir, "k")), dst.dsn, &out, &errb, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "нет ключа псевдонимов") {
		t.Fatalf("ключа HMAC нет в копии: %v", err)
	}
	// Н40: недавно активная сессия — признак работающего сервера, отказ.
	dst.exec(t, `INSERT INTO sessions (id, user_id, token_hash, csrf_hash, state, created_at, last_seen_at, expires_at,
		user_agent) VALUES ('0192a000-0000-7000-8000-00000000bbbb', '0192a000-0000-7000-8000-00000000aaaa', $1, $2,
		'active', now(), now(), now() + interval '1 hour', 'test')`, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err := backupCmd(append(args, "-allow-nonempty"), dst.dsn, &out, &errb, time.Now()); !errors.Is(err, errServerRunning) {
		t.Fatalf("при работающем сервере: %v", err)
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND result = 'denied'
		AND details->>'reason' LIKE 'server_running:%'`); n != 1 {
		t.Fatalf("отказ из-за сессии в аудите: %d", n)
	}
	dst.exec(t, "UPDATE sessions SET last_seen_at = now() - interval '10 minutes'")
	if err := backupCmd(append(args, "-allow-nonempty"), dst.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("с флагом: %v %s", err, errb.String())
	}
	if n := dst.count(t, "SELECT count(*) FROM users"); n != 3 {
		t.Fatalf("пользователей после восстановления: %d", n)
	}
	if n := dst.count(t, "SELECT count(*) FROM policy_versions"); n != 3 {
		t.Fatalf("версий политик: %d", n)
	}
	// В непустую установку настройки и название организации не переносятся.
	if n := dst.count(t, `SELECT count(*) FROM event_settings WHERE content_days = 90`); n != 1 {
		t.Fatal("сроки хранения заменены в непустой установке")
	}
	if n := dst.count(t, "SELECT count(*) FROM auth_settings"); n != 0 {
		t.Fatal("настройки входа заменены в непустой установке")
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND details->>'stage' = 'done'
		AND details->>'settings_restored' = 'false'`); n != 1 {
		t.Fatal("в записи «после» нет признака, что настройки не переносились")
	}
	// Объекты этапов 3–4 добавлены, настройки (OIDC, LDAP, сертификат шлюза,
	// лицензия, встроенные правила, инструкции, отметки) — нет.
	for table, want := range map[string]int{"notify_channels": 3, "alert_rules": 1, "report_schedules": 2, "agents": 1,
		"agent_tools": 2, "mcp_servers": 1, "model_prices": 1, "app_budgets": 1, "prompt_baselines": 1,
		"oidc_settings": 0, "ldap_settings": 0, "gateway_tls": 0, "licenses": 0, "incident_instructions": 0,
		"compliance_marks": 0, "shadow_ai_exclusions": 0} {
		if n := dst.count(t, "SELECT count(*) FROM "+table); n != want {
			t.Errorf("%s: %d, ожидалось %d", table, n, want)
		}
	}
	if n := dst.count(t, "SELECT count(*) FROM report_schedules WHERE id = $1 AND applies = 'kii'", tScheduleKII); n != 1 {
		t.Fatal("применимость расписания отчёта соответствия не восстановлена")
	}
	if !strings.Contains(out.String(), "настройки этапов 3 и 4 из копии") {
		t.Fatalf("вывод без строки о непереносе настроек: %s", out.String())
	}
}

// 4В38 ревью 4.r4 и задача 5.8: с версии 2 агенты входят в копию, поэтому
// ключ, закреплённый за агентом, восстанавливается действующим с той же
// привязкой (без неё он выбрал бы любого агента приложения заголовком
// X-AISec-Agent); отзыва и строки о нём нет. Копия версии 1 —
// TestBackupRestoreVersion1OnRealDB.
func TestBackupRestoreAgentKeyBoundOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src6")
	dst := newInstallation(t, admin, base, "cli_backup_dst6")
	populate(t, src)
	const agent, agentKey = "0192a000-0000-7000-8000-000000000601", "0192a000-0000-7000-8000-000000000303"
	src.exec(t, `INSERT INTO agents (id, org_id, app_id, slug, name, status, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, $3, 'reader', 'Синтетический агент', 'active', now(), 'user:x', now(), 'user:x')`, agent, audit.DefaultOrgID, tApp)
	src.exec(t, `INSERT INTO app_keys (id, org_id, app_id, agent_id, name, prefix, key_hash, hash_alg, expires_at, created_at,
		created_by) VALUES ($1, $2, $3, $4, 'агент', 'aisec_cccc3333', $5, 'SHA-256', now() + interval '30 days', now(), 'user:x')`,
		agentKey, audit.DefaultOrgID, tApp, agent, bytes.Repeat([]byte{3}, 32))
	dir := t.TempDir()
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join(dir, "config.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"create", "-keys", src.keys, "-out", file, "-passphrase-file", phrase, "-no-user-hmac-key"},
		src.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("create: %v", err)
	}
	out.Reset()
	if err := backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase}, dst.dsn, &out, &errb,
		time.Now()); err != nil {
		t.Fatalf("restore: %v %s", err, errb.String())
	}
	if n := dst.count(t, `SELECT count(*) FROM app_keys WHERE id = $1 AND agent_id = $2 AND revoked_at IS NULL`,
		agentKey, agent); n != 1 {
		t.Fatal("ключ агента восстановлен без привязки или отозванным")
	}
	if n := dst.count(t, "SELECT count(*) FROM app_keys WHERE id = $1 AND revoked_at IS NULL", tKey2); n != 1 {
		t.Fatal("обычный ключ отозван")
	}
	if strings.Contains(out.String(), "закреплённые за агентами") || strings.Contains(out.String(), "не отмечавшим привязку") {
		t.Fatalf("вывод: %s", out.String())
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND details->>'stage' = 'done'
		AND details->>'agent_keys_revoked' = '0' AND details->>'agent_keys_unknown' = 'false'`); n != 1 {
		t.Fatal("в записи «после» нет счётчика ключей агентов")
	}
}

// В21: копия старше 7 суток восстанавливается только с -accept-old-copy;
// с -keep-api-tokens токены остаются как в копии и принимаются.
func TestBackupRestoreOldCopyKeepTokensOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src4")
	dst := newInstallation(t, admin, base, "cli_backup_dst4")
	populate(t, src)
	dir := t.TempDir()
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join(dir, "config.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"create", "-keys", src.keys, "-out", file, "-passphrase-file", phrase, "-no-user-hmac-key"},
		src.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("create: %v", err)
	}
	later := time.Now().Add(8 * 24 * time.Hour)
	args := []string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase, "-keep-api-tokens"}
	if err := backupCmd(args, dst.dsn, &out, &errb, later); err == nil || !strings.Contains(err.Error(), "-accept-old-copy") {
		t.Fatalf("старая копия без флага: %v", err)
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND result = 'denied'
		AND details->>'reason' LIKE 'old_copy:%'`); n != 1 || dst.count(t, "SELECT count(*) FROM users") != 0 {
		t.Fatalf("отказ по возрасту: записей %d", n)
	}
	out.Reset()
	if err := backupCmd(append(args, "-accept-old-copy"), dst.dsn, &out, &errb, later); err != nil {
		t.Fatalf("с флагами: %v %s", err, errb.String())
	}
	if err := authToken(t, dst, tTokenRaw); err != nil {
		t.Fatalf("токен с -keep-api-tokens: %v", err)
	}
	if strings.Contains(out.String(), "восстановлены отозванными") {
		t.Fatalf("вывод: %s", out.String())
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND details->>'stage' = 'started'
		AND details->>'keep_api_tokens' = 'true' AND details->>'accept_old_copy' = 'true'
		AND (details->>'copy_age_hours')::int >= 191`); n != 1 {
		t.Fatal("в записи «до» нет флагов и возраста копии")
	}
}

// В22: копия, объекты которой сервис этого выпуска не принял бы (правило
// на категорию, которой нет в каталоге детекторов, — как после
// переименования; токен с правом безопасности users.manage — правило 2.10;
// словарь со старым полем),
// отклоняется целиком до записи: код 3, stage=refused, reason=invalid,
// в ошибке — перечень объектов, БД не меняется.
func TestBackupRestoreInvalidObjectsOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src5")
	dst := newInstallation(t, admin, base, "cli_backup_dst5")
	populate(t, src)
	h, err := standardProvider(t).Hasher()
	if err != nil {
		t.Fatal(err)
	}
	org := audit.DefaultOrgID
	legacy := "id: legacy\nversion: 1\nname: Старая\nmode: monitor\nrules:\n  - id: cards\n    detector: pii.ru\n" +
		"    directions: [input]\n    categories: [pii.renamed_card]\n    action: block\n    severity: high\n"
	const legacyID = "0192a000-0000-7000-8000-000000000402"
	// Ссылка на текущую версию проверяется при фиксации: обе вставки — в одной транзакции.
	src.exec(t, `WITH p AS (INSERT INTO policies (id, org_id, slug, name, mode, current_version, created_at, created_by,
		updated_at, updated_by) VALUES ($1, $2, 'legacy', 'Старая', 'monitor', 1, now(), 'user:x', now(), 'user:x') RETURNING id)
		INSERT INTO policy_versions (policy_id, version, spec_yaml, spec_hash, hash_alg, source, created_at, created_by)
		SELECT id, 1, $3, $4, 'SHA-256', 'api', now(), 'user:x' FROM p`, legacyID, org, legacy, h.Sum([]byte(legacy)))
	src.exec(t, `INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, hash_alg, permissions, expires_at,
		created_at) VALUES ('0192a000-0000-7000-8000-000000000503', $1, $2, 'verify', 'aisec_pat_vvvv7777', $3, 'SHA-256',
		'{users.manage:all}', now() + interval '10 days', now())`, org, tUser, h.Sum([]byte("token-verify")))
	src.exec(t, `UPDATE applications SET lists = '[{"name":"stop"}]' WHERE id = $1`, tApp)
	// Файл лицензии с испорченной подписью: сервер его не принял бы (задача 5.8).
	lic := readLicenseFixture(t)
	lic[len(lic)/2] ^= 0x01
	src.exec(t, "INSERT INTO licenses (org_id, number, file, loaded_at, loaded_by) VALUES ($1, 9, $2, now(), 'user:x')", org, lic)
	// Правило оповещений, которое API этого выпуска не примет (каждое событие —
	// оповещение), и каталог LDAP с фильтром без логина — задача 5.8.
	src.exec(t, `INSERT INTO alert_rules (id, org_id, kind, name, description, enabled, severity, condition, group_by,
		suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
		VALUES ('0192a000-0000-7000-8000-000000000504', $1, 'frequency', 'Каждое событие', '', true, 'high',
		'{"count":1,"window_minutes":1}', '{}', 0, 5, '{"roles":["duty_analyst"],"users":[]}', 1, now(), 'user:x', now(), 'user:x')`, org)
	src.exec(t, `INSERT INTO ldap_settings (org_id, enabled, url, ca_pem, bind_dn, bind_password, bind_password_key_id,
		user_base_dn, user_filter, id_attribute, display_attribute, group_mode, group_base_dn, version, updated_at, updated_by)
		VALUES ($1, false, 'ldaps://ldap.example.test', 'CA-PEM', 'cn=aisec,ou=svc,dc=example,dc=test', $2, $3,
		'ou=people,dc=example,dc=test', '(uid=*)', 'entryUUID', 'cn', 'member_of', '', 1, now(), $4)`,
		org, src.seal(t, []byte(tLDAPPassword), "ldap_settings", "bind_password", org), src.box.KeyID(), tUser)
	// По неверному значению в каждом разделе, проверку которого вынесли из
	// модулей (остатки волны A этапа 5): url_origin канала не по адресу из
	// секретов (консоль показала бы другой адресат), встроенное правило с
	// ключом, которого нет в выпуске, MCP-сервер на localhost (правило адресов),
	// группы для модели не из приложения, ключ сертификата шлюза от другой
	// цепочки.
	ca := testCAPEM(t)
	k := src.box.KeyID()
	const hookID = "0192a000-0000-7000-8000-000000000705"
	src.exec(t, `INSERT INTO notify_channels (id, org_id, name, type, enabled, min_severity, settings, secret_fields, secret,
		secret_key_id, audit_stream, version, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'Подменённый webhook', 'webhook', true, 'medium', $3::jsonb, '{signing_key,url}', $4, $5, false, 1, now(),
		'user:x', now(), 'user:x')`, hookID, org, channelSettings(t, notify.Settings{CAPEM: ca, Format: notify.FormatGeneric,
		URLOrigin: "https://other.example.test"}), src.seal(t, []byte(tWebhookSecret), "notify_channels", "secret", hookID), k)
	src.exec(t, `INSERT INTO alert_rules (id, org_id, builtin_key, kind, name, description, enabled, severity, condition, group_by,
		suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
		VALUES ('0192a000-0000-7000-8000-000000000505', $1, 'threshold.removed', 'threshold', 'Снятое встроенное', '', true,
		'high', '{"min_severity":"high"}', '{app}', 0, 10, '{"roles":[],"users":[]}', 1, now(), 'system', now(), 'system')`, org)
	src.exec(t, `INSERT INTO mcp_servers (id, org_id, slug, name, url, ca_pem, external, insecure_http, call_timeout_s, versions,
		created_at, created_by, updated_at, updated_by) VALUES ('0192a000-0000-7000-8000-000000000742', $1, 'plain', 'Локальный',
		'https://localhost/mcp', $2, true, false, 30, '{2025-11-25}', now(), 'user:x', now(), 'user:x')`, org, ca)
	src.exec(t, `INSERT INTO app_user_access (app_id, org_id, mode, issuer, audience, groups_claim, leeway_seconds, model_groups,
		updated_at, updated_by) VALUES ($1, $2, 'required', 'https://idp.example.test/realms/aisec', 'support-bot', 'groups', 30,
		'{"gpt-unknown":["support"]}', now(), 'user:x')`, tApp, org)
	_, cert, _ := testGatewayChain(t)
	other, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"gw.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	insertGatewayTLS(t, src, cert, other.Key)

	dir := t.TempDir()
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join(dir, "config.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"create", "-keys", src.keys, "-out", file, "-passphrase-file", phrase, "-no-user-hmac-key"},
		src.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Токены проверяются, только если остаются действующими (-keep-api-tokens).
	err = backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase, "-keep-api-tokens"},
		dst.dsn, &out, &errb, time.Now())
	var ie *invalidObjectsError
	if !errors.Is(err, errBackupInvalid) || !errors.As(err, &ie) {
		t.Fatalf("недопустимые объекты: %v", err)
	}
	for _, want := range []string{"политика legacy", "pii.renamed_card", "токен API aisec_pat_vvvv7777", "приложение support-bot",
		"лицензия № 9", "правило оповещений «Каждое событие»", "вход через LDAP", "канал «Подменённый webhook»: settings",
		"правило оповещений «Снятое встроенное»: builtin_key", "MCP-сервер plain: url", "доступ по группам приложения support-bot",
		"сертификат шлюза: закрытый ключ не подходит"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в ошибке нет %q: %v", want, err)
		}
	}
	t.Setenv("AISEC_DATABASE_URL", dst.dsn)
	if code := run([]string{"backup", "restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase}, &out, &errb,
		time.Now()); code != 3 || strings.Contains(errb.String(), "aisec_pat_vvvv7777") {
		t.Fatalf("код возврата %d: %s", code, errb.String())
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND result = 'failure'
		AND details->>'stage' = 'refused' AND details->>'reason' LIKE 'invalid:%'`); n != 2 {
		t.Fatalf("отказов в аудите: %d", n)
	}
	if n := auditCount(t, dst, "backup.restore", "success", "started"); n != 0 {
		t.Fatalf("запись «до» при отказе: %d", n)
	}
	for _, table := range []string{"users", "api_tokens", "providers", "applications", "policies", "licenses", "notify_channels",
		"mcp_servers", "app_user_access", "gateway_tls"} {
		if n := dst.count(t, "SELECT count(*) FROM "+table); n != 0 {
			t.Fatalf("отказ изменил %s: %d", table, n)
		}
	}
	if n := dst.count(t, "SELECT count(*) FROM roles WHERE id = 'duty_analyst'"); n != 0 {
		t.Fatal("отказ добавил свою роль")
	}
}

// Отказы до записи: установка без init и схема БД старше копии.
func TestBackupRestorePreconditionsOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src3")
	populate(t, src)
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join(t.TempDir(), "config.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"create", "-keys", src.keys, "-out", file, "-passphrase-file", phrase, "-no-user-hmac-key"},
		src.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Н41: фраза, равная названию организации, для новой копии не годится.
	const orgPhrase = "ООО Синтетика Восток"
	src.exec(t, "UPDATE organizations SET name = $2 WHERE id = $1", audit.DefaultOrgID, orgPhrase)
	err = backupCmd([]string{"create", "-keys", src.keys, "-out", filepath.Join(t.TempDir(), "org.aisec-backup"),
		"-passphrase-file", writePhraseFile(t, strings.ToLower(orgPhrase), 0o400), "-no-user-hmac-key"}, src.dsn, &out, &errb, time.Now())
	if err == nil || !strings.Contains(err.Error(), "названием организации") {
		t.Fatalf("фраза — название организации: %v", err)
	}

	// Только migrate, без init: ключа данных нет.
	const bare = "cli_backup_bare"
	for _, q := range []string{"DROP SCHEMA IF EXISTS " + bare + " CASCADE", "CREATE SCHEMA " + bare} {
		if _, err := admin.Pool().Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = admin.Pool().Exec(context.Background(), "DROP SCHEMA IF EXISTS "+bare+" CASCADE") //nolint:gosec // G104: уборка теста
	}()
	bareDSN := strings.Replace(src.dsn, "search_path=cli_backup_src3", "search_path="+bare, 1)
	if err := migrate(nil, bareDSN, &out, &errb); err != nil {
		t.Fatal(err)
	}
	err = backupCmd([]string{"restore", "-keys", keyDir(t), "-in", file, "-passphrase-file", phrase}, bareDSN, &out, &errb, time.Now())
	if err == nil || !strings.Contains(err.Error(), "нет ключа данных") {
		t.Fatalf("без init: %v", err)
	}

	// Схема старше копии: последняя миграция будто не применена.
	dst := newInstallation(t, admin, base, "cli_backup_dst3")
	dst.exec(t, "DELETE FROM schema_migrations WHERE version = (SELECT max(version) FROM schema_migrations)")
	err = backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase}, dst.dsn, &out, &errb, time.Now())
	if err == nil || !strings.Contains(err.Error(), "схема БД старше копии") {
		t.Fatalf("старая схема: %v", err)
	}
	if n := auditCount(t, dst, "backup.restore", "failure", "refused"); n != 1 {
		t.Fatalf("отказ по схеме в аудите: %d", n)
	}
	if n := dst.count(t, "SELECT count(*) FROM users"); n != 0 {
		t.Fatal("отказ изменил БД")
	}
}
