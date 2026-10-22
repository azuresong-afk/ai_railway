package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/backup"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
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
	entries, _ := os.ReadDir(filepath.Dir(path))
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
		now() + interval '10 days', now(), '10.0.0.7')`, tToken, org, tUser, h.Sum([]byte("token")))
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
		'monitor', 'masked', 'fail_open', 'header', '{"requests_per_minute": 60}', '[{"name":"stop"}]', '{example.test}',
		now(), 'user:x', now(), 'user:x')`, tApp, org, tUser, tProvider)
	in.exec(t, `INSERT INTO app_keys (id, org_id, app_id, name, prefix, key_hash, hash_alg, allowed_cidrs, expires_at,
		created_at, created_by, revoked_at, revoked_by) VALUES ($1, $2, $3, 'первый', 'aisec_aaaa1111', $4, 'SHA-256',
		'{10.0.0.0/8}', now() + interval '1 day', now() - interval '1 hour', 'user:x', now(), 'user:x')`,
		tKey1, org, tApp, h.Sum([]byte("k1")))
	in.exec(t, `INSERT INTO app_keys (id, org_id, app_id, name, prefix, key_hash, hash_alg, expires_at, created_at,
		created_by, rotated_from) VALUES ($1, $2, $3, 'второй', 'aisec_bbbb2222', $4, 'SHA-256', now() + interval '30 days',
		now(), 'user:x', $5)`, tKey2, org, tApp, h.Sum([]byte("k2")), tKey1)
	v1, v2 := "id: corp\nname: Синтетическая\nmode: monitor\n", "id: corp\nname: Синтетическая\nmode: enforce\n"
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
			VALUES ($1, 3, $2, $3, 'SHA-256', 'rollback', 1, now(), 'user:x')`, []any{tPolicy, v1, h.Sum([]byte(v1))}},
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
	out, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
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
	for _, leak := range [][]byte{tCredential, tTOTP, hmacKey, []byte("sec.admin"), []byte("argon2id")} {
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
	if !strings.Contains(out.String(), "Конфигурация восстановлена") {
		t.Fatalf("вывод: %s", out.String())
	}
	w, err := backup.NewWriter(ctx, standardProvider(t), []byte(testBackupPhrase), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a, b := view(t, src, w), view(t, dst, w); a != b {
		t.Fatalf("данные после восстановления отличаются:\n--- исходная\n%s\n--- восстановленная\n%s", a, b)
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
		AND details->>'settings_restored' = 'true' AND details->'settings'->'events'->>'content_days' = '30'
		AND details->'settings'->'install'->>'timezone' = 'Asia/Yekaterinburg'`); n != 1 {
		t.Fatal("в записи «после» нет новых значений настроек")
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
