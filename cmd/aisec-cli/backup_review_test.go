package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// 5В1 ревью 5.r1 этапа 5: у системных правил и правил безопасности копия
// переносит только получателей — пониженная в копии важность правила
// безопасности, название, условие, группировка и окно группировки после
// восстановления — значения выпуска (через API их не вернуть; выключение
// такого правила останавливает ещё CHECK миграции 0028). Встроенное правило, которого в выпуске
// нет, пропускается строкой отчёта, копия восстанавливается.
func TestBackupRestoreLockedBuiltinRulesOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src_5v1")
	dst := newInstallation(t, admin, base, "cli_backup_dst_5v1")
	populate(t, src)
	org := audit.DefaultOrgID
	src.exec(t, `INSERT INTO alert_rules (id, org_id, builtin_key, kind, name, description, enabled, severity, condition, group_by,
		suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
		VALUES ('0192a000-0000-7000-8000-000000000521', $1, $2, 'security', 'Подменённое', 'подменённое', true, 'info',
		'{"filter":"action = \"allow\""}', '{}', 0, 0, '{"roles":["security_admin"],"users":[]}', 4, now(), 'system',
		now(), 'user:x')`, org, alerting.BuiltinRecipientsChanged)
	src.exec(t, `INSERT INTO alert_rules (id, org_id, builtin_key, kind, name, description, enabled, severity, condition, group_by,
		suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
		VALUES ('0192a000-0000-7000-8000-000000000522', $1, 'threshold.removed', 'threshold', 'Снятое встроенное', '', true,
		'high', '{"min_severity":"high"}', '{app}', 0, 10, '{"roles":[],"users":[]}', 1, now(), 'system', now(), 'system')`, org)

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
	b, _ := alerting.StoredBuiltin(alerting.BuiltinRecipientsChanged)
	if n := dst.count(t, `SELECT count(*) FROM alert_rules WHERE id = '0192a000-0000-7000-8000-000000000521' AND enabled
		AND severity = $1 AND name = $2 AND suppress_minutes = $3 AND group_minutes = $4 AND group_by = $5
		AND condition = '{}'::jsonb AND recipients = '{"roles":["security_admin"],"users":[]}'::jsonb AND version = 4`,
		b.Severity, b.Name, b.SuppressMinutes, b.GroupMinutes, b.GroupBy); n != 1 {
		t.Fatal("правило безопасности восстановлено значениями копии, а не выпуска")
	}
	if n := dst.count(t, "SELECT count(*) FROM alert_rules WHERE builtin_key = 'threshold.removed'"); n != 0 {
		t.Fatal("снятое встроенное правило восстановлено")
	}
	if !strings.Contains(out.String(), "встроенное правило оповещений «Снятое встроенное» (threshold.removed): в этом выпуске его нет") {
		t.Fatalf("нет строки о пропуске: %s", out.String())
	}
}

// 5Н1 ревью 5.r1 этапа 5: в непустую установку настройки копии не пишутся,
// поэтому и не проверяются — лицензия чужим ключом и встроенное правило с
// неверными получателями копию не отклоняют. В пустую установку та же копия
// — отказ (TestBackupRestoreInvalidObjectsOnRealDB).
func TestBackupRestoreNonEmptySkipsSettingsCheckOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src_5n1")
	dst := newInstallation(t, admin, base, "cli_backup_dst_5n1")
	populate(t, src)
	org := audit.DefaultOrgID
	lic := readLicenseFixture(t)
	lic[len(lic)/2] ^= 0x01
	src.exec(t, "INSERT INTO licenses (org_id, number, file, loaded_at, loaded_by) VALUES ($1, 9, $2, now(), 'user:x')", org, lic)
	src.exec(t, `INSERT INTO alert_rules (id, org_id, builtin_key, kind, name, description, enabled, severity, condition, group_by,
		suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
		VALUES ('0192a000-0000-7000-8000-000000000531', $1, $2, 'security', 'Получатели', '', true, 'high', '{}', '{actor}', 0, 10,
		'{"roles":["Не роль"],"users":[]}', 1, now(), 'system', now(), 'user:x')`, org, alerting.BuiltinRecipientsChanged)
	dst.exec(t, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by) VALUES ('0192a000-0000-7000-8000-00000000aaab', $1, 'first.admin',
		'Синтетический первый', 'security_admin', 'active', 'x', now(), false, now(), 'setup')`, org)

	dir := t.TempDir()
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join(dir, "config.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"create", "-keys", src.keys, "-out", file, "-passphrase-file", phrase, "-no-user-hmac-key"},
		src.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase, "-allow-nonempty"},
		dst.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("restore в непустую установку: %v", err)
	}
	if n := dst.count(t, "SELECT count(*) FROM licenses"); n != 0 {
		t.Fatalf("лицензия записана в непустую установку: %d", n)
	}
	if n := dst.count(t, "SELECT count(*) FROM alert_rules WHERE builtin_key IS NOT NULL"); n != 0 {
		t.Fatalf("встроенное правило записано в непустую установку: %d", n)
	}
	if n := dst.count(t, "SELECT count(*) FROM users"); n != 3 {
		t.Fatalf("пользователей после восстановления: %d", n)
	}
}

// 5Н2 ревью 5.r1 этапа 5: при восстановлении служебной базы поверх более
// старой версии установки её текущая версия уходит в предыдущую, только
// если проходит проверку (как при загрузке, PGStore.Save); непрошедшая
// удаляется, и откат не ведёт на непроверенную базу.
func TestBackupServiceDBsStaleCurrentOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	if _, testKey, err := integrity.EmbeddedVerifier(standardProvider(t)); err != nil || !testKey {
		t.Skip("сборка с ключом производителя: тестовые базы она не принимает")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src_5n2")
	populate(t, src)
	v1, err := os.ReadFile("../../testdata/shadowai/catalog-test.aisecdb")
	if err != nil {
		t.Fatal(err)
	}
	v2 := signTestCatalog(t, 2)
	insertServiceDB(t, src, "shadow_ai_catalog", "current", 2, v2)
	dir := t.TempDir()
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join(dir, "config.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"create", "-keys", src.keys, "-out", file, "-passphrase-file", phrase, "-no-user-hmac-key"},
		src.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("create: %v %s", err, errb.String())
	}
	broken := bytes.Clone(v1)
	broken[len(broken)/2] ^= 0x01
	for _, tc := range []struct {
		schema   string
		file     []byte
		want     string
		previous int
	}{
		{"cli_backup_dst_5n2a", v1, "shadow_ai_catalog: восстановлена версия 2 (текущая), версия установки 1 — предыдущая", 1},
		{"cli_backup_dst_5n2b", broken, "shadow_ai_catalog: восстановлена версия 2 (текущая), версия установки 1 не прошла проверку — удалена", 0},
	} {
		dst := newInstallation(t, admin, base, tc.schema)
		insertServiceDB(t, dst, "shadow_ai_catalog", "current", 1, tc.file)
		out.Reset()
		if err := backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase}, dst.dsn, &out, &errb,
			time.Now()); err != nil {
			t.Fatalf("%s: restore: %v %s", tc.schema, err, errb.String())
		}
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("%s: в выводе нет %q: %s", tc.schema, tc.want, out.String())
		}
		if n := dst.count(t, "SELECT count(*) FROM service_dbs WHERE slot = 'current' AND version = 2 AND file = $1", v2); n != 1 {
			t.Fatalf("%s: текущая версия не из копии", tc.schema)
		}
		if n := dst.count(t, "SELECT count(*) FROM service_dbs WHERE slot = 'previous' AND file = $1", v1); n != tc.previous {
			t.Fatalf("%s: предыдущих версий %d, ожидалось %d", tc.schema, n, tc.previous)
		}
		if n := dst.count(t, "SELECT count(*) FROM service_dbs WHERE file = $1", broken); n != 0 {
			t.Fatalf("%s: непроверенная версия установки осталась", tc.schema)
		}
	}
}
