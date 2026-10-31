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

// insertModel добавляет модель реестра ИИ (миграция 0069) с файлами.
func insertModel(t *testing.T, in *installation, id, kind, provider, name, title, origin string, files ...string) {
	t.Helper()
	in.exec(t, `INSERT INTO inventory_models (id, org_id, kind, provider, name, title, origin, status, first_seen, last_seen,
		created_at, created_by, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active',
		CASE WHEN $7 = 'traffic' THEN now() - interval '1 day' END, CASE WHEN $7 = 'traffic' THEN now() END,
		now(), 'system', now(), 'user:x')`, id, audit.DefaultOrgID, kind, provider, name, title, origin)
	for i, path := range files {
		in.exec(t, `INSERT INTO inventory_model_files (model_id, path, size, role, hash_alg, hash) VALUES ($1, $2, $3, 'weights',
			'SHA-256', $4)`, id, path, 1000+i, bytes.Repeat([]byte{byte(i + 1)}, 32))
	}
}

// Остаток 5.17 этапа 5: реестр ИИ в копии конфигурации. Ручные модели —
// с файлами и эталонными хешами; модели из трафика — только с правками,
// без отметок трафика; модель из трафика без правок и использование не
// переносятся. В непустой установке правки сопоставляются по паре
// «провайдер, имя»: модель без своих правок их получает, со своими — нет
// (строка отчёта); ручная модель с той же парой — совпадение, отказ.
func TestBackupInventoryOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src_inv")
	populate(t, src)
	const (
		mCustomer = "0192a000-0000-7000-8000-000000000901"
		mManual   = "0192a000-0000-7000-8000-000000000902"
		mEdited   = "0192a000-0000-7000-8000-000000000903"
		mPlain    = "0192a000-0000-7000-8000-000000000904"
		mOwn      = "0192a000-0000-7000-8000-000000000905"
	)
	insertModel(t, src, mCustomer, "customer", "", "llama-support-ft", "Модель поддержки", "manual", "model.gguf", "adapter/lora.bin")
	insertModel(t, src, mManual, "provider", "mock-llm", "gpt-manual", "", "manual")
	insertModel(t, src, mEdited, "provider", "mock-llm", "gpt-edited", "Основная модель", "traffic")
	insertModel(t, src, mPlain, "provider", "mock-llm", "gpt-plain", "", "traffic")
	insertModel(t, src, mOwn, "provider", "mock-llm", "gpt-own", "Из копии", "traffic")
	src.exec(t, `INSERT INTO inventory_usage (org_id, app, provider, model, first_seen, last_seen)
		VALUES ($1, 'support-bot', 'mock-llm', 'gpt-plain', now() - interval '1 day', now())`, audit.DefaultOrgID)

	dir := t.TempDir()
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join(dir, "config.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"create", "-keys", src.keys, "-out", file, "-passphrase-file", phrase, "-no-user-hmac-key"},
		src.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("create: %v %s", err, errb.String())
	}

	// Пустая установка: 4 модели (без gpt-plain), файлы с хешами, без отметок
	// трафика и без использования.
	dst := newInstallation(t, admin, base, "cli_backup_dst_inv")
	out.Reset()
	if err := backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase}, dst.dsn, &out, &errb,
		time.Now()); err != nil {
		t.Fatalf("restore: %v %s", err, errb.String())
	}
	if !strings.Contains(out.String(), "моделей реестра ИИ 4") || strings.Contains(out.String(), "Реестр ИИ:") {
		t.Fatalf("вывод: %s", out.String())
	}
	if n := dst.count(t, "SELECT count(*) FROM inventory_models"); n != 4 {
		t.Fatalf("моделей: %d", n)
	}
	if n := dst.count(t, `SELECT count(*) FROM inventory_model_files f JOIN inventory_models m ON m.id = f.model_id
		WHERE m.id = $1 AND m.title = 'Модель поддержки' AND m.origin = 'manual' AND ((f.path = 'model.gguf' AND f.hash = $2)
		OR (f.path = 'adapter/lora.bin' AND f.hash = $3))`, mCustomer, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)); n != 2 {
		t.Fatalf("файлы ручной модели с хешами: %d", n)
	}
	if n := dst.count(t, `SELECT count(*) FROM inventory_models WHERE id = $1 AND origin = 'traffic' AND title = 'Основная модель'
		AND first_seen IS NULL AND last_seen IS NULL`, mEdited); n != 1 {
		t.Fatal("правки модели из трафика не восстановлены или перенесены отметки трафика")
	}
	if n := dst.count(t, "SELECT count(*) FROM inventory_models WHERE name = 'gpt-plain'") + dst.count(t,
		"SELECT count(*) FROM inventory_usage"); n != 0 {
		t.Fatalf("модель без правок или использование в копии: %d", n)
	}

	// Непустая установка: gpt-edited уже найдена трафиком без правок —
	// правки копии переходят на неё; у gpt-own свои правки — остаются.
	ne := newInstallation(t, admin, base, "cli_backup_ne_inv")
	ne.exec(t, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by) VALUES ('0192a000-0000-7000-8000-00000000aaac', $1, 'first.admin',
		'Синтетический первый', 'security_admin', 'active', 'x', now(), false, now(), 'setup')`, audit.DefaultOrgID)
	const neEdited, neOwn = "0192a000-0000-7000-8000-000000000911", "0192a000-0000-7000-8000-000000000912"
	insertModel(t, ne, neEdited, "provider", "mock-llm", "gpt-edited", "", "traffic")
	insertModel(t, ne, neOwn, "provider", "mock-llm", "gpt-own", "Своё название", "traffic")
	out.Reset()
	if err := backupCmd([]string{"restore", "-keys", ne.keys, "-in", file, "-passphrase-file", phrase, "-allow-nonempty"},
		ne.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("restore в непустую: %v %s", err, errb.String())
	}
	for _, want := range []string{"Реестр ИИ:", "модель mock-llm/gpt-edited: правки копии перенесены на модель установки",
		"модель mock-llm/gpt-own: в установке у неё свои правки — правки копии не перенесены"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("в выводе нет %q: %s", want, out.String())
		}
	}
	if n := ne.count(t, `SELECT count(*) FROM inventory_models WHERE (id = $1 AND title = 'Основная модель' AND last_seen IS NOT NULL)
		OR (id = $2 AND title = 'Своё название')`, neEdited, neOwn); n != 2 {
		t.Fatal("сопоставление по паре «провайдер, имя» в непустой установке")
	}
	if n := ne.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND details->>'stage' = 'done'
		AND json_array_length(details->'inventory_report') = 2`); n != 1 {
		t.Fatal("отчёт о реестре ИИ не записан в аудит")
	}

	// Ручная модель копии с парой, которая в установке уже есть, — совпадение.
	cf := newInstallation(t, admin, base, "cli_backup_cf_inv")
	cf.exec(t, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by) VALUES ('0192a000-0000-7000-8000-00000000aaad', $1, 'first.admin',
		'Синтетический первый', 'security_admin', 'active', 'x', now(), false, now(), 'setup')`, audit.DefaultOrgID)
	insertModel(t, cf, "0192a000-0000-7000-8000-000000000921", "provider", "mock-llm", "gpt-manual", "", "traffic")
	err = backupCmd([]string{"restore", "-keys", cf.keys, "-in", file, "-passphrase-file", phrase, "-allow-nonempty"},
		cf.dsn, &out, &errb, time.Now())
	if err == nil || !strings.Contains(err.Error(), "модель реестра mock-llm/gpt-manual") {
		t.Fatalf("совпадение ручной модели: %v", err)
	}
}
