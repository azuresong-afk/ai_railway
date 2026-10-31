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
