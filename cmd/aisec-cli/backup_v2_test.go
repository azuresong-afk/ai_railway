package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/backup"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Синтетические объекты этапов 3 и 4 (задача 5.8 этапа 5).
const (
	tChannelMail = "0192a000-0000-7000-8000-000000000701"
	tChannelHook = "0192a000-0000-7000-8000-000000000702"
	tChannelLog  = "0192a000-0000-7000-8000-000000000703"
	tRule        = "0192a000-0000-7000-8000-000000000711"
	tBuiltinRule = "0192a000-0000-7000-8000-000000000712"
	tSchedule    = "0192a000-0000-7000-8000-000000000721"
	tPrice       = "0192a000-0000-7000-8000-000000000731"
	tMCP         = "0192a000-0000-7000-8000-000000000741"
	tAgent       = "0192a000-0000-7000-8000-000000000751"
	tAgentKey    = "0192a000-0000-7000-8000-000000000304"
	tToolMCP     = "0192a000-0000-7000-8000-000000000761"
	tToolFunc    = "0192a000-0000-7000-8000-000000000762"
)

// Секреты этапов 3 и 4 под ключом данных: ни один не должен попасть в файл
// копии и в вывод команд открытым текстом.
var (
	tSMTPSecret    = `{"password":"synthetic-smtp-password"}`
	tWebhookSecret = `{"url":"https://hooks.example.test/synthetic-webhook-path","signing_key":"synthetic-webhook-signing"}` //nolint:gosec // G101: синтетический секрет для теста, нигде не выдан
	tLDAPPassword  = "synthetic-ldap-bind-password"                                                                          //nolint:gosec // G101: синтетический секрет для теста, нигде не выдан
	tOIDCSecret    = "synthetic-oidc-client-secret"                                                                          //nolint:gosec // G101: синтетический секрет для теста, нигде не выдан
	tGatewayTLSKey = "synthetic-gateway-tls-key-material"
	tMCPCredential = "synthetic-mcp-credential" //nolint:gosec // G101: синтетический секрет для теста, нигде не выдан
	tPromptText    = "Синтетический системный промпт бота поддержки"
)

func stage34Secrets() [][]byte {
	return [][]byte{[]byte("synthetic-smtp-password"), []byte("synthetic-webhook-path"), []byte("synthetic-webhook-signing"),
		[]byte(tLDAPPassword), []byte(tOIDCSecret), []byte(tGatewayTLSKey), []byte(tMCPCredential), []byte(tPromptText)}
}

// builtinRuleKey — ключ встроенного правила, которое сервер создаёт при
// запуске (internal/alerting.BuiltinInjectionBlocked).
const builtinRuleKey = "threshold.injection_blocked"

// populateStage34 добавляет к populate по объекту каждого вида этапов 3 и 4
// с секретами под ключом данных установки.
func populateStage34(t *testing.T, in *installation) {
	t.Helper()
	org := audit.DefaultOrgID
	h, err := standardProvider(t).Hasher()
	if err != nil {
		t.Fatal(err)
	}
	in.exec(t, `UPDATE install_settings SET alert_retention_days = 400, incident_retention_days = 730,
		shadow_ai_retention_days = 90, quota_mode = 'leased', quota_mode_changed_at = now() WHERE org_id = $1`, org)
	in.exec(t, "UPDATE users SET email = 'sec.admin@example.test' WHERE id = $1", tUser)
	for _, c := range []struct {
		id, name, typ, settings, fields, secret string
	}{
		{tChannelMail, "Почта ИБ", "email", `{"host":"smtp.example.test","port":587,"to":["soc@example.test"]}`, "{password}", tSMTPSecret},
		{tChannelHook, "Webhook SOC", "webhook", `{"format":"json"}`, "{url,signing_key}", tWebhookSecret},
		{tChannelLog, "Syslog", "syslog", `{"address":"syslog.example.test:6514"}`, "{}", ""},
	} {
		var sealed []byte
		var keyID *string
		if c.secret != "" {
			k := in.box.KeyID()
			sealed, keyID = in.seal(t, []byte(c.secret), "notify_channels", "secret", c.id), &k
		}
		in.exec(t, `INSERT INTO notify_channels (id, org_id, name, type, enabled, min_severity, settings, secret_fields, secret,
			secret_key_id, audit_stream, version, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, true, 'medium', $5::jsonb, $6::text[], $7, $8::uuid, $9, 1, now(), 'user:x', now(), 'user:x')`,
			c.id, org, c.name, c.typ, c.settings, c.fields, sealed, keyID, c.typ == "syslog")
	}
	in.exec(t, `INSERT INTO alert_rules (id, org_id, kind, name, description, enabled, severity, condition, group_by,
		suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'frequency', 'Частые блокировки', 'синтетическое', true, 'high', '{"min_severity":"high","count":5,"window_minutes":10}',
		'{app}', 30, 5, $3::jsonb, 2, now(), 'user:x', now(), 'user:x')`,
		tRule, org, `{"roles":["duty_analyst"],"users":["`+tUser+`"]}`)
	in.exec(t, `INSERT INTO alert_rules (id, org_id, builtin_key, kind, name, description, enabled, severity, condition, group_by,
		suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, $3, 'threshold', 'Заблокированные инъекции', 'встроенное', false, 'critical', '{"count":3}', '{}',
		0, 10, '{"roles":[],"users":[]}', 3, now(), 'system', now(), 'user:x')`, tBuiltinRule, org, builtinRuleKey)
	in.exec(t, `INSERT INTO report_schedules (id, org_id, name, report, frequency, weekday, at_time, format, channel_id, enabled,
		next_run_at, scope_incidents, scope_alerts, recipient_user_ids, version, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'Еженедельная сводка', 'summary', 'weekly', 1, '09:30', 'xlsx', $3, true, now() + interval '2 days',
		true, true, $4::uuid[], 1, now(), 'user:x', now(), 'user:x')`, tSchedule, org, tChannelMail, []string{tUser})
	in.exec(t, `INSERT INTO model_prices (id, org_id, provider_id, model, input_price, output_price, created_at, created_by,
		updated_at, updated_by) VALUES ($1, $2, $3, 'gpt-x', 150, 600, now(), 'user:x', now(), 'user:x')`, tPrice, org, tProvider)
	in.exec(t, `INSERT INTO app_budgets (app_id, org_id, mode, monthly_limit, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'hard', 500000, now(), 'user:x', now(), 'user:x')`, tApp, org)
	in.exec(t, `INSERT INTO prompt_baselines (app_id, org_id, mode, hash, text_bytes, text_sealed, text_key_id, text_alg,
		created_at, created_by, updated_at, updated_by) VALUES ($1, $2, 'block', $3, $4, $5, $6, $7, now(), 'user:x', now(), 'user:x')`,
		tApp, org, strings.Repeat("ab", 32), len(tPromptText), in.seal(t, []byte(tPromptText), "prompt_baselines", "text", tApp),
		in.box.KeyID(), in.box.Alg())
	in.exec(t, `INSERT INTO app_user_access (app_id, org_id, mode, issuer, audience, groups_claim, leeway_seconds, model_groups,
		updated_at, updated_by) VALUES ($1, $2, 'required', 'https://idp.example.test/realms/aisec', 'support-bot', 'groups', 30,
		'{"gpt-x":["support"]}', now(), 'user:x')`, tApp, org)
	in.exec(t, `INSERT INTO incident_instructions (org_id, category, version, body, created_at, created_by) VALUES
		($1, 'pii_leak', 2, 'Синтетическая инструкция, версия 2', now() - interval '1 day', 'user:x'),
		($1, 'pii_leak', 3, 'Синтетическая инструкция, версия 3', now(), 'user:x')`, org)
	in.exec(t, `INSERT INTO gateway_tls (org_id, host, chain_pem, chain_len, subject, issuer, serial, fingerprint, not_before,
		not_after, dns_names, ip_addresses, cert_key_alg, key_sealed, key_key_id, key_alg, created_at, created_by, updated_at,
		updated_by) VALUES ($1, 'gw.example.test', 'CHAIN-PEM', 2, 'CN=gw.example.test', 'CN=Синтетический УЦ', '0a1b',
		$2, now() - interval '1 day', now() + interval '300 days', '{gw.example.test}', '{10.0.0.5}', 'ECDSA P-256', $3, $4, $5,
		now(), 'user:x', now(), 'user:x')`, org, strings.Repeat("c", 64),
		in.seal(t, []byte(tGatewayTLSKey), "gateway_tls", "key", org), in.box.KeyID(), in.box.Alg())
	in.exec(t, `INSERT INTO oidc_settings (org_id, enabled, display_name, issuer, client_id, client_secret, client_secret_key_id,
		console_url, ca_pem, scopes, groups_claim, required_acr, required_amr, version, updated_at, updated_by)
		VALUES ($1, true, 'Синтетический IdP', 'https://idp.example.test/realms/aisec', 'aisec-console', $2, $3,
		'https://aisec.example.test', 'CA-PEM', '{openid,profile}', 'groups', '{}', '{mfa}', 2, now(), $4)`,
		org, in.seal(t, []byte(tOIDCSecret), "oidc_settings", "client_secret", org), in.box.KeyID(), tUser)
	in.exec(t, `INSERT INTO oidc_group_roles (org_id, group_name, role) VALUES ($1, 'soc', 'security_admin'),
		($1, 'duty', 'duty_analyst')`, org)
	in.exec(t, `INSERT INTO ldap_settings (org_id, enabled, url, ca_pem, bind_dn, bind_password, bind_password_key_id,
		user_base_dn, user_filter, id_attribute, display_attribute, group_mode, group_base_dn, version, updated_at, updated_by)
		VALUES ($1, false, 'ldaps://ldap.example.test', 'CA-PEM', 'cn=aisec,ou=svc,dc=example,dc=test', $2, $3,
		'ou=people,dc=example,dc=test', '(uid={login})', 'entryUUID', 'cn', 'member_of', '', 1, now(), $4)`,
		org, in.seal(t, []byte(tLDAPPassword), "ldap_settings", "bind_password", org), in.box.KeyID(), tUser)
	in.exec(t, `INSERT INTO ldap_group_roles (org_id, group_dn, role) VALUES ($1, 'cn=auditors,dc=example,dc=test', 'auditor')`, org)
	in.exec(t, `INSERT INTO mcp_servers (id, org_id, slug, name, url, ca_pem, auth_header, credential, credential_key_id,
		credential_alg, credential_set_at, external, insecure_http, call_timeout_s, versions, created_at, created_by, updated_at,
		updated_by) VALUES ($1, $2, 'files', 'Синтетические файлы', 'https://mcp.example.test/mcp', 'CA-PEM', 'X-Api-Key', $3, $4,
		$5, now(), false, false, 30, '{2025-11-25}', now(), 'user:x', now(), 'user:x')`,
		tMCP, org, in.seal(t, []byte(tMCPCredential), "mcp_servers", "credential", tMCP), in.box.KeyID(), in.box.Alg())
	in.exec(t, `INSERT INTO agents (id, org_id, app_id, slug, name, description, owner, status, created_at, created_by,
		updated_at, updated_by) VALUES ($1, $2, $3, 'reader', 'Синтетический агент', 'только чтение', 'ИБ', 'active', now(),
		'user:x', now(), 'user:x')`, tAgent, org, tApp)
	in.exec(t, "INSERT INTO agent_servers (org_id, agent_id, server_id) VALUES ($1, $2, $3)", org, tAgent, tMCP)
	in.exec(t, `INSERT INTO app_keys (id, org_id, app_id, agent_id, name, prefix, key_hash, hash_alg, expires_at, created_at,
		created_by) VALUES ($1, $2, $3, $4, 'агент', 'aisec_dddd4444', $5, 'SHA-256', now() + interval '30 days', now(), 'user:x')`,
		tAgentKey, org, tApp, tAgent, h.Sum([]byte("k-agent")))
	desc := `{"name":"read_file"}`
	in.exec(t, `INSERT INTO agent_tools (id, org_id, server_id, name, descriptor, descriptor_hash, approved_descriptor,
		approved_hash, hash_alg, risk, status, first_seen, last_seen, decided_by, decided_at, comment, updated_at)
		VALUES ($1, $2, $3, 'read_file', $4, $5, $4, $5, 'SHA-256', 'medium', 'approved', now(), now(), 'user:x', now(),
		'одобрено', now())`, tToolMCP, org, tMCP, desc, h.Sum([]byte(desc)))
	fn := `{"name":"lookup"}`
	in.exec(t, `INSERT INTO agent_tools (id, org_id, agent_id, name, descriptor, descriptor_hash, hash_alg, risk, status,
		first_seen, last_seen, updated_at) VALUES ($1, $2, $3, 'lookup', $4, $5, 'SHA-256', 'high', 'new', now(), now(), now())`,
		tToolFunc, org, tAgent, fn, h.Sum([]byte(fn)))
	in.exec(t, `INSERT INTO shadow_ai_exclusions (org_id, kind, value, comment, created_at, created_by) VALUES
		($1, 'service', 'chatgpt', 'разрешён договором', now(), 'user:x'), ($1, 'user', $2, '', now(), 'user:x')`,
		org, strings.Repeat("0f", 16))
	in.exec(t, "INSERT INTO licenses (org_id, number, file, loaded_at, loaded_by) VALUES ($1, 1, $2, now(), 'user:x')",
		org, readLicenseFixture(t))
	in.exec(t, "INSERT INTO license_clock (org_id, high_water) VALUES ($1, now() + interval '1 hour')", org)
	in.exec(t, `INSERT INTO compliance_marks (org_id, requirement_id, status, comment, document, review_by, set_at, set_by)
		VALUES ($1, 'fstec.upd.1', 'partial', 'Синтетическая отметка', 'Приказ № 1', current_date + 30, now(), 'user:x')`, org)
}

// readLicenseFixture — тестовая лицензия № 1, подписанная тестовым рабочим
// ключом (testdata/license).
func readLicenseFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/license/license-test.aiseclic") //nolint:gosec // G304: фикстура теста из репозитория
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// openSectionSecrets открывает секреты разделов версии 2 ключом копии w и
// приводит к сравнимому виду то, что восстановление законно меняет: ID и
// время создания встроенного правила (его создаёт сервер) и отметку часов лицензии
// (наибольшее из копии и установки).
func openSectionSecrets(t *testing.T, s *backup.Snapshot, w *backup.Writer) {
	t.Helper()
	open := func(sealed []byte, kind, id string) []byte {
		out, err := w.Keys().OpenSecret(sealed, kind, id)
		if err != nil {
			t.Fatalf("%s %s: %v", kind, id, err)
		}
		return out
	}
	for i, c := range s.Channels {
		if c.Secret != nil {
			s.Channels[i].Secret = open(c.Secret, "notify_channels.secret", c.ID)
		}
	}
	for i, a := range s.Applications {
		if a.Baseline != nil {
			s.Applications[i].Baseline.Text = open(a.Baseline.Text, "prompt_baselines.text", a.ID)
		}
	}
	for i, m := range s.MCPServers {
		if m.Credential != nil {
			s.MCPServers[i].Credential = open(m.Credential, "mcp_servers.credential", m.ID)
		}
	}
	if g := s.GatewayTLS; g != nil {
		g.Key = open(g.Key, "gateway_tls.key", s.OrgID)
	}
	if o := s.OIDC; o != nil {
		o.ClientSecret = open(o.ClientSecret, "oidc_settings.client_secret", s.OrgID)
	}
	if l := s.LDAP; l != nil {
		l.BindPassword = open(l.BindPassword, "ldap_settings.bind_password", s.OrgID)
	}
	for i, r := range s.AlertRules {
		if r.BuiltinKey != nil {
			s.AlertRules[i].ID, s.AlertRules[i].CreatedAt = "", time.Time{}
		}
	}
	s.LicenseClock = nil
}

// Копия формата версии 1 (снята выпуском до задачи 5.8,
// testdata/config-v1.aisec-backup) восстанавливается: настроек этапов 3 и 4
// в ней нет — строка в отчёте; ключ, закреплённый за агентом, —
// отозванным (4В38), формат — в записи аудита.
func TestBackupRestoreVersion1OnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	dst := newInstallation(t, admin, base, "cli_backup_dst_v1")
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join("testdata", "config-v1.aisec-backup")
	var out, errb bytes.Buffer
	if err := backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase, "-accept-old-copy"},
		dst.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("restore: %v %s", err, errb.String())
	}
	if !strings.Contains(out.String(), "Копия формата версии 1") {
		t.Fatalf("вывод без строки о версии 1: %s", out.String())
	}
	if n := dst.count(t, "SELECT count(*) FROM users"); n != 2 {
		t.Fatalf("пользователей: %d", n)
	}
	const agentKey = "0192a000-0000-7000-8000-000000000303"
	if n := dst.count(t, `SELECT count(*) FROM app_keys WHERE id = $1 AND agent_id IS NULL AND revoked_by = 'backup_restore'`,
		agentKey); n != 1 {
		t.Fatal("ключ агента из копии версии 1 не отозван")
	}
	if n := dst.count(t, "SELECT count(*) FROM agents"); n != 0 {
		t.Fatal("агенты в копии версии 1")
	}
	if n := dst.count(t, `SELECT count(*) FROM install_settings WHERE alert_retention_days = 365 AND quota_mode = 'local'
		AND timezone = 'Asia/Yekaterinburg'`); n != 1 {
		t.Fatal("поля версии 2 настроек установки изменены копией версии 1")
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND details->>'format_version' = '1'
		AND details->>'stage' IN ('started', 'done')`); n != 2 {
		t.Fatalf("версия формата в записях аудита: %d", n)
	}
}
