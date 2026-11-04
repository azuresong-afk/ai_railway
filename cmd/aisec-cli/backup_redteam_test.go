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
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Синтетические ID тестирования устойчивости.
const (
	rtProvider   = "0192a000-0000-7000-8000-000000000d01"
	rtEndpoint   = "0192a000-0000-7000-8000-000000000d11"
	rtSecretTgt  = "0192a000-0000-7000-8000-000000000d12"
	rtGatewayTgt = "0192a000-0000-7000-8000-000000000d13"
	rtSchedule   = "0192a000-0000-7000-8000-000000000d21"
	rtLimits     = `{"rate_per_minute": 30, "concurrency": 2, "request_timeout_sec": 30, "run_timeout_min": 30}`
)

// insertRedTeam добавляет провайдер «у заказчика» (оценщик judge.llm), три
// цели (endpoint без секрета, endpoint с секретным заголовком, gateway на
// приложение populate) и расписание первой цели — в обход API, как их
// записал бы сервер.
func insertRedTeam(t *testing.T, in *installation) {
	t.Helper()
	org := audit.DefaultOrgID
	in.exec(t, `INSERT INTO providers (id, org_id, slug, name, type, base_url, ca_pem, external, on_premise, created_at, created_by,
		updated_at, updated_by) VALUES ($1, $2, 'local-llm', 'Синтетическая модель заказчика', 'openai', 'https://10.0.0.20:8443', 'PEM',
		false, true, now(), 'user:x', now(), 'user:x')`, rtProvider, org)
	insert := func(id, name, kind string, appID any, model, url, auth, judge string) {
		tmpl, path, note, storage, headers := "", "", "", "", "[]"
		if kind == "endpoint" {
			tmpl, path = `{"model":"m","messages":"{{messages}}"}`, "choices.0.message.content"
			note, storage, headers = "Договор о пилоте № 17 от 01.11.2026", "masked", `[{"name":"X-Tenant","value":"crm-prod-01"}]`
		}
		jm := ""
		if judge != "" {
			jm = "llama-local"
		}
		in.exec(t, `INSERT INTO redteam_targets (id, org_id, name, kind, app_id, model, url, request_template, response_path, headers,
			auth_header, ca_pem, authorization_note, storage, judge_provider, judge_model, limits, created_at, created_by, updated_at,
			updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, '', $12, $13, $14, $15, $16, now(), 'user:x', now(), 'user:x')`,
			id, org, name, kind, appID, model, url, tmpl, path, headers, auth, note, storage, judge, jm, rtLimits)
	}
	insert(rtEndpoint, "Бот поддержки", "endpoint", nil, "", "http://bot.example.test:8080/v1/chat/completions", "", "local-llm")
	insert(rtSecretTgt, "Бот с ключом", "endpoint", nil, "", "http://bot2.example.test:8080/v1/chat/completions", "X-Api-Key", "")
	insert(rtGatewayTgt, "Бот через шлюз", "gateway", tApp, "gpt-x", "", "", "")
	in.exec(t, `INSERT INTO redteam_schedules (id, org_id, name, target_id, frequency, weekday, day, at_time, threats, lang, enabled,
		next_run_at, last_status, retries, version, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'Ночной прогон', $3, 'weekly', 2, 0, '03:00', '["DM-01","DM-08"]', 'ru', true, now() + interval '1 day',
		'started', 0, 3, now(), 'user:x', now(), 'user:x')`, rtSchedule, org, rtEndpoint)
}

// G3 этапа 5: цели и расписания тестирования устойчивости и признак «у
// заказчика» провайдера в копии конфигурации. Пустая установка — всё как в
// копии, итог последней попытки расписания не переносится; значения
// секретного заголовка в копии нет (он не хранится и в установке).
// Непустая — объекты добавляются; ID цели в установке — совпадение,
// отказ. Цель и расписание, которые API не принял бы, останавливают
// восстановление до записи.
func TestBackupRedTeamOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	src := newInstallation(t, admin, base, "cli_backup_src_rt")
	populate(t, src)
	insertRedTeam(t, src)

	dir := t.TempDir()
	phrase := writePhraseFile(t, testBackupPhrase, 0o400)
	file := filepath.Join(dir, "config.aisec-backup")
	var out, errb bytes.Buffer
	create := func(path string) {
		t.Helper()
		if err := backupCmd([]string{"create", "-keys", src.keys, "-out", path, "-passphrase-file", phrase, "-no-user-hmac-key"},
			src.dsn, &out, &errb, time.Now()); err != nil {
			t.Fatalf("create: %v %s", err, errb.String())
		}
	}
	create(file)

	// Пустая установка.
	dst := newInstallation(t, admin, base, "cli_backup_dst_rt")
	out.Reset()
	if err := backupCmd([]string{"restore", "-keys", dst.keys, "-in", file, "-passphrase-file", phrase}, dst.dsn, &out, &errb,
		time.Now()); err != nil {
		t.Fatalf("restore: %v %s", err, errb.String())
	}
	if want := "Тестирование устойчивости: целей перенесено 3, расписаний 1"; !strings.Contains(out.String(), want) {
		t.Errorf("в выводе нет %q: %s", want, out.String())
	}
	if n := dst.count(t, "SELECT count(*) FROM providers WHERE id = $1 AND on_premise AND NOT external", rtProvider); n != 1 {
		t.Fatal("признак «у заказчика» провайдера не восстановлен")
	}
	if n := dst.count(t, `SELECT count(*) FROM redteam_targets WHERE (id = $1 AND judge_provider = 'local-llm' AND storage = 'masked'
		AND headers = '[{"name":"X-Tenant","value":"crm-prod-01"}]' AND limits->>'rate_per_minute' = '30')
		OR (id = $2 AND auth_header = 'X-Api-Key') OR (id = $3 AND app_id = $4 AND model = 'gpt-x')`,
		rtEndpoint, rtSecretTgt, rtGatewayTgt, tApp); n != 3 {
		t.Fatalf("цели: %d", n)
	}
	if n := dst.count(t, `SELECT count(*) FROM redteam_schedules WHERE id = $1 AND target_id = $2 AND frequency = 'weekly'
		AND weekday = 2 AND threats = '["DM-01","DM-08"]' AND version = 3 AND last_status = '' AND last_run_id IS NULL`,
		rtSchedule, rtEndpoint); n != 1 {
		t.Fatal("расписание не восстановлено как в копии")
	}
	if n := dst.count(t, `SELECT count(*) FROM audit_log WHERE action = 'backup.restore' AND details->>'stage' = 'done'
		AND details->>'redteam_report' LIKE 'целей перенесено 3%'`); n != 1 {
		t.Fatal("отчёт о тестировании устойчивости не записан в аудит")
	}

	// Непустая установка со своей целью: объекты копии добавляются.
	ne := newInstallation(t, admin, base, "cli_backup_ne_rt")
	ne.exec(t, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by) VALUES ('0192a000-0000-7000-8000-00000000aab1', $1, 'first.admin',
		'Синтетический первый', 'security_admin', 'active', 'x', now(), false, now(), 'setup')`, audit.DefaultOrgID)
	ne.exec(t, `INSERT INTO redteam_targets (id, org_id, name, kind, model, url, request_template, response_path, headers, auth_header,
		ca_pem, authorization_note, storage, judge_provider, judge_model, limits, created_at, created_by, updated_at, updated_by)
		VALUES ('0192a000-0000-7000-8000-000000000d91', $1, 'Своя цель', 'endpoint', '', 'http://own.example.test:8080/', '{"q":"{{prompt}}"}',
		'a', '[]', '', '', 'Письмо владельца адреса', 'none', '', '', $2, now(), 'user:x', now(), 'user:x')`, audit.DefaultOrgID, rtLimits)
	if err := backupCmd([]string{"restore", "-keys", ne.keys, "-in", file, "-passphrase-file", phrase, "-allow-nonempty"},
		ne.dsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("restore в непустую: %v %s", err, errb.String())
	}
	if n := ne.count(t, "SELECT count(*) FROM redteam_targets"); n != 4 {
		t.Fatalf("целей в непустой установке: %d", n)
	}

	// Совпадение: цель с ID из копии уже есть.
	cf := newInstallation(t, admin, base, "cli_backup_cf_rt")
	cf.exec(t, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by) VALUES ('0192a000-0000-7000-8000-00000000aab2', $1, 'first.admin',
		'Синтетический первый', 'security_admin', 'active', 'x', now(), false, now(), 'setup')`, audit.DefaultOrgID)
	cf.exec(t, `INSERT INTO redteam_targets (id, org_id, name, kind, model, url, request_template, response_path, headers, auth_header,
		ca_pem, authorization_note, storage, judge_provider, judge_model, limits, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, 'Чужая цель', 'endpoint', '', 'http://own.example.test:8080/', '{"q":"{{prompt}}"}', 'a', '[]', '', '',
		'Письмо владельца адреса', 'none', '', '', $3, now(), 'user:x', now(), 'user:x')`, rtEndpoint, audit.DefaultOrgID, rtLimits)
	err = backupCmd([]string{"restore", "-keys", cf.keys, "-in", file, "-passphrase-file", phrase, "-allow-nonempty"},
		cf.dsn, &out, &errb, time.Now())
	if err == nil || !strings.Contains(err.Error(), "цель тестирования устойчивости Чужая цель") {
		t.Fatalf("совпадение цели: %v", err)
	}
	if n := cf.count(t, "SELECT count(*) FROM redteam_targets"); n != 1 {
		t.Fatalf("после отказа целей: %d", n)
	}

	// Неверные объекты — проверками API до записи: секретный заголовок в
	// постоянных заголовках (5Н21), расписание цели с секретным
	// заголовком, оценщик без признака «у заказчика».
	bad := map[string]string{
		"секрет в заголовке":         `UPDATE redteam_targets SET headers = '[{"name":"Authorization","value":"x"}]' WHERE id = '` + rtEndpoint + `'`,
		"расписание цели с секретом": `UPDATE redteam_schedules SET target_id = '` + rtSecretTgt + `'`,
		"оценщик не у заказчика":     `UPDATE redteam_targets SET judge_provider = 'mock-llm' WHERE id = '` + rtEndpoint + `'`,
	}
	undo := map[string]string{
		"секрет в заголовке":         `UPDATE redteam_targets SET headers = '[]' WHERE id = '` + rtEndpoint + `'`,
		"расписание цели с секретом": `UPDATE redteam_schedules SET target_id = '` + rtEndpoint + `'`,
		"оценщик не у заказчика":     `UPDATE redteam_targets SET judge_provider = 'local-llm' WHERE id = '` + rtEndpoint + `'`,
	}
	for name, q := range bad {
		src.exec(t, q)
		path := filepath.Join(dir, "bad.aisec-backup")
		_ = os.Remove(path) //nolint:gosec // G104: файл прошлой итерации может отсутствовать
		create(path)
		src.exec(t, undo[name])
		chk := newInstallation(t, admin, base, "cli_backup_chk_rt")
		err := backupCmd([]string{"restore", "-keys", chk.keys, "-in", path, "-passphrase-file", phrase}, chk.dsn, &out, &errb, time.Now())
		if err == nil || !strings.Contains(err.Error(), "тестирования устойчивости") {
			t.Errorf("%s: %v", name, err)
		}
		if n := chk.count(t, "SELECT count(*) FROM redteam_targets"); n != 0 {
			t.Errorf("%s: после отказа целей %d", name, n)
		}
	}
}
