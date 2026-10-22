package alerting_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Правила безопасности и системные правила на PostgreSQL: точка вызова в
// транзакции записи аудита, счёт по журналу в окне, DM-38 в транзакции
// приёма; сбой правил откатывает запись аудита вместе с действием.
func TestPGSecurityRulesOnAudit(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.log.SetRecordHook(e.alerts.OnAudit)
	ip := netip.MustParseAddr("192.0.2.10")
	anon := audit.Actor{Type: audit.ActorUser, ID: "unknown", Name: "unknown"}
	for range alerting.ConsoleFailThreshold {
		if err := e.log.Record(ctx, audit.Entry{Actor: anon, SourceIP: ip, Action: "auth.login_failed", Result: audit.ResultFailure,
			Details: map[string]any{"reason": "unknown_login"}}); err != nil {
			t.Fatal(err)
		}
	}
	brute := e.list(t, alerting.BuiltinConsoleBrute)
	if len(brute) != 1 || brute[0].Count != alerting.ConsoleFailThreshold || brute[0].Values["source_ip"] != "192.0.2.10" {
		t.Fatalf("перебор: %+v", brute)
	}
	user := audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000c1", Name: "petrov"}
	for _, act := range []string{"policy.update", "provider.external_changed"} {
		if err := e.log.Record(ctx, audit.Entry{Actor: user, Action: act, Object: audit.Object{Type: "x", ID: "1"},
			Result: audit.ResultSuccess, Details: map[string]any{"weakening": true}}); err != nil {
			t.Fatal(err)
		}
	}
	weak := e.list(t, alerting.BuiltinWeakening)
	if len(weak) != 1 || weak[0].Count != 2 || weak[0].Severity != "high" {
		t.Fatalf("ослабление: %+v", weak)
	}
	if err := e.log.Record(ctx, audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, ID: "system-status"}, Action: "system.alert",
		Object: audit.Object{Type: "system", ID: "integrity:server"}, Result: audit.ResultFailure,
		Details: map[string]any{"condition": "integrity:server", "state": "raised", "requirement": "ОЦЛ.5", "component": "server"}}); err != nil {
		t.Fatal(err)
	}
	if got := e.list(t, alerting.BuiltinIntegrity); len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("целостность: %+v", got)
	}
	// Сбой правил: запись аудита не фиксируется.
	var before int
	if err := e.app.QueryRow(ctx, "SELECT count(*) FROM audit_log").Scan(&before); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("сбой правил")
	e.log.SetRecordHook(func(context.Context, pgx.Tx, *audit.Record) error { return boom })
	if err := e.log.Record(ctx, audit.Entry{Actor: user, Action: "auth.mfa_reset", Result: audit.ResultSuccess}); !errors.Is(err, boom) {
		t.Fatalf("ошибка правил не дошла: %v", err)
	}
	var after int
	if err := e.app.QueryRow(ctx, "SELECT count(*) FROM audit_log").Scan(&after); err != nil || after != before {
		t.Fatalf("запись зафиксирована при сбое правил: %d → %d %v", before, after, err)
	}
	e.log.SetRecordHook(nil)

	// DM-38 при приёме: отозванный ключ.
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	e.ingest(t, events.Event{ID: u.String(), Time: u.Time(), Type: events.TypeAuthFailure, Threats: []string{"DM-38"},
		AuthFailure: &events.AuthFailure{RemoteAddr: "198.51.100.7", KeyPrefix: "ak_test_cccc", Reason: auth.ReasonRevoked}})
	if got := e.list(t, alerting.BuiltinGatewayAuth); len(got) != 1 || got[0].Values["key_prefix"] != "ak_test_cccc" {
		t.Fatalf("DM-38: %+v", got)
	}
}

// Срок хранения на PostgreSQL: закрытое оповещение старше срока удаляется
// вместе с историей и ссылками, открытое — никогда; удаление раньше срока
// отклоняют триггеры даже прямым запросом роли сервера; сокращение срока
// пишется в аудит.
func TestPGAlertRetention(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.owner.Exec(ctx, `INSERT INTO install_settings (org_id, timezone, retention_mode, updated_at)
		VALUES ($1, 'Europe/Moscow', 'masked', now())`, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	svc, err := alerting.New(alerting.Options{Store: e.alerts, Provider: providerPG(t), Retention: e.alerts})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := svc.Retention(ctx); err != nil || got.RetentionDays != alerting.DefaultRetentionDays {
		t.Fatalf("срок по умолчанию: %+v %v", got, err)
	}
	e.ingest(t, e.event(t, "crm-bot", "gigachat", "block", "DM-01"), e.event(t, "hr-bot", "gigachat", "block", "DM-01"))
	list := e.list(t, alerting.BuiltinInjectionBlocked)
	if len(list) != 2 {
		t.Fatalf("оповещения: %+v", list)
	}
	closed, open := list[0], list[1]
	if _, err := e.svc.SetStatus(ctx, e.by, closed.ID, alerting.StatusClosed, "разобрано"); err != nil {
		t.Fatal(err)
	}
	// Раньше срока роль сервера удалить не может.
	_, err = e.app.Exec(ctx, "DELETE FROM alert_history WHERE alert_id = $1", closed.ID)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "42501" {
		t.Fatalf("удаление раньше срока: %v", err)
	}
	if n, err := e.alerts.PurgeExpired(ctx); err != nil || n != 0 {
		t.Fatalf("очистка раньше срока: %d %v", n, err)
	}
	// Закрыто 400 суток назад; открытое — тоже старое, но не удаляется.
	if _, err := e.owner.Exec(ctx, `ALTER TABLE alerts DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `UPDATE alerts SET closed_at = now() - interval '400 days', created_at = now() - interval '401 days'
		WHERE id = $1`, closed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `UPDATE alerts SET created_at = now() - interval '900 days' WHERE id = $1`, open.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `ALTER TABLE alerts ENABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if n, err := e.alerts.PurgeExpired(ctx); err != nil || n != 1 {
		t.Fatalf("очистка: %d %v", n, err)
	}
	if _, err := e.svc.Alert(ctx, closed.ID); !errors.Is(err, alerting.ErrNotFound) {
		t.Fatalf("закрытое не удалено: %v", err)
	}
	if _, err := e.svc.Alert(ctx, open.ID); err != nil {
		t.Fatalf("открытое удалено: %v", err)
	}
	var recs int
	if err := e.app.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'alert.retention'`).Scan(&recs); err != nil || recs != 1 {
		t.Fatalf("запись alert.retention: %d %v", recs, err)
	}
	// Сокращение срока — с проверкой и записью в аудит.
	if _, err := svc.SetRetention(ctx, e.by, 120); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.Retention(ctx); err != nil || got.RetentionDays != 120 {
		t.Fatalf("срок: %+v %v", got, err)
	}
	var weak bool
	if err := e.app.QueryRow(ctx, `SELECT (details::jsonb ->> 'weakening')::boolean FROM audit_log
		WHERE action = 'alert.settings_changed'`).Scan(&weak); err != nil || !weak {
		t.Fatalf("аудит сокращения: %v %v", weak, err)
	}
	// Ограничение столбца: меньше 90 суток не сохраняется даже напрямую.
	if _, err := e.app.Exec(ctx, `UPDATE install_settings SET alert_retention_days = 30`); err == nil {
		t.Fatal("срок 30 суток принят")
	}
}

func providerPG(t *testing.T) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
