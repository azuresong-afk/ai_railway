package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// rec — синтетическая запись журнала аудита в момент часов теста.
func (e *env) rec(t *testing.T, actor audit.Actor, ip, action string, obj audit.Object, res audit.Result, details any) audit.Record {
	t.Helper()
	raw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	if details == nil {
		raw = []byte("{}")
	}
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	var addr netip.Addr
	if ip != "" {
		addr = netip.MustParseAddr(ip)
	}
	return audit.Record{ID: u.String(), OrgID: audit.DefaultOrgID, TS: e.clock.t, Actor: actor, SourceIP: addr,
		Action: action, Object: obj, Result: res, Details: raw}
}

func (e *env) audit(t *testing.T, r audit.Record) {
	t.Helper()
	if err := e.mem.Audit(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func (e *env) tick(d time.Duration) { e.clock.t = e.clock.t.Add(d) }

var (
	tUser    = audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000c1", Name: "petrov"}
	tOther   = audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000c2", Name: "ivanova"}
	tUnknown = audit.Actor{Type: audit.ActorUser, ID: "unknown", Name: "unknown"}
	tGateway = audit.Actor{Type: audit.ActorGateway, ID: testGateway, Name: "gw-1"}
)

// Встроенные правила 3.11 — системные или безопасности: не отключаются,
// у них меняются только получатели (ТЗ 5.6).
func TestSecurityRulesLocked(t *testing.T) {
	e := newEnv(t)
	for _, key := range []string{BuiltinGatewayAuth, BuiltinConsoleBrute, BuiltinAccessDenied, BuiltinWeakening, BuiltinContentAccess,
		BuiltinIntegrity, BuiltinAuditChain, BuiltinEventsDropped, BuiltinGatewayOffline, BuiltinTimeSync, BuiltinAuditStorage,
		BuiltinCertExpiry, BuiltinReportsStale, BuiltinConfigBundle, BuiltinNotifyFailed} {
		r := e.rule(t, key)
		if !Locked(r.Kind) || !r.Enabled || r.Severity == "" {
			t.Fatalf("%s: %+v", key, r)
		}
		off := false
		_, err := e.svc.UpdateRule(context.Background(), e.admin, r.ID, RuleInput{Enabled: &off, Version: r.Version,
			Recipients: Recipients{Roles: []string{}, Users: []string{}}})
		if err != ErrLocked {
			t.Fatalf("%s: отключение: %v", key, err)
		}
	}
}

// DM-38 (оповещение, этап 3): адрес, заблокированный ограничителем шлюза
// после серии неудач, и запрос с отозванным ключом дают оповещение;
// одиночный неверный ключ — нет. Ключ в оповещении — только префикс.
func TestDM38_KeyBruteForceAlert(t *testing.T) {
	e := newEnv(t)
	fail := func(addr, prefix, reason string) *events.Event {
		u, err := e.ids.New()
		if err != nil {
			t.Fatal(err)
		}
		return &events.Event{ID: u.String(), Time: e.clock.t, Type: events.TypeAuthFailure, Threats: []string{"DM-38"},
			AuthFailure: &events.AuthFailure{RemoteAddr: addr, KeyPrefix: prefix, Reason: reason}}
	}
	e.ingest(t, fail("203.0.113.5", "ak_test_aaaa", auth.ReasonInvalid), fail("203.0.113.5", "", auth.ReasonMalformed),
		fail("203.0.113.6", "ak_test_bbbb", auth.ReasonExpired))
	if got := e.alerts(t, BuiltinGatewayAuth); len(got) != 0 {
		t.Fatalf("оповещение без серии: %+v", got)
	}
	e.ingest(t, fail("203.0.113.5", "ak_test_aaaa", auth.ReasonInvalid), fail("203.0.113.5", "", auth.ReasonRateLimited),
		fail("198.51.100.7", "ak_test_cccc", auth.ReasonRevoked), fail("198.51.100.8", "ak_test_cccc", auth.ReasonRevoked))
	got := e.alerts(t, BuiltinGatewayAuth)
	if len(got) != 2 {
		t.Fatalf("оповещений %d, ожидалось 2 (адрес и ключ): %+v", len(got), got)
	}
	by := map[string]Alert{}
	for _, a := range got {
		by[a.Title] = a
	}
	brute, revoked := by["Перебор или отозванный ключ на шлюзе — 203.0.113.5"], by["Перебор или отозванный ключ на шлюзе — ak_test_cccc"]
	if brute.Count != 1 || brute.Severity != "high" || brute.Kind != KindSecurity || revoked.Count != 2 {
		t.Fatalf("оповещения: %+v", by)
	}
	card, err := e.svc.Alert(context.Background(), revoked.ID)
	if err != nil || len(card.Events) != 2 {
		t.Fatalf("ссылки на события: %+v %v", card, err)
	}
	// Повтор с тем же ключом дополняет открытое оповещение.
	e.ingest(t, fail("198.51.100.9", "ak_test_cccc", auth.ReasonRevoked))
	if got := e.alerts(t, BuiltinGatewayAuth); len(got) != 2 {
		t.Fatalf("дедупликация: %+v", got)
	}
}

// DM-39 (оповещение, этап 3), ИАФ.4: блокировка учётной записи даёт
// оповещение сразу; перебор по многим записям с одного адреса — при
// достижении порога за окно; ниже порога и вне окна — без оповещения.
func TestDM39_ConsoleBruteForceAlert(t *testing.T) {
	e := newEnv(t)
	for i := range ConsoleFailThreshold - 1 {
		e.audit(t, e.rec(t, tUnknown, "192.0.2.10", "auth.login_failed", audit.Object{}, audit.ResultFailure,
			map[string]any{"reason": "unknown_login", "n": i}))
	}
	if got := e.alerts(t, BuiltinConsoleBrute); len(got) != 0 {
		t.Fatalf("оповещение ниже порога: %+v", got)
	}
	// Неудачи с другого адреса в счёт не идут.
	e.audit(t, e.rec(t, tUnknown, "192.0.2.11", "auth.login_failed", audit.Object{}, audit.ResultFailure, nil))
	if got := e.alerts(t, BuiltinConsoleBrute); len(got) != 0 {
		t.Fatalf("чужой адрес в счёте: %+v", got)
	}
	e.audit(t, e.rec(t, tUnknown, "192.0.2.10", "auth.mfa_failed", audit.Object{}, audit.ResultFailure, nil))
	got := e.alerts(t, BuiltinConsoleBrute)
	if len(got) != 1 || got[0].Count != ConsoleFailThreshold || got[0].Values["source_ip"] != "192.0.2.10" ||
		got[0].Title != "Перебор паролей к консоли — 192.0.2.10" {
		t.Fatalf("перебор с адреса: %+v", got)
	}
	e.audit(t, e.rec(t, tUnknown, "192.0.2.10", "api_token.auth_failed", audit.Object{}, audit.ResultFailure, nil))
	if got := e.alerts(t, BuiltinConsoleBrute); len(got) != 1 || got[0].Count != ConsoleFailThreshold+1 {
		t.Fatalf("дополнение открытого: %+v", got)
	}
	// Вне окна счёт начинается заново.
	e.tick(ConsoleFailWindow + time.Minute)
	e.audit(t, e.rec(t, tUnknown, "192.0.2.12", "auth.login_failed", audit.Object{}, audit.ResultFailure, nil))
	// Блокировка учётной записи — сразу.
	e.audit(t, e.rec(t, tUser, "192.0.2.12", "auth.locked", audit.Object{Type: "user", ID: tUser.ID}, audit.ResultSuccess,
		map[string]any{"attempts": 5}))
	got = e.alerts(t, BuiltinConsoleBrute)
	if len(got) != 2 || got[0].Values["account"] != "petrov" || got[0].Severity != "high" {
		t.Fatalf("блокировка: %+v", got)
	}
	// УПД.6: серия отказов в доступе одному субъекту.
	for range DeniedThreshold {
		e.audit(t, e.rec(t, tOther, "192.0.2.20", "access.denied", audit.Object{}, audit.ResultDenied,
			map[string]any{"path": "/api/v1/users", "permission": "users.manage"}))
	}
	e.audit(t, e.rec(t, tUser, "192.0.2.21", "access.denied", audit.Object{}, audit.ResultDenied, nil))
	denied := e.alerts(t, BuiltinAccessDenied)
	if len(denied) != 1 || denied[0].Values["actor"] != "ivanova" || denied[0].Count != DeniedThreshold {
		t.Fatalf("отказы в доступе: %+v", denied)
	}
}

// DM-40 (этап 3): ослабление защиты — оповещение высокой серьёзности;
// изменения одного пользователя за 10 минут объединяются в одно со списком
// изменений, после окна — новое; у другого пользователя — своё.
func TestDM40_WeakeningAlertGrouped(t *testing.T) {
	e := newEnv(t)
	app := audit.Object{Type: "application", ID: "crm-bot"}
	e.audit(t, e.rec(t, tUser, "192.0.2.1", "application.protection_changed", app, audit.ResultSuccess,
		map[string]any{"weakening": false}))
	if got := e.alerts(t, BuiltinWeakening); len(got) != 0 {
		t.Fatalf("оповещение без ослабления: %+v", got)
	}
	e.audit(t, e.rec(t, tUser, "192.0.2.1", "application.protection_changed", app, audit.ResultSuccess,
		map[string]any{"weakening": true}))
	e.tick(3 * time.Minute)
	e.audit(t, e.rec(t, tUser, "192.0.2.1", "policy.update", audit.Object{Type: "policy", ID: "org-default"}, audit.ResultSuccess,
		map[string]any{"weakening": true, "weakening_reasons": []string{"mode_monitor"}}))
	e.audit(t, e.rec(t, tUser, "192.0.2.1", "auth.mfa_reset", audit.Object{Type: "user", ID: tOther.ID}, audit.ResultSuccess, nil))
	e.audit(t, e.rec(t, tUser, "192.0.2.1", "events.settings_changed", audit.Object{Type: "event_settings"}, audit.ResultSuccess,
		map[string]any{"reduced": true}))
	e.audit(t, e.rec(t, tUser, "192.0.2.1", "audit.settings_changed", audit.Object{Type: "audit_settings"}, audit.ResultSuccess,
		map[string]any{"before": map[string]any{"retention_days": 365, "disabled_actions": []string{}},
			"after": map[string]any{"retention_days": 365, "disabled_actions": []string{"events.list"}}}))
	got := e.alerts(t, BuiltinWeakening)
	if len(got) != 1 {
		t.Fatalf("оповещений %d, ожидалось одно сгруппированное: %+v", len(got), got)
	}
	a := got[0]
	items, _ := a.Details["items"].([]any)
	if a.Count != 5 || len(items) != 5 || a.Severity != "high" || a.Values["actor"] != "petrov" {
		t.Fatalf("группа: %+v", a)
	}
	if it, _ := items[1].(map[string]any); it["action"] != "policy.update" || fmt.Sprint(it["reasons"]) != "[mode_monitor]" {
		t.Fatalf("элемент списка: %+v", items[1])
	}
	// Другой пользователь — своё оповещение.
	e.audit(t, e.rec(t, tOther, "192.0.2.2", "provider.external_changed", audit.Object{Type: "provider", ID: "gc"},
		audit.ResultSuccess, map[string]any{"weakening": true}))
	// После окна группировки — новое оповещение того же пользователя.
	e.tick(WeakeningGroupMinutes * time.Minute)
	e.audit(t, e.rec(t, tUser, "192.0.2.1", "alert_rule.update", audit.Object{Type: "alert_rule", ID: "r1"}, audit.ResultSuccess,
		map[string]any{"weakening": true, "weakening_reasons": []string{"disabled"}}))
	if got := e.alerts(t, BuiltinWeakening); len(got) != 3 {
		t.Fatalf("после окна и другой пользователь: %+v", got)
	}
	// Отказ и неуспех ослаблением не считаются.
	e.audit(t, e.rec(t, tUser, "192.0.2.1", "auth.mfa_reset", audit.Object{}, audit.ResultDenied, nil))
	if got := e.alerts(t, BuiltinWeakening); len(got) != 3 || got[0].Count != 1 {
		t.Fatalf("отказ посчитан: %+v", got)
	}
}

// DM-41 (этап 3): массовый просмотр содержимого одним субъектом за окно и
// крупная выгрузка дают оповещение; единичный просмотр — нет.
func TestDM41_MassContentViewAlert(t *testing.T) {
	e := newEnv(t)
	for i := range ContentReadThreshold - 1 {
		e.audit(t, e.rec(t, tUser, "192.0.2.1", "events.content_read", audit.Object{Type: "event", ID: fmt.Sprint(i)},
			audit.ResultSuccess, map[string]any{"reason": "разбор инцидента"}))
		e.audit(t, e.rec(t, tOther, "192.0.2.2", "events.content_read", audit.Object{Type: "event", ID: fmt.Sprint(i)},
			audit.ResultSuccess, nil))
	}
	if got := e.alerts(t, BuiltinContentAccess); len(got) != 0 {
		t.Fatalf("ниже порога: %+v", got)
	}
	e.audit(t, e.rec(t, tUser, "192.0.2.1", "events.content_read", audit.Object{Type: "event", ID: "x"}, audit.ResultSuccess, nil))
	got := e.alerts(t, BuiltinContentAccess)
	if len(got) != 1 || got[0].Values["actor"] != "petrov" || got[0].Count != ContentReadThreshold {
		t.Fatalf("массовый просмотр: %+v", got)
	}
	// Небольшая выгрузка — нет, крупная — да (оповещение другого субъекта).
	e.audit(t, e.rec(t, tOther, "192.0.2.2", "data.export", audit.Object{Type: "events"}, audit.ResultSuccess,
		map[string]any{"rows": 120, "format": "csv"}))
	if got := e.alerts(t, BuiltinContentAccess); len(got) != 1 {
		t.Fatalf("малая выгрузка: %+v", got)
	}
	e.audit(t, e.rec(t, tOther, "192.0.2.2", "data.export", audit.Object{Type: "events"}, audit.ResultSuccess,
		map[string]any{"rows": LargeExportRows, "format": "json"}))
	got = e.alerts(t, BuiltinContentAccess)
	if len(got) != 2 || got[0].Values["actor"] != "ivanova" {
		t.Fatalf("крупная выгрузка: %+v", got)
	}
	// Серия выгрузок за час.
	for range ExportThreshold {
		e.audit(t, e.rec(t, tUnknown, "192.0.2.3", "data.export", audit.Object{Type: "events"}, audit.ResultSuccess,
			map[string]any{"rows": 10}))
	}
	if got := e.alerts(t, BuiltinContentAccess); len(got) != 3 {
		t.Fatalf("серия выгрузок: %+v", got)
	}
}

// systemAlert — запись system.alert о смене состояния условия.
func (e *env) systemAlert(t *testing.T, code, state string, extra map[string]any) {
	t.Helper()
	d := map[string]any{"condition": code, "state": state}
	for k, v := range extra {
		d[k] = v
	}
	res := audit.ResultSuccess
	if state == "raised" {
		res = audit.ResultFailure
	}
	e.audit(t, e.rec(t, audit.Actor{Type: audit.ActorSystem, ID: "system-status"}, "", "system.alert",
		audit.Object{Type: "system", ID: code}, res, d))
}

// DM-42 (оповещение, этап 3), ОЦЛ.5: нарушение целостности сервера или
// шлюза и отклонённый шлюзом пакет дают критическое оповещение по
// компоненту; снятие условия оповещение не закрывает.
func TestDM42_IntegrityAlert(t *testing.T) {
	e := newEnv(t)
	e.systemAlert(t, "integrity:server", "raised", map[string]any{"requirement": "ОЦЛ.5", "component": "server",
		"issues": []any{map[string]any{"component": "aisec-server", "source": "integrity", "reason": "files_mismatch"}}})
	e.systemAlert(t, "integrity:gateway:"+testGateway, "raised", map[string]any{"requirement": "ОЦЛ.5",
		"component": "gateway:" + testGateway, "gateway_name": "gw-1"})
	e.systemAlert(t, "integrity:server", "cleared", nil)
	got := e.alerts(t, BuiltinIntegrity)
	if len(got) != 2 {
		t.Fatalf("оповещений %d: %+v", len(got), got)
	}
	for _, a := range got {
		if a.Severity != "critical" || a.Kind != KindSystem || a.Status != StatusNew {
			t.Fatalf("оповещение: %+v", a)
		}
	}
	e.audit(t, e.rec(t, tGateway, "", "bundle.rejected", audit.Object{Type: "bundle", ID: "17"}, audit.ResultFailure,
		map[string]any{"reason": "signature_invalid"}))
	got = e.alerts(t, BuiltinIntegrity)
	if len(got) != 3 || got[0].Values["component"] != "gateway:"+testGateway {
		t.Fatalf("отклонённый пакет: %+v", got)
	}
}

// DM-43 (оповещение, этап 3), РСБ.4: нарушение цепочки журнала аудита —
// запись audit.chain_broken проверки и условие audit_chain состояния
// системы — одно критическое оповещение.
func TestDM43_ChainBrokenAlert(t *testing.T) {
	e := newEnv(t)
	e.audit(t, e.rec(t, audit.Actor{Type: audit.ActorSystem, ID: "aisec-server"}, "", "audit.chain_verified",
		audit.Object{Type: "audit_log"}, audit.ResultSuccess, map[string]any{"checked": 10}))
	if got := e.alerts(t, BuiltinAuditChain); len(got) != 0 {
		t.Fatalf("цела, но оповещение: %+v", got)
	}
	e.audit(t, e.rec(t, audit.Actor{Type: audit.ActorSystem, ID: "aisec-server"}, "", "audit.chain_broken",
		audit.Object{Type: "audit_log"}, audit.ResultFailure, map[string]any{"reason": "rewritten", "broken_seq": 42}))
	e.systemAlert(t, "audit_chain", "raised", map[string]any{"requirement": "РСБ.4", "reason": "rewritten"})
	got := e.alerts(t, BuiltinAuditChain)
	if len(got) != 1 || got[0].Count != 2 || got[0].Severity != "critical" {
		t.Fatalf("цепочка: %+v", got)
	}
}

// DM-44 (этап 3), ВРМ.1, РСБ.5, Н29: условия «ослепления» мониторинга —
// отброшенные события, шлюз недоступен, время, хранилище, сертификат,
// устаревший итог целостности — и недоставленное уведомление дают
// оповещения своих правил; заголовок называет шлюз.
func TestDM44_SystemAlerts(t *testing.T) {
	e := newEnv(t)
	gw := map[string]any{"gateway_name": "gw-1", "component": "gateway:" + testGateway}
	cases := []struct{ code, rule, title string }{
		{"events_dropped:" + testGateway, BuiltinEventsDropped, "Шлюз отбрасывает события — gw-1"},
		{"gateway_offline:" + testGateway, BuiltinGatewayOffline, "Шлюз недоступен — gw-1"},
		{"cert_expiry:" + testGateway, BuiltinCertExpiry, "Скоро истекает сертификат — шлюз gw-1"},
		{"reports_stale:" + testGateway, BuiltinReportsStale, "Нет данных контроля целостности шлюза — gw-1"},
		{"time_sync", BuiltinTimeSync, "Время не синхронизировано"},
		{"audit_storage", BuiltinAuditStorage, "Журнал аудита приближается к пределу хранилища"},
		{"config_bundle_lag:" + testGateway, BuiltinConfigBundle, "Пакет конфигурации шлюзов не применён — gateway:" + testGateway + " (gw-1)"},
	}
	for _, c := range cases {
		e.systemAlert(t, c.code, "cleared", gw)
		if got := e.alerts(t, c.rule); len(got) != 0 {
			t.Fatalf("%s: снятое условие дало оповещение", c.code)
		}
		e.systemAlert(t, c.code, "raised", gw)
		e.systemAlert(t, c.code, "raised", gw)
		got := e.alerts(t, c.rule)
		if len(got) != 1 || got[0].Title != c.title || got[0].Count != 2 || !strings.HasPrefix(c.rule, "system.") {
			t.Fatalf("%s: %+v", c.code, got)
		}
		if got[0].Details["condition"] != c.code {
			t.Fatalf("%s: подробности %+v", c.code, got[0].Details)
		}
	}
	// Корень внутреннего УЦ (условие 3В5): то же правило, отдельное
	// оповещение; условие за 7 суток — ещё одно, чтобы не потерялось в закрытом.
	e.systemAlert(t, "ca_expiry", "raised", nil)
	e.systemAlert(t, "ca_expiry:critical", "raised", nil)
	if got := e.alerts(t, BuiltinCertExpiry); len(got) != 3 || got[0].Title != "Скоро истекает сертификат — корень УЦ" {
		t.Fatalf("корень УЦ: %+v", got)
	}
	// Неизвестное условие оповещения не даёт.
	e.systemAlert(t, "something_new", "raised", nil)
	// Недоставленное уведомление — тоже DM-44.
	e.audit(t, e.rec(t, audit.Actor{Type: audit.ActorSystem, ID: "aisec-server"}, "", "notify.delivery_failed",
		audit.Object{Type: "notify_channel", ID: "ch-1"}, audit.ResultFailure,
		map[string]any{"channel_name": "SOC почта", "error": "dial", "attempts": 5}))
	if got := e.alerts(t, BuiltinNotifyFailed); len(got) != 1 || got[0].Title != "Уведомление не доставлено — SOC почта" {
		t.Fatalf("доставка: %+v", got)
	}
}

// Правило безопасности не создано (сервер не вызвал EnsureBuiltins) —
// запись аудита, порождающая оповещение, отклоняется: действие без
// оповещения не фиксируется.
func TestAuditRuleRequiresBuiltin(t *testing.T) {
	m := NewMemory()
	err := m.Audit(context.Background(), audit.Record{OrgID: audit.DefaultOrgID, TS: time.Now(), Action: "auth.locked",
		Actor: tUser, Object: audit.Object{Type: "user", ID: tUser.ID}, Result: audit.ResultSuccess, Details: []byte("{}")})
	if err != errNoBuiltin {
		t.Fatalf("ожидалась ошибка отсутствия правила: %v", err)
	}
	// Запись, не порождающая оповещений, проходит и без правил.
	if err := m.Audit(context.Background(), audit.Record{OrgID: audit.DefaultOrgID, TS: time.Now(), Action: "events.list",
		Actor: tUser, Result: audit.ResultSuccess, Details: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
}

// memRetention — срок хранения в памяти для тестов сервиса.
type memRetention struct {
	days int
	recs []audit.Entry
}

func (m *memRetention) RetentionDays(context.Context) (int, error) { return m.days, nil }

func (m *memRetention) SetRetentionDays(_ context.Context, days int, fn func(int) (audit.Entry, error)) (int, error) {
	old := m.days
	rec, err := fn(old)
	if err != nil {
		return old, err
	}
	m.days = days
	m.recs = append(m.recs, rec)
	return old, nil
}

func (m *memRetention) PurgeExpired(context.Context) (int, error) { return 0, nil }

// Срок хранения оповещений: пределы, сокращение — только с повторной
// проверкой и признаком weakening (DM-40), увеличение — без неё.
func TestRetentionSettings(t *testing.T) {
	e := newEnv(t)
	st := &memRetention{days: DefaultRetentionDays}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Options{Store: e.mem, Provider: p, Retention: st})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, bad := range []int{0, MinRetentionDays - 1, MaxRetentionDays + 1} {
		if _, err := svc.SetRetention(ctx, e.admin, bad); err == nil {
			t.Fatalf("%d суток приняты", bad)
		}
	}
	noConfirm := e.admin
	noConfirm.Confirm = nil
	if _, err := svc.SetRetention(ctx, noConfirm, 180); err != ErrConfirmRequired {
		t.Fatalf("сокращение без проверки: %v", err)
	}
	if _, err := svc.SetRetention(ctx, noConfirm, 730); err != nil {
		t.Fatalf("увеличение: %v", err)
	}
	if _, err := svc.SetRetention(ctx, e.admin, 90); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Retention(ctx)
	if err != nil || got.RetentionDays != 90 || len(st.recs) != 2 {
		t.Fatalf("срок: %+v %v %d", got, err, len(st.recs))
	}
	d, _ := st.recs[1].Details.(map[string]any)
	if st.recs[1].Action != "alert.settings_changed" || d["weakening"] != true || st.recs[0].Details.(map[string]any)["weakening"] != false {
		t.Fatalf("аудит: %+v", st.recs)
	}
}
