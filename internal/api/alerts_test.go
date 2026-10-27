package api

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Оповещения и правила (задача 3.10 этапа 3) на хранилище Memory: права,
// жизненный цикл, ослабление правил, аудит.

type alertsEnv struct {
	*authEnv
	alerts *alerting.Memory
	ids    *ids.Generator
}

func newAlertsEnv(t *testing.T) *alertsEnv {
	t.Helper()
	e := &alertsEnv{authEnv: &authEnv{mem: authtest.NewMemory(), log: &bytes.Buffer{}, clock: &testClock{t: time.Now()},
		secrets: map[string][]byte{}}, alerts: alerting.NewMemory()}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, u := range []struct {
		id, login string
		role      auth.Role
	}{
		{tAdminID, "admin", auth.RoleSecurityAdmin}, {tSysAdminID, "sysadm", auth.RoleSystemAdmin},
		{tAuditorID, "auditor", auth.RoleAuditor}, {tOwnerID, "owner", auth.RoleAppOwner}, {tAnalystID, "analyst", auth.RoleAnalyst},
	} {
		e.mem.AddUser(auth.User{ID: u.id, OrgID: audit.DefaultOrgID, Login: u.login, DisplayName: u.login, Role: u.role,
			Status: auth.StatusActive, PasswordHash: authtest.HashOf(tPhrase), PasswordChangedAt: now, CreatedAt: now, CreatedBy: "test"})
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	e.ids = ids.NewGenerator(r)
	svc, err := alerting.New(alerting.Options{Store: e.alerts, Provider: p,
		UserCheck: func(ctx context.Context, id string) error {
			_, err := e.mem.UserByID(ctx, audit.DefaultOrgID, id)
			return err
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureBuiltins(context.Background()); err != nil {
		t.Fatal(err)
	}
	h, _, err := New(Options{Hasher: testHasher(t), Logger: slog.New(slog.NewTextHandler(e.log, nil)),
		Auth: testAuth(t, e.mem, auth.WithClock(e.clock.now)), Alerts: svc,
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 100000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e
}

// blocked — синтетическое событие с заблокированной инъекцией (DM-01).
func (e *alertsEnv) blocked(t *testing.T, app string) *events.Event {
	t.Helper()
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	return &events.Event{ID: u.String(), Time: u.Time(), Type: events.TypeGatewayRequest, App: app, User: "a1b2c3",
		Provider: "mock", Model: "mock-echo", PolicyMode: events.ModeEnforce,
		Decision: &events.Decision{Action: "block", Rule: "injection", Severity: "high"}, Threats: []string{"DM-01"}}
}

func (e *alertsEnv) ingest(t *testing.T, evs ...*events.Event) {
	t.Helper()
	if err := e.alerts.Ingest(context.Background(), "01900000-0000-7000-8000-0000000000a1", evs); err != nil {
		t.Fatal(err)
	}
}

func (e *alertsEnv) actions(action string) int {
	n := 0
	for _, r := range e.alerts.Records() {
		if r.Action == action {
			n++
		}
	}
	return n
}

// ТЗ 5.6, УПД.1–3: список и карточка — alerts.read (аналитик, аудитор,
// администратор безопасности); смена статуса — alerts.manage (не у
// аудитора); владелец приложения и администратор системы оповещений не видят.
func TestAlertsViaAPI(t *testing.T) {
	e := newAlertsEnv(t)
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	sys := e.mustLogin(t, "sysadm")
	e.ingest(t, e.blocked(t, "crm-bot"), e.blocked(t, "crm-bot"), e.blocked(t, "hr-bot"))

	for _, s := range []session{owner, sys} {
		mustProblem(t, e.call(s, "GET", "/api/v1/alerts", "", false), 403, CodeForbidden)
	}
	w := e.call(auditor, "GET", "/api/v1/alerts?status=new&severity=high&limit=1", "", false)
	if w.Code != 200 {
		t.Fatalf("список: %d %s", w.Code, w.Body)
	}
	page := decode[PageResponse[AlertView]](t, w.Body.Bytes())
	if len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("первая страница: %+v", page)
	}
	w = e.call(auditor, "GET", "/api/v1/alerts?status=new&severity=high&limit=1&cursor="+page.NextCursor, "", false)
	page2 := decode[PageResponse[AlertView]](t, w.Body.Bytes())
	if len(page2.Items) != 1 || page2.Items[0].ID == page.Items[0].ID || page2.NextCursor != "" {
		t.Fatalf("вторая страница: %+v", page2)
	}
	for _, q := range []string{"status=open", "severity=urgent", "rule_id=x", "status=new&status=closed", "cursor=bad"} {
		mustProblem(t, e.call(auditor, "GET", "/api/v1/alerts?"+q, "", false), 400, CodeInvalidRequest)
	}
	var crm AlertView
	for _, a := range append(page.Items, page2.Items...) {
		if a.Group["app"] == "crm-bot" {
			crm = a
		}
	}
	if crm.Count != 2 || crm.Kind != "threshold" || crm.RuleName == "" {
		t.Fatalf("оповещение crm-bot: %+v", crm)
	}
	w = e.call(analyst, "GET", "/api/v1/alerts/"+crm.ID, "", false)
	card := decode[AlertCardView](t, w.Body.Bytes())
	if w.Code != 200 || len(card.Events) != 2 || card.EventsTruncated || len(card.History) != 0 {
		t.Fatalf("карточка: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "GET", "/api/v1/alerts/01900000-0000-7000-8000-0000000fffff", "", false), 404, CodeNotFound)
	mustProblem(t, e.call(analyst, "GET", "/api/v1/alerts/not-a-uuid", "", false), 404, CodeNotFound)
	mustProblem(t, e.call(owner, "GET", "/api/v1/alerts/"+crm.ID, "", false), 403, CodeForbidden)

	// Жизненный цикл.
	status := "/api/v1/alerts/" + crm.ID + "/status"
	for _, s := range []session{auditor, owner, sys} {
		mustProblem(t, e.call(s, "POST", status, `{"status":"in_progress"}`, true), 403, CodeForbidden)
	}
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"new"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"closed","extra":1}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"closed","comment":"`+strings.Repeat("я", 2001)+`"}`, true), 400, CodeInvalidRequest)
	w = e.call(analyst, "POST", status, `{"status":"in_progress","comment":"Беру в работу"}`, true)
	got := decode[AlertView](t, w.Body.Bytes())
	if w.Code != 200 || got.Status != "in_progress" || got.AssigneeID != tAnalystID {
		t.Fatalf("в работу: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"in_progress"}`, true), 409, CodeConflict)
	w = e.call(analyst, "POST", status, `{"status":"closed","comment":"Подтверждено"}`, true)
	if got := decode[AlertView](t, w.Body.Bytes()); w.Code != 200 || got.Status != "closed" || got.ClosedAt == nil ||
		got.ClosedBy != "user:"+tAnalystID {
		t.Fatalf("закрытие: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"closed"}`, true), 409, CodeConflict)
	mustProblem(t, e.call(analyst, "POST", "/api/v1/alerts/01900000-0000-7000-8000-0000000fffff/status", `{"status":"closed"}`, true),
		404, CodeNotFound)
	if n := e.actions("alert.status_changed"); n != 2 {
		t.Fatalf("записей alert.status_changed: %d", n)
	}
	w = e.call(analyst, "GET", "/api/v1/alerts/"+crm.ID, "", false)
	if card := decode[AlertCardView](t, w.Body.Bytes()); len(card.History) != 2 || card.History[1].Comment != "Подтверждено" {
		t.Fatalf("история: %s", w.Body)
	}
	// Отказы пишутся в аудит (УПД.6).
	if _, n := lastDenied(t, e.mem); n == 0 {
		t.Fatal("нет записей access.denied")
	}
}

// Правила: чтение — alert_rules.read, изменение — только администратор
// безопасности; ослабление требует пароля или кода (DM-40); правило
// безопасности не отключается; изменение получателей порождает оповещение.
func TestAlertRulesViaAPI(t *testing.T) {
	e := newAlertsEnv(t)
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	sys := e.mustLogin(t, "sysadm")

	for _, s := range []session{owner, sys} {
		mustProblem(t, e.call(s, "GET", "/api/v1/alert-rules", "", false), 403, CodeForbidden)
	}
	w := e.call(auditor, "GET", "/api/v1/alert-rules", "", false)
	list := decode[AlertRuleList](t, w.Body.Bytes())
	// 5 встроенных задачи 3.10, 15 задачи 3.11, 5 задачи 3.12, правило DM-08 с инцидентом задачи 3.16, 1 задачи 3.14
	// и system.alert_job (3В17 ревью 3.r2), 3 правила DM-03, DM-06, DM-26 задач 4.13 и 4.14,
	// agents.tool_new и agents.tool_changed задачи 4.8, agents.tool_blocked и agents.tool_poisoning задачи 4.11.
	if w.Code != 200 || len(list.Items) != 35 {
		t.Fatalf("правила: %d %s", w.Code, w.Body)
	}
	var sec AlertRuleView
	for _, r := range list.Items {
		if r.Builtin == alerting.BuiltinRecipientsChanged {
			sec = r
		}
		if strings.Join(r.EffectiveRoles, ",") != "auditor,security_admin" {
			t.Fatalf("обязательные получатели: %+v", r)
		}
	}
	if !sec.Locked || sec.Kind != "security" {
		t.Fatalf("правило безопасности: %+v", sec)
	}

	create := `{"kind":"threshold","name":"Утечка ПДн","condition":{"filter":"threat = \"DM-09\""},"group_by":["app"],` +
		`"recipients":{"roles":["analyst"]}}`
	for _, s := range []session{analyst, auditor, owner, sys} {
		mustProblem(t, e.call(s, "POST", "/api/v1/alert-rules", create, true), 403, CodeForbidden)
	}
	w = e.call(admin, "POST", "/api/v1/alert-rules", create, true)
	r := decode[AlertRuleView](t, w.Body.Bytes())
	if w.Code != 201 || w.Header().Get("Location") != "/api/v1/alert-rules/"+r.ID || r.Version != 1 || r.SuppressMinutes != 60 ||
		strings.Join(r.EffectiveRoles, ",") != "analyst,auditor,security_admin" {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	w = e.call(admin, "POST", "/api/v1/alert-rules", `{"kind":"threshold","name":"x","condition":{"filter":"app ~ \"x\""}}`, true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"condition.filter"`) {
		t.Fatalf("поле ошибки: %s", w.Body)
	}
	mustProblem(t, e.call(admin, "POST", "/api/v1/alert-rules", `{"kind":"security","name":"x"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "POST", "/api/v1/alert-rules",
		`{"kind":"new","name":"x","condition":{"field":"model"},"recipients":{"users":["01900000-0000-7000-8000-0000000fffff"]}}`, true),
		400, CodeInvalidRequest)
	if w := e.call(auditor, "GET", "/api/v1/alert-rules/"+r.ID, "", false); w.Code != 200 {
		t.Fatalf("правило: %d", w.Code)
	}
	mustProblem(t, e.call(auditor, "GET", "/api/v1/alert-rules/01900000-0000-7000-8000-0000000fffff", "", false), 404, CodeNotFound)

	// Отключение — ослабление: без пароля 400, с неверным 403, с верным 200.
	url := "/api/v1/alert-rules/" + r.ID
	off := `{"name":"Утечка ПДн","condition":{"filter":"threat = \"DM-09\""},"group_by":["app"],"enabled":false,"version":1,` +
		`"recipients":{"roles":["analyst"]}`
	mustProblem(t, e.call(analyst, "PUT", url, off+`}`, true), 403, CodeForbidden)
	w = e.call(admin, "PUT", url, off+`}`, true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"password"`) {
		t.Fatalf("нет требования пароля: %s", w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", url, off+`,"password":"неверный"}`, true), 403, CodeReauthFailed)
	w = e.call(admin, "PUT", url, off+`,"password":"`+tPhrase+`"}`, true)
	if got := decode[AlertRuleView](t, w.Body.Bytes()); w.Code != 200 || got.Enabled || got.Version != 2 {
		t.Fatalf("отключение: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", url, off+`,"password":"`+tPhrase+`"}`, true), 409, CodeConflict)
	// Включение — не ослабление: пароль не нужен.
	on := strings.Replace(strings.Replace(off, `"enabled":false`, `"enabled":true`, 1), `"version":1`, `"version":2`, 1) + `}`
	if w := e.call(admin, "PUT", url, on, true); w.Code != 200 {
		t.Fatalf("включение: %d %s", w.Code, w.Body)
	}
	if n := e.actions("alert_rule.update"); n != 2 {
		t.Fatalf("записей alert_rule.update: %d", n)
	}

	// Правило безопасности: отключить нельзя, получателей — можно, с оповещением.
	secURL := "/api/v1/alert-rules/" + sec.ID
	mustProblem(t, e.call(admin, "PUT", secURL, fmt.Sprintf(`{"enabled":false,"version":%d}`, sec.Version), true),
		422, CodeUnprocessable)
	w = e.call(admin, "PUT", secURL, fmt.Sprintf(`{"version":%d,"recipients":{"users":["%s"]}}`, sec.Version, tAnalystID), true)
	if got := decode[AlertRuleView](t, w.Body.Bytes()); w.Code != 200 || !got.Enabled || len(got.Recipients.Users) != 1 {
		t.Fatalf("получатели правила безопасности: %d %s", w.Code, w.Body)
	}
	w = e.call(auditor, "GET", "/api/v1/alerts?rule_id="+sec.ID, "", false)
	if p := decode[PageResponse[AlertView]](t, w.Body.Bytes()); len(p.Items) != 1 || p.Items[0].Severity != "high" ||
		p.Items[0].Kind != "security" {
		t.Fatalf("оповещение об изменении получателей: %s", w.Body)
	}
}

// Токен API (ИАФ.9): разбор оповещений доступен токену, правила — нет.
func TestAlertsByAPIToken(t *testing.T) {
	e := newAlertsEnv(t)
	admin := e.mustLogin(t, "admin")
	e.ingest(t, e.blocked(t, "crm-bot"))
	created := e.issueToken(t, admin, auth.PermAlertsRead, auth.PermAlertsManage, auth.PermAlertRulesRead)
	bearer := session{bearer: created.Token}
	w := e.call(bearer, "GET", "/api/v1/alerts?severity=high", "", false)
	p := decode[PageResponse[AlertView]](t, w.Body.Bytes())
	if w.Code != 200 || len(p.Items) != 1 {
		t.Fatalf("список по токену: %d %s", w.Code, w.Body)
	}
	w = e.call(bearer, "POST", "/api/v1/alerts/"+p.Items[0].ID+"/status", `{"status":"in_progress"}`, false)
	if got := decode[AlertView](t, w.Body.Bytes()); w.Code != http.StatusOK || got.AssigneeID != tAdminID {
		t.Fatalf("в работу по токену: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(bearer, "POST", "/api/v1/alert-rules", `{"kind":"new","name":"x","condition":{"field":"model"}}`, false),
		403, CodeForbidden)
	if auth.TokenGrantable(auth.PermAlertRulesManage) {
		t.Fatal("правила оповещений выдаются токену")
	}
}

// Состояние правил фоновой задачи (задача 3.12): чтение — alert_rules.read;
// аномалия без истории — обучение; правило «порог» фоновой задачей не
// считается. Создание правил «частота», «аномалия», «бюджет» — через API.
func TestAlertRuleStateViaAPI(t *testing.T) {
	e := newAlertsEnv(t)
	admin := e.mustLogin(t, "admin")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	w := e.call(auditor, "GET", "/api/v1/alert-rules", "", false)
	var spike, threshold string
	for _, r := range decode[AlertRuleList](t, w.Body.Bytes()).Items {
		switch r.Builtin {
		case alerting.BuiltinActivitySpike:
			spike = r.ID
		case alerting.BuiltinInjectionBlocked:
			threshold = r.ID
		}
	}
	state := "/api/v1/alert-rules/" + spike + "/state"
	if got := decode[AlertRuleStateView](t, e.call(auditor, "GET", state, "", false).Body.Bytes()); got.Evaluated || got.Kind != "anomaly" {
		t.Fatalf("до прохода: %+v", got)
	}
	e.alerts.AddActivity(alerting.Activity{Bucket: time.Now().Add(-30 * time.Minute), App: "crm-bot", Requests: 500})
	if _, err := e.alerts.Periodic(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	w = e.call(auditor, "GET", state, "", false)
	got := decode[AlertRuleStateView](t, w.Body.Bytes())
	if w.Code != 200 || !got.Evaluated || !got.Learning || got.LearningUntil == nil || len(got.Keys) != 1 ||
		got.Keys[0].Group["app"] != "crm-bot" || !got.Keys[0].Learning {
		t.Fatalf("обучение: %d %s", w.Code, w.Body)
	}
	if got := decode[AlertRuleStateView](t, e.call(auditor, "GET", "/api/v1/alert-rules/"+threshold+"/state", "", false).Body.Bytes()); got.Evaluated || got.Keys == nil {
		t.Fatalf("порог: %+v", got)
	}
	mustProblem(t, e.call(owner, "GET", state, "", false), 403, CodeForbidden)
	mustProblem(t, e.call(auditor, "GET", "/api/v1/alert-rules/01900000-0000-7000-8000-0000000fffff/state", "", false), 404, CodeNotFound)
	// Токен только с alert_rules.read: объёмы приложений скрыты (нужно
	// events.read), состояние вычисления видно.
	bearer := session{bearer: e.issueToken(t, admin, auth.PermAlertRulesRead).Token}
	w = e.call(bearer, "GET", state, "", false)
	if got := decode[AlertRuleStateView](t, w.Body.Bytes()); w.Code != 200 || !got.Evaluated || !got.KeysHidden ||
		len(got.Keys) != 0 || got.KeysTotal != 0 {
		t.Fatalf("без events.read: %d %s", w.Code, w.Body)
	}

	w = e.call(admin, "POST", "/api/v1/alert-rules", `{"kind":"frequency","name":"Серия блокировок",`+
		`"condition":{"filter":"action = \"block\"","count":5,"window_minutes":15},"group_by":["user"]}`, true)
	if r := decode[AlertRuleView](t, w.Body.Bytes()); w.Code != 201 || r.Condition.Count != 5 || r.Condition.WindowMinutes != 15 {
		t.Fatalf("частота: %d %s", w.Code, w.Body)
	}
	w = e.call(admin, "POST", "/api/v1/alert-rules", `{"kind":"budget","name":"Бюджет 90","condition":{"warn_percent":90}}`, true)
	if r := decode[AlertRuleView](t, w.Body.Bytes()); w.Code != 201 || r.Condition.WarnPercent != 90 {
		t.Fatalf("бюджет: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "POST", "/api/v1/alert-rules", `{"kind":"anomaly","name":"x","condition":{"metric":"requests","factor":0.5}}`, true),
		400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "POST", "/api/v1/alert-rules", `{"kind":"system","name":"x"}`, true), 400, CodeInvalidRequest)
}

// from/to в списке оповещений: период по времени последнего срабатывания,
// граница from включается, to не включается; неверные значения — 400.
func TestAlertsPeriodViaAPI(t *testing.T) {
	e := newAlertsEnv(t)
	analyst := e.mustLogin(t, "analyst")
	e.ingest(t, e.blocked(t, "crm-bot"), e.blocked(t, "hr-bot"))
	all := decode[PageResponse[AlertView]](t, e.call(analyst, "GET", "/api/v1/alerts", "", false).Body.Bytes())
	total := len(all.Items)
	if total < 2 {
		t.Fatalf("без периода: %+v", all)
	}
	at := all.Items[0].LastTriggeredAt
	count := func(q string) int {
		t.Helper()
		w := e.call(analyst, "GET", "/api/v1/alerts?"+q, "", false)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body)
		}
		return len(decode[PageResponse[AlertView]](t, w.Body.Bytes()).Items)
	}
	f := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	if n := count("from=" + f(at.Add(-time.Hour)) + "&to=" + f(at.Add(time.Hour))); n != total {
		t.Fatalf("период вокруг срабатывания: %d", n)
	}
	if n := count("from=" + f(at.Add(time.Hour))); n != 0 {
		t.Fatalf("from после срабатываний: %d", n)
	}
	if n := count("to=" + f(at.Add(-time.Hour))); n != 0 {
		t.Fatalf("to до срабатываний: %d", n)
	}
	// Границы: from включается, to не включается (наибольшее время срабатывания).
	latest := at
	for _, a := range all.Items {
		if a.LastTriggeredAt.After(latest) {
			latest = a.LastTriggeredAt
		}
	}
	if n := count("from=" + f(latest)); n < 1 {
		t.Fatalf("from не включил границу: %d", n)
	}
	if n := count("to=" + f(latest)); n >= total {
		t.Fatalf("to включил границу: %d из %d", n, total)
	}
	for _, q := range []string{"from=вчера", "to=2026-13-01", "from=" + f(at) + "&from=" + f(at), "from=" + f(at) + "&to=" + f(at),
		"from=" + f(at.Add(time.Hour)) + "&to=" + f(at)} {
		mustProblem(t, e.call(analyst, "GET", "/api/v1/alerts?"+q, "", false), 400, CodeInvalidRequest)
	}
}

// 3В15 ревью 3.r2: оповещение DM-40 о действиях администратора он сам не
// закрывает (409 self_review), его токен — тоже (403); закрывает аналитик.
func TestAlertSelfCloseViaAPI(t *testing.T) {
	e := newAlertsEnv(t)
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.alerts.Audit(context.Background(), audit.Record{ID: u.String(), OrgID: audit.DefaultOrgID, TS: time.Now(),
		Actor: audit.Actor{Type: audit.ActorUser, ID: tAdminID, Name: "admin"}, Action: "auth.mfa_reset",
		Object: audit.Object{Type: "user", ID: tAnalystID}, Result: audit.ResultSuccess, Details: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	w := e.call(admin, "GET", "/api/v1/alerts?kind=security", "", false)
	p := decode[PageResponse[AlertView]](t, w.Body.Bytes())
	if w.Code != 200 || len(p.Items) != 1 {
		t.Fatalf("оповещения: %d %s", w.Code, w.Body)
	}
	path := "/api/v1/alerts/" + p.Items[0].ID + "/status"
	mustProblem(t, e.call(admin, "POST", path, `{"status":"closed"}`, true), http.StatusConflict, CodeSelfReview)
	created := e.issueToken(t, admin, auth.PermAlertsRead, auth.PermAlertsManage)
	mustProblem(t, e.call(session{bearer: created.Token}, "POST", path, `{"status":"closed"}`, false), http.StatusForbidden, CodeForbidden)
	if w := e.call(analyst, "POST", path, `{"status":"closed","comment":"проверено"}`, true); w.Code != http.StatusOK {
		t.Fatalf("закрытие аналитиком: %d %s", w.Code, w.Body)
	}

	// 3Н48 ревью 3.r4: оповещение о действиях токена его владелец в консоли
	// не закрывает; другой пользователь закрывает.
	u, err = e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.alerts.Audit(context.Background(), audit.Record{ID: u.String(), OrgID: audit.DefaultOrgID, TS: time.Now(),
		Actor:  audit.Actor{Type: audit.ActorAPIToken, ID: created.APIToken.ID, Name: "admin (" + created.APIToken.Prefix + ")"},
		Action: "auth.mfa_reset", Object: audit.Object{Type: "user", ID: tAnalystID}, Result: audit.ResultSuccess,
		Details: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	w = e.call(admin, "GET", "/api/v1/alerts?kind=security&status=new", "", false)
	p = decode[PageResponse[AlertView]](t, w.Body.Bytes())
	if w.Code != 200 || len(p.Items) != 1 {
		t.Fatalf("оповещение о действиях токена: %d %s", w.Code, w.Body)
	}
	path = "/api/v1/alerts/" + p.Items[0].ID + "/status"
	mustProblem(t, e.call(admin, "POST", path, `{"status":"closed"}`, true), http.StatusConflict, CodeSelfReview)
	if w := e.call(analyst, "POST", path, `{"status":"closed","comment":"проверено"}`, true); w.Code != http.StatusOK {
		t.Fatalf("закрытие аналитиком оповещения о чужом токене: %d %s", w.Code, w.Body)
	}
}
