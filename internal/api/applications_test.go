package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/agents"
	"github.com/azuresong-afk/ai_railway/internal/approvals"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
	"github.com/azuresong-afk/ai_railway/internal/reports"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

// Синтетические учётные записи для приложений.
const (
	tSysAdminID = "01900000-0000-7000-8000-00000000d001"
	tOwnerID    = "01900000-0000-7000-8000-00000000e001"
	tOwner2ID   = "01900000-0000-7000-8000-00000000e002"
	tKeyMgrID   = "01900000-0000-7000-8000-00000000e003"
	tKeyRole    = "key_owner"
	tSecret     = "sk-synthetic-provider-credential-0042" //nolint:gosec // G101: синтетические учётные данные провайдера для теста, нигде не выданы
)

type appsEnv struct {
	*authEnv
	apps  *apps.Memory
	pols  *versions.Memory
	ev    *events.Memory
	rec   *recAudit
	caPEM string
	// dash — подмена агрегатов дашбордов (dashboards_test.go).
	dash *fakeDash
	// stopping — Options.Stopping: закрытие — остановка сервера.
	stopping chan struct{}
	// reports — сервис отчётов (reports_test.go).
	reports *reports.Service
	// agents и agentsSvc — реестр агентов (agents_test.go).
	agents    *agents.Memory
	agentsSvc *agents.Service
	// approvals и approvalsSvc — очередь подтверждений со своими часами
	// (approvals_test.go).
	approvals    *approvals.Memory
	approvalsSvc *approvals.Service
	aclock       *testClock
	// shadow и shadowSvc — теневой ИИ (shadowai_test.go).
	shadow    *shadowai.Memory
	shadowSvc *shadowai.Service
}

func newAppsEnv(t testing.TB) *appsEnv {
	t.Helper()
	e := &appsEnv{authEnv: &authEnv{mem: authtest.NewMemory(), log: &bytes.Buffer{}, clock: &testClock{t: time.Now()}, secrets: map[string][]byte{}},
		apps: apps.NewMemory(), pols: versions.NewMemory(), ev: events.NewMemory(), rec: &recAudit{}, dash: &fakeDash{}, stopping: make(chan struct{})}
	e.ev.SetRetentionAudit(func(a audit.Entry) error { return e.rec.Record(context.Background(), a) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	ctx := context.Background()
	// Своя роль: только свои приложения и их ключи (УПД.2, объектный уровень).
	rec := audit.Entry{Actor: audit.Actor{Type: audit.ActorCLI, ID: "test"}, Action: "role.create", Result: audit.ResultSuccess}
	if err := e.mem.CreateRole(ctx, audit.DefaultOrgID, "", auth.RoleDef{ID: tKeyRole, DisplayName: tKeyRole,
		Grants:    auth.Grants{auth.PermApplicationsRead: auth.ScopeOwn, auth.PermAppKeysManage: auth.ScopeOwn},
		CreatedAt: now, UpdatedAt: now, CreatedBy: "test"}, func(auth.Actor) (audit.Entry, error) { return rec, nil }); err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct {
		id, login string
		role      auth.Role
	}{
		{tAdminID, "admin", auth.RoleSecurityAdmin}, {tSysAdminID, "sysadm", auth.RoleSystemAdmin},
		{tAuditorID, "auditor", auth.RoleAuditor}, {tOwnerID, "owner", auth.RoleAppOwner}, {tAnalystID, "analyst", auth.RoleAnalyst},
		{tOwner2ID, "owner2", auth.RoleAppOwner}, {tKeyMgrID, "keymgr", tKeyRole},
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
	key, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	box, err := keyring.NewStaticKey(p, "01900000-0000-7000-8000-0000000000d1", key)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := detect.NewRegistry(builtin.All()...)
	if err != nil {
		t.Fatal(err)
	}
	pols, err := versions.New(versions.Options{Store: e.pols, Provider: p, Catalog: reg})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := apps.New(apps.Options{Store: e.apps, Provider: p, Box: box, Policies: pols, OwnerCheck: func(ctx context.Context, id string) error {
		u, err := e.mem.UserByID(ctx, audit.DefaultOrgID, id)
		if err != nil || u.Status != auth.StatusActive {
			return errors.New("владелец не найден")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("AISec test provider CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.caPEM = string(ca.CertPEM())
	logger := slog.New(slog.NewTextHandler(e.log, nil))
	authSvc := testAuth(t, e.mem, auth.WithClock(e.clock.now))
	e.reports = newTestReports(t, e.dash, ReportDirectory{Auth: authSvc})
	e.agents = agents.NewMemory()
	if e.agentsSvc, err = agents.New(agents.Options{Store: e.agents, Provider: p, Box: box, Apps: agents.AppsOf(svc),
		Clock: e.clock.now}); err != nil {
		t.Fatal(err)
	}
	e.approvals, e.aclock = approvals.NewMemory(), &testClock{t: time.Now().UTC()}
	if e.approvalsSvc, err = approvals.New(approvals.Options{Store: e.approvals, Provider: p, Box: box, Clock: e.aclock.now}); err != nil {
		t.Fatal(err)
	}
	e.shadow = shadowai.NewMemory()
	if e.shadowSvc, err = shadowai.New(shadowai.Options{Store: e.shadow, Provider: p, UserMAC: shadowTestMAC(t, p),
		Clock: func() time.Time { return shadowTestNow }, Logger: logger,
		Location: func(context.Context) (*time.Location, error) { return time.LoadLocation("Europe/Moscow") }}); err != nil {
		t.Fatal(err)
	}
	h, _, err := New(Options{Hasher: testHasher(t), Logger: logger, Auth: authSvc, Apps: svc,
		Policies: pols, Events: e.ev, Audit: e.rec, Dashboards: e.dash, Reports: e.reports, Agents: e.agentsSvc, Approvals: e.approvalsSvc,
		ShadowAI:  e.shadowSvc,
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 100000, Window: time.Minute}}}, Stopping: e.stopping})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e
}

func (e *appsEnv) appAction(action string) (audit.Entry, int) {
	var (
		last audit.Entry
		n    int
	)
	for _, r := range e.apps.Records() {
		if r.Action == action {
			last, n = r, n+1
		}
	}
	return last, n
}

func (e *appsEnv) provider(t *testing.T, s session, slug string) ProviderView {
	t.Helper()
	body := fmt.Sprintf(`{"slug":%q,"name":"Провайдер","type":"openai","base_url":"https://llm.example/v1","ca_pem":%q}`, slug, e.caPEM)
	w := e.call(s, "POST", "/api/v1/providers", body, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание провайдера: %d %s", w.Code, w.Body)
	}
	return decode[ProviderView](t, w.Body.Bytes())
}

func (e *appsEnv) application(t *testing.T, s session, slug, providerID, owner string) ApplicationView {
	t.Helper()
	body := fmt.Sprintf(`{"slug":%q,"name":"Приложение","owner_id":%q,"env":"test","provider_id":%q,"models":["gpt-4o-mini"]}`, slug, owner, providerID)
	w := e.call(s, "POST", "/api/v1/applications", body, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание приложения: %d %s", w.Code, w.Body)
	}
	return decode[ApplicationView](t, w.Body.Bytes())
}

// ЗИ.1, ИАФ.8: учётные данные провайдера принимаются, но не возвращаются
// ни в одном ответе и не попадают в журналы; признак «внешний» снимает
// только обладатель отдельного права и только с обоснованием.
func TestProvidersViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	admin := e.mustLogin(t, "admin")
	auditor := e.mustLogin(t, "auditor")
	p := e.provider(t, sys, "openai-main")
	if !p.External || p.CredentialSet {
		t.Fatalf("новый провайдер: %+v", p)
	}
	dup := fmt.Sprintf(`{"slug":"openai-main","name":"Дубль","type":"openai","base_url":"https://x.example/v1","ca_pem":%q}`, e.caPEM)
	mustProblem(t, e.call(sys, "POST", "/api/v1/providers", dup, true), 409, CodeConflict)
	mustProblem(t, e.call(sys, "POST", "/api/v1/providers", `{"slug":"x","name":"X","type":"openai","base_url":"http://x.example/v1","extra":1}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(auditor, "POST", "/api/v1/providers", `{"slug":"y","name":"Y","type":"openai","base_url":"https://y.example/v1"}`, true), 403, CodeForbidden)

	w := e.call(sys, "PUT", "/api/v1/providers/"+p.ID+"/credentials", mustJSON(t, credentialRequest{Credential: tSecret}), true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"credential_set":true`) {
		t.Fatalf("учётные данные: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "PUT", "/api/v1/providers/"+p.ID+"/credentials", `{"credential":""}`, true), 400, CodeInvalidRequest)
	for _, path := range []string{"/api/v1/providers", "/api/v1/providers/" + p.ID} {
		w := e.call(auditor, "GET", path, "", false)
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), tSecret) || !strings.Contains(w.Body.String(), `"credential_set":true`) {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body)
		}
	}

	// Снятие признака «внешний» — функция безопасности (DM-40).
	mustProblem(t, e.call(sys, "PUT", "/api/v1/providers/"+p.ID+"/external", `{"external":false,"reason":"Свой контур"}`, true), 403, CodeForbidden)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/providers/"+p.ID+"/external", `{"external":false}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/providers/"+p.ID+"/external", `{"reason":"Свой контур"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/providers/"+p.ID+"/external", `{"external":false,"reason":"Свой контур"}`, true), 400, CodeInvalidRequest)
	w = e.call(admin, "PUT", "/api/v1/providers/"+p.ID+"/external", `{"external":false,"reason":"Модель развёрнута в контуре заказчика","password":"`+tPhrase+`"}`, true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"external":false`) {
		t.Fatalf("снятие признака: %d %s", w.Code, w.Body)
	}
	rec, n := e.appAction("provider.external_changed")
	d, _ := rec.Details.(map[string]any)
	if n != 1 || rec.Actor.ID != tAdminID || d["weakening"] != true || d["reason"] == "" {
		t.Fatalf("аудит снятия признака: %+v", rec)
	}

	// Используемого провайдера не удалить; неиспользуемого — можно.
	e.application(t, sys, "helpdesk", p.ID, tOwnerID)
	mustProblem(t, e.call(sys, "DELETE", "/api/v1/providers/"+p.ID, "", true), 409, CodeConflict)
	p2 := e.provider(t, sys, "spare")
	if w := e.call(sys, "DELETE", "/api/v1/providers/"+p2.ID, "", true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "GET", "/api/v1/providers/"+p2.ID, "", false), 404, CodeNotFound)
	mustProblem(t, e.call(sys, "GET", "/api/v1/providers/not-a-uuid", "", false), 404, CodeNotFound)

	if strings.Contains(e.log.String(), tSecret) || strings.Contains(fmt.Sprintf("%+v", e.apps.Records()), tSecret) {
		t.Fatal("учётные данные провайдера в журналах")
	}
	for _, a := range []string{"provider.create", "provider.credentials_set", "provider.delete", "application.create"} {
		if _, n := e.appAction(a); n == 0 {
			t.Errorf("нет записи %s", a)
		}
	}
}

// УПД.2: поля защиты задаёт только администратор безопасности.
func TestApplicationProtectionViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	admin := e.mustLogin(t, "admin")
	p := e.provider(t, sys, "openai-main")
	body := fmt.Sprintf(`{"slug":"crm","name":"CRM","owner_id":%q,"env":"prod","provider_id":%q,"models":["gpt-4o-mini"],"storage":"full"}`, tOwnerID, p.ID)
	mustProblem(t, e.call(sys, "POST", "/api/v1/applications", body, true), 422, CodeUnprocessable)
	a := e.application(t, sys, "crm", p.ID, tOwnerID)
	if a.Policy != "base" || a.PolicyMode != "monitor" || a.Storage != "masked" || a.FailMode != "fail_closed" || a.Status != "active" {
		t.Fatalf("умолчания: %+v", a)
	}
	mustProblem(t, e.call(sys, "PUT", "/api/v1/applications/"+a.ID+"/protection", `{"policy":"base","policy_mode":"monitor","storage":"none"}`, true), 403, CodeForbidden)
	w := e.call(admin, "PUT", "/api/v1/applications/"+a.ID+"/protection", `{"policy":"pii-strict","policy_mode":"enforce","storage":"masked"}`, true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"policy_mode":"enforce"`) {
		t.Fatalf("смена защиты: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", "/api/v1/applications/"+a.ID+"/protection", `{"policy":"no-such","policy_mode":"enforce","storage":"masked"}`, true), 400, CodeInvalidRequest)
	if _, n := e.appAction("application.protection_changed"); n != 1 {
		t.Fatalf("аудит смены защиты: %d", n)
	}
	// Ослабление при создании — с текущим паролем (Н32 ревью 2.r3b).
	body = fmt.Sprintf(`{"slug":"bot","name":"Бот","owner_id":%q,"env":"prod","provider_id":%q,"models":["gpt-4o-mini"],"storage":"none"%%s}`, tOwnerID, p.ID)
	mustProblem(t, e.call(admin, "POST", "/api/v1/applications", fmt.Sprintf(body, ``), true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "POST", "/api/v1/applications", fmt.Sprintf(body, `,"password":"неверный"`), true), 403, CodeReauthFailed)
	if w := e.call(admin, "POST", "/api/v1/applications", fmt.Sprintf(body, `,"password":"`+tPhrase+`"`), true); w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"storage":"none"`) {
		t.Fatalf("создание с защитой: %d %s", w.Code, w.Body)
	}
	// Изменение без полей защиты их не трогает; неизвестный владелец — 400.
	upd := fmt.Sprintf(`{"name":"CRM 2","owner_id":%q,"env":"prod","provider_id":%q,"models":["gpt-4o"]}`, tOwner2ID, p.ID)
	if w := e.call(sys, "PUT", "/api/v1/applications/"+a.ID, upd, true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"policy":"pii-strict"`) {
		t.Fatalf("изменение: %d %s", w.Code, w.Body)
	}
	bad := fmt.Sprintf(`{"name":"CRM","owner_id":"01900000-0000-7000-8000-0000000000ee","env":"prod","provider_id":%q,"models":["gpt-4o"]}`, p.ID)
	mustProblem(t, e.call(sys, "PUT", "/api/v1/applications/"+a.ID, bad, true), 400, CodeInvalidRequest)
	if w := e.call(sys, "DELETE", "/api/v1/applications/"+a.ID, "", true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"archived"`) {
		t.Fatalf("архивация: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "PUT", "/api/v1/applications/"+a.ID, upd, true), 409, CodeConflict)
}

// В15 ревью 2.r3b: fail_mode, словари и домены-исключения DM-11 — поля
// защиты; через PUT приложения их не изменить, ослабление через
// /protection — с повторной проверкой и отметкой weakening (DM-40).
func TestApplicationGuardFieldsViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	admin := e.mustLogin(t, "admin")
	p := e.provider(t, sys, "openai-main")
	a := e.application(t, sys, "crm", p.ID, tOwnerID)
	base := fmt.Sprintf(`{"slug":"x","name":"X","owner_id":%q,"env":"prod","provider_id":%q,"models":["m"]`, tOwnerID, p.ID)
	for _, f := range []string{`"fail_mode":"fail_open"`, `"exfil_allow_domains":["evil.example"]`, `"lists":[]`} {
		mustProblem(t, e.call(sys, "POST", "/api/v1/applications", base+","+f+"}", true), 422, CodeUnprocessable)
		upd := fmt.Sprintf(`{"name":"CRM","owner_id":%q,"env":"prod","provider_id":%q,"models":["m"],%s}`, tOwnerID, p.ID, f)
		mustProblem(t, e.call(sys, "PUT", "/api/v1/applications/"+a.ID, upd, true), 400, CodeInvalidRequest)
		mustProblem(t, e.call(sys, "PUT", "/api/v1/applications/"+a.ID+"/protection", "{"+f+"}", true), 403, CodeForbidden)
	}
	// Усиление (новый словарь) — без пароля.
	lists := `{"lists":[{"id":"codename","category":"codename","words":["Северное сияние","Зенит"]}]}`
	w := e.call(admin, "PUT", "/api/v1/applications/"+a.ID+"/protection", lists, true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"Зенит"`) {
		t.Fatalf("словарь: %d %s", w.Code, w.Body)
	}
	rec, n := e.appAction("application.protection_changed")
	if n != 1 || rec.Details.(map[string]any)["weakening"] != false {
		t.Fatalf("усиление: %d %v", n, rec.Details)
	}
	// Ослабления: без пароля — 400, неверный — 403, с паролем — weakening.
	for i, f := range []string{
		`"lists":[{"id":"codename","category":"codename","words":["Северное сияние"]}]`,
		`"fail_mode":"fail_open"`,
		`"exfil_allow_domains":["files.example"]`,
	} {
		mustProblem(t, e.call(admin, "PUT", "/api/v1/applications/"+a.ID+"/protection", "{"+f+"}", true), 400, CodeInvalidRequest)
		mustProblem(t, e.call(admin, "PUT", "/api/v1/applications/"+a.ID+"/protection", "{"+f+`,"password":"неверный"}`, true), 403, CodeReauthFailed)
		if w := e.call(admin, "PUT", "/api/v1/applications/"+a.ID+"/protection", "{"+f+`,"password":"`+tPhrase+`"}`, true); w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", f, w.Code, w.Body)
		}
		rec, n := e.appAction("application.protection_changed")
		if n != i+2 || rec.Details.(map[string]any)["weakening"] != true {
			t.Fatalf("%s: %d %v", f, n, rec.Details)
		}
		// После двух неудач в каждом шаге — новый вход, чтобы не упереться в блокировку.
		admin = e.mustLogin(t, "admin")
	}
	got := e.call(sys, "GET", "/api/v1/applications/"+a.ID, "", false)
	v := decode[ApplicationView](t, got.Body.Bytes())
	if v.FailMode != "fail_open" || len(v.ExfilAllowDomains) != 1 || len(v.Lists) != 1 || len(v.Lists[0].Words) != 1 {
		t.Fatalf("поля защиты: %+v", v)
	}
	// Изменение приложения поля защиты не сбрасывает.
	upd := fmt.Sprintf(`{"name":"CRM 2","owner_id":%q,"env":"prod","provider_id":%q,"models":["m"]}`, tOwnerID, p.ID)
	if w := e.call(sys, "PUT", "/api/v1/applications/"+a.ID, upd, true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"fail_open"`) {
		t.Fatalf("изменение: %d %s", w.Code, w.Body)
	}
}

// В15 ревью 2.r3b: переход приложения на невнешнего провайдера выключает
// маскирование в monitor — только администратор безопасности и с паролем.
func TestApplicationInternalProviderViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	admin := e.mustLogin(t, "admin")
	ext := e.provider(t, sys, "openai-main")
	in := e.provider(t, sys, "vllm")
	if w := e.call(admin, "PUT", "/api/v1/providers/"+in.ID+"/external", `{"external":false,"reason":"vLLM в контуре","password":"`+tPhrase+`"}`, true); w.Code != http.StatusOK {
		t.Fatalf("снятие признака: %d %s", w.Code, w.Body)
	}
	a := e.application(t, sys, "crm", ext.ID, tOwnerID)
	upd := func(prov, extra string) string {
		return fmt.Sprintf(`{"name":"CRM","owner_id":%q,"env":"prod","provider_id":%q,"models":["m"]%s}`, tOwnerID, prov, extra)
	}
	mustProblem(t, e.call(sys, "PUT", "/api/v1/applications/"+a.ID, upd(in.ID, ""), true), 403, CodeForbidden)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/applications/"+a.ID, upd(in.ID, `,"password":"неверный"`), true), 403, CodeReauthFailed)
	admin = e.mustLogin(t, "admin")
	if w := e.call(admin, "PUT", "/api/v1/applications/"+a.ID, upd(in.ID, `,"password":"`+tPhrase+`"`), true); w.Code != http.StatusOK {
		t.Fatalf("смена провайдера: %d %s", w.Code, w.Body)
	}
	rec, _ := e.appAction("application.update")
	if rec.Details.(map[string]any)["weakening"] != true {
		t.Fatalf("смена провайдера без отметки: %v", rec.Details)
	}
	// Обратно на внешнего и другие правки на невнешнем — без права и пароля.
	if w := e.call(sys, "PUT", "/api/v1/applications/"+a.ID, upd(ext.ID, ""), true); w.Code != http.StatusOK {
		t.Fatalf("на внешнего: %d %s", w.Code, w.Body)
	}
}

// ИАФ.8 и объектный уровень доступа: ключ показывается один раз, ответ не
// кэшируется; владелец видит и ведёт только свои приложения, чужие — 404.
func TestAppKeysAndOwnerScopeViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	owner := e.mustLogin(t, "owner")
	keymgr := e.mustLogin(t, "keymgr")
	p := e.provider(t, sys, "openai-main")
	mine := e.application(t, sys, "mine", p.ID, tKeyMgrID)
	theirs := e.application(t, sys, "theirs", p.ID, tOwnerID)

	w := e.call(owner, "GET", "/api/v1/applications", "", false)
	page := decode[PageResponse[ApplicationView]](t, w.Body.Bytes())
	if w.Code != http.StatusOK || len(page.Items) != 1 || page.Items[0].ID != theirs.ID {
		t.Fatalf("список владельца: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(owner, "GET", "/api/v1/applications/"+mine.ID, "", false), 404, CodeNotFound)
	mustProblem(t, e.call(owner, "GET", "/api/v1/applications/"+mine.ID+"/keys", "", false), 404, CodeNotFound)
	mustProblem(t, e.call(owner, "POST", "/api/v1/applications/"+theirs.ID+"/keys", `{"name":"k"}`, true), 403, CodeForbidden)
	mustProblem(t, e.call(owner, "GET", "/api/v1/providers", "", false), 403, CodeForbidden)

	// Выпуск: секрет один раз, без кэша, в формате Р1.
	mustProblem(t, e.call(keymgr, "POST", "/api/v1/applications/"+theirs.ID+"/keys", `{"name":"k"}`, true), 404, CodeNotFound)
	mustProblem(t, e.call(keymgr, "POST", "/api/v1/applications/"+mine.ID+"/keys", `{"name":"k","allowed_cidrs":["10.0.0.1/8"]}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(keymgr, "POST", "/api/v1/applications/"+mine.ID+"/keys", `{"name":"k","expires_in_days":731}`, true), 400, CodeInvalidRequest)
	w = e.call(keymgr, "POST", "/api/v1/applications/"+mine.ID+"/keys", `{"name":"prod","allowed_cidrs":["10.0.0.0/8"],"expires_in_days":30}`, true)
	if w.Code != http.StatusCreated || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("выпуск ключа: %d %q %s", w.Code, w.Header().Get("Cache-Control"), w.Body)
	}
	created := decode[CreatedAppKey](t, w.Body.Bytes())
	prefix, err := auth.ParseAppKey(created.Key)
	if err != nil || prefix != created.AppKey.Prefix || created.AppKey.Status != "active" {
		t.Fatalf("ключ %+v: %v", created.AppKey, err)
	}
	// Секрет — по длине префикса: в base64url есть «_».
	secret := created.Key[len(prefix)+1:]
	w = e.call(keymgr, "GET", "/api/v1/applications/"+mine.ID+"/keys", "", false)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), secret) || !strings.Contains(w.Body.String(), created.AppKey.Prefix) {
		t.Fatalf("список ключей: %d %s", w.Code, w.Body)
	}

	// Ротация с перекрытием 0: прежний ключ истекает сразу.
	mustProblem(t, e.call(owner, "POST", "/api/v1/app-keys/"+created.AppKey.ID+"/rotate", `{}`, true), 403, CodeForbidden)
	w = e.call(keymgr, "POST", "/api/v1/app-keys/"+created.AppKey.ID+"/rotate", `{"overlap_hours":0}`, true)
	if w.Code != http.StatusCreated || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("ротация: %d %s", w.Code, w.Body)
	}
	rotated := decode[CreatedAppKey](t, w.Body.Bytes())
	if rotated.Previous == nil || rotated.Previous.ID != created.AppKey.ID || rotated.AppKey.RotatedFrom != created.AppKey.ID ||
		rotated.Key == created.Key || len(rotated.AppKey.AllowedCIDRs) != 1 {
		t.Fatalf("ответ ротации: %s", w.Body)
	}
	mustProblem(t, e.call(keymgr, "POST", "/api/v1/app-keys/"+rotated.AppKey.ID+"/rotate", `{"overlap_hours":721}`, true), 400, CodeInvalidRequest)
	if w := e.call(keymgr, "POST", "/api/v1/app-keys/"+rotated.AppKey.ID+"/revoke", "", true); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"status":"revoked"`) {
		t.Fatalf("отзыв: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(keymgr, "POST", "/api/v1/app-keys/"+rotated.AppKey.ID+"/revoke", "", true), 409, CodeConflict)

	// Ключ чужого приложения недоступен своей роли.
	w = e.call(sys, "POST", "/api/v1/applications/"+theirs.ID+"/keys", `{"name":"other"}`, true)
	other := decode[CreatedAppKey](t, w.Body.Bytes())
	mustProblem(t, e.call(keymgr, "POST", "/api/v1/app-keys/"+other.AppKey.ID+"/revoke", "", true), 404, CodeNotFound)
	mustProblem(t, e.call(keymgr, "POST", "/api/v1/app-keys/"+other.AppKey.ID+"/rotate", `{}`, true), 404, CodeNotFound)

	for _, k := range []string{created.Key, rotated.Key, other.Key} {
		p, err := auth.ParseAppKey(k)
		if err != nil {
			t.Fatal(err)
		}
		s := k[len(p)+1:]
		if strings.Contains(e.log.String(), s) || strings.Contains(fmt.Sprintf("%+v", e.apps.Records()), s) {
			t.Fatal("секрет ключа в журналах")
		}
	}
	for a, want := range map[string]int{"app_key.issue": 2, "app_key.rotate": 1, "app_key.revoke": 1} {
		if _, n := e.appAction(a); n != want {
			t.Errorf("%s: %d записей, ожидалось %d", a, n, want)
		}
	}
}

// fuzzSession — вход администратора безопасности один раз на fuzz-тест.
func fuzzSession(f *testing.F) (*appsEnv, session, string) {
	f.Helper()
	e := newAppsEnv(f)
	s := e.mustLogin(f, "admin")
	w := e.call(s, "POST", "/api/v1/providers", fmt.Sprintf(`{"slug":"base","name":"Base","type":"openai","base_url":"https://llm.example/v1","ca_pem":%q}`, e.caPEM), true)
	if w.Code != http.StatusCreated {
		f.Fatalf("провайдер: %d %s", w.Code, w.Body)
	}
	var p ProviderView
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		f.Fatal(err)
	}
	return e, s, p.ID
}

// FuzzApplicationRequest: разбор и проверка тела создания приложения не
// приводят к 5xx и панике; принятое тело даёт приложение, которое читается.
func FuzzApplicationRequest(f *testing.F) {
	e, s, pid := fuzzSession(f)
	f.Add(`{"slug":"a1","name":"A","owner_id":"` + tAdminID + `","env":"prod","provider_id":"` + pid + `","models":["gpt-4o"]}`)
	f.Add(`{"slug":"a2","name":"A","env":"test","provider_id":"` + pid + `","models":["m"],"aliases":{"x":"m"},"quotas":{"requests_per_minute":-1}}`)
	f.Add(`{"slug":"a3","name":"A","env":"dev","provider_id":"` + pid + `","models":["m"],"lists":[{"id":"l","category":"c","words":["x"]}],"exfil_allow_domains":["*.example"]}`)
	f.Add(`{"slug":"A B","name":"","models":[],"storage":"full","policy_mode":"enforce"}`)
	f.Add(`{"slug":"a4","name":"\u0000","env":"prod","provider_id":"` + pid + `","models":["m"],"user_from":"header:X-User"}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, body string) {
		w := e.call(s, "POST", "/api/v1/applications", body, true)
		if w.Code >= 500 {
			t.Fatalf("%d на %q: %s", w.Code, body, w.Body)
		}
		if w.Code == http.StatusCreated {
			var a ApplicationView
			if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
				t.Fatal(err)
			}
			if g := e.call(s, "GET", "/api/v1/applications/"+a.ID, "", false); g.Code != http.StatusOK {
				t.Fatalf("созданное приложение не читается: %d", g.Code)
			}
		}
	})
}

// FuzzProviderRequest: тело провайдера (адреса, PEM, таймауты) не приводит
// к 5xx и панике.
func FuzzProviderRequest(f *testing.F) {
	e, s, _ := fuzzSession(f)
	f.Add(`{"slug":"p1","name":"P","type":"openai","base_url":"https://x.example/v1","timeouts":{"connect":5}}`)
	f.Add(`{"slug":"p2","name":"P","type":"gigachat","base_url":"https://x.example/api/v1","auth_url":"https://auth.example/oauth","scope":"GIGACHAT_API_PERS"}`)
	f.Add(`{"slug":"p3","name":"P","type":"yandexgpt","base_url":"https://x.example/","folder_id":"b1g0000000000000000"}`)
	f.Add(`{"slug":"p4","name":"P","type":"openai","base_url":"https://x.example","ca_pem":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}`)
	f.Add(`{"slug":"p5","name":"P","type":"openai","base_url":"http://user:pass@x.example","timeouts":{"response":601}}`)
	f.Fuzz(func(t *testing.T, body string) {
		if w := e.call(s, "POST", "/api/v1/providers", body, true); w.Code >= 500 {
			t.Fatalf("%d на %q: %s", w.Code, body, w.Body)
		}
	})
}
