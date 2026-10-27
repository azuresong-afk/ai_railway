package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/approvals"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	keyringPkg "github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Очередь подтверждений (задача 4.10, DM-22, ADR-0023, раздел 5): решает
// человек с approvals.decide (администратор безопасности, аналитик), не
// токен и не администратор системы; аргументы видит только тот, кто решает;
// одобрение связано с показанным хешем аргументов; critical — с повторной
// проверкой; решение после срока — 409. Шлюз видит только свои запросы.

const tApprovalGW = "01900000-0000-7000-8000-00000000c0a1"

var tArgsHash = strings.Repeat("ab", 32)

// newApprovalsService — очередь в памяти с ключом данных.
func newApprovalsService(t testing.TB, clock func() time.Time) *approvals.Service {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	box, err := keyringPkg.NewStaticKey(p, "01900000-0000-7000-8000-0000000000d1", make([]byte, aisecCrypto.AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := approvals.New(approvals.Options{Store: approvals.NewMemory(), Provider: p, Box: box, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func approvalInput(risk policy.ToolRisk) approvals.CreateInput {
	return approvals.CreateInput{Path: approvals.PathMCP, App: "crm", Agent: "support-bot", Server: "files", Tool: "delete_file",
		Risk: risk, Rule: "tools-approve", Severity: policy.High, ArgsHash: tArgsHash,
		Args: `{"path":"/srv/report.txt","owner":"[ФИО]"}`, Timeout: 10 * time.Minute}
}

func (e *appsEnv) pendingApproval(t *testing.T, risk policy.ToolRisk) approvals.Request {
	t.Helper()
	r, err := e.approvalsSvc.Create(context.Background(), tApprovalGW, approvalInput(risk))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *appsEnv) approvalRecords(action string) []audit.Entry {
	var out []audit.Entry
	for _, r := range e.approvals.Records() {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

func approveBody(hash, extra string) string {
	return fmt.Sprintf(`{"args_hash":%q%s}`, hash, extra)
}

func TestDM22_ApprovalsConsoleFlow(t *testing.T) {
	e := newAppsEnv(t)
	analyst, auditor := e.mustLogin(t, "analyst"), e.mustLogin(t, "auditor")
	r := e.pendingApproval(t, policy.RiskHigh)

	w := e.call(analyst, "GET", "/api/v1/approvals?state=pending", "", false)
	list := decode[PageResponse[ApprovalView]](t, w.Body.Bytes())
	if w.Code != 200 || len(list.Items) != 1 || list.Items[0].ID != r.ID || list.Items[0].Args != nil {
		t.Fatalf("список: %d %s", w.Code, w.Body)
	}
	// Аргументы для решения видит дежурный; аудитор — запрос без них.
	w = e.call(analyst, "GET", "/api/v1/approvals/"+r.ID, "", false)
	v := decode[ApprovalView](t, w.Body.Bytes())
	if w.Code != 200 || v.Args == nil || !strings.Contains(*v.Args, "report.txt") || v.ApplicationID != "crm" || v.ArgsHash != tArgsHash {
		t.Fatalf("дежурный: %d %s", w.Code, w.Body)
	}
	w = e.call(auditor, "GET", "/api/v1/approvals/"+r.ID, "", false)
	if w.Code != 200 || strings.Contains(w.Body.String(), "report.txt") || strings.Contains(w.Body.String(), `"args"`) {
		t.Fatalf("аудитор: %d %s", w.Code, w.Body)
	}
	// Одобрение по хешу показанных аргументов.
	w = e.call(analyst, "POST", "/api/v1/approvals/"+r.ID+"/approve", approveBody(tArgsHash, `,"comment":"Проверено"`), true)
	v = decode[ApprovalView](t, w.Body.Bytes())
	if w.Code != 200 || v.State != approvals.Approved || v.DecidedBy != "analyst" || v.Comment != "Проверено" {
		t.Fatalf("одобрение: %d %s", w.Code, w.Body)
	}
	recs := e.approvalRecords("agent.approval.approve")
	if len(recs) != 1 || recs[0].Actor.Name != "analyst" || recs[0].SourceIP.String() != "192.0.2.1" {
		t.Fatalf("аудит: %+v", recs)
	}
	if strings.Contains(fmt.Sprint(recs[0].Details), "report.txt") {
		t.Fatal("аргументы в журнале аудита")
	}
	// Повторное решение — 409.
	mustProblem(t, e.call(analyst, "POST", "/api/v1/approvals/"+r.ID+"/deny", `{}`, true), http.StatusConflict, CodeConflict)
	// Неизвестный и неверный ID — 404.
	mustProblem(t, e.call(analyst, "GET", "/api/v1/approvals/"+tUnknownID, "", false), http.StatusNotFound, CodeNotFound)
	mustProblem(t, e.call(analyst, "POST", "/api/v1/approvals/x/deny", `{}`, true), http.StatusNotFound, CodeNotFound)
}

func TestDM22_ApprovalsDeny(t *testing.T) {
	e := newAppsEnv(t)
	admin := e.mustLogin(t, "admin")
	r := e.pendingApproval(t, policy.RiskHigh)
	w := e.call(admin, "POST", "/api/v1/approvals/"+r.ID+"/deny", `{"comment":"Не по регламенту"}`, true)
	if v := decode[ApprovalView](t, w.Body.Bytes()); w.Code != 200 || v.State != approvals.Denied {
		t.Fatalf("отказ: %d %s", w.Code, w.Body)
	}
	if n := len(e.approvalRecords("agent.approval.deny")); n != 1 {
		t.Fatalf("аудит отказа: %d", n)
	}
}

// Администратор системы, владелец приложения и аудитор решать не могут;
// администратор системы и владелец не видят очередь вовсе.
func TestDM22_ApprovalsAccessDenied(t *testing.T) {
	e := newAppsEnv(t)
	r := e.pendingApproval(t, policy.RiskHigh)
	for _, login := range []string{"sysadm", "owner", "auditor"} {
		s := e.mustLogin(t, login)
		for _, act := range []string{"approve", "deny"} {
			mustProblem(t, e.call(s, "POST", "/api/v1/approvals/"+r.ID+"/"+act, approveBody(tArgsHash, ""), true),
				http.StatusForbidden, CodeForbidden)
		}
		if login == "auditor" {
			continue
		}
		mustProblem(t, e.call(s, "GET", "/api/v1/approvals", "", false), http.StatusForbidden, CodeForbidden)
		mustProblem(t, e.call(s, "GET", "/api/v1/approvals/"+r.ID, "", false), http.StatusForbidden, CodeForbidden)
	}
	if got := mustApproval(t, e.approvalsSvc, r.ID); got.State != approvals.Pending {
		t.Fatalf("запрос закрыт без права: %s", got.State)
	}
}

// Токену API право решения не выдаётся; токен с approvals.read читает
// очередь без аргументов и не решает.
func TestDM22_ApprovalsDecideNotTokenGrantable(t *testing.T) {
	if auth.TokenGrantable(auth.PermApprovalsDecide) || !auth.TokenGrantable(auth.PermApprovalsRead) {
		t.Fatal("права токена на очередь подтверждений")
	}
	e := newAppsEnv(t)
	admin := e.mustLogin(t, "admin")
	r := e.pendingApproval(t, policy.RiskHigh)
	tok := e.issueToken(t, admin, auth.PermApprovalsRead)
	w := e.callAuthz(session{}, "GET", "/api/v1/approvals/"+r.ID, "Bearer "+tok.Token)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"args"`) {
		t.Fatalf("чтение токеном: %d %s", w.Code, w.Body)
	}
	if w := e.callAuthz(session{}, "POST", "/api/v1/approvals/"+r.ID+"/deny", "Bearer "+tok.Token); w.Code != http.StatusForbidden {
		t.Fatalf("решение токеном: %d %s", w.Code, w.Body)
	}
}

func TestDM22_ApprovalsStaleArgs(t *testing.T) {
	e := newAppsEnv(t)
	analyst := e.mustLogin(t, "analyst")
	r := e.pendingApproval(t, policy.RiskHigh)
	for _, body := range []string{`{}`, approveBody(strings.Repeat("cd", 32), "")} {
		mustProblem(t, e.call(analyst, "POST", "/api/v1/approvals/"+r.ID+"/approve", body, true), http.StatusConflict, CodeConflict)
	}
}

func TestDM22_ApprovalsCriticalReauth(t *testing.T) {
	e := newAppsEnv(t)
	analyst := e.mustLogin(t, "analyst")
	r := e.pendingApproval(t, policy.RiskCritical)
	path := "/api/v1/approvals/" + r.ID + "/approve"
	if w := e.call(analyst, "POST", path, approveBody(tArgsHash, ""), true); w.Code != http.StatusBadRequest {
		t.Fatalf("без пароля: %d %s", w.Code, w.Body)
	}
	if w := e.call(analyst, "POST", path, approveBody(tArgsHash, `,"password":"неверный пароль 1"`), true); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("неверный пароль: %d %s", w.Code, w.Body)
	}
	if got := mustApproval(t, e.approvalsSvc, r.ID); got.State != approvals.Pending {
		t.Fatalf("одобрено без проверки: %s", got.State)
	}
	w := e.call(analyst, "POST", path, approveBody(tArgsHash, `,"password":"`+tPhrase+`"`), true)
	if v := decode[ApprovalView](t, w.Body.Bytes()); w.Code != 200 || v.State != approvals.Approved {
		t.Fatalf("с паролем: %d %s", w.Code, w.Body)
	}
}

func TestDM22_ApprovalsDecisionAfterDeadline(t *testing.T) {
	e := newAppsEnv(t)
	analyst := e.mustLogin(t, "analyst")
	r := e.pendingApproval(t, policy.RiskHigh)
	e.aclock.mu.Lock()
	e.aclock.t = e.aclock.t.Add(10 * time.Minute)
	e.aclock.mu.Unlock()
	w := e.call(analyst, "POST", "/api/v1/approvals/"+r.ID+"/approve", approveBody(tArgsHash, ""), true)
	mustProblem(t, w, http.StatusConflict, CodeConflict)
	if !strings.Contains(w.Body.String(), "Срок подтверждения истёк") {
		t.Fatalf("текст: %s", w.Body)
	}
	if got := mustApproval(t, e.approvalsSvc, r.ID); got.State != approvals.Timeout {
		t.Fatalf("состояние: %s", got.State)
	}
}

func TestApprovalsListValidation(t *testing.T) {
	e := newAppsEnv(t)
	analyst := e.mustLogin(t, "analyst")
	for _, q := range []string{"state=done", "state=pending&state=denied", "application=CRM", "agent=a%20b", "cursor=zzz"} {
		if w := e.call(analyst, "GET", "/api/v1/approvals?"+q, "", false); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", q, w.Code, w.Body)
		}
	}
	for range 3 {
		e.pendingApproval(t, policy.RiskLow)
		e.aclock.next()
	}
	w := e.call(analyst, "GET", "/api/v1/approvals?limit=2&application=crm&agent=support-bot", "", false)
	page := decode[PageResponse[ApprovalView]](t, w.Body.Bytes())
	if w.Code != 200 || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("страница: %d %s", w.Code, w.Body)
	}
	w = e.call(analyst, "GET", "/api/v1/approvals?limit=2&cursor="+page.NextCursor, "", false)
	if next := decode[PageResponse[ApprovalView]](t, w.Body.Bytes()); w.Code != 200 || len(next.Items) != 1 || next.NextCursor != "" {
		t.Fatalf("вторая страница: %d %s", w.Code, w.Body)
	}
}

// Без очереди на сервере эндпоинты отвечают 503.
func TestApprovalsUnavailable(t *testing.T) {
	e := newAppsEnv(t)
	h, _, err := New(Options{Hasher: testHasher(t), Logger: quiet(), Auth: testAuth(t, e.mem, auth.WithClock(e.clock.now)),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 100000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	analyst := e.mustLogin(t, "analyst")
	mustProblem(t, e.call(analyst, "GET", "/api/v1/approvals", "", false), http.StatusServiceUnavailable, CodeUnavailable)
}

// internalApprovals — внутренний порт шлюза gw с очередью svc.
func internalApprovals(t testing.TB, svc *approvals.Service, gw string) http.Handler {
	t.Helper()
	reg, _ := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: reg, Authorizer: asGateway(gw),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}, Extra: ApprovalsInternalRoutes(svc, quiet())})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func createBody(t testing.TB, agent string, timeout int) string {
	t.Helper()
	b, err := json.Marshal(CreateApprovalRequest{Path: "mcp", App: "crm", Agent: agent, Server: "files", Tool: "delete_file",
		Risk: policy.RiskHigh, Rule: "tools-approve", Severity: policy.High, ArgsHash: tArgsHash, Args: `{"path":"/srv/a"}`,
		TimeoutSeconds: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDM22_ApprovalsInternalFlow(t *testing.T) {
	svc := newApprovalsService(t, nil)
	h := internalApprovals(t, svc, tApprovalGW)
	other := internalApprovals(t, svc, "01900000-0000-7000-8000-00000000c0b2")
	post := func(h http.Handler, path, body string) *httptest.ResponseRecorder {
		return do(h, "POST", path, body, "Content-Type", "application/json")
	}
	w := post(h, "/internal/v1/approvals", createBody(t, "support-bot", 600))
	st := decode[ApprovalStatus](t, w.Body.Bytes())
	if w.Code != http.StatusCreated || st.State != approvals.Pending || st.ArgsHash != tArgsHash || !approvals.ValidID(st.ID) {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	// Ответ создания не возвращает аргументы.
	if strings.Contains(w.Body.String(), "/srv/a") {
		t.Fatal("аргументы в ответе")
	}
	// Чужой шлюз не видит и не отменяет запрос.
	mustProblem(t, do(other, "GET", "/internal/v1/approvals/"+st.ID+"?wait=0s", ""), http.StatusNotFound, CodeNotFound)
	mustProblem(t, post(other, "/internal/v1/approvals/"+st.ID+"/cancel", `{}`), http.StatusNotFound, CodeNotFound)
	// Долгий опрос будится решением.
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- do(h, "GET", "/internal/v1/approvals/"+st.ID+"?wait=25s", "") }()
	time.Sleep(50 * time.Millisecond)
	by := approvals.By{Actor: audit.Actor{Type: audit.ActorUser, ID: tAnalystID, Name: "analyst"}}
	if _, err := svc.Decide(context.Background(), by, st.ID, approvals.DecideInput{Approve: true, ArgsHash: tArgsHash}); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-done:
		if got := decode[ApprovalStatus](t, w.Body.Bytes()); w.Code != 200 || got.State != approvals.Approved || got.DecidedBy != "analyst" {
			t.Fatalf("опрос: %d %s", w.Code, w.Body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("опрос не разбужен решением")
	}
	// Отмена ожидающего.
	w = post(h, "/internal/v1/approvals", createBody(t, "support-bot", 60))
	st = decode[ApprovalStatus](t, w.Body.Bytes())
	w = post(h, "/internal/v1/approvals/"+st.ID+"/cancel", `{}`)
	if got := decode[ApprovalStatus](t, w.Body.Bytes()); w.Code != 200 || got.State != approvals.Cancelled {
		t.Fatalf("отмена: %d %s", w.Code, w.Body)
	}
}

func TestDM22_ApprovalsInternalRejects(t *testing.T) {
	svc := newApprovalsService(t, nil)
	h := internalApprovals(t, svc, tApprovalGW)
	post := func(body string) *httptest.ResponseRecorder {
		return do(h, "POST", "/internal/v1/approvals", body, "Content-Type", "application/json")
	}
	for _, body := range []string{createBody(t, "", 600), createBody(t, "support-bot", 30), createBody(t, "support-bot", 3601),
		createBody(t, "support-bot", -1), `{"path":"mcp"}`, `[]`} {
		if w := post(body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	big := strings.Replace(createBody(t, "support-bot", 600), `{\"path\":\"/srv/a\"}`, strings.Repeat("я", approvals.MaxArgs), 1)
	if w := post(big); w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("большие аргументы: %d", w.Code)
	}
	// Предел агента — 429 approval_queue_full.
	for range approvals.MaxPerAgent {
		if w := post(createBody(t, "support-bot", 600)); w.Code != http.StatusCreated {
			t.Fatalf("создание: %d %s", w.Code, w.Body)
		}
	}
	mustProblem(t, post(createBody(t, "support-bot", 600)), http.StatusTooManyRequests, CodeApprovalQueueFull)
	// Параметры опроса.
	w := post(createBody(t, "other-bot", 600))
	id := decode[ApprovalStatus](t, w.Body.Bytes()).ID
	for _, q := range []string{"?wait=26s", "?wait=1m", "?wait=5", "?wait=-1s", "?wait=0s&wait=1s", "?x=1", "?wait=100s"} {
		if w := do(h, "GET", "/internal/v1/approvals/"+id+q, ""); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	if w := do(h, "GET", "/internal/v1/approvals/"+id, ""); w.Code != 200 {
		t.Fatalf("без ожидания: %d %s", w.Code, w.Body)
	}
}

// heartbeat со списком ожидающих: запросы, которых шлюз уже не ждёт,
// закрываются как interrupted; сервер сообщает о поддержке очереди.
func TestDM22_HeartbeatInterruptsLostApprovals(t *testing.T) {
	now := time.Now().UTC()
	clock := &testClock{t: now}
	svc := newApprovalsService(t, clock.now)
	reg, gw := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: reg, Authorizer: asGateway(gw.ID),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}, Approvals: svc})
	if err != nil {
		t.Fatal(err)
	}
	lost, err := svc.Create(context.Background(), gw.ID, approvalInput(policy.RiskHigh))
	if err != nil {
		t.Fatal(err)
	}
	kept, err := svc.Create(context.Background(), gw.ID, approvalInput(policy.RiskHigh))
	if err != nil {
		t.Fatal(err)
	}
	clock.mu.Lock()
	clock.t = clock.t.Add(2 * time.Minute)
	clock.mu.Unlock()
	hb := `{"version":"1","approvals_pending":["` + kept.ID + `"]}`
	w := do(h, "POST", "/internal/v1/heartbeat", hb, "Content-Type", "application/json")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"approvals":true`) {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body)
	}
	for id, want := range map[string]approvals.State{lost.ID: approvals.Interrupted, kept.ID: approvals.Pending} {
		if got := mustApproval(t, svc, id); got.State != want {
			t.Errorf("%s: %s, ожидалось %s", id, got.State, want)
		}
	}
	// Неверный список — 400; без списка запросы не трогаются.
	for _, body := range []string{`{"version":"1","approvals_pending":["x"]}`,
		`{"version":"1","approvals_pending":["` + kept.ID + `","` + kept.ID + `"]}`} {
		if w := do(h, "POST", "/internal/v1/heartbeat", body, "Content-Type", "application/json"); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	if w := do(h, "POST", "/internal/v1/heartbeat", `{"version":"1"}`, "Content-Type", "application/json"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if got := mustApproval(t, svc, kept.ID); got.State != approvals.Pending {
		t.Fatalf("без списка: %s", got.State)
	}
	// Остановка шлюза закрывает все его запросы.
	stop := `{"version":"1","started_at":"2026-10-27T10:00:00Z","stopping":true,"approvals_pending":[]}`
	if w := do(h, "POST", "/internal/v1/heartbeat", stop, "Content-Type", "application/json"); w.Code != 200 {
		t.Fatalf("остановка: %d %s", w.Code, w.Body)
	}
	if got := mustApproval(t, svc, kept.ID); got.State != approvals.Interrupted {
		t.Fatalf("после остановки: %s", got.State)
	}
}

func TestParseWait(t *testing.T) {
	for s, want := range map[string]time.Duration{"": 0, "0s": 0, "1s": time.Second, "25s": 25 * time.Second, "05s": 5 * time.Second} {
		if d, ok := ParseWait(s); !ok || d != want {
			t.Errorf("%q: %v %v", s, d, ok)
		}
	}
	for _, s := range []string{"26s", "s", "1", "1m", "-1s", "+1s", "1.5s", " 1s", "001s", "1s1s", "９s"} {
		if _, ok := ParseWait(s); ok {
			t.Errorf("%q принят", s)
		}
	}
}

// FuzzParseWait: любая строка — не больше MaxWait и не меньше нуля.
func FuzzParseWait(f *testing.F) {
	for _, s := range []string{"", "0s", "25s", "26s", "99s", "1m", "-1s", "\x00s"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, ok := ParseWait(s)
		if ok && (d < 0 || d > approvals.MaxWait) {
			t.Fatalf("%q: %v", s, d)
		}
		if !ok && d != 0 {
			t.Fatalf("%q: отказ с длительностью %v", s, d)
		}
	})
}

// FuzzApprovalDecision: любое тело решения — 200, ошибка клиента или 409,
// без паники и 500; запрос закрывается не больше одного раза.
func FuzzApprovalDecision(f *testing.F) {
	e := newAppsEnv(f)
	analyst := e.mustLogin(f, "analyst")
	for _, s := range []string{`{}`, approveBody(tArgsHash, ""), approveBody(tArgsHash, `,"comment":"ок"`), `{"args_hash":1}`,
		`{"comment":"` + strings.Repeat("я", 501) + `"}`, `[]`, "\x00", `{"password":"x","code":"1"}`, `{"args_hash":"` + tArgsHash + `"}{}`} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, body string, approve bool) {
		r, err := e.approvalsSvc.Create(context.Background(), tApprovalGW, approvalInput(policy.RiskHigh))
		if err != nil {
			t.Fatal(err)
		}
		act := "deny"
		if approve {
			act = "approve"
		}
		w := e.call(analyst, "POST", "/api/v1/approvals/"+r.ID+"/"+act, body, true)
		switch w.Code {
		case http.StatusOK, http.StatusBadRequest, http.StatusConflict, http.StatusRequestEntityTooLarge,
			http.StatusUnsupportedMediaType:
		default:
			t.Fatalf("код %d: %s", w.Code, w.Body)
		}
		got, err := e.approvalsSvc.Get(context.Background(), r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if (w.Code == http.StatusOK) == (got.State == approvals.Pending) {
			t.Fatalf("ответ %d, состояние %s", w.Code, got.State)
		}
		// Освобождает очередь агента для следующего прогона.
		if got.State == approvals.Pending {
			if _, err := e.approvalsSvc.Cancel(context.Background(), tApprovalGW, r.ID); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func mustApproval(t testing.TB, svc *approvals.Service, id string) approvals.Request {
	t.Helper()
	r, err := svc.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// FuzzApprovalCreate: тело запроса подтверждения от шлюза — без паники и
// 500; принятый запрос ждёт решения, хеш аргументов в ответе — сохранённый.
func FuzzApprovalCreate(f *testing.F) {
	f.Add(createBody(f, "support-bot", 600))
	f.Add(createBody(f, "", 600))
	f.Add(createBody(f, "support-bot", 3601))
	f.Add(`{"path":"chat","app":"crm","server":"function","tool":"x","risk":"critical","rule":"r","severity":"high","args_hash":"` +
		tArgsHash + `","args":"{}","timeout_seconds":60}`)
	f.Add(`{"path":"mcp","path":"chat"}`)
	f.Add(`[]`)
	f.Add("\xff")
	svc := newApprovalsService(f, nil)
	h := internalApprovals(f, svc, tApprovalGW)
	f.Fuzz(func(t *testing.T, body string) {
		w := do(h, "POST", "/internal/v1/approvals", body, "Content-Type", "application/json")
		switch w.Code {
		case http.StatusCreated:
			st := decode[ApprovalStatus](t, w.Body.Bytes())
			r := mustApproval(t, svc, st.ID)
			if r.State != approvals.Pending || st.ArgsHash != r.ArgsHash {
				t.Fatalf("%q: %+v %+v", body, st, r)
			}
			// Не копим ожидающие: иначе предел агента закроет приём.
			if _, err := svc.Cancel(context.Background(), tApprovalGW, st.ID); err != nil {
				t.Fatal(err)
			}
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusTooManyRequests:
		default:
			t.Fatalf("%q: %d %s", body, w.Code, w.Body)
		}
	})
}

// FuzzApprovalsPending: список ожидающих из heartbeat — принят только
// список до MaxPending разных ID запросов.
func FuzzApprovalsPending(f *testing.F) {
	f.Add("01900000-0000-7000-8000-0000000000aa,01900000-0000-7000-8000-0000000000ab")
	f.Add("01900000-0000-7000-8000-0000000000aa,01900000-0000-7000-8000-0000000000aa")
	f.Add("")
	f.Add("x")
	f.Fuzz(func(t *testing.T, s string) {
		list := strings.Split(s, ",")
		if !validPending(&list) {
			return
		}
		seen := map[string]bool{}
		for _, id := range list {
			if !approvals.ValidID(id) || seen[id] {
				t.Fatalf("%q принят", s)
			}
			seen[id] = true
		}
		if len(list) > approvals.MaxPending {
			t.Fatalf("%d принято", len(list))
		}
	})
}
