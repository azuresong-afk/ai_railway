package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/api"
	"github.com/azuresong-afk/ai_railway/internal/approvals"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Клиент очереди подтверждений шлюза на настоящем внутреннем API сервера
// (задача 4.10, DM-22): решение дежурного, срок, отмена клиентом,
// недоступный сервер, переполнение, подмена ответа.

const approvalGateway = "01900000-0000-7000-8000-00000000c0a1"

// gatewayAuthz — внутренний порт: запрос от шлюза approvalGateway.
type gatewayAuthz struct{}

func (gatewayAuthz) Authorize(*http.Request, string) (api.Principal, api.Decision) {
	return api.Principal{ID: approvalGateway, Grants: auth.Grants{api.PermGatewayInternal: auth.ScopeAll}}, api.Allow
}

type approvalEnv struct {
	svc    *approvals.Service
	srv    *httptest.Server
	client *gateway.ApprovalClient
	hasher aisecCrypto.Hasher
}

func newApprovalEnv(t *testing.T, clock func() time.Time) *approvalEnv {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	box, err := keyring.NewStaticKey(p, "01900000-0000-7000-8000-0000000000d1", make([]byte, aisecCrypto.AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	e := &approvalEnv{hasher: h}
	if e.svc, err = approvals.New(approvals.Options{Store: approvals.NewMemory(), Provider: p, Box: box, Clock: clock}); err != nil {
		t.Fatal(err)
	}
	reg, err := gwregistry.New(gwregistry.Options{Store: gwregistry.NewMemory(), Provider: p, Audit: nopAuditor{}, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ih, _, err := api.NewInternal(api.InternalOptions{Logger: quiet(), Hasher: h, Gateways: reg, Authorizer: gatewayAuthz{},
		RateLimit: api.RateConfig{Rules: []api.RateRule{{Prefix: "/", Max: 0}}}, Extra: api.ApprovalsInternalRoutes(e.svc, quiet())})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(ih)
	t.Cleanup(e.srv.Close)
	e.client = e.newClient(t, e.srv.URL)
	return e
}

func (e *approvalEnv) newClient(t *testing.T, server string) *gateway.ApprovalClient {
	t.Helper()
	u, err := url.Parse(server)
	if err != nil {
		t.Fatal(err)
	}
	c, err := gateway.NewApprovalClient(gateway.ApprovalClientConfig{Client: e.srv.Client(), Server: u, Hasher: e.hasher,
		Logger: quiet(), PollWait: time.Second, Sleep: func(ctx context.Context, d time.Duration) bool {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(20 * time.Millisecond):
				return true
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const approvalArgs = `{"path":"/srv/reports/q3.txt"}`

func approvalRequest() gateway.ApprovalRequest {
	return gateway.ApprovalRequest{Path: gateway.ApprovalPathMCP, App: "crm", Agent: "support-bot", Server: "files",
		Tool: "delete_file", ApprovedHash: strings.Repeat("ab", 32), Risk: policy.RiskHigh, Rule: "tools-approve",
		Severity: policy.High, Args: []byte(approvalArgs), ShownArgs: approvalArgs, Timeout: 10 * time.Minute}
}

// pendingID ждёт, пока клиент создаст запрос, и возвращает его ID.
func (e *approvalEnv) pendingID(t *testing.T) string {
	t.Helper()
	for range 500 {
		if ids := e.client.Pending(); len(ids) == 1 {
			return ids[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("запрос не создан")
	return ""
}

var duty = approvals.By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000c1", Name: "duty"}}

func TestDM22_ApprovedCallForwardedWithSameArgs(t *testing.T) {
	e := newApprovalEnv(t, nil)
	var ticks atomic.Int32
	done := make(chan gateway.ApprovalResult, 1)
	go func() { done <- e.client.Await(context.Background(), approvalRequest(), func() { ticks.Add(1) }) }()
	id := e.pendingID(t)
	r, err := e.svc.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	// Решение связано с хешем ровно тех аргументов, что уйдут дальше.
	if r.ArgsHash != gateway.ToolArgsHash(e.hasher, []byte(approvalArgs)) || r.ApprovedHash != strings.Repeat("ab", 32) {
		t.Fatalf("запрос: %+v", r)
	}
	if shown, err := e.svc.Args(context.Background(), r); err != nil || string(shown) != approvalArgs {
		t.Fatalf("аргументы для дежурного: %q %v", shown, err)
	}
	time.Sleep(1200 * time.Millisecond) // один опрос с ожиданием: keep-alive
	if _, err := e.svc.Decide(context.Background(), duty, id, approvals.DecideInput{Approve: true, ArgsHash: r.ArgsHash}); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if !res.Approved() || res.ID != id || res.DecidedBy != "duty" || res.Waited <= 0 {
		t.Fatalf("итог: %+v", res)
	}
	if ticks.Load() == 0 {
		t.Fatal("keep-alive не вызывался во время ожидания")
	}
	if len(e.client.Pending()) != 0 {
		t.Fatal("запрос остался в списке ожидающих")
	}
}

func TestDM22_DeniedCall(t *testing.T) {
	e := newApprovalEnv(t, nil)
	done := make(chan gateway.ApprovalResult, 1)
	go func() { done <- e.client.Await(context.Background(), approvalRequest(), nil) }()
	id := e.pendingID(t)
	if _, err := e.svc.Decide(context.Background(), duty, id, approvals.DecideInput{Comment: "нельзя"}); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.Approved() || res.State != gateway.ApprovalDenied || res.Comment != "нельзя" {
		t.Fatalf("итог: %+v", res)
	}
	if msg := res.AgentMessage(""); msg != "Вызов отклонён" || strings.Contains(msg, "нельзя") {
		t.Fatalf("сообщение агенту: %q", msg)
	}
}

// Срок вышел на сервере: вызов отклоняется как timeout.
func TestDM22_ApprovalTimeoutDenies(t *testing.T) {
	// Часы сервера идут на минуту за каждое обращение: срок 10 минут
	// истекает за несколько опросов.
	var mu sync.Mutex
	now := time.Now().UTC()
	e := newApprovalEnv(t, func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(time.Minute)
		return now
	})
	res := e.client.Await(context.Background(), approvalRequest(), nil)
	if res.Approved() || res.State != gateway.ApprovalTimeout || res.ID == "" {
		t.Fatalf("итог: %+v", res)
	}
	if res.AgentMessage("правило") != "Вызов не подтверждён вовремя" {
		t.Fatal(res.AgentMessage("правило"))
	}
}

// Клиент закрыл поток: запрос отменяется на сервере.
func TestDM22_ClientCancelClosesRequest(t *testing.T) {
	e := newApprovalEnv(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan gateway.ApprovalResult, 1)
	go func() { done <- e.client.Await(ctx, approvalRequest(), nil) }()
	id := e.pendingID(t)
	cancel()
	res := <-done
	if res.Approved() || res.State != gateway.ApprovalCancelled {
		t.Fatalf("итог: %+v", res)
	}
	if r, err := e.svc.Get(context.Background(), id); err != nil || r.State != approvals.Cancelled {
		t.Fatalf("на сервере: %s %v", r.State, err)
	}
}

func TestDM22_ApprovalServerUnavailable(t *testing.T) {
	e := newApprovalEnv(t, nil)
	e.srv.Close()
	res := e.client.Await(context.Background(), approvalRequest(), nil)
	if res.Approved() || res.State != gateway.ApprovalUnavailable || res.ID != "" {
		t.Fatalf("итог: %+v", res)
	}
	// 5xx сервера — тоже отказ.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if res := e.newClient(t, srv.URL).Await(context.Background(), approvalRequest(), nil); res.State != gateway.ApprovalUnavailable {
		t.Fatalf("500: %+v", res)
	}
}

func TestDM22_ApprovalQueueFull(t *testing.T) {
	e := newApprovalEnv(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range approvals.MaxPerAgent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.client.Await(ctx, approvalRequest(), nil)
		}()
	}
	for range 500 {
		if len(e.client.Pending()) == approvals.MaxPerAgent {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	res := e.client.Await(context.Background(), approvalRequest(), nil)
	cancel()
	wg.Wait()
	if res.Approved() || res.State != gateway.ApprovalQueueFull || res.ID != "" {
		t.Fatalf("итог: %+v", res)
	}
}

// Ответ сервера, не связанный с запросом (другой хеш аргументов), —
// отказ: решение действует только для показанных аргументов.
func TestDM22_ApprovalResponseMismatchDenied(t *testing.T) {
	e := newApprovalEnv(t, nil)
	id := "01900000-0000-7000-8000-0000000000aa"
	status := func(state, hash string) map[string]any {
		return map[string]any{"id": id, "state": state, "args_hash": hash, "approved_hash": strings.Repeat("ab", 32),
			"deadline": time.Now().Add(time.Minute)}
	}
	good := gateway.ToolArgsHash(e.hasher, []byte(approvalArgs))
	for name, c := range map[string]struct {
		create, poll map[string]any
		want         gateway.ApprovalState
	}{
		"создание с чужим хешем": {status("pending", strings.Repeat("cd", 32)), nil, gateway.ApprovalUnavailable},
		"решение с чужим хешем":  {status("pending", good), status("approved", strings.Repeat("cd", 32)), gateway.ApprovalDenied},
		"неизвестное состояние":  {status("pending", good), status("maybe", good), gateway.ApprovalDenied},
		"создание не pending":    {status("approved", good), nil, gateway.ApprovalUnavailable},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cancel") {
				_ = json.NewEncoder(w).Encode(status("cancelled", good)) //nolint:gosec // G104: ответ тестового сервера
				return
			}
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(c.create) //nolint:gosec // G104: ответ тестового сервера
				return
			}
			_ = json.NewEncoder(w).Encode(c.poll) //nolint:gosec // G104: ответ тестового сервера
		}))
		res := e.newClient(t, srv.URL).Await(context.Background(), approvalRequest(), nil)
		srv.Close()
		if res.Approved() || res.State != c.want {
			t.Errorf("%s: %+v", name, res)
		}
	}
}

// Путь chat: срок не больше 5 минут; без срока — по умолчанию политики.
func TestApprovalChatTimeoutCapped(t *testing.T) {
	e := newApprovalEnv(t, nil)
	for _, c := range []struct {
		path    gateway.ApprovalPath
		timeout time.Duration
		want    time.Duration
	}{
		{gateway.ApprovalPathChat, 30 * time.Minute, gateway.MaxChatApprovalWait},
		{gateway.ApprovalPathMCP, 30 * time.Minute, 30 * time.Minute},
		{gateway.ApprovalPathMCP, 0, policy.DefaultApprovalTimeout},
		{gateway.ApprovalPathMCP, 10 * time.Second, time.Minute},
	} {
		req := approvalRequest()
		req.Path, req.Timeout = c.path, c.timeout
		if c.path == gateway.ApprovalPathChat {
			req.Agent, req.Server, req.Tool, req.ApprovedHash = "", policy.FunctionServer, "send_mail", ""
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { e.client.Await(ctx, req, nil); close(done) }()
		id := e.pendingID(t)
		r, err := e.svc.Get(context.Background(), id)
		cancel()
		<-done
		if err != nil || r.Deadline.Sub(r.CreatedAt) != c.want {
			t.Errorf("%s %v: срок %v %v", c.path, c.timeout, r.Deadline.Sub(r.CreatedAt), err)
		}
	}
}

// Heartbeat передаёт ожидающие запросы только серверу, который сообщил о
// поддержке очереди (approvals: true).
func TestHeartbeatApprovalsPending(t *testing.T) {
	var bodies []map[string]any
	supported := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b) //nolint:gosec // G104: тело проверяет тест
		bodies = append(bodies, b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now(), "interval_seconds": 60, "approvals": supported}) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	run := func(pending func() []string) {
		n := 0
		gateway.RunHeartbeat(context.Background(), gateway.HeartbeatConfig{Client: srv.Client(), Server: u, Version: "1",
			Logger: quiet(), PendingApprovals: pending, Sleep: func(context.Context, time.Duration) bool { n++; return n < 2 }})
	}
	id := "01900000-0000-7000-8000-0000000000aa"
	run(func() []string { return []string{id} })
	run(func() []string { return []string{} })
	supported = false
	run(func() []string { return []string{id} })
	if len(bodies) != 6 {
		t.Fatalf("heartbeat: %d", len(bodies))
	}
	if _, ok := bodies[0]["approvals_pending"]; ok {
		t.Fatalf("первый heartbeat со списком: %v", bodies[0])
	}
	if l, ok := bodies[1]["approvals_pending"].([]any); !ok || len(l) != 1 || l[0] != id {
		t.Fatalf("второй heartbeat: %v", bodies[1])
	}
	// Пустой список передаётся: сервер закроет все запросы шлюза старше минуты.
	if l, ok := bodies[3]["approvals_pending"].([]any); !ok || len(l) != 0 {
		t.Fatalf("пустой список: %v", bodies[3])
	}
	if _, ok := bodies[5]["approvals_pending"]; ok {
		t.Fatalf("сервер без очереди: %v", bodies[5])
	}
}
