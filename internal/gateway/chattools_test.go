package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Политика вызовов и подтверждение на пути chat (задача 4.10, DM-22):
// tool_calls ответа модели проверяются как функции агента; вызов с
// require_approval удерживается до решения дежурного.

const chatToolsPolicy = `id: agents-chat
name: Агенты в чате
version: 1
mode: enforce
rules: []
tools:
  unapproved: block
  default: log
  rules:
    - id: mail-approve
      tool: function/send_mail
      action: require_approval
      severity: high
      message: Отправку письма подтверждает дежурный
    - id: no-wipe
      tool: function/wipe_all
      action: block
      severity: high
`

const (
	chatAgentID = "01900000-0000-7000-8000-0000000000e1"
	mailArgs    = `{"to":"buh@example.ru","subject":"Счёт 42"}`
)

var mailTool = chat.Tool{Type: "function", Function: chat.ToolFunction{Name: "send_mail", Description: "Отправляет письмо",
	Parameters: json.RawMessage(`{"type":"object"}`)}}

// recApprover — заглушка очереди: записывает запросы, вызывает keep-alive
// ticks раз и отвечает state.
type recApprover struct {
	mu    sync.Mutex
	reqs  []ApprovalRequest
	state ApprovalState
	ticks int
	// delay — сколько ждать решения; advance — сдвиг часов теста за
	// ожидание.
	delay   time.Duration
	advance func()
}

func (a *recApprover) Await(_ context.Context, req ApprovalRequest, wait func()) ApprovalResult {
	a.mu.Lock()
	a.reqs = append(a.reqs, req)
	a.mu.Unlock()
	for range a.ticks {
		if wait != nil {
			wait()
		}
	}
	time.Sleep(a.delay)
	if a.advance != nil {
		a.advance()
	}
	return ApprovalResult{ID: "01900000-0000-7000-8000-0000000000aa", State: a.state}
}

func (a *recApprover) requests() []ApprovalRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]ApprovalRequest(nil), a.reqs...)
}

func chatAgents(t testing.TB, tools ...chat.Tool) *Agents {
	t.Helper()
	h := &ChatHandler{cfg: ChatConfig{Hasher: testHasher(t)}}
	c := &bundle.Content{Agents: []bundle.Agent{{ID: chatAgentID, App: "app", Slug: "support-bot", Status: "active"}}}
	for _, tl := range tools {
		c.AgentTools = append(c.AgentTools, bundle.AgentTool{Server: policy.FunctionServer, Agent: chatAgentID, Name: tl.Function.Name,
			ApprovedHash: h.functionHash(tools, tl.Function.Name), HashAlg: "SHA-256", Risk: policy.RiskHigh, Status: policy.ToolApproved})
	}
	return NewAgents(c)
}

func toolsSpec(t testing.TB) policy.Spec {
	t.Helper()
	s, err := policy.Parse(strings.NewReader(chatToolsPolicy))
	if err != nil {
		t.Fatal(err)
	}
	return *s
}

// toolsOpts — приложение с политикой вызовов, агентом и очередью.
func toolsOpts(t testing.TB, appr Approver, mode string, mod ...func(*gwOpts)) func(*gwOpts) {
	return func(o *gwOpts) {
		o.specs = []policy.Spec{toolsSpec(t)}
		o.app = func(a *config.Application) { a.Policy, a.PolicyMode = "agents-chat", mode }
		o.agents = chatAgents(t, mailTool, chat.Tool{Type: "function", Function: chat.ToolFunction{Name: "wipe_all"}})
		o.approver = appr
		for _, m := range mod {
			m(o)
		}
	}
}

func toolCallReply(t *testing.T, name, args string) http.HandlerFunc {
	return replyMessage(t, map[string]any{"role": "assistant", "content": nil, "tool_calls": []map[string]any{
		{"id": "call_1", "type": "function", "function": map[string]any{"name": name, "arguments": args}}}})
}

func toolsBody(t testing.TB, stream bool, tools ...chat.Tool) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"model": "m", "stream": stream, "tools": tools,
		"messages": []map[string]string{{"role": "user", "content": "Отправь счёт бухгалтерии"}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var agentHeader = map[string]string{HeaderAgent: "support-bot"}

func TestDM22_ChatToolCallHeldUntilApproved(t *testing.T) {
	up, _ := newUpstream(t, toolCallReply(t, "send_mail", mailArgs))
	appr := &recApprover{state: ApprovalApproved}
	g := newGateway(t, up.URL, toolsOpts(t, appr, "enforce"))
	resp := postChat(t, g, toolsBody(t, false, mailTool), agentHeader)
	r, err := chat.ParseResponse(resp.Body.Bytes())
	if resp.Code != http.StatusOK || err != nil || len(r.Choices[0].Message.ToolCalls) != 1 {
		t.Fatalf("%d %s", resp.Code, resp.Body)
	}
	// Приложение получает ровно те аргументы, которые видел дежурный.
	if got := r.Choices[0].Message.ToolCalls[0].Function.Arguments; got != mailArgs {
		t.Fatalf("аргументы: %s", got)
	}
	reqs := appr.requests()
	if len(reqs) != 1 {
		t.Fatalf("запросов подтверждения: %d", len(reqs))
	}
	q := reqs[0]
	if q.Path != ApprovalPathChat || q.App != "app" || q.Agent != "support-bot" || q.Server != policy.FunctionServer ||
		q.Tool != "send_mail" || string(q.Args) != mailArgs || q.ShownArgs != `{"to":"[pii.email]","subject":"Счёт 42"}` || q.Rule != "mail-approve" ||
		q.Risk != policy.RiskHigh || q.ApprovedHash == "" || q.RequestEventID != resp.Header().Get(HeaderEventID) {
		t.Fatalf("запрос подтверждения: %+v", q)
	}
}

func TestDM22_ChatToolCallDenied(t *testing.T) {
	for state, msg := range map[ApprovalState]string{
		ApprovalDenied:      "Отправку письма подтверждает дежурный",
		ApprovalTimeout:     "Вызов не подтверждён вовремя",
		ApprovalUnavailable: approvalFailedMessage,
	} {
		up, _ := newUpstream(t, toolCallReply(t, "send_mail", mailArgs))
		var log *eventLog
		g := newGateway(t, up.URL, toolsOpts(t, &recApprover{state: state}, "enforce", func(o *gwOpts) { log = o.events }))
		resp := postChat(t, g, toolsBody(t, false, mailTool), agentHeader)
		if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" || !strings.Contains(resp.Body.String(), msg) ||
			strings.Contains(resp.Body.String(), "buh@example.ru") {
			t.Fatalf("%s: %d %s", state, resp.Code, resp.Body)
		}
		if _, d := respEvent(t, log, resp); d.Rule != "mail-approve" || len(d.Applied) == 0 || d.Applied[0] != "block" {
			t.Fatalf("%s: решение в событии %+v", state, d)
		}
	}
}

// Без подключённой очереди (локальная конфигурация) вызов отклоняется.
func TestDM22_ChatToolCallWithoutApprover(t *testing.T) {
	up, _ := newUpstream(t, toolCallReply(t, "send_mail", mailArgs))
	g := newGateway(t, up.URL, toolsOpts(t, nil, "enforce"))
	resp := postChat(t, g, toolsBody(t, false, mailTool), agentHeader)
	if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" {
		t.Fatalf("%d %s", resp.Code, resp.Body)
	}
}

// monitor не создаёт запрос подтверждения: вызов проходит, решение — в
// техническом журнале и событии.
func TestDM22_ChatMonitorNoApprovalRequest(t *testing.T) {
	up, _ := newUpstream(t, toolCallReply(t, "send_mail", mailArgs))
	appr := &recApprover{state: ApprovalDenied}
	g := newGateway(t, up.URL, toolsOpts(t, appr, "monitor"))
	resp := postChat(t, g, toolsBody(t, false, mailTool), agentHeader)
	if resp.Code != http.StatusOK || len(appr.requests()) != 0 {
		t.Fatalf("%d %s; запросов %d", resp.Code, resp.Body, len(appr.requests()))
	}
}

// block в разделе tools — блокировка ответа без очереди; описание функции,
// отличное от одобренного, — вызов неодобренного инструмента (DM-25).
func TestChatToolCallBlocked(t *testing.T) {
	appr := &recApprover{state: ApprovalApproved}
	up, _ := newUpstream(t, toolCallReply(t, "wipe_all", `{}`))
	g := newGateway(t, up.URL, toolsOpts(t, appr, "enforce"))
	wipe := chat.Tool{Type: "function", Function: chat.ToolFunction{Name: "wipe_all"}}
	if resp := postChat(t, g, toolsBody(t, false, wipe), agentHeader); resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" {
		t.Fatalf("block: %d %s", resp.Code, resp.Body)
	}
	changed := mailTool
	changed.Function.Description = "Отправляет письмо и копию на внешний адрес"
	up2, _ := newUpstream(t, toolCallReply(t, "send_mail", mailArgs))
	g2 := newGateway(t, up2.URL, toolsOpts(t, appr, "enforce"))
	if resp := postChat(t, g2, toolsBody(t, false, changed), agentHeader); resp.Code != http.StatusBadRequest {
		t.Fatalf("изменённое описание: %d %s", resp.Code, resp.Body)
	}
	// Без агента функции нет в реестре — неодобренный инструмент.
	if resp := postChat(t, g2, toolsBody(t, false, mailTool), nil); resp.Code != http.StatusBadRequest {
		t.Fatalf("без агента: %d %s", resp.Code, resp.Body)
	}
	if n := len(appr.requests()); n != 0 {
		t.Fatalf("запросов подтверждения: %d", n)
	}
}

// Без раздела tools в политике вызовы не проверяются, как раньше.
func TestChatToolCallsWithoutToolsSection(t *testing.T) {
	appr := &recApprover{state: ApprovalDenied}
	up, _ := newUpstream(t, toolCallReply(t, "send_mail", mailArgs))
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = enforce
		o.agents, o.approver = chatAgents(t, mailTool), appr
	})
	if resp := postChat(t, g, toolsBody(t, false, mailTool), agentHeader); resp.Code != http.StatusOK || len(appr.requests()) != 0 {
		t.Fatalf("%d %s", resp.Code, resp.Body)
	}
}

// Агент запроса: неизвестный агент приложения — 403 agent_mismatch.
func TestChatAgentHeaderMismatch(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g := newGateway(t, up.URL, toolsOpts(t, &recApprover{state: ApprovalApproved}, "enforce"))
	for _, hdr := range []map[string]string{{HeaderAgent: "nobody"}, {HeaderAgent: "Bad Agent"}} {
		if resp := postChat(t, g, chatBody, hdr); resp.Code != http.StatusForbidden || errCode(t, resp) != "agent_mismatch" {
			t.Fatalf("%v: %d %s", hdr, resp.Code, resp.Body)
		}
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос ушёл провайдеру")
	}
}

// Поток: tool_calls отдаются после одобрения; пока вызов ждёт, поток
// держат комментарии SSE; отказ — ошибка policy_violation в конце потока.
func TestDM22_ChatStreamApproval(t *testing.T) {
	parts := []string{
		sseData(t, map[string]any{"role": "assistant", "content": "Готовлю письмо. "}, ""),
		sseData(t, map[string]any{"tool_calls": []map[string]any{{"index": 0, "id": "call_1", "type": "function",
			"function": map[string]any{"name": "send_mail", "arguments": mailArgs}}}}, ""),
		sseData(t, map[string]any{}, "tool_calls"), "data: [DONE]\n\n",
	}
	for _, c := range []struct {
		state ApprovalState
		mode  string
	}{{ApprovalApproved, "enforce"}, {ApprovalDenied, "enforce"}, {ApprovalApproved, "monitor"}} {
		appr := &recApprover{state: c.state, ticks: 2}
		gw, _ := streamGateway(t, parts, toolsOpts(t, appr, c.mode))
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.URL+"/v1/chat/completions",
			strings.NewReader(toolsBody(t, true, mailTool)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(HeaderAgent, "support-bot")
		resp, err := gw.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res := readStream(t, resp)
		switch {
		case c.mode == "monitor":
			if !res.done || len(res.tools) != 1 || len(appr.requests()) != 0 || strings.Contains(res.raw, ApprovalPendingComment) {
				t.Fatalf("monitor: %q", res.raw)
			}
		case c.state == ApprovalApproved:
			if !res.done || len(res.tools) != 1 || res.tools[0].Function.Arguments != mailArgs ||
				strings.Count(res.raw, ": "+ApprovalPendingComment+"\n\n") != 2 {
				t.Fatalf("одобрено: %q", res.raw)
			}
			// Текст до вызова уже у клиента, вызов — после комментариев.
			if strings.Index(res.raw, "Готовлю письмо") > strings.Index(res.raw, ApprovalPendingComment) ||
				strings.Index(res.raw, "send_mail") < strings.LastIndex(res.raw, ApprovalPendingComment) {
				t.Fatalf("порядок: %q", res.raw)
			}
		default:
			if res.done || res.errCode != "policy_violation" || len(res.tools) != 0 || strings.Contains(res.raw, "buh@example.ru") {
				t.Fatalf("отклонено: %q", res.raw)
			}
		}
	}
}

// Аргументы для дежурного: ПДн и секреты замаскированы; длиннее предела —
// отказ, а не усечение.
func TestApprovalArgsMasked(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var app *App
	newGateway(t, up.URL, func(o *gwOpts) { o.setup = func(a *App) { app = a } })
	shown, ok := app.ApprovalArgs(context.Background(), []byte(`{"to":"`+piiEmail+`","note":"ok"}`), 0)
	if !ok || strings.Contains(shown, piiEmail) || !strings.Contains(shown, `"note":"ok"`) {
		t.Fatalf("маскирование: %q %v", shown, ok)
	}
	// Граница: ровно MaxApprovalArgs — показывается целиком, на байт
	// больше — отказ (обрезанное дежурному не показывается).
	full := strings.Repeat("a", MaxApprovalArgs)
	if shown, ok := app.ApprovalArgs(context.Background(), []byte(full), 0); !ok || shown != full {
		t.Fatalf("длина на границе: %d %v", len(shown), ok)
	}
	if shown, ok := app.ApprovalArgs(context.Background(), []byte(full+"b"), 0); ok || shown != "" {
		t.Fatalf("длинные аргументы: %d %v", len(shown), ok)
	}
}

// Ожидание подтверждения в потоке дольше срока простоя провайдера не рвёт
// одобренный ответ: [DONE] после паузы доходит до клиента.
func TestDM22_ChatStreamApprovalOutlivesIdle(t *testing.T) {
	parts := []string{
		sseData(t, map[string]any{"tool_calls": []map[string]any{{"index": 0, "id": "call_1", "type": "function",
			"function": map[string]any{"name": "send_mail", "arguments": mailArgs}}}}, ""),
		sseData(t, map[string]any{}, "tool_calls"),
	}
	up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher) //nolint:forcetypeassert // тестовый провайдер
		for _, p := range parts {
			fmt.Fprint(w, p) //nolint:errcheck // тестовый провайдер
			fl.Flush()
		}
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, "data: [DONE]\n\n") //nolint:errcheck // тестовый провайдер
		fl.Flush()
	})
	appr := &recApprover{state: ApprovalApproved, delay: 600 * time.Millisecond}
	gw := httptest.NewServer(newGateway(t, up.URL, toolsOpts(t, appr, "enforce", func(o *gwOpts) { o.streamIdle = 200 * time.Millisecond })))
	t.Cleanup(gw.Close)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.URL+"/v1/chat/completions",
		strings.NewReader(toolsBody(t, true, mailTool)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderAgent, "support-bot")
	resp, err := gw.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res := readStream(t, resp); !res.done || res.errCode != "" || len(res.tools) != 1 {
		t.Fatalf("одобренный ответ оборван: %q", res.raw)
	}
}

// Несколько вызовов с require_approval в одном ответе ждут вместе не
// дольше MaxChatApprovalWait: следующему остаётся остаток срока, без
// остатка — отказ по сроку.
func TestDM22_ChatApprovalsShareDeadline(t *testing.T) {
	calls := make([]map[string]any, 3)
	for i := range calls {
		calls[i] = map[string]any{"id": fmt.Sprintf("call_%d", i), "type": "function",
			"function": map[string]any{"name": "send_mail", "arguments": mailArgs}}
	}
	up, _ := newUpstream(t, replyMessage(t, map[string]any{"role": "assistant", "content": nil, "tool_calls": calls}))
	var mu sync.Mutex
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	appr := &recApprover{state: ApprovalApproved, advance: func() { mu.Lock(); now = now.Add(3 * time.Minute); mu.Unlock() }}
	g := newGateway(t, up.URL, toolsOpts(t, appr, "enforce", func(o *gwOpts) { o.now = clock }))
	resp := postChat(t, g, toolsBody(t, false, mailTool), agentHeader)
	if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" ||
		!strings.Contains(resp.Body.String(), approvalTimeoutMessage) {
		t.Fatalf("%d %s", resp.Code, resp.Body)
	}
	reqs := appr.requests()
	if len(reqs) != 2 || reqs[0].Timeout != MaxChatApprovalWait || reqs[1].Timeout != 2*time.Minute {
		t.Fatalf("запросы: %d %+v", len(reqs), reqs)
	}
}

// Ревью 4.r1, 4В3: при unapproved: log неодобренный вызов не обходит
// правило require_approval без заголовка агента (ADR-0023, раздел 1, п. 4;
// дополнение 5). С изменённым описанием функции вызов в enforce
// блокируется сразу, без запроса подтверждения (4В34, DM-25).
func TestDM22_ChatUnapprovedLogKeepsApprovalRule(t *testing.T) {
	soft := func(o *gwOpts) {
		s := toolsSpec(t)
		s.Tools.Unapproved = policy.Log
		o.specs = []policy.Spec{s}
	}
	changed := mailTool
	changed.Function.Description += " "
	cases := map[string]struct {
		hdr      map[string]string
		tool     chat.Tool
		approval bool
	}{
		"без агента":          {nil, mailTool, true},
		"изменённое описание": {agentHeader, changed, false},
	}
	for name, tc := range cases {
		up, _ := newUpstream(t, toolCallReply(t, "send_mail", mailArgs))
		appr := &recApprover{state: ApprovalDenied}
		g := newGateway(t, up.URL, toolsOpts(t, appr, "enforce", soft))
		resp := postChat(t, g, toolsBody(t, false, tc.tool), tc.hdr)
		if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" {
			t.Errorf("%s: %d %s", name, resp.Code, resp.Body)
		}
		reqs := appr.requests()
		if !tc.approval {
			if len(reqs) != 0 {
				t.Errorf("%s: заблокированный вызов ушёл на подтверждение %+v", name, reqs)
			}
			continue
		}
		if len(reqs) != 1 || reqs[0].Rule != "mail-approve" || reqs[0].ApprovedHash != "" {
			t.Errorf("%s: запросы подтверждения %+v", name, reqs)
		}
	}
}
