package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

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

// Аргументы для дежурного: ПДн и секреты замаскированы, длина ограничена.
func TestApprovalArgsMasked(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var app *App
	newGateway(t, up.URL, func(o *gwOpts) { o.setup = func(a *App) { app = a } })
	shown, ok := app.ApprovalArgs(context.Background(), []byte(`{"to":"`+piiEmail+`","note":"ok"}`), 0)
	if !ok || strings.Contains(shown, piiEmail) || !strings.Contains(shown, `"note":"ok"`) {
		t.Fatalf("маскирование: %q %v", shown, ok)
	}
	long := strings.Repeat("я", MaxApprovalArgs)
	if shown, ok := app.ApprovalArgs(context.Background(), []byte(long), 0); !ok || len(shown) > MaxApprovalArgs ||
		!strings.HasPrefix(long, shown) {
		t.Fatalf("длина: %d %v", len(shown), ok)
	}
}
