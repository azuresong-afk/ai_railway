package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/tooldesc"
)

// Политика вызовов на пути chat (ADR-0023, разделы 2 и 5; задача 4.10):
// вызовы функций в ответе модели (tool_calls) проверяются по разделу tools
// политики приложения как инструменты (агент, function/<имя>). Блокировка
// оформляется как блокировка ответа (policy_violation); require_approval
// удерживает ответ до решения дежурного, все вызовы ответа вместе — не
// дольше MaxChatApprovalWait (и запаса на ответ сервера).
// Без раздела tools в версии политики вызовы не проверяются, как раньше.

// ApprovalPendingComment — комментарий SSE, которым шлюз держит поток,
// пока вызов ждёт подтверждения.
const ApprovalPendingComment = "aisec-approval-pending"

// minApprovalWait — наименьший срок запроса подтверждения (как у сервера):
// если от общего срока ответа осталось меньше, вызов отклоняется по сроку.
const minApprovalWait = time.Minute

// toolsCheck — по ответу нужно решение политики вызовов.
func toolsCheck(app *App, resp *chat.Response) bool {
	return app.Policy.ToolsDeclared() && len(resp.Choices) > 0 && len(resp.Choices[0].Message.ToolCalls) > 0
}

// toolBlock — вызов не передаётся: правило и сообщение для клиента.
type toolBlock struct {
	rule, message string
}

// agent определяет агента запроса чата (ADR-0023, раздел 1): агент
// необязателен, но заголовок X-AISec-Agent, не совпадающий с агентом ключа
// или не называющий агента приложения, — 403. Приложение без агентов
// заголовок не проверяет. При ошибке ответ уже записан.
func (h *ChatHandler) agent(w http.ResponseWriter, r *http.Request, app *App) (*Agent, bool) {
	reg := h.cfg.Router.Agents()
	if !reg.HasAgents(app.ID) {
		return nil, true
	}
	id, ok := IdentityFrom(r.Context())
	if !ok {
		return nil, true
	}
	ag, err := reg.Resolve(*id, r.Header.Values(HeaderAgent))
	if err != nil {
		err.Write(w)
		return nil, false
	}
	return ag, true
}

// functionHash — хеш описания функции из запроса (tools) в форме
// дескриптора инструмента (name, description, inputSchema); пусто —
// функции нет в запросе или описание не разбирается.
func (h *ChatHandler) functionHash(tools []chat.Tool, name string) string {
	i := slices.IndexFunc(tools, func(t chat.Tool) bool { return t.Function.Name == name })
	if i < 0 || h.cfg.Hasher == nil {
		return ""
	}
	f := tools[i].Function
	desc := map[string]any{"name": f.Name}
	if f.Description != "" {
		desc["description"] = f.Description
	}
	if len(f.Parameters) > 0 {
		desc["inputSchema"] = f.Parameters
	}
	raw, err := json.Marshal(desc)
	if err != nil {
		return ""
	}
	d, err := tooldesc.Parse(raw)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(tooldesc.Hash(h.cfg.Hasher, d))
}

// decideTools — решение политики вызовов по каждому вызову ответа. Вызов
// с require_approval ждёт решения дежурного (wait — keep-alive потока,
// nil — без него). nil — все вызовы передаются как есть.
func (h *ChatHandler) decideTools(ctx context.Context, app *App, rec *record, calls []chat.ToolCall, wait func()) *toolBlock {
	reg, agent := h.cfg.Router.Agents(), rec.agent
	session := ""
	if rec.sess != nil {
		session = rec.sess.ev.ID
	}
	// until — общий срок ожидания подтверждений ответа: несколько вызовов
	// с require_approval ждут по очереди, но вместе не дольше
	// MaxChatApprovalWait.
	var until time.Time
	for i := range calls {
		name, args := calls[i].Function.Name, []byte(calls[i].Function.Arguments)
		c := policy.ToolCall{Mode: app.Mode, App: app.ID, Session: session, Server: policy.FunctionServer, Name: name,
			Args: args, Now: h.cfg.Now()}
		var approved string
		if agent != nil {
			c.Agent = agent.Slug
			if t, ok := reg.Function(agent.ID, name); ok {
				c.Status, c.Risk = t.Status, t.Risk
				c.HashMatch = t.ApprovedHash != "" && h.functionHash(rec.tools, name) == t.ApprovedHash
				approved = t.ApprovedHash
			}
		}
		if h.cfg.Hasher != nil {
			c.ArgsHash = ToolArgsHash(h.cfg.Hasher, args)
		}
		d := app.Policy.DecideTool(c, h.cfg.ToolRate)
		switch {
		case d.Block:
			h.logger.Info("вызов функции заблокирован политикой вызовов", "app", app.ID, "agent", c.Agent,
				"tool", policy.FunctionServer+"/"+name, "rule", d.Rule, "event_id", rec.ev.ID)
			return &toolBlock{rule: d.Rule, message: d.Message}
		case !d.Approval:
			continue
		}
		now := h.cfg.Now()
		if until.IsZero() {
			until = now.Add(MaxChatApprovalWait)
		}
		left := until.Sub(now)
		if left < minApprovalWait {
			h.logger.Info("подтверждение вызова функции: общий срок ожидания ответа исчерпан", "app", app.ID, "agent", c.Agent,
				"tool", policy.FunctionServer+"/"+name, "rule", d.Rule, "event_id", rec.ev.ID)
			return &toolBlock{rule: d.Rule, message: approvalTimeoutMessage}
		}
		if d.ApprovalTimeout <= 0 {
			d.ApprovalTimeout = policy.DefaultApprovalTimeout
		}
		d.ApprovalTimeout = min(d.ApprovalTimeout, left)
		res := h.approve(ctx, app, rec, c, approved, d, wait)
		h.logger.Info("подтверждение вызова функции", "app", app.ID, "agent", c.Agent, "tool", policy.FunctionServer+"/"+name,
			"rule", d.Rule, "approval_id", res.ID, "state", string(res.State), "waited_ms", res.Waited.Milliseconds(),
			"event_id", rec.ev.ID)
		if !res.Approved() {
			return &toolBlock{rule: d.Rule, message: res.AgentMessage(d.Message)}
		}
	}
	return nil
}

// approve ставит вызов в очередь подтверждений и ждёт решения.
func (h *ChatHandler) approve(ctx context.Context, app *App, rec *record, c policy.ToolCall, approvedHash string,
	d policy.ToolDecision, wait func()) ApprovalResult {
	if h.cfg.Hasher == nil {
		return ApprovalResult{State: ApprovalUnavailable}
	}
	shown, ok := app.ApprovalArgs(ctx, c.Args, h.cfg.DetectorTimeout)
	if !ok {
		// Аргументы без маскирования дежурному не показываются: вызов не
		// подтверждается.
		return ApprovalResult{State: ApprovalUnavailable}
	}
	if !c.HashMatch {
		approvedHash = ""
	}
	return h.cfg.Router.Approver().Await(ctx, ApprovalRequest{Path: ApprovalPathChat, App: app.ID, Agent: c.Agent,
		User: rec.ev.User, Session: c.Session, Server: policy.FunctionServer, Tool: c.Name, ApprovedHash: approvedHash,
		Risk: risk(c.Risk), Rule: d.Rule, Message: d.Message, Severity: d.Severity, Args: c.Args, ShownArgs: shown,
		Timeout: d.ApprovalTimeout, RequestEventID: rec.ev.ID}, wait)
}

// risk — уровень риска для очереди: инструмент вне реестра — high.
func risk(r policy.ToolRisk) policy.ToolRisk {
	if policy.ValidRisk(r) {
		return r
	}
	return policy.RiskHigh
}

// ApprovalArgs — аргументы вызова для дежурного (ADR-0023, раздел 5): ПДн
// и секреты замаскированы категорией находки независимо от режима
// хранения приложения. false — замаскировать не удалось (сбой детектора)
// или маскированные аргументы длиннее MaxApprovalArgs: показывать такие
// аргументы нельзя, вызов не подтверждается.
func (a *App) ApprovalArgs(ctx context.Context, args []byte, timeout time.Duration) (string, bool) {
	if timeout <= 0 {
		timeout = DefaultDetectorTimeout
	}
	text := string(args)
	var ids []string
	for _, id := range maskDetectors {
		if _, ok := a.Detectors.Get(id); ok {
			ids = append(ids, id)
		}
	}
	if len(ids) < len(maskDetectors) {
		return "", false
	}
	// pii.ner — если он в политике (4Н33 ревью 4.r4): имена закрыты и в
	// событии (maskFindings). Сбой ML — не отказ: ПДн с контрольными
	// суммами закрывает pii.ru.
	if _, ok := a.Detectors.Get(builtin.PIINERID); ok && a.Policy != nil &&
		(slices.Contains(a.Policy.Detectors(detect.Input), builtin.PIINERID) ||
			slices.Contains(a.Policy.Detectors(detect.Output), builtin.PIINERID)) {
		ids = append(ids, builtin.PIINERID)
	}
	fs, rerrs, err := a.Detectors.Run(ctx, ids, detect.Text{Text: text, Direction: detect.Output, Source: detect.SourceOutput},
		detectorTimeout(timeout, len(text)))
	if err != nil {
		return "", false
	}
	for _, re := range rerrs {
		if !mlBacked(a.Detectors, re.Detector) {
			return "", false
		}
	}
	spans := make([]span, 0, len(fs))
	for _, f := range fs {
		spans = append(spans, span{f.Start, f.End, "[" + f.Category + "]"})
	}
	out := rewrite(text, spans)
	if len(out) > MaxApprovalArgs {
		// Обрезанные аргументы показывать нельзя: дежурный одобрил бы то,
		// чего не видел, а дальше ушли бы аргументы целиком.
		return "", false
	}
	return out, true
}
