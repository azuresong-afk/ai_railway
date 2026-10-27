package gateway

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/injection"
	"github.com/azuresong-afk/ai_railway/internal/detect/unihidden"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/mcp"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
	"github.com/azuresong-afk/ai_railway/internal/policy/tooldesc"
)

// Методы MCP-прокси с проверками содержимого (ADR-0023, раздел 6).

// descriptionDetectors — встроенная проверка описаний инструментов,
// ресурсов, промптов и instructions сервера (DM-24): работает и без
// входных правил политики с источником tool.
var descriptionDetectors = []string{injection.ID, unihidden.ID}

// descriptionMinScore — порог находки встроенной проверки (как у корпусов).
const descriptionMinScore = 0.5

// threatPoisoned — строка матрицы находок в описаниях.
const threatPoisoned = policy.ThreatToolPoisoned

// Правила событий MCP-прокси без правила политики.
const (
	ruleMCPDescriptions = "mcp.descriptions"
	ruleMCPResult       = "mcp.result"
)

// msgApprovalPending — текст notifications/progress во время ожидания
// подтверждения (ADR-0023, раздел 5).
const msgApprovalPending = "Ожидает подтверждения"

// dropServer — сообщения сервера до ответа, кроме разрешённых
// уведомлений, клиенту не передаются (запросы к клиенту, журнал сервера).
func (m *MCPHandler) dropServer(q *mcpReq) func(*mcp.Message) bool {
	return func(msg *mcp.Message) bool {
		if q.sse != nil && mcp.ServerMessageAllowed(msg, false) {
			q.sse.send(mcp.Sanitize(msg))
			return q.sse.err == nil
		}
		q.ev.Dropped++
		return true
	}
}

// checkDescriptions — встроенная проверка строк описаний: признак находки
// (строка DM-24) и признак сбоя по каждому фрагменту, находки и сбои.
// Сбой детектора — не находка: описание, которое не удалось проверить,
// агенту не показывается (fail-closed, если приложение не fail_open), но
// отравленным не считается — ни в событии, ни в реестре.
func (m *MCPHandler) checkDescriptions(ctx context.Context, app *App, texts []inspectText) ([]bool, []bool, *inspection, error) {
	flagged := make([]bool, len(texts))
	failed := make([]bool, len(texts))
	in := &inspection{}
	var ids []string
	for _, id := range descriptionDetectors {
		if _, ok := app.Detectors.Get(id); ok {
			ids = append(ids, id)
		}
	}
	base := m.h.cfg.DetectorTimeout
	if base <= 0 {
		base = DefaultDetectorTimeout
	}
	for i, t := range texts {
		if t.Text == "" {
			continue
		}
		fs, rerrs, err := app.Detectors.Run(ctx, ids, detect.Text{Text: t.Text, Direction: detect.Input, Source: detect.SourceTool},
			detectorTimeout(base, len(t.Text)))
		if err != nil {
			return nil, nil, nil, err
		}
		for _, f := range fs {
			if f.Score < descriptionMinScore {
				continue
			}
			f.Threat = threatPoisoned
			in.Findings = append(in.Findings, locatedFinding{Finding: f, Text: i})
			flagged[i] = true
		}
		for _, re := range rerrs {
			in.Failures = append(in.Failures, events.DetectorFailure{Detector: re.Detector, Location: t.Location, Reason: events.FailureError})
			failed[i] = true
		}
	}
	return flagged, failed, in, ctx.Err()
}

// policyBlocked — фрагменты, по находкам которых правило политики
// требует block в enforce.
func policyBlocked(in *inspection, n int) []bool {
	out := make([]bool, n)
	if in == nil || in.Decision.Mode != policy.Enforce {
		return out
	}
	for _, mt := range in.Decision.Matches {
		if mt.Action == policy.Block {
			if t := in.Findings[mt.Hit].Text; t >= 0 && t < n {
				out[t] = true
			}
		}
	}
	return out
}

// listTexts — строки описаний элементов списка для детекторов.
func listTexts(l *mcp.List) []inspectText {
	texts := make([]inspectText, len(l.Items))
	for i, it := range l.Items {
		loc := l.Key + "[" + strconv.Itoa(i) + "]"
		if it.Tool.Name != "" {
			loc = l.Key + "[" + it.Tool.Name + "]"
		}
		texts[i] = inspectText{Text: it.Text, Source: detect.SourceTool, Location: loc, Threat: threatPoisoned, Message: -1}
	}
	return texts
}

// inspectDescriptions — встроенная проверка и входные правила политики по
// описаниям (только находки, тексты не меняются): отравленные, скрытые и
// непроверенные (сбой в fail_closed) фрагменты.
func (m *MCPHandler) inspectDescriptions(q *mcpReq, texts []inspectText) ([]bool, []bool, []bool, bool) {
	flagged, failed, builtin, err := m.checkDescriptions(q.r.Context(), q.app, texts)
	if err != nil {
		m.inspectFailed(q, err)
		return nil, nil, nil, false
	}
	in, err := q.app.inspect(q.r.Context(), inspectRequest{Endpoint: policy.EndpointCheck, Direction: detect.Input,
		External: q.up.srv.External, Texts: texts, DetectOnly: true, User: q.user, Timeout: m.h.cfg.DetectorTimeout})
	if err != nil {
		m.inspectFailed(q, err)
		return nil, nil, nil, false
	}
	q.rec.addThreats(q.rec.findings(builtin, texts))
	q.rec.addThreats(q.rec.findings(in, texts))
	blocked := policyBlocked(in, len(texts))
	q.failures = append(append(q.failures, builtin.Failures...), in.Failures...)
	unchecked := make([]bool, len(texts))
	for i := range failed {
		// Правила политики не проверены: показываются только описания,
		// которые проверка признала бы чистыми — то есть никакие.
		unchecked[i] = (failed[i] || len(in.Failures) > 0) && !q.app.FailOpen
		blocked[i] = blocked[i] || unchecked[i]
	}
	return flagged, blocked, unchecked, true
}

// inspectFailed — проверка не выполнена: клиент ушёл или сбой конвейера.
func (m *MCPHandler) inspectFailed(q *mcpReq, err error) {
	if q.r.Context().Err() != nil {
		m.clientGone(q)
		return
	}
	m.h.logger.Error("проверка MCP не выполнена", "app", q.app.ID, "event_id", q.rec.ev.ID, "error", err)
	m.rpcError(q, http.StatusInternalServerError, idOf(q.msg), mcp.CodeInternalError, "внутренняя ошибка шлюза", nil, violationResultCheck)
}

// toolsList — tools/list (DM-24, DM-25): разбор описаний, хеш и сверка с
// реестром, встроенная проверка и правила политики; в enforce агент видит
// только разрешённое; новые и изменённые описания — на сервер.
func (m *MCPHandler) toolsList(q *mcpReq) {
	req, stripped := upstreamRequest(q.msg)
	q.ev.Stripped = stripped
	resp, _, err := m.call(q, req, mcpListTimeout, nil, m.dropServer(q))
	if err != nil {
		m.upstreamFailed(q, err)
		return
	}
	if resp.Kind == mcp.KindError {
		m.upstreamError(q, resp)
		return
	}
	l, err := mcp.ParseList("tools/list", resp.Result)
	if err != nil {
		m.upstreamFailed(q, &mcpUpstreamError{Status: q.ev.Upstream, Msg: "MCP-сервер: " + err.Error()})
		return
	}
	keep, ok := m.reviewTools(q, l)
	if !ok {
		return
	}
	m.writeResult(q, l.Rebuild(func(i int) bool { return keep[i] }, q.version))
}

// reviewTools — решение по каждому инструменту списка l; запоминает
// увиденные описания и отправляет новые на сервер. Решение и угрозы — в
// событии.
func (m *MCPHandler) reviewTools(q *mcpReq, l *mcp.List) ([]bool, bool) {
	texts := listTexts(l)
	flagged, blocked, unchecked, ok := m.inspectDescriptions(q, texts)
	if !ok {
		return nil, false
	}
	q.ev.Items, q.ev.Invalid = len(l.Items), l.Invalid
	slug, agents := q.up.srv.ID, m.h.cfg.Router.Agents()
	enforce := effectiveMode(q.app) == policy.Enforce
	keep := make([]bool, len(l.Items))
	seen := make(map[string]*seenTool, len(l.Items))
	var observed []ObservedTool
	threats := map[string]bool{}
	for i, it := range l.Items {
		name := it.Tool.Name
		hash := hex.EncodeToString(tooldesc.Hash(m.cfg.Hasher, it.Tool))
		reg, inReg := agents.Tool(slug, name)
		status := reg.Status
		if !inReg {
			status = policy.ToolUnknown
		}
		match := inReg && reg.ApprovedHash != "" && reg.ApprovedHash == hash && reg.HashAlg == m.cfg.Hasher.Name()
		// Описание, одобренное после проверки находки, с тем же хешем
		// отравленным снова не считается (ADR-0023, ревью 4.r1).
		poisoned := flagged[i] && (status != policy.ToolApproved || !match)
		changed := inReg && reg.ApprovedHash != "" && !match
		if poisoned {
			q.ev.Poisoned = append(q.ev.Poisoned, name)
			threats[threatPoisoned] = true
		}
		if changed {
			q.ev.Changed = append(q.ev.Changed, name)
			threats[policy.ThreatToolChanged] = true
		}
		listed := q.app.Policy.ToolListed(policy.ToolCall{Mode: q.app.Mode, App: q.app.ID, Agent: q.agent.Slug, Server: slug, Name: name,
			Status: status, HashMatch: match, Risk: reg.Risk}) && !poisoned && !changed && !blocked[i]
		keep[i] = !enforce || listed
		if !listed && len(q.ev.Hidden) < events.MaxAgentNames {
			q.ev.Hidden = append(q.ev.Hidden, name)
		}
		seen[name] = &seenTool{hash: hash, headers: it.Headers, poisoned: poisoned, unchecked: unchecked[i]}
		if !inReg || reg.ApprovedHash != hash || poisoned && status != policy.ToolSuspicious {
			observed = append(observed, ObservedTool{Descriptor: it.Raw, Hash: hash, Suspicious: poisoned})
		}
	}
	if !enforce {
		q.ev.Hidden = nil // в monitor ничего не убрано
	}
	m.remember(slug, seen)
	m.cfg.Observer.Observe(slug, observed)
	q.rec.addThreats(threats)
	m.listDecision(q, threats, enforce)
	return keep, true
}

// listDecision — решение события списка: block, если найдены отравленные,
// подменённые или запрещённые политикой описания.
func (m *MCPHandler) listDecision(q *mcpReq, threats map[string]bool, enforce bool) {
	a, sev := policy.Allow, ""
	if len(threats) > 0 || len(q.rec.ev.Findings) > 0 {
		a, sev = policy.Block, string(policy.High)
	}
	m.decide(q, a, ruleMCPDescriptions)
	q.rec.ev.Decision.Severity = sev
	if len(q.failures) > 0 {
		ed := q.rec.ev.Decision
		ed.Failures, ed.FailMode = q.failures, "fail_closed"
		if q.app.FailOpen {
			ed.FailMode = failOpen
		}
	}
	if !enforce || len(q.ev.Hidden) == 0 {
		q.rec.ev.Decision.Applied = []string{}
	}
}

// remember — описания из tools/list сервера: следующая страница
// дополняет предыдущую.
func (m *MCPHandler) remember(server string, tools map[string]*seenTool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.seen[server]
	if cur == nil || len(cur)+len(tools) > maxSeenTools {
		cur = map[string]*seenTool{}
		m.seen[server] = cur
	}
	for k, v := range tools {
		cur[k] = v
	}
}

// lookupSeen — описание инструмента из последнего tools/list сервера.
func (m *MCPHandler) lookupSeen(server, name string) (*seenTool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.seen[server][name]
	return t, ok
}

// fetchTools — tools/list у сервера перед первым вызовом (ADR-0023,
// раздел 6, tools/call, п. 1), без ответа клиенту: страницы по порядку,
// пока не встретится инструмент name, не больше mcpFetchPages.
func (m *MCPHandler) fetchTools(q *mcpReq, name string) error {
	cursor := ""
	for page := 0; page < mcpFetchPages; page++ {
		next, found, err := m.fetchPage(q, cursor, page, name)
		if err != nil || found || next == "" {
			return err
		}
		cursor = next
	}
	return nil
}

// mcpFetchPages — страниц tools/list, которые шлюз читает сам; mcpMaxCursor
// — предел nextCursor.
const (
	mcpFetchPages = 8
	mcpMaxCursor  = 1024
)

// fetchPage — одна страница tools/list: следующий курсор и признак, что
// инструмент name на ней есть.
func (m *MCPHandler) fetchPage(q *mcpReq, cursor string, page int, name string) (string, bool, error) {
	p := mcp.Object()
	if cursor != "" {
		mcp.Set(&p, "cursor", mcp.String(cursor))
	}
	if q.version == mcp.Version20260728 {
		meta := mcp.Object()
		mcp.Set(&meta, mcp.MetaProtocolVersion, mcp.String(q.version))
		mcp.Set(&p, "_meta", meta)
	}
	req := &mcp.Message{Kind: mcp.KindRequest, ID: mcp.String("aisec-tools-list-" + q.rec.ev.ID + "-" + strconv.Itoa(page)), HasID: true,
		Method: "tools/list", Params: &p}
	resp, _, err := m.call(q, req, mcpListTimeout, nil, func(*mcp.Message) bool { return true })
	if err != nil {
		return "", false, err
	}
	if resp.Kind == mcp.KindError {
		return "", false, &mcpUpstreamError{Status: q.ev.Upstream, Msg: "MCP-сервер не вернул список инструментов"}
	}
	l, err := mcp.ParseList("tools/list", resp.Result)
	if err != nil {
		return "", false, &mcpUpstreamError{Status: q.ev.Upstream, Msg: "MCP-сервер: " + err.Error()}
	}
	// Статус в событии — статус самого вызова, а не служебного tools/list.
	q.ev.Upstream = 0
	seen := map[string]*seenTool{}
	flagged, failed, builtin, err := m.checkDescriptions(q.r.Context(), q.app, listTexts(l))
	if err != nil {
		return "", false, err
	}
	q.failures = append(q.failures, builtin.Failures...)
	found := false
	var observed []ObservedTool
	agents := m.h.cfg.Router.Agents()
	for i, it := range l.Items {
		hash := hex.EncodeToString(tooldesc.Hash(m.cfg.Hasher, it.Tool))
		reg, inReg := agents.Tool(q.up.srv.ID, it.Tool.Name)
		match := inReg && reg.ApprovedHash == hash && reg.HashAlg == m.cfg.Hasher.Name()
		poisoned := flagged[i] && (reg.Status != policy.ToolApproved || !match)
		seen[it.Tool.Name] = &seenTool{hash: hash, headers: it.Headers, poisoned: poisoned, unchecked: failed[i] && !q.app.FailOpen}
		found = found || it.Tool.Name == name
		if !inReg || reg.ApprovedHash != hash {
			observed = append(observed, ObservedTool{Descriptor: it.Raw, Hash: hash, Suspicious: poisoned})
		}
	}
	m.remember(q.up.srv.ID, seen)
	m.cfg.Observer.Observe(q.up.srv.ID, observed)
	next, _ := mcp.GetString(&l.Result, "nextCursor")
	if len(next) > mcpMaxCursor {
		next = ""
	}
	return next, found, nil
}

// toolsCall — tools/call (DM-20–DM-23, DM-07): реестр и хеш, политика
// вызовов, детекторы по аргументам, подтверждение, вызов сервера,
// детекторы по результату.
func (m *MCPHandler) toolsCall(q *mcpReq) {
	cp, err := mcp.ParseCallParams(q.msg.Params)
	if err == nil && !tooldesc.ValidName(cp.Name) {
		err = &mcp.ProtocolError{Code: mcp.CodeInvalidParams, Msg: "params.name — имя инструмента"}
	}
	if err != nil {
		m.rpcError(q, http.StatusOK, idOf(q.msg), mcp.CodeOf(err), err.Error(), nil, violationInvalid)
		return
	}
	// Вызов назван верно: событие — agent_tool_call (неверный вызов
	// остаётся agent_mcp с нарушением).
	q.rec.ev.Type, q.ev.Path = events.TypeAgentToolCall, events.AgentPathMCP
	slug, name := q.up.srv.ID, cp.Name
	q.ev.Tool = name
	seen, ok := m.lookupSeen(slug, name)
	if !ok {
		if err := m.fetchTools(q, name); err != nil {
			m.upstreamFailed(q, err)
			return
		}
		seen, ok = m.lookupSeen(slug, name)
	}
	reg, inReg := m.h.cfg.Router.Agents().Tool(slug, name)
	status := reg.Status
	if !inReg {
		status = policy.ToolUnknown
	}
	match := ok && inReg && reg.ApprovedHash != "" && reg.ApprovedHash == seen.hash && reg.HashAlg == m.cfg.Hasher.Name()
	if ok {
		q.ev.ToolHash = seen.hash
	}
	q.ev.Risk, q.ev.ToolStatus = string(reg.Risk), toolStatus(status)
	args := mcp.AppendJSON(nil, cp.Args)
	now := m.h.cfg.Now()
	d := q.app.Policy.DecideTool(policy.ToolCall{Mode: q.app.Mode, App: q.app.ID, Agent: q.agent.Slug, Session: q.alias,
		Server: slug, Name: name, Status: status, HashMatch: match, Risk: reg.Risk, Args: args,
		ArgsHash: ToolArgsHash(m.cfg.Hasher, args), Now: now}, m.cfg.Rates)
	if d.Args != nil {
		// Серверу уходят ровно разобранные политикой аргументы.
		cp.Args = *d.Args
		args = mcp.AppendJSON(nil, cp.Args)
	}

	// Детекторы по аргументам (tool_args): маскирование сломало бы вызов,
	// поэтому действуют block и журнал (ADR-0023, раздел 6, п. 3).
	argTexts := textsOf(mcp.ArgTexts(&cp.Args), detect.SourceToolArgs)
	argIn, err := q.app.inspect(q.r.Context(), inspectRequest{Endpoint: policy.EndpointCheck, Direction: detect.Input,
		External: q.up.srv.External, Texts: argTexts, DetectOnly: true, User: q.user, Timeout: m.h.cfg.DetectorTimeout,
		Mask: q.app.Storage == events.StorageMasked})
	if err != nil {
		m.inspectFailed(q, err)
		return
	}
	q.rec.addThreats(q.rec.findings(argIn, argTexts))
	switch argIn.Decision.Action {
	case policy.Redact, policy.Pseudonymize:
		q.ev.ArgsUnmasked = true
	}
	m.toolDecision(q, d, argIn)
	m.storeContent(q, argIn, argTexts, true)
	// Описание с внедрёнными инструкциями (DM-24) или не проверенное из-за
	// сбоя (fail_closed), скрытое из tools/list, не вызывается и тогда,
	// когда политика пропускает неодобренные.
	poisonedBlock := ok && (seen.poisoned || seen.unchecked) && effectiveMode(q.app) == policy.Enforce
	if ok && seen.poisoned {
		q.rec.addThreats(map[string]bool{threatPoisoned: true})
		q.ev.Poisoned = []string{name}
	}
	if len(q.failures) > 0 || ok && seen.unchecked {
		ed := q.rec.ev.Decision
		ed.Failures = append(ed.Failures, q.failures...)
		if ed.FailMode = "fail_closed"; q.app.FailOpen {
			ed.FailMode = failOpen
		}
	}
	if poisonedBlock && !d.Block && !argIn.Blocked() {
		ed := q.rec.ev.Decision
		ed.Action, ed.Rule, ed.Severity = string(policy.Block), ruleMCPDescriptions, string(policy.High)
		if !slices.Contains(ed.Applied, string(policy.Block)) {
			ed.Applied = append([]string{string(policy.Block)}, ed.Applied...)
		}
	}
	if d.Block || argIn.Blocked() || poisonedBlock {
		msg := d.Message
		if msg == "" {
			msg = argIn.Decision.Message
		}
		if msg == "" {
			msg = policy.DefaultToolBlockMessage
		}
		m.respondTool(q, mcp.ErrorResult(msg, q.version, m.decisionMeta(q)))
		return
	}
	if q.accepted {
		m.stream(q)
	}
	if d.Approval {
		if !m.approve(q, d, cp, reg, args) {
			return
		}
	}

	// Вызов сервера: тело из проверенного документа, Mcp-Param-* — по
	// x-mcp-header увиденного описания.
	var hdrs map[string][]string
	if q.version == mcp.Version20260728 && ok {
		h, err := mcp.BuildParamHeaders(seen.headers, &cp.Args)
		if err != nil {
			m.rpcError(q, http.StatusOK, idOf(q.msg), mcp.CodeInvalidParams, err.Error(), nil, violationInvalid)
			return
		}
		hdrs = h
	}
	req, stripped := upstreamRequest(q.msg)
	q.ev.Stripped = stripped
	mcp.Set(req.Params, "arguments", cp.Args)
	resp, _, err := m.call(q, req, q.up.callTimeout, hdrs, m.dropServer(q))
	if err != nil {
		m.upstreamFailed(q, err)
		return
	}
	if resp.Kind == mcp.KindError {
		m.upstreamError(q, resp)
		return
	}
	q.ev.ResultBytes = len(mcp.AppendJSON(nil, *resp.Result))
	m.checkResult(q, resp.Result)
}

// toolStatus — состояние инструмента для события.
func toolStatus(s policy.ToolStatus) string {
	if s == policy.ToolUnknown {
		return "unknown"
	}
	return string(s)
}

// textsOf — строки документа для детекторов с источником src.
func textsOf(ts []mcp.Text, src detect.Source) []inspectText {
	out := make([]inspectText, len(ts))
	for i, t := range ts {
		out[i] = inspectText{Text: t.Ref.Str, Source: src, Location: t.Path, Message: -1}
	}
	return out
}

// toolDecision — решение события agent_tool_call: решение политики
// вызовов и находки по аргументам, сильнейшее из них.
func (m *MCPHandler) toolDecision(q *mcpReq, d policy.ToolDecision, argIn *inspection) {
	ed := q.rec.decision(argIn)
	if policy.Stronger(d.Action, policy.Action(ed.Action)) || ed.Action == "" {
		ed.Action, ed.Rule, ed.Severity = string(d.Action), d.Rule, string(d.Severity)
		ed.Policy, ed.PolicyVersion = d.PolicyID, d.Version
	}
	if d.Block && !slices.Contains(ed.Applied, string(policy.Block)) {
		ed.Applied = append([]string{string(policy.Block)}, ed.Applied...)
	}
	for _, s := range d.Trace {
		ed.Trace = append(ed.Trace, events.TraceStep{Rule: s.Rule, Matched: true, Action: string(s.Action), Note: s.Reason})
	}
	for _, t := range d.Threats {
		q.rec.addThreats(map[string]bool{t: true})
	}
	q.rec.ev.Decision = ed
	q.rec.ev.PolicyMode = string(d.Mode)
}

// decisionMeta — решение шлюза для _meta результата с отказом.
func (m *MCPHandler) decisionMeta(q *mcpReq) *argschema.Value {
	d := mcp.Object()
	mcp.Set(&d, "event_id", mcp.String(q.rec.ev.ID))
	if ed := q.rec.ev.Decision; ed != nil {
		mcp.Set(&d, "action", mcp.String(ed.Action))
		if ed.Rule != "" {
			mcp.Set(&d, "rule", mcp.String(ed.Rule))
		}
	}
	return &d
}

// respondTool — результат tools/call клиенту (в поток, если он открыт).
func (m *MCPHandler) respondTool(q *mcpReq, result argschema.Value) {
	m.writeMsg(q, http.StatusOK, mcp.ResultMessage(q.msg.ID, result))
}

// approve — ожидание подтверждения (DM-22): keep-alive SSE каждые 15 с и
// notifications/progress, если клиент передал progressToken. Отказ —
// результат с isError. true — вызов подтверждён.
func (m *MCPHandler) approve(q *mcpReq, d policy.ToolDecision, cp *mcp.CallParams, reg AgentTool, args []byte) bool {
	var n int64
	wait := func() {
		if q.sse == nil {
			return
		}
		q.sse.comment(ApprovalPendingComment)
		if cp.ProgressToken != nil {
			n++
			q.sse.send(mcp.ProgressNotification(*cp.ProgressToken, n, msgApprovalPending))
		}
	}
	// Аргументы без маскирования дежурному не показываются: при сбое
	// детекторов вызов не подтверждается.
	res := ApprovalResult{State: ApprovalUnavailable}
	if shown, ok := q.app.ApprovalArgs(q.r.Context(), args, m.cfg.Chat.cfg.DetectorTimeout); ok {
		res = m.cfg.Approver.Await(q.r.Context(), ApprovalRequest{Path: ApprovalPathMCP, App: q.app.ID, Agent: q.agent.Slug,
			User: q.user, Session: q.alias, Server: q.up.srv.ID, Tool: cp.Name, ApprovedHash: reg.ApprovedHash, Risk: risk(reg.Risk),
			Rule: d.Rule, Message: d.Message, Severity: d.Severity, Args: args, ShownArgs: shown,
			Timeout: d.ApprovalTimeout}, wait)
	}
	q.ev.Approval = &events.Approval{ID: res.ID, State: string(res.State), DecidedBy: res.DecidedBy,
		WaitedMS: res.Waited.Milliseconds(), Comment: res.Comment}
	if res.Approved() {
		return true
	}
	if q.r.Context().Err() != nil && res.State == ApprovalCancelled {
		return false // клиент закрыл поток: отвечать некому
	}
	ed := q.rec.ev.Decision
	ed.Action, ed.Applied = string(policy.Block), []string{string(policy.Block)}
	m.respondTool(q, mcp.ErrorResult(res.AgentMessage(d.Message), q.version, m.decisionMeta(q)))
	return false
}

// checkResult — результат tools/call (DM-07): детекторы политики с
// источником tool по строкам content и structuredContent; block —
// результат с isError, redact — строки маскируются в документе.
func (m *MCPHandler) checkResult(q *mcpReq, result *argschema.Value) {
	cr, err := mcp.ParseContentResult(q.msg.Method, result)
	if errors.Is(err, mcp.ErrInputRequired) {
		m.rpcError(q, http.StatusOK, idOf(q.msg), mcp.CodeInternalError,
			"MCP-сервер запросил ввод у клиента: такие запросы шлюз не передаёт", nil, violationInput)
		return
	}
	if err != nil {
		m.upstreamFailed(q, &mcpUpstreamError{Status: q.ev.Upstream, Msg: "MCP-сервер: " + err.Error()})
		return
	}
	q.ev.IsError = cr.IsError
	texts := textsOf(cr.Texts, detect.SourceTool)
	in, err := q.app.inspect(q.r.Context(), inspectRequest{Endpoint: policy.EndpointCheck, Direction: detect.Input,
		External: q.up.srv.External, Texts: texts, Media: mediaOf(cr.Media), User: q.user, Timeout: m.h.cfg.DetectorTimeout,
		Mask: q.app.Storage == events.StorageMasked})
	if err != nil {
		m.inspectFailed(q, err)
		return
	}
	q.rec.addThreats(q.rec.findings(in, texts))
	if d := in.Decision; d.NonTextUnchecked || d.Rule == policy.NonTextRule {
		q.rec.addThreats(map[string]bool{"DM-14": true})
	}
	m.storeContent(q, in, texts, false)
	m.resultDecision(q, in)
	if in.Blocked() {
		msg := in.Decision.Message
		if msg == "" {
			msg = "Результат инструмента заблокирован политикой безопасности."
		}
		if q.msg.Method != "tools/call" {
			m.rpcError(q, http.StatusOK, idOf(q.msg), mcp.CodeInternalError, msg, m.decisionMeta(q), violationResultCheck)
			return
		}
		m.respondTool(q, mcp.ErrorResult(msg, q.version, m.decisionMeta(q)))
		return
	}
	for i, t := range cr.Texts {
		if i < len(in.Changed) && in.Changed[i] {
			t.Ref.Str = in.Texts[i]
		}
	}
	m.writeResult(q, cr.Result)
}

// resultDecision — решение по результату дополняет решение события:
// сильнейшее действие, применённое и трассировка.
func (m *MCPHandler) resultDecision(q *mcpReq, in *inspection) {
	rd := q.rec.decision(in)
	ed := q.rec.ev.Decision
	if ed == nil {
		if rd.Rule == "" && rd.Action == string(policy.Allow) {
			rd.Rule = ruleMCPResult
		}
		q.rec.ev.Decision = rd
		return
	}
	if policy.Stronger(policy.Action(rd.Action), policy.Action(ed.Action)) {
		ed.Action, ed.Rule, ed.Severity = rd.Action, rd.Rule, rd.Severity
	}
	for _, a := range rd.Applied {
		if !slices.Contains(ed.Applied, a) {
			ed.Applied = append(ed.Applied, a)
		}
	}
	ed.Trace = append(ed.Trace, rd.Trace...)
	ed.Failures = append(ed.Failures, rd.Failures...)
	if rd.FailMode != "" {
		ed.FailMode = rd.FailMode
	}
}

// storeContent — аргументы (request) или результат (response) в событии
// по режиму хранения приложения (ТЗ 5.5): masked — с маскированием ПДн и
// секретов, full — как есть, none — ничего.
func (m *MCPHandler) storeContent(q *mcpReq, in *inspection, texts []inspectText, request bool) {
	c, ok := "", false
	switch q.app.Storage {
	case events.StorageMasked:
		c, ok = in.maskedContent(texts)
	case events.StorageFull:
		c, ok = fullContent(texts), true
	}
	if !ok || c == "" {
		return
	}
	if q.rec.ev.Content == nil {
		q.rec.ev.Content = &events.Content{}
	}
	if request {
		q.rec.ev.Content.Request = c
	} else {
		q.rec.ev.Content.Response = c
	}
}

// mediaOf — не текстовые части результата для правила non_text.
func mediaOf(kinds []string) []policy.MediaPart {
	out := make([]policy.MediaPart, 0, len(kinds))
	for _, k := range kinds {
		if k == "blob" {
			k = "file"
		}
		out = append(out, policy.MediaPart{Kind: k})
	}
	return out
}

// otherList — resources/list, resources/templates/list, prompts/list:
// встроенная проверка описаний; в enforce элементы с находками убираются.
func (m *MCPHandler) otherList(q *mcpReq) {
	req, stripped := upstreamRequest(q.msg)
	q.ev.Stripped = stripped
	resp, _, err := m.call(q, req, mcpListTimeout, nil, m.dropServer(q))
	if err != nil {
		m.upstreamFailed(q, err)
		return
	}
	if resp.Kind == mcp.KindError {
		m.upstreamError(q, resp)
		return
	}
	l, err := mcp.ParseList(q.msg.Method, resp.Result)
	if err != nil {
		m.upstreamFailed(q, &mcpUpstreamError{Status: q.ev.Upstream, Msg: "MCP-сервер: " + err.Error()})
		return
	}
	texts := listTexts(l)
	flagged, blocked, _, ok := m.inspectDescriptions(q, texts)
	if !ok {
		return
	}
	q.ev.Items, q.ev.Invalid = len(l.Items), l.Invalid
	enforce := effectiveMode(q.app) == policy.Enforce
	threats := map[string]bool{}
	hidden := 0
	for i := range l.Items {
		if flagged[i] {
			threats[threatPoisoned] = true
		}
		if flagged[i] || blocked[i] {
			hidden++
		}
	}
	q.rec.addThreats(threats)
	m.listDecision(q, threats, enforce)
	if !enforce || hidden == 0 {
		q.rec.ev.Decision.Applied = []string{}
	}
	m.writeResult(q, l.Rebuild(func(i int) bool { return !enforce || !flagged[i] && !blocked[i] }, q.version))
}

// contentMethod — resources/read, prompts/get: результат проверяется как
// результат инструмента (DM-07).
func (m *MCPHandler) contentMethod(q *mcpReq) {
	req, stripped := upstreamRequest(q.msg)
	q.ev.Stripped = stripped
	resp, _, err := m.call(q, req, q.up.callTimeout, nil, m.dropServer(q))
	if err != nil {
		m.upstreamFailed(q, err)
		return
	}
	if resp.Kind == mcp.KindError {
		m.upstreamError(q, resp)
		return
	}
	q.ev.ResultBytes = len(mcp.AppendJSON(nil, *resp.Result))
	m.checkResult(q, resp.Result)
}

// handshake — initialize (2025-11-25) и server/discover (2026-07-28):
// возможности клиента вырезаются, instructions сервера проходят встроенную
// проверку описаний; initialize открывает сессию шлюза.
func (m *MCPHandler) handshake(q *mcpReq) {
	req, stripped := upstreamRequest(q.msg)
	q.ev.Stripped = stripped
	if q.msg.Method == "initialize" {
		// Шлюз ведёт сессии только ревизии 2025-11-25: другая
		// предложенная версия заменяется ею (сервер ответит своей).
		mcp.Set(req.Params, "protocolVersion", mcp.String(mcp.Version20251125))
	}
	resp, upSess, err := m.call(q, req, mcpListTimeout, nil, m.dropServer(q))
	if err != nil {
		m.upstreamFailed(q, err)
		return
	}
	if resp.Kind == mcp.KindError {
		m.upstreamError(q, resp)
		return
	}
	result := mcp.Clone(*resp.Result)
	if q.msg.Method == "initialize" {
		if v, _ := mcp.GetString(&result, "protocolVersion"); v != mcp.Version20251125 {
			m.upstreamFailed(q, &mcpUpstreamError{Status: q.ev.Upstream, Msg: "MCP-сервер предложил неподдерживаемую версию"})
			return
		}
	}
	if ins, ok := mcp.Instructions(&result); ok {
		texts := []inspectText{{Text: ins.Str, Source: detect.SourceTool, Location: "instructions", Threat: threatPoisoned, Message: -1}}
		flagged, blocked, _, ok := m.inspectDescriptions(q, texts)
		if !ok {
			return
		}
		enforce := effectiveMode(q.app) == policy.Enforce
		threats := map[string]bool{}
		if flagged[0] {
			threats[threatPoisoned] = true
		}
		q.rec.addThreats(threats)
		m.listDecision(q, threats, enforce)
		if enforce && (flagged[0] || blocked[0]) {
			mcp.Delete(&result, "instructions")
		} else {
			q.rec.ev.Decision.Applied = []string{}
		}
	}
	if q.msg.Method == "initialize" {
		sid, err := m.cfg.Sessions.create(m.owner(q), upSess)
		if err != nil {
			q.w.Header().Set("Retry-After", "60")
			m.rpcError(q, http.StatusServiceUnavailable, idOf(q.msg), mcp.CodeInternalError, "шлюз не может открыть новую сессию MCP",
				mcpData(mcpCodeUnavailable), violationSession)
			return
		}
		q.w.Header().Set(mcp.HeaderSessionID, sid)
		if q.alias == "" {
			q.alias = sid
		}
		q.ev.Session = q.alias
	}
	m.writeResult(q, result)
}

// listen — subscriptions/listen (2026-07-28): поток не дольше часа, клиенту
// — только подтверждение подписки и notifications/*/list_changed.
func (m *MCPHandler) listen(q *mcpReq) {
	if !q.accepted {
		m.rpcError(q, http.StatusNotAcceptable, idOf(q.msg), mcp.CodeInvalidRequest,
			"subscriptions/listen — только потоком text/event-stream", nil, violationInvalid)
		return
	}
	req, stripped := upstreamRequest(q.msg)
	q.ev.Stripped = stripped
	m.decide(q, policy.Allow, "")
	m.stream(q)
	resp, _, err := m.call(q, req, mcpListenTimeout, nil, func(msg *mcp.Message) bool {
		if mcp.ServerMessageAllowed(msg, true) {
			q.sse.send(mcp.Sanitize(msg))
			return q.sse.err == nil
		}
		q.ev.Dropped++
		return true
	})
	switch {
	case err != nil && (errors.Is(err, context.DeadlineExceeded) || q.r.Context().Err() != nil):
		return // срок потока или клиент ушёл: поток закрывается
	case err != nil:
		m.upstreamFailed(q, err)
	case resp.Kind == mcp.KindError:
		m.upstreamError(q, resp)
	default:
		m.writeResult(q, *resp.Result)
	}
}
