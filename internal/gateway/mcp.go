package gateway

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/mcp"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

// MCP-прокси шлюза (ТЗ 5.10; ADR-0023, раздел 6; задача 4.11): POST
// /mcp/v1/{server} — Streamable HTTP ревизий 2025-11-25 и 2026-07-28. Шлюз
// стоит между агентом и вышестоящим MCP-сервером из реестра:
//   - tools/list — встроенная проверка описаний (DM-24), сверка хеша с
//     одобренным (DM-25), в enforce агент видит только разрешённое;
//   - tools/call — политика вызовов (DM-20–DM-23), детекторы по
//     аргументам (tool_args), подтверждение человеком (DM-22), детекторы по
//     результату (DM-07);
//   - тело к серверу собирается из проверенного документа, заголовки — свои.
// Разборщики — internal/mcp, клиент сервера — mcp_upstream.go.

// MCPRoute — шаблон маршрута MCP-прокси.
const MCPRoute = "POST /mcp/v1/{server}"

// Коды отказов маршрута (data.code ошибки JSON-RPC и событие).
const (
	mcpCodeOrigin      = "origin_not_allowed"
	mcpCodeNotAllowed  = "mcp_server_not_allowed"
	mcpCodeUnavailable = "mcp_unavailable"
)

// Нарушения протокола (поле agent.violation события).
const (
	violationOrigin      = "origin"
	violationAgent       = "agent"
	violationServer      = "server_not_allowed"
	violationInvalid     = "invalid_message"
	violationBatch       = "batch"
	violationVersion     = "unsupported_version"
	violationHeaders     = "header_mismatch"
	violationMethod      = "method_not_allowed"
	violationSession     = "session_unknown"
	violationInput       = "input_required"
	violationUpstream    = "upstream_error"
	violationNotRequest  = "not_request"
	violationMediaType   = "media_type"
	violationResultCheck = "result_check"
	violationClientGone  = "client_gone"
)

// MCPConfig — зависимости MCP-прокси.
type MCPConfig struct {
	// Chat — обработчик чата: маршруты приложений, события, псевдонимы
	// пользователей, квоты и сроки детекторов — общие.
	Chat *ChatHandler
	// Servers — вышестоящие серверы из пакета по slug.
	Servers MCPServers
	// Hasher — хеш описаний (tooldesc.Hash) и аргументов на криптопрофиле
	// шлюза.
	Hasher aisecCrypto.Hasher
	// Approver — очередь подтверждений (DM-22); nil — Router.Approver().
	Approver Approver
	// Observer — tools:observe; nil — описания на сервер не уходят.
	Observer *ToolObserver
	// Sessions — сессии 2025-11-25; обязательны.
	Sessions *MCPSessions
	// Rates — счётчики лимитов политики вызовов (toolrate); nil — лимиты
	// не считаются.
	Rates policy.RateCounter
}

// MCPHandler обслуживает MCPRoute.
type MCPHandler struct {
	cfg MCPConfig
	h   *ChatHandler
	// seen — описания из последнего tools/list по приложению и серверу:
	// хеш, заголовки Mcp-Param-* и итог проверки правилами этого
	// приложения (живут до смены пакета). Ключ — seenKey: итог проверки у
	// приложений свой (правила, fail_open), общий кэш давал бы одному
	// приложению решение другого (ревью 4.r1, остаток для G3).
	mu   sync.Mutex
	seen map[string]map[string]*seenTool
}

// seenTool — инструмент из последнего tools/list сервера.
type seenTool struct {
	hash     string
	headers  []mcp.ParamHeader
	poisoned bool
	// unchecked — проверка описания не выполнена (сбой детектора в
	// fail_closed): инструмент скрыт и не вызывается, но не отравлен.
	unchecked bool
	// blocked — правило политики приложения с block по находке в
	// описании (enforce): инструмент скрыт и не вызывается.
	blocked bool
}

// seenKey — ключ кэша описаний: приложение и сервер.
func seenKey(app, server string) string { return app + "\x00" + server }

// maxSeenTools — запомненных описаний на сервер (несколько страниц).
const maxSeenTools = 1024

// NewMCPHandler проверяет параметры.
func NewMCPHandler(cfg MCPConfig) (*MCPHandler, error) {
	if cfg.Chat == nil || cfg.Hasher == nil || cfg.Sessions == nil {
		return nil, errors.New("mcp: не заданы обработчик чата, хеш или сессии")
	}
	if cfg.Approver == nil {
		cfg.Approver = cfg.Chat.cfg.Router.Approver()
	}
	return &MCPHandler{cfg: cfg, h: cfg.Chat, seen: map[string]map[string]*seenTool{}}, nil
}

// Close закрывает соединения с серверами (смена пакета).
func (m *MCPHandler) Close() {
	for _, u := range m.cfg.Servers {
		u.close()
	}
}

// mcpReq — запрос в работе: приложение, агент, сервер, сообщение и
// событие.
type mcpReq struct {
	w       http.ResponseWriter
	r       *http.Request
	app     *App
	agent   *Agent
	up      *mcpUpstream
	msg     *mcp.Message
	version string
	user    string
	rec     *record
	ev      *events.Agent
	session string // Mcp-Session-Id клиента (2025-11-25)
	upSess  string // Mcp-Session-Id сервера (2025-11-25)
	alias   string // сессия для политики и событий
	// failures — сбои детекторов проверки описаний (в решение события).
	failures []events.DetectorFailure
	// sent — запрос ушёл серверу: событие пишется и при уходе клиента.
	sent     bool
	sse      *mcpStream
	accepted bool // клиент принимает text/event-stream
}

// ServeHTTP — проверка запроса по порядку: Origin, приложение, агент,
// сервер агента, тело, версия, заголовки, метод, сессия.
func (m *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := m.h
	start := h.cfg.Now()
	app, ok := h.cfg.Router.app(r)
	if !ok {
		h.cfg.Router.noApp(w, r)
		return
	}
	slug := r.PathValue("server")
	q := &mcpReq{w: w, r: r, app: app, ev: &events.Agent{Server: slug}}
	if !validSlug(slug) {
		q.ev.Server = ""
	}
	q.accepted = acceptsSSE(r.Header)
	rec, ok := h.newEventRecord(w, app, events.TypeAgentMCP, "", false, "", start)
	if !ok {
		return
	}
	q.rec = rec
	rec.ev.Provider, rec.ev.Storage = "", app.Storage
	defer m.emit(q)

	// Origin: браузерные клиенты по умолчанию не допускаются (ADR-0023,
	// раздел 6; DNS rebinding к локальному агенту).
	if len(r.Header.Values("Origin")) > 0 {
		m.deny(q, http.StatusForbidden, violationOrigin, mcpCodeOrigin, "запросы из браузера (заголовок Origin) не принимаются")
		return
	}
	// Агент — по ключу или X-AISec-Agent (agents.go); MCP-прокси без
	// агента не работает: права на серверы и политика вызовов — у агента.
	var id auth.Identity
	if p, ok := IdentityFrom(r.Context()); ok {
		id = *p
	}
	agent, aerr := h.cfg.Router.Agents().Resolve(id, r.Header.Values(HeaderAgent))
	if aerr == nil && agent == nil {
		aerr = ErrAgentRequired
	}
	if aerr != nil {
		m.deny(q, http.StatusForbidden, violationAgent, aerr.Code, aerr.Message)
		return
	}
	q.agent, q.ev.Agent = agent, agent.Slug
	up, ok := m.cfg.Servers[slug]
	if !ok || !agent.AllowsServer(slug) {
		m.deny(q, http.StatusForbidden, violationServer, mcpCodeNotAllowed, "агенту не разрешено обращаться к этому MCP-серверу")
		return
	}
	q.up = up
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		m.deny(q, http.StatusUnsupportedMediaType, violationMediaType, "unsupported_media_type", "ожидается Content-Type: application/json")
		return
	}
	body, ok := m.readBody(q)
	if !ok {
		return
	}
	msg2, err := mcp.Parse(body, mcp.Limits(len(body)))
	switch {
	case errors.Is(err, mcp.ErrBatch):
		m.rpcError(q, http.StatusBadRequest, nil, mcp.CodeInvalidRequest, err.Error(), nil, violationBatch)
		return
	case err != nil:
		m.rpcError(q, http.StatusBadRequest, nil, mcp.CodeOf(err), "сообщение JSON-RPC не принято: "+err.Error(), nil, violationInvalid)
		return
	}
	q.msg = msg2
	q.ev.Method = methodForEvent(msg2.Method)
	if msg2.Kind != mcp.KindRequest && msg2.Kind != mcp.KindNotification {
		// Ответы клиента на запросы сервера: таких запросов шлюз не передаёт.
		m.rpcError(q, http.StatusBadRequest, nil, mcp.CodeInvalidRequest, "шлюз не передаёт серверу ответы клиента", nil, violationNotRequest)
		return
	}
	eu, ok := h.user(w, r, app, "")
	if !ok {
		return
	}
	user := eu.ID
	q.user, rec.ev.User = user, user
	if !m.version(q) || !m.allowed(q) || !m.bindSession(q) {
		return
	}
	if !h.admitSize(w, r, rec, user, len(body), 0) {
		return
	}
	switch msg2.Method {
	case "tools/call":
		m.toolsCall(q)
	case "tools/list":
		m.toolsList(q)
	case "resources/list", "resources/templates/list", "prompts/list":
		m.otherList(q)
	case "resources/read", "prompts/get":
		m.contentMethod(q)
	case "initialize", "server/discover":
		m.handshake(q)
	case "ping":
		m.writeResult(q, mcp.Object())
	case "subscriptions/listen":
		m.listen(q)
	default:
		// Уведомления 2025-11-25 (initialized, cancelled) — серверу как есть,
		// клиенту 202.
		m.notify(q)
	}
}

// readBody — тело до предела шлюза и до mcp.MaxMessage.
func (m *MCPHandler) readBody(q *mcpReq) ([]byte, bool) {
	limit := min(m.h.cfg.MaxBodyBytes, int64(mcp.MaxMessage))
	body, err := m.h.readLimited(q.w, q.r, limit)
	if err != nil {
		var tooLarge *http.MaxBytesError
		var ne net.Error
		switch {
		case errors.As(err, &tooLarge):
			m.rpcError(q, http.StatusRequestEntityTooLarge, nil, mcp.CodeInvalidRequest,
				fmt.Sprintf("тело запроса больше %d байт", limit), nil, violationInvalid)
			return nil, false
		case errors.As(err, &ne) && ne.Timeout():
			m.rpcError(q, http.StatusRequestTimeout, nil, mcp.CodeInvalidRequest,
				"тело запроса передавалось слишком долго", nil, violationInvalid)
			return nil, false
		}
		q.rec.skip = true
		return nil, false
	}
	return body, true
}

// version — ревизия запроса: initialize — 2025-11-25 (версия в
// params.protocolVersion), иначе MCP-Protocol-Version; ревизия должна быть
// у сервера в карточке реестра.
func (m *MCPHandler) version(q *mcpReq) bool {
	if q.msg.Method == "initialize" {
		q.version = mcp.Version20251125
	} else {
		v, err := mcp.ProtocolVersion(q.r.Header)
		if err != nil {
			m.rpcError(q, http.StatusBadRequest, idOf(q.msg), mcp.CodeHeaderMismatch, err.Error(), nil, violationHeaders)
			return false
		}
		q.version = v
	}
	q.ev.Protocol = q.version
	if !mcp.Supported(q.version) || !slices.Contains(q.up.srv.Versions, q.version) {
		q.ev.Protocol = ""
		data := mcp.Object()
		var sup []argschema.Value
		for _, v := range q.up.srv.Versions {
			sup = append(sup, mcp.String(v))
		}
		mcp.Set(&data, "supported", mcp.Array(sup...))
		mcp.Set(&data, "requested", mcp.String(truncate(q.version, 64)))
		m.rpcError(q, http.StatusBadRequest, idOf(q.msg), mcp.CodeUnsupportedVersion, "версия MCP не поддерживается", &data, violationVersion)
		return false
	}
	if q.version == mcp.Version20260728 {
		if err := mcp.CheckHeaders(q.r.Header, q.msg); err != nil {
			m.rpcError(q, http.StatusBadRequest, idOf(q.msg), mcp.CodeHeaderMismatch, err.Error(), nil, violationHeaders)
			return false
		}
	}
	return true
}

// allowed — метод разрешён ревизии (ADR-0023, раздел 6).
func (m *MCPHandler) allowed(q *mcpReq) bool {
	if mcp.MethodAllowed(q.msg.Method, q.version) {
		return true
	}
	if q.msg.Kind == mcp.KindNotification {
		// Уведомление без ответа: событие и 202, серверу не уходит.
		q.ev.Violation = violationMethod
		m.decide(q, policy.Block, "mcp.method")
		q.w.WriteHeader(http.StatusAccepted)
		return false
	}
	status := http.StatusOK
	if q.version == mcp.Version20260728 {
		status = http.StatusNotFound
	}
	m.rpcError(q, status, idOf(q.msg), mcp.CodeMethodNotFound, "метод не поддерживается шлюзом", nil, violationMethod)
	return false
}

// bindSession — сессия 2025-11-25: идентификатор шлюза связан с ключом,
// агентом и сервером; чужой или неизвестный — 404. Псевдоним сессии для
// политики и событий — X-AISec-Session, иначе сессия MCP.
func (m *MCPHandler) bindSession(q *mcpReq) bool {
	hdr, err := parseSessionHeader(q.r.Header.Values(HeaderSession))
	if err != nil {
		m.rpcError(q, http.StatusBadRequest, idOf(q.msg), mcp.CodeInvalidRequest, err.Error(), nil, violationInvalid)
		return false
	}
	if hdr != "" && m.h.cfg.Sessions != nil {
		q.alias = m.h.cfg.Sessions.headerAlias(q.app.ID, hdr)
	}
	if q.version != mcp.Version20251125 || q.msg.Method == "initialize" {
		q.ev.Session = q.alias
		return true
	}
	sid, err := mcp.SessionID(q.r.Header)
	if err != nil || sid == "" {
		m.rpcError(q, http.StatusBadRequest, idOf(q.msg), mcp.CodeInvalidRequest, "нужен заголовок Mcp-Session-Id", nil, violationSession)
		return false
	}
	up, ok := m.cfg.Sessions.get(sid, m.owner(q))
	if !ok {
		m.rpcError(q, http.StatusNotFound, idOf(q.msg), mcp.CodeInvalidRequest, "сессия не найдена", nil, violationSession)
		return false
	}
	q.session, q.upSess = sid, up
	if q.alias == "" {
		q.alias = sid
	}
	q.ev.Session = q.alias
	return true
}

// owner — владелец сессии MCP.
func (m *MCPHandler) owner(q *mcpReq) string {
	prefix := ""
	if id, ok := IdentityFrom(q.r.Context()); ok {
		prefix = id.KeyPrefix
	}
	return mcpOwner(q.app.ID, prefix, q.agent.ID, q.up.srv.ID)
}

// headerAlias — псевдоним сессии из X-AISec-Session, как у чата
// (Sessions.identify): хронология сессии агента (4.12) связывает события
// чата и MCP одного диалога.
func (s *Sessions) headerAlias(appID, id string) string {
	return hex.EncodeToString(s.mac.Sum([]byte(sessionDomain + appID + "\x00h\x00" + id))[:16])
}

// call — запрос к серверу со сроком d и чтение ответа на него. Сообщения
// сервера до ответа получает onServer.
func (m *MCPHandler) call(q *mcpReq, msg *mcp.Message, d time.Duration, params map[string][]string,
	onServer func(*mcp.Message) bool) (*mcp.Message, string, error) {
	ctx, cancel := context.WithTimeout(q.r.Context(), d)
	defer cancel()
	reply, err := q.up.send(ctx, mcpOutgoing{Msg: msg, Version: q.version, Session: q.upSess, Params: params,
		Traceparent: traceparent(q.r.Header)})
	if err != nil {
		return nil, "", err
	}
	defer reply.Close()
	q.sent = true
	q.ev.Upstream = reply.Status
	if reply.Status == http.StatusNotFound && q.session != "" {
		// Сервер забыл сессию: клиент по спецификации начнёт новую.
		m.cfg.Sessions.drop(q.session)
		return nil, "", errMCPSessionGone
	}
	resp, err := reply.await(msg.ID, onServer)
	return resp, reply.Session, err
}

// errMCPSessionGone — вышестоящий сервер не знает сессию (404).
var errMCPSessionGone = errors.New("MCP: сервер закрыл сессию")

// upstreamFailed — ответ клиенту при сбое вышестоящего сервера: без
// подробностей сервера, причина — в событии и техническом журнале.
func (m *MCPHandler) upstreamFailed(q *mcpReq, err error) {
	q.ev.Violation = violationUpstream
	switch {
	case errors.Is(err, errMCPSessionGone):
		m.rpcError(q, http.StatusNotFound, idOf(q.msg), mcp.CodeInvalidRequest, "сессия не найдена", nil, violationSession)
		return
	case q.r.Context().Err() != nil:
		m.clientGone(q)
		return
	case errors.Is(err, errMCPBusy):
		q.w.Header().Set("Retry-After", "1")
		m.rpcError(q, http.StatusServiceUnavailable, idOf(q.msg), mcp.CodeInternalError, "MCP-сервер перегружен, повторите позже",
			mcpData(mcpCodeUnavailable), violationUpstream)
		return
	}
	var ue *mcpUpstreamError
	if errors.As(err, &ue) && ue.Status != 0 {
		q.ev.Upstream = ue.Status
	}
	m.h.logger.Warn("MCP-сервер не ответил по протоколу", "app", q.app.ID, "mcp_server", q.up.srv.ID, "event_id", q.rec.ev.ID,
		"error", err)
	m.rpcError(q, http.StatusBadGateway, idOf(q.msg), mcp.CodeInternalError, "MCP-сервер недоступен или ответил не по протоколу",
		mcpData(mcpCodeUnavailable), violationUpstream)
}

// clientGone — клиент закрыл соединение. До отправки серверу событие не
// пишется (как у чата); после — пишется с нарушением client_gone: вызов
// мог выполниться, и в журнале он должен остаться.
func (m *MCPHandler) clientGone(q *mcpReq) {
	if !q.sent {
		q.rec.skip = true
		return
	}
	q.ev.Violation = violationClientGone
	if q.rec.ev.Decision == nil {
		m.decide(q, policy.Allow, "")
	}
}

// upstreamError — ответ сервера с ошибкой JSON-RPC: клиенту — только код,
// текст сервера (недоверенный, уходит модели) не передаётся.
func (m *MCPHandler) upstreamError(q *mcpReq, resp *mcp.Message) {
	code := resp.ErrorCode()
	if code < -32768 || code > 32767 {
		code = mcp.CodeInternalError
	}
	q.ev.IsError = true
	m.decide(q, policy.Allow, "")
	m.writeMsg(q, http.StatusOK, mcp.ErrorMessage(idOf(q.msg), int(code), "MCP-сервер вернул ошибку", nil))
}

// notify — уведомление клиента серверу; клиенту 202.
func (m *MCPHandler) notify(q *mcpReq) {
	params, _ := mcp.UpstreamParams(q.msg.Method, q.msg.Params)
	out := &mcp.Message{Kind: mcp.KindNotification, Method: q.msg.Method, Params: params}
	ctx, cancel := context.WithTimeout(q.r.Context(), mcpListTimeout)
	defer cancel()
	reply, err := q.up.send(ctx, mcpOutgoing{Msg: out, Version: q.version, Session: q.upSess, Traceparent: traceparent(q.r.Header)})
	if err != nil {
		m.upstreamFailed(q, err)
		return
	}
	q.ev.Upstream = reply.Status
	reply.Close()
	m.decide(q, policy.Allow, "")
	q.w.WriteHeader(http.StatusAccepted)
}

// upstreamRequest — запрос серверу, собранный из проверенного документа.
func upstreamRequest(msg *mcp.Message) (*mcp.Message, []string) {
	params, stripped := mcp.UpstreamParams(msg.Method, msg.Params)
	return &mcp.Message{Kind: mcp.KindRequest, ID: msg.ID, HasID: true, Method: msg.Method, Params: params}, stripped
}

// decide — решение события без находок: действие и правило.
func (m *MCPHandler) decide(q *mcpReq, a policy.Action, rule string) {
	applied := []string{}
	if a == policy.Block {
		applied = append(applied, string(policy.Block))
	}
	q.rec.ev.Decision = &events.Decision{Action: string(a), Applied: applied, Rule: rule, Policy: q.app.Policy.ID,
		PolicyVersion: q.app.Policy.Version}
}

// deny — отказ до разбора сообщения (Origin, агент, сервер, тип тела).
func (m *MCPHandler) deny(q *mcpReq, status int, violation, code, msg string) {
	m.rpcError(q, status, nil, mcp.CodeInvalidRequest, msg, mcpData(code), violation)
}

// rpcError — ответ ошибкой JSON-RPC и отметка нарушения в событии.
func (m *MCPHandler) rpcError(q *mcpReq, status int, id *argschema.Value, code int, msg string, data *argschema.Value, violation string) {
	if q.ev.Violation == "" {
		q.ev.Violation = violation
	}
	if q.rec.ev.Decision == nil {
		m.decide(q, policy.Block, "mcp."+violation)
	}
	q.w.Header().Set(HeaderDecision, string(policy.Block))
	m.writeMsg(q, status, mcp.ErrorMessage(id, code, msg, data))
}

// mcpData — data ошибки с кодом отказа шлюза.
func mcpData(code string) *argschema.Value {
	d := mcp.Object()
	mcp.Set(&d, "code", mcp.String(code))
	return &d
}

// writeResult — ответ с результатом на запрос клиента.
func (m *MCPHandler) writeResult(q *mcpReq, result argschema.Value) {
	if q.rec.ev.Decision == nil {
		m.decide(q, policy.Allow, "")
	}
	m.writeMsg(q, http.StatusOK, mcp.ResultMessage(q.msg.ID, result))
}

// writeMsg — сообщение клиенту: в открытый поток SSE или ответом JSON.
func (m *MCPHandler) writeMsg(q *mcpReq, status int, msg *mcp.Message) {
	if q.sse != nil {
		q.sse.send(msg)
		return
	}
	if q.rec.ev.Decision != nil && q.w.Header().Get(HeaderDecision) == "" {
		q.w.Header().Set(HeaderDecision, q.rec.ev.Decision.Action)
	}
	q.w.Header().Set("Content-Type", "application/json")
	q.w.WriteHeader(status)
	if _, err := q.w.Write(msg.Encode()); err != nil {
		return // клиент ушёл; писать больше некуда
	}
}

// emit отправляет событие агента.
func (m *MCPHandler) emit(q *mcpReq) {
	rec := q.rec
	rec.res.Settle(0)
	if rec.skip {
		return
	}
	if rec.ev.Decision == nil {
		m.decide(q, policy.Allow, "")
	}
	rec.ev.Agent = q.ev
	rec.ev.LatencyMS["total"] = m.h.cfg.Now().Sub(rec.start).Milliseconds()
	if err := m.h.cfg.Events.Enqueue(rec.ev); err != nil {
		m.h.logger.Error("событие не принято", "type", rec.ev.Type, "event_id", rec.ev.ID, "error", err)
	}
}

// mcpStream — ответ клиенту потоком SSE (tools/call с ожиданием
// подтверждения и уведомлениями о ходе, subscriptions/listen).
type mcpStream struct {
	w   io.Writer
	rc  *http.ResponseController
	err error
}

// stream открывает поток SSE ответа.
func (m *MCPHandler) stream(q *mcpReq) *mcpStream {
	if q.sse != nil {
		return q.sse
	}
	if q.rec.ev.Decision != nil {
		q.w.Header().Set(HeaderDecision, q.rec.ev.Decision.Action)
	}
	q.w.Header().Set("Content-Type", "text/event-stream")
	q.w.WriteHeader(http.StatusOK)
	q.sse = &mcpStream{w: q.w, rc: http.NewResponseController(q.w)}
	q.sse.flush()
	return q.sse
}

func (s *mcpStream) send(msg *mcp.Message) {
	s.write("event: message\ndata: " + mcp.SSEData(msg.Value()) + "\n\n")
}

// comment — комментарий SSE (keep-alive ожидания подтверждения).
func (s *mcpStream) comment(text string) { s.write(": " + text + "\n\n") }

func (s *mcpStream) write(data string) {
	if s.err != nil {
		return
	}
	if _, s.err = io.WriteString(s.w, data); s.err == nil {
		s.flush()
	}
}

func (s *mcpStream) flush() {
	if err := s.rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.err = err
	}
}

// acceptsSSE — клиент принимает text/event-stream.
func acceptsSSE(h http.Header) bool {
	for _, v := range h.Values("Accept") {
		for _, part := range strings.Split(v, ",") {
			if mt, _, err := mime.ParseMediaType(strings.TrimSpace(part)); err == nil && (mt == "text/event-stream" || mt == "*/*") {
				return true
			}
		}
	}
	return false
}

// idOf — id запроса для ответа с ошибкой; у уведомления — nil.
func idOf(m *mcp.Message) *argschema.Value {
	if m == nil || !m.HasID {
		return nil
	}
	return &m.ID
}

// methodForEvent — метод для события: служебное имя или пусто.
func methodForEvent(method string) string {
	if len(method) > mcp.MaxMethodLen || strings.ContainsFunc(method, func(r rune) bool {
		return !lowerAlnum(r) && (r < 'A' || r > 'Z') && !strings.ContainsRune("_./-", r)
	}) {
		return ""
	}
	return method
}

// lowerAlnum — строчная латинская буква или цифра.
func lowerAlnum(r rune) bool { return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' }

// validSlug — slug MCP-сервера.
func validSlug(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !lowerAlnum(r) && r != '-' {
			return false
		}
	}
	return true
}

// traceparent — W3C traceparent клиента, только верного вида
// (00-<32 hex>-<16 hex>-<2 hex>).
func traceparent(h http.Header) string {
	vals := h.Values("traceparent")
	if len(vals) != 1 || len(vals[0]) != 55 {
		return ""
	}
	v := vals[0]
	for i, c := range v {
		switch i {
		case 2, 35, 52:
			if c != '-' {
				return ""
			}
		default:
			if !lowerAlnum(c) || c > 'f' {
				return ""
			}
		}
	}
	return v
}

// truncate — строка не длиннее n байт (без разрыва UTF-8 не нужно: только
// ASCII-версии; прочее заменяется).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
