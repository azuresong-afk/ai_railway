package gateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/mcp"
	"github.com/azuresong-afk/ai_railway/internal/mockmcp"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/tooldesc"
	"github.com/azuresong-afk/ai_railway/internal/policy/toolrate"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// Синтетические агенты тестов MCP-прокси.
const (
	mcpAgentID    = "01900000-0000-7000-8000-0000000000a1"
	mcpOtherAgent = "01900000-0000-7000-8000-0000000000a2"
	mcpToken      = "upstream-token-1"
)

// mcpOpts — параметры тестового MCP-прокси.
type mcpOpts struct {
	poisoned bool
	mode     policy.Mode
	tools    *policy.ToolsSpec
	// approve — инструменты реестра, одобренные с текущим описанием мока
	// (имя → риск); new — инструменты в реестре со статусом new.
	approve map[string]policy.ToolRisk
	newTool []string
	storage string
	// approver — очередь подтверждений; nil — NoApprover.
	approver Approver
	// upstream — свой обработчик вместо мока; allowed — сети сверх
	// правила адресов (по умолчанию loopback для httptest).
	upstream http.Handler
	allowed  []netip.Prefix
	// host — имя вместо 127.0.0.1 в адресе сервера (проверка адреса после
	// разрешения имени).
	host     string
	versions []string
}

type mcpEnv struct {
	t     *testing.T
	g     http.Handler
	log   *eventLog
	mock  *mockmcp.Mock
	srv   *httptest.Server
	up    *mcpUpstream
	bound string // ключ, привязанный к агенту report-bot
	free  string // ключ без привязки
}

// defaultTools — политика вызовов тестов: неодобренное и не разрешённое
// блокируется, чтение файлов низкого риска — разрешено, высокий риск —
// подтверждение, удаление — запрещено.
func defaultTools() *policy.ToolsSpec {
	return &policy.ToolsSpec{Unapproved: policy.Block, Default: policy.Block, Rules: []policy.ToolRuleSpec{
		{ID: "files-delete", Tool: "files/delete*", Action: policy.Block, Severity: policy.Critical},
		{ID: "files-low", Tool: "files/*", Risk: []policy.ToolRisk{policy.RiskLow}, Action: policy.Allow, Severity: policy.Medium},
		{ID: "risky", Risk: []policy.ToolRisk{policy.RiskHigh}, Action: policy.RequireApproval, Severity: policy.High},
	}}
}

// mockHashes — хеши описаний инструментов мока, как их считает шлюз.
func mockHashes(t *testing.T, m *mockmcp.Mock, h aisecCrypto.Hasher) map[string]string {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, mockmcp.Path, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`))
	r.Header.Set(mcp.HeaderProtocolVersion, mcp.Version20260728)
	r.Header.Set(mcp.HeaderMethod, "tools/list")
	r.Header.Set("Authorization", "Bearer "+mcpToken)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	msg, err := mcp.Parse(w.Body.Bytes(), mcp.Limits(mcp.MaxMessage))
	if err != nil || msg.Result == nil {
		t.Fatalf("tools/list мока: %v %s", err, w.Body)
	}
	l, err := mcp.ParseList("tools/list", msg.Result)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, it := range l.Items {
		out[it.Tool.Name] = hex.EncodeToString(tooldesc.Hash(h, it.Tool))
	}
	return out
}

func newMCPEnv(t *testing.T, mod func(*mcpOpts)) *mcpEnv {
	t.Helper()
	o := mcpOpts{mode: policy.Enforce, tools: defaultTools(), storage: events.StorageNone,
		approve:  map[string]policy.ToolRisk{"read_file": policy.RiskLow, "fetch_page": policy.RiskLow, "slow_job": policy.RiskLow, "ask_user": policy.RiskLow},
		allowed:  []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")},
		versions: []string{mcp.Version20251125, mcp.Version20260728}}
	if mod != nil {
		mod(&o)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	e := &mcpEnv{t: t, log: &eventLog{}}
	e.mock = mockmcp.New(mockmcp.Options{Token: mcpToken, Poisoned: o.poisoned}, quiet())
	handler := o.upstream
	if handler == nil {
		handler = e.mock.Handler()
	}
	e.srv = httptest.NewTLSServer(handler)
	t.Cleanup(e.srv.Close)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.srv.Certificate().Raw}))

	bound, pb, hb, err := auth.NewAppKey(rnd, h)
	if err != nil {
		t.Fatal(err)
	}
	free, pf, hf, err := auth.NewAppKey(rnd, h)
	if err != nil {
		t.Fatal(err)
	}
	e.bound, e.free = bound, free
	a, err := auth.NewAuthenticator(h, []auth.KeyRecord{{AppID: "app", Env: "test", Prefix: pb, SHA256: hb},
		{AppID: "app", Env: "test", Prefix: pf, SHA256: hf}})
	if err != nil {
		t.Fatal(err)
	}
	gen := ids.NewGenerator(rnd)
	authCfg := &AuthConfig{Authenticator: a, Limiter: auth.NewFailureLimiter(auth.LimiterConfig{}), Events: &eventLog{}, IDs: gen, Logger: quiet()}

	hashes := mockHashes(t, mockmcp.New(mockmcp.Options{Token: mcpToken, Poisoned: o.poisoned}, quiet()), h)
	content := &bundle.Content{
		Applications: []bundle.Application{{ID: "app", Keys: []bundle.Key{{Prefix: pb, Agent: mcpAgentID}, {Prefix: pf}}}},
		Agents: []bundle.Agent{
			{ID: mcpAgentID, App: "app", Slug: "report-bot", Status: "active", MCPServers: []string{"files"}},
			{ID: mcpOtherAgent, App: "app", Slug: "other-bot", Status: "active", MCPServers: []string{}},
		},
	}
	for name, risk := range o.approve {
		content.AgentTools = append(content.AgentTools, bundle.AgentTool{Server: "files", Name: name, ApprovedHash: hashes[name],
			HashAlg: h.Name(), Risk: risk, Status: policy.ToolApproved})
	}
	for _, name := range o.newTool {
		content.AgentTools = append(content.AgentTools, bundle.AgentTool{Server: "files", Name: name, HashAlg: h.Name(),
			Risk: policy.RiskLow, Status: policy.ToolNew})
	}

	spec, _ := policy.Template(policy.TemplateBase)
	spec.ID, spec.Mode, spec.Tools = "mcp", o.mode, o.tools
	u, err := url.Parse("https://127.0.0.1:1/v1")
	if err != nil {
		t.Fatal(err)
	}
	prov, err := providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: providers.BaseConfig{ID: "up", External: true, Transport: &http.Transport{}, Logger: quiet()}, BaseURL: u})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRouter([]config.Application{{ID: "app", Env: "test", Provider: "up", Models: []string{"m"}, Policy: "mcp",
		Storage: o.storage}}, map[string]providers.Provider{"up": prov}, []policy.Spec{*spec})
	if err != nil {
		t.Fatal(err)
	}
	rt.SetAgents(NewAgents(content))
	ch, err := NewChatHandler(ChatConfig{Router: rt, MaxBodyBytes: 1 << 20, Logger: quiet(), Events: e.log, IDs: gen,
		Sessions: testSessions(t, 0, nil)})
	if err != nil {
		t.Fatal(err)
	}
	srvURL := e.srv.URL
	if o.host != "" {
		srvURL = strings.Replace(srvURL, "127.0.0.1", o.host, 1)
	}
	up, err := newMCPUpstream(bundle.MCPServer{ID: "files", URL: srvURL + mockmcp.Path, CAPEM: caPEM, External: true,
		Versions: o.versions}, mcpToken, tp, o.allowed)
	if err != nil {
		t.Fatal(err)
	}
	e.up = up
	mh, err := NewMCPHandler(MCPConfig{Chat: ch, Servers: map[string]*mcpUpstream{"files": up}, Hasher: h, Approver: o.approver,
		Sessions: NewMCPSessions(rnd, nil), Rates: toolrate.New(1000)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mh.Close)
	e.g = mustNew(t, Options{Logger: quiet(), MCP: mh, Router: rt, Auth: authCfg})
	return e
}

// dialer подменяет соединение с сервером (разрешение имени в тестах).
func (e *mcpEnv) dialer(g mcpDialer) {
	e.up.client.Transport.(*http.Transport).DialContext = g.dial
}

const meta2026 = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`

// call26 — запрос ревизии 2026-07-28 с верными заголовками.
func (e *mcpEnv) call26(key, method, name, params string, hdr map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	h := map[string]string{mcp.HeaderProtocolVersion: mcp.Version20260728, mcp.HeaderMethod: method,
		"Accept": "application/json, text/event-stream"}
	if name != "" {
		h[mcp.HeaderName] = name
	}
	for k, v := range hdr {
		h[k] = v
	}
	if params != "" {
		params += ","
	}
	return e.post(key, `{"jsonrpc":"2.0","id":7,"method":"`+method+`","params":{`+params+meta2026+`}}`, h)
}

func (e *mcpEnv) post(key, body string, hdr map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/v1/files", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range hdr {
		if strings.HasPrefix(k, "path:") {
			req.URL.Path = strings.TrimPrefix(k, "path:")
			continue
		}
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.g.ServeHTTP(w, req)
	return w
}

// reply — последнее сообщение ответа (JSON или поток SSE).
func mreply(t *testing.T, w *httptest.ResponseRecorder) *mcp.Message {
	t.Helper()
	msgs := replies(t, w)
	return msgs[len(msgs)-1]
}

func replies(t *testing.T, w *httptest.ResponseRecorder) []*mcp.Message {
	t.Helper()
	if strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
		msgs, err := mcp.ParseSSE(bytes.NewReader(w.Body.Bytes()))
		if err != nil || len(msgs) == 0 {
			t.Fatalf("поток: %v %q", err, w.Body)
		}
		return msgs
	}
	m, err := mcp.Parse(w.Body.Bytes(), mcp.Limits(mcp.MaxMessage))
	if err != nil {
		t.Fatalf("ответ не JSON-RPC: %d %q", w.Code, w.Body)
	}
	return []*mcp.Message{m}
}

// lastEvent — последнее событие агента.
func (e *mcpEnv) lastEvent() events.Event {
	e.t.Helper()
	evs := e.log.all()
	if len(evs) == 0 {
		e.t.Fatal("нет событий")
	}
	return evs[len(evs)-1]
}

// toolNames — имена инструментов в результате tools/list.
func toolNames(t *testing.T, m *mcp.Message) []string {
	t.Helper()
	if m.Result == nil {
		t.Fatalf("нет результата: %s", m.Encode())
	}
	arr, _ := m.Result.Get("tools")
	var out []string
	for i := range arr.Arr {
		n, _ := mcp.GetString(&arr.Arr[i], "name")
		out = append(out, n)
	}
	return out
}

// lastUpstream — что последним получил мок.
func (e *mcpEnv) lastUpstream() (http.Header, string) {
	e.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, e.srv.URL+mockmcp.LastRequestPath, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:gosec // G104: тело прочитано ниже, ошибка закрытия тесту не важна
	var last struct {
		Headers http.Header
		Body    string
	}
	if err := json.NewDecoder(resp.Body).Decode(&last); err != nil {
		e.t.Fatal(err)
	}
	return last.Headers, last.Body
}

// Покрывает: DM-24
// Отравленное описание (внедрённые инструкции) убирается из tools/list в
// enforce, событие agent_mcp называет инструмент; в monitor список не
// меняется. Икон и _meta модель не видит, ttlMs не больше минуты.
func TestDM24_PoisonedDescriptionHidden(t *testing.T) {
	tools := defaultTools()
	tools.Unapproved = policy.Log
	e := newMCPEnv(t, func(o *mcpOpts) { o.poisoned, o.tools, o.newTool = true, tools, []string{"add_numbers"} })
	w := e.call26(e.bound, "tools/list", "", "", nil)
	m := mreply(t, w)
	names := toolNames(t, m)
	if w.Code != 200 || slices.Contains(names, "add_numbers") || !slices.Contains(names, "read_file") {
		t.Fatalf("список: %d %v", w.Code, names)
	}
	if s := string(m.Encode()); strings.Contains(s, "icons") || strings.Contains(s, "id_rsa") || !strings.Contains(s, `"cacheScope":"private"`) {
		t.Fatalf("результат: %s", s)
	}
	ev := e.lastEvent()
	if ev.Type != events.TypeAgentMCP || ev.Agent == nil || !slices.Contains(ev.Agent.Poisoned, "add_numbers") ||
		!slices.Contains(ev.Agent.Hidden, "add_numbers") || !slices.Contains(ev.Threats, "DM-24") || ev.Decision.Action != "block" {
		t.Fatalf("событие: %+v %+v", ev, ev.Agent)
	}
	if !slices.ContainsFunc(ev.Findings, func(f events.Finding) bool { return f.Threat == "DM-24" && f.Source == "tool" }) {
		t.Fatalf("находки: %+v", ev.Findings)
	}
	mon := newMCPEnv(t, func(o *mcpOpts) {
		o.poisoned, o.tools, o.mode, o.newTool = true, tools, policy.Monitor, []string{"add_numbers"}
	})
	if names := toolNames(t, mreply(t, mon.call26(mon.bound, "tools/list", "", "", nil))); !slices.Contains(names, "add_numbers") {
		t.Fatalf("monitor: %v", names)
	}
	if ev := mon.lastEvent(); !slices.Contains(ev.Agent.Poisoned, "add_numbers") || len(ev.Agent.Hidden) != 0 {
		t.Fatalf("monitor: событие %+v", ev.Agent)
	}
}

// Покрывает: DM-25
// Описание одобренного инструмента подменено после одобрения (rug pull):
// инструмент убирается из списка, вызов блокируется до вышестоящего
// сервера.
func TestDM25_ChangedToolCallBlocked(t *testing.T) {
	e := newMCPEnv(t, nil)
	args := `"name":"read_file","arguments":{"path":"/data/a.txt"}`
	if m := mreply(t, e.call26(e.bound, "tools/call", "read_file", args, nil)); m.Result == nil || isErrorResult(m) {
		t.Fatalf("до подмены: %s", m.Encode())
	}
	e.mock.RugPull()
	m := mreply(t, e.call26(e.bound, "tools/list", "", "", nil))
	if slices.Contains(toolNames(t, m), "read_file") {
		t.Fatal("подменённый инструмент в списке")
	}
	if ev := e.lastEvent(); !slices.Contains(ev.Agent.Changed, "read_file") || !slices.Contains(ev.Threats, "DM-25") {
		t.Fatalf("событие списка: %+v", ev.Agent)
	}
	m = mreply(t, e.call26(e.bound, "tools/call", "read_file", args, nil))
	if !isErrorResult(m) {
		t.Fatalf("вызов подменённого: %s", m.Encode())
	}
	ev := e.lastEvent()
	if ev.Type != events.TypeAgentToolCall || ev.Decision.Action != "block" || !slices.Contains(ev.Threats, "DM-25") || ev.Agent.Upstream != 0 {
		t.Fatalf("событие вызова: %+v %+v", ev.Decision, ev.Agent)
	}
	if _, body := e.lastUpstream(); !strings.Contains(body, "tools/list") {
		t.Fatalf("вызов дошёл до сервера: %s", body)
	}
}

func isErrorResult(m *mcp.Message) bool {
	if m.Result == nil {
		return false
	}
	v, ok := m.Result.Get("isError")
	return ok && v.Bool
}

// Покрывает: DM-07 (MCP)
// Результат инструмента с косвенной инъекцией блокируется: агент получает
// isError, событие — находку с источником tool.
func TestDM07_MCPToolResultInjection(t *testing.T) {
	e := newMCPEnv(t, nil)
	m := mreply(t, e.call26(e.bound, "tools/call", "fetch_page", `"name":"fetch_page","arguments":{"url":"https://example.com/"}`, nil))
	if !isErrorResult(m) || strings.Contains(string(m.Encode()), "Игнорируй") {
		t.Fatalf("результат: %s", m.Encode())
	}
	ev := e.lastEvent()
	if ev.Type != events.TypeAgentToolCall || ev.Decision.Action != "block" || !slices.Contains(ev.Threats, "DM-07") ||
		ev.Agent.Upstream != 200 || ev.Agent.Tool != "fetch_page" {
		t.Fatalf("событие: %+v %+v %v", ev.Decision, ev.Agent, ev.Threats)
	}
	if !slices.ContainsFunc(ev.Findings, func(f events.Finding) bool { return f.Source == "tool" && f.Threat == "DM-07" }) {
		t.Fatalf("находки: %+v", ev.Findings)
	}
	// resources/read с инъекцией — тоже.
	w := e.call26(e.bound, "resources/read", "file:///inject", `"uri":"file:///inject"`, nil)
	if m := mreply(t, w); m.Kind != mcp.KindError || strings.Contains(string(m.Encode()), "Игнорируй") {
		t.Fatalf("resources/read: %s", m.Encode())
	}
}

// Покрывает: DM-20
// Неодобренный и запрещённый правилом инструменты не вызываются.
func TestDM20_MCPUnapprovedCallBlocked(t *testing.T) {
	e := newMCPEnv(t, nil)
	for _, name := range []string{"delete_file", "add_numbers"} {
		m := mreply(t, e.call26(e.bound, "tools/call", name, `"name":"`+name+`","arguments":{"path":"/a"}`, nil))
		if !isErrorResult(m) {
			t.Fatalf("%s: %s", name, m.Encode())
		}
		ev := e.lastEvent()
		if ev.Decision.Action != "block" || !slices.Contains(ev.Threats, "DM-20") || ev.Agent.Upstream != 0 {
			t.Fatalf("%s: событие %+v %+v", name, ev.Decision, ev.Agent)
		}
	}
	if _, body := e.lastUpstream(); strings.Contains(body, "tools/call") {
		t.Fatalf("вызов дошёл до сервера: %s", body)
	}
}

// Отказы в доступе к маршруту MCP-прокси: без ключа, ключ без агента,
// агент без права на сервер, неизвестный сервер, запрос из браузера.
func TestMCPAccessDenied(t *testing.T) {
	e := newMCPEnv(t, nil)
	if w := e.call26("", "tools/list", "", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("без ключа: %d", w.Code)
	}
	cases := []struct {
		name, key string
		hdr       map[string]string
		code      string
	}{
		{"ключ без агента", e.free, nil, "agent_required"},
		{"чужой агент в заголовке", e.bound, map[string]string{HeaderAgent: "other-bot"}, "agent_mismatch"},
		{"агент без права на сервер", e.free, map[string]string{HeaderAgent: "other-bot"}, mcpCodeNotAllowed},
		{"неизвестный сервер", e.bound, map[string]string{"path:/mcp/v1/db": ""}, mcpCodeNotAllowed},
		{"Origin", e.bound, map[string]string{"Origin": "https://evil.example"}, mcpCodeOrigin},
	}
	for _, c := range cases {
		w := e.call26(c.key, "tools/list", "", "", c.hdr)
		m := mreply(t, w)
		data, _ := mcp.GetObject(m.Error, "data")
		code, _ := mcp.GetString(data, "code")
		if w.Code != http.StatusForbidden || m.Kind != mcp.KindError || code != c.code {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body)
		}
		if ev := e.lastEvent(); ev.Type != events.TypeAgentMCP || ev.Agent.Violation == "" || ev.Decision.Action != "block" {
			t.Errorf("%s: событие %+v", c.name, ev.Agent)
		}
	}
	// Агент из заголовка при ключе без привязки — допускается.
	if w := e.call26(e.free, "tools/list", "", "", map[string]string{HeaderAgent: "report-bot"}); w.Code != 200 {
		t.Fatalf("агент из заголовка: %d %s", w.Code, w.Body)
	}
}

// Протокол: несовпадение заголовков (-32020), неизвестная версия
// (-32022), пакет, неразрешённый метод (-32601), уведомление от клиента
// без метода в списке, GET — 405.
func TestMCPProtocolChecks(t *testing.T) {
	e := newMCPEnv(t, nil)
	errCodeOf := func(w *httptest.ResponseRecorder) int64 { return mreply(t, w).ErrorCode() }
	if w := e.call26(e.bound, "tools/call", "other", `"name":"read_file","arguments":{}`, nil); w.Code != 400 || errCodeOf(w) != mcp.CodeHeaderMismatch {
		t.Fatalf("Mcp-Name: %d %s", w.Code, w.Body)
	}
	if w := e.call26(e.bound, "tools/list", "", "", map[string]string{mcp.HeaderProtocolVersion: "2024-11-05"}); w.Code != 400 ||
		errCodeOf(w) != mcp.CodeUnsupportedVersion {
		t.Fatalf("версия: %d %s", w.Code, w.Body)
	}
	if w := e.post(e.bound, `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, nil); w.Code != 400 || errCodeOf(w) != mcp.CodeInvalidRequest {
		t.Fatalf("пакет: %d %s", w.Code, w.Body)
	}
	if w := e.call26(e.bound, "completion/complete", "", "", nil); w.Code != 404 || errCodeOf(w) != mcp.CodeMethodNotFound {
		t.Fatalf("метод: %d %s", w.Code, w.Body)
	}
	if ev := e.lastEvent(); ev.Agent.Violation != violationMethod || ev.Agent.Method != "completion/complete" {
		t.Fatalf("событие: %+v", ev.Agent)
	}
	dup := `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list","params":{` + meta2026 + `}}`
	if w := e.post(e.bound, dup, map[string]string{mcp.HeaderProtocolVersion: mcp.Version20260728, mcp.HeaderMethod: "tools/list"}); w.Code != 400 {
		t.Fatalf("повтор ключа: %d %s", w.Code, w.Body)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp/v1/files", nil)
	req.Header.Set("Authorization", "Bearer "+e.bound)
	w := httptest.NewRecorder()
	e.g.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", w.Code)
	}
}

// Вышестоящему серверу уходят только заголовки шлюза: учётные данные из
// реестра вместо ключа приложения, без Cookie и X-AISec-*; тело собрано
// заново (неизвестные поля params отброшены), Mcp-Param-* — по описанию.
func TestMCPUpstreamHeadersAndBody(t *testing.T) {
	e := newMCPEnv(t, nil)
	w := e.call26(e.bound, "tools/call", "read_file", `"name":"read_file","task":{"ttl":1},"arguments":{"path":"/data/a.txt"}`,
		map[string]string{"Cookie": "a=b", HeaderSession: "sess-1", "X-Custom": "x"})
	if m := mreply(t, w); isErrorResult(m) || m.Result == nil {
		t.Fatalf("вызов: %s", w.Body)
	}
	hdr, body := e.lastUpstream()
	if got := hdr.Get("Authorization"); got != "Bearer "+mcpToken {
		t.Fatalf("Authorization у сервера: %q", got)
	}
	for _, h := range []string{"Cookie", HeaderSession, "X-Custom"} {
		if hdr.Get(h) != "" {
			t.Errorf("заголовок %s ушёл серверу", h)
		}
	}
	if hdr.Get("Mcp-Param-Path") != "/data/a.txt" || hdr.Get(mcp.HeaderName) != "read_file" {
		t.Fatalf("заголовки MCP: %v", hdr)
	}
	if strings.Contains(body, "task") || !strings.Contains(body, `"arguments":{"path":"/data/a.txt"}`) {
		t.Fatalf("тело: %s", body)
	}
	ev := e.lastEvent()
	if ev.Decision.Action != "allow" || ev.Agent.Session == "" || ev.Content != nil {
		t.Fatalf("событие: %+v %+v", ev.Decision, ev.Agent)
	}
}

// 2025-11-25: сессия шлюза связана с ключом, возможности клиента
// вырезаются, запросы сервера к клиенту в потоке не передаются.
func TestMCPSession2025(t *testing.T) {
	e := newMCPEnv(t, nil)
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",` +
		`"capabilities":{"sampling":{},"roots":{"listChanged":true}},"clientInfo":{"name":"t","version":"1"}}}`
	w := e.post(e.bound, init, nil)
	sid := w.Header().Get(mcp.HeaderSessionID)
	if w.Code != 200 || len(sid) != 32 || strings.HasPrefix(sid, "mock-session") {
		t.Fatalf("initialize: %d %q %s", w.Code, sid, w.Body)
	}
	if _, body := e.lastUpstream(); strings.Contains(body, "sampling") || strings.Contains(body, "roots") {
		t.Fatalf("возможности клиента ушли серверу: %s", body)
	}
	if ev := e.lastEvent(); !slices.Contains(ev.Agent.Stripped, "sampling") || ev.Agent.Session != sid {
		t.Fatalf("событие: %+v", ev.Agent)
	}
	hdr := func(s string) map[string]string {
		return map[string]string{mcp.HeaderProtocolVersion: mcp.Version20251125, mcp.HeaderSessionID: s, "Accept": "application/json, text/event-stream"}
	}
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ask_user","arguments":{"question":"?"}}}`
	// Чужой ключ (тот же агент из заголовка) — сессии нет.
	if w := e.post(e.free, call, map[string]string{mcp.HeaderProtocolVersion: mcp.Version20251125, mcp.HeaderSessionID: sid,
		HeaderAgent: "report-bot"}); w.Code != http.StatusNotFound {
		t.Fatalf("чужая сессия: %d %s", w.Code, w.Body)
	}
	if w := e.post(e.bound, call, hdr("0123456789abcdef0123456789abcdef")); w.Code != http.StatusNotFound {
		t.Fatalf("неизвестная сессия: %d", w.Code)
	}
	w = e.post(e.bound, call, hdr(sid))
	msgs := replies(t, w)
	for _, m := range msgs {
		if m.Method == "sampling/createMessage" {
			t.Fatal("запрос сервера к клиенту передан")
		}
	}
	if m := msgs[len(msgs)-1]; m.Result == nil || isErrorResult(m) {
		t.Fatalf("результат: %s", w.Body)
	}
	if ev := e.lastEvent(); ev.Agent.Dropped != 1 || ev.Agent.Protocol != mcp.Version20251125 {
		t.Fatalf("событие: %+v", ev.Agent)
	}
	// ping отвечает шлюз.
	if w := e.post(e.bound, `{"jsonrpc":"2.0","id":3,"method":"ping"}`, hdr(sid)); w.Code != 200 || mreply(t, w).Result == nil {
		t.Fatalf("ping: %d %s", w.Code, w.Body)
	}
}

// 2026-07-28: результат input_required клиенту не передаётся; уведомления о
// ходе — только progressToken, progress и total.
func TestMCPInputRequiredAndProgress(t *testing.T) {
	e := newMCPEnv(t, nil)
	w := e.call26(e.bound, "tools/call", "ask_user", `"name":"ask_user","arguments":{"question":"?"}`, nil)
	if m := mreply(t, w); m.Kind != mcp.KindError || strings.Contains(w.Body.String(), "elicitation") {
		t.Fatalf("input_required: %s", w.Body)
	}
	if ev := e.lastEvent(); ev.Agent.Violation != violationInput {
		t.Fatalf("событие: %+v", ev.Agent)
	}
	w = e.post(e.bound, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"slow_job","arguments":{"job":"j1"},`+
		`"_meta":{"progressToken":"p1","io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		map[string]string{mcp.HeaderProtocolVersion: mcp.Version20260728, mcp.HeaderMethod: "tools/call", mcp.HeaderName: "slow_job",
			"Accept": "application/json, text/event-stream"})
	msgs := replies(t, w)
	var progress int
	for _, m := range msgs {
		switch m.Method {
		case "notifications/progress":
			progress++
			if _, ok := m.Params.Get("message"); ok {
				t.Fatalf("текст сервера в ходе выполнения: %s", m.Encode())
			}
			if tok, _ := mcp.GetString(m.Params, "progressToken"); tok != "p1" {
				t.Fatalf("progressToken: %s", m.Encode())
			}
		case "":
		default:
			t.Fatalf("уведомление %s передано клиенту", m.Method)
		}
	}
	if last := msgs[len(msgs)-1]; progress != 2 || last.Result == nil || isErrorResult(last) {
		t.Fatalf("поток slow_job: %d %s", progress, w.Body)
	}
	if ev := e.lastEvent(); ev.Agent.Dropped != 1 {
		t.Fatalf("событие: %+v", ev.Agent)
	}
}

// Покрывает: DM-22
// Вызов инструмента высокого риска ждёт подтверждения: keep-alive и ход
// в потоке, отказ — isError с сообщением, одобрение — вызов сервера с теми
// же аргументами.
func TestDM22_MCPApprovalFlow(t *testing.T) {
	var got ApprovalRequest
	state := ApprovalDenied
	ap := ApproverFunc(func(_ context.Context, req ApprovalRequest, wait func()) ApprovalResult {
		got = req
		wait()
		return ApprovalResult{ID: "0192d6e0-0000-7000-8000-00000000000a", State: state, DecidedBy: "duty", Waited: time.Second}
	})
	e := newMCPEnv(t, func(o *mcpOpts) {
		o.approver = ap
		o.approve["read_file"] = policy.RiskHigh
	})
	params := `"name":"read_file","arguments":{"path":"/data/a.txt"},"_meta":{"progressToken":7,"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
	post := func() *httptest.ResponseRecorder {
		h := map[string]string{mcp.HeaderProtocolVersion: mcp.Version20260728, mcp.HeaderMethod: "tools/call", mcp.HeaderName: "read_file",
			"Accept": "application/json, text/event-stream"}
		return e.post(e.bound, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{`+params+`}}`, h)
	}
	w := post()
	if !strings.Contains(w.Body.String(), ": aisec-approval-pending") || !strings.Contains(w.Body.String(), msgApprovalPending) {
		t.Fatalf("поток ожидания: %s", w.Body)
	}
	if m := mreply(t, w); !isErrorResult(m) {
		t.Fatalf("отказ: %s", w.Body)
	}
	if got.Path != ApprovalPathMCP || got.Agent != "report-bot" || got.Server != "files" || got.Tool != "read_file" ||
		string(got.Args) != `{"path":"/data/a.txt"}` || got.ApprovedHash == "" {
		t.Fatalf("запрос подтверждения: %+v", got)
	}
	ev := e.lastEvent()
	if ev.Agent.Approval == nil || ev.Agent.Approval.State != "denied" || ev.Decision.Action != "block" || ev.Agent.Upstream != 0 {
		t.Fatalf("событие отказа: %+v %+v", ev.Agent, ev.Decision)
	}
	state = ApprovalApproved
	w = post()
	if m := mreply(t, w); isErrorResult(m) || m.Result == nil {
		t.Fatalf("одобрено: %s", w.Body)
	}
	if ev := e.lastEvent(); ev.Agent.Approval.State != "approved" || ev.Agent.Upstream != 200 {
		t.Fatalf("событие одобрения: %+v", ev.Agent)
	}
}

// Перенаправление вышестоящего сервера не выполняется; адрес вне
// разрешённых сетей (loopback) не принимается в реестре и не соединяется
// после разрешения имени.
func TestMCPUpstreamRedirectAndBlockedAddress(t *testing.T) {
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest", http.StatusFound)
	})
	e := newMCPEnv(t, func(o *mcpOpts) { o.upstream = redirect })
	if w := e.call26(e.bound, "tools/list", "", "", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("перенаправление: %d %s", w.Code, w.Body)
	}
	if ev := e.lastEvent(); ev.Agent.Violation != violationUpstream || ev.Agent.Upstream != http.StatusFound {
		t.Fatalf("событие: %+v", ev.Agent)
	}
	tp, err := testProvider(t).TLS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newMCPUpstream(bundle.MCPServer{ID: "files", URL: "https://127.0.0.1:1/mcp", External: true}, "", tp, nil); err == nil {
		t.Fatal("loopback принят в реестре")
	}
	// Имя разрешается в loopback уже после проверки реестра (DNS rebinding).
	blocked := newMCPEnv(t, func(o *mcpOpts) { o.host = "mcp.example.ru" })
	blocked.dialer(mcpDialer{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}})
	if w := blocked.call26(blocked.bound, "tools/list", "", "", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("loopback после разрешения имени: %d %s", w.Code, w.Body)
	}
	if ev := blocked.lastEvent(); ev.Agent.Violation != violationUpstream || ev.Agent.Upstream != 0 {
		t.Fatalf("событие: %+v", ev.Agent)
	}
}

// Содержимое (аргументы и результат) — только по режиму хранения: none —
// ничего, full — аргументы и результат.
func TestMCPContentByStorage(t *testing.T) {
	e := newMCPEnv(t, func(o *mcpOpts) { o.storage = events.StorageFull })
	mreply(t, e.call26(e.bound, "tools/call", "read_file", `"name":"read_file","arguments":{"path":"/data/a.txt"}`, nil))
	ev := e.lastEvent()
	if ev.Content == nil || !strings.Contains(ev.Content.Request, "/data/a.txt") || !strings.Contains(ev.Content.Response, "отчёт") {
		t.Fatalf("содержимое: %+v", ev.Content)
	}
	if strings.Contains(ev.Agent.Tool, "/") || ev.Agent.ResultBytes == 0 {
		t.Fatalf("событие: %+v", ev.Agent)
	}
}
