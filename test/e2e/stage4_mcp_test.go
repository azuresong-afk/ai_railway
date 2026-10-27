//go:build e2e

package e2e

// MCP-прокси шлюза (задача 4.11 этапа 4) на живой PostgreSQL: сервер,
// зарегистрированный шлюз с пакетами от сервера и mock-mcp. Администратор
// регистрирует MCP-сервер с учётными данными, агента и привязанный к нему
// ключ. Шлюз показывает агенту только одобренные инструменты: увиденные
// описания уходят на сервер (tools:observe), отравленное описание
// становится suspicious и поднимает оповещение agents.tool_poisoning
// (DM-24); после одобрения вызов проходит с учётными данными из реестра,
// а результат с инъекцией блокируется (DM-07).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/mockmcp"
)

// s4MCPToken — синтетический токен MCP-сервера стенда.
const s4MCPToken = "e2e-mcp-token-7f3a" //nolint:gosec // G101: синтетический токен стенда e2e

// s4HostIP — адрес узла вне loopback: правило адресов (internal/netguard)
// не пускает шлюз и реестр к loopback, поэтому mock-mcp слушает внешний
// интерфейс. Без такого адреса тест пропускается.
func s4HostIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	t.Skip("нет адреса IPv4 вне loopback для mock-mcp")
	return ""
}

// s4MCP — mock-mcp стенда: адрес, корневой сертификат и последний запрос.
type s4MCP struct {
	t     *testing.T
	addr  string
	caPEM []byte
	hc    *http.Client
}

func s4StartMCP(t *testing.T, ip string) *s4MCP {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	ca, err := aisecCrypto.NewCA("e2e MCP CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{ip}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"mcp.pem": cert, "mcp-key.pem": key, "token": []byte(s4MCPToken)}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	addr := start(t, "mock-mcp", "-listen", net.JoinHostPort(ip, "0"), "-cert", filepath.Join(dir, "mcp.pem"),
		"-key", filepath.Join(dir, "mcp-key.pem"), "-token-file", filepath.Join(dir, "token"), "-poisoned")
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tp.ClientConfig(ca.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	m := &s4MCP{t: t, addr: addr, caPEM: ca.CertPEM(), hc: &http.Client{Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout: 10 * time.Second}}
	t.Cleanup(m.hc.CloseIdleConnections)
	return m
}

// rugPull подменяет описание read_file на сервере (DM-25).
func (m *s4MCP) rugPull() {
	m.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+m.addr+mockmcp.RugPullPath, nil)
	if err != nil {
		m.t.Fatal(err)
	}
	resp, err := m.hc.Do(req)
	if err != nil {
		m.t.Fatal(err)
	}
	_ = resp.Body.Close() //nolint:gosec // G104: тела у ответа нет
	if resp.StatusCode != http.StatusNoContent {
		m.t.Fatalf("подмена описания: %d", resp.StatusCode)
	}
}

// last — заголовки и тело последнего запроса, дошедшего до mock-mcp.
func (m *s4MCP) last() (http.Header, string) {
	m.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+m.addr+mockmcp.LastRequestPath, nil)
	if err != nil {
		m.t.Fatal(err)
	}
	resp, err := m.hc.Do(req)
	if err != nil {
		m.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // тело прочитано ниже
	var last struct {
		Headers http.Header
		Body    string
	}
	if err := json.NewDecoder(resp.Body).Decode(&last); err != nil {
		m.t.Fatal(err)
	}
	return last.Headers, last.Body
}

// s4MCPCall — запрос ревизии 2026-07-28 к /mcp/v1/files: код и тело.
func s4MCPCall(t *testing.T, st *s3Stack, key, method, name, params string) (int, string) {
	t.Helper()
	hc := &http.Client{Transport: st.s.transport(), Timeout: 30 * time.Second}
	defer hc.CloseIdleConnections()
	if params != "" {
		params += ","
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + params +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, st.gw.base+"/mcp/v1/files", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", method)
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close() //nolint:errcheck // ошибка закрытия тела ответа не влияет на тест
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

// s4ToolNames — имена инструментов из ответа tools/list (JSON).
func s4ToolNames(t *testing.T, body string) []string {
	t.Helper()
	var r struct {
		Result struct{ Tools []struct{ Name string } }
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("tools/list: %v: %s", err, body)
	}
	var out []string
	for _, tl := range r.Result.Tools {
		out = append(out, tl.Name)
	}
	return out
}

// s4AgentTool — инструмент реестра.
type s4AgentTool struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Hash   string `json:"hash"`
}

func TestE2EStage4_MCPProxy(t *testing.T) {
	ip := s4HostIP(t)
	st := s3NewStack(t, s3Opts{})
	mcpSrv := s4StartMCP(t, ip)

	// Политика: инъекция на входе блокируется (результат инструмента —
	// вход модели), неодобренное и не разрешённое — запрет, файлы низкого
	// риска — разрешены.
	spec := map[string]any{"name": "Агенты e2e", "mode": "enforce", "rules": []map[string]any{
		{"id": "injection", "detector": "injection.heuristic", "directions": []string{"input"}, "action": "block", "severity": "high"},
	}, "tools": map[string]any{"unapproved": "block", "default": "block", "rules": []map[string]any{
		{"id": "files-low", "tool": "files/*", "risk": []string{"low"}, "action": "allow", "severity": "medium"},
	}}}
	if r := st.admin.do("POST", "/api/v1/policies", map[string]any{"id": "agents-e2e", "spec": spec}); r.code != http.StatusCreated {
		t.Fatalf("политика: %s", r)
	}
	app := st.app("agents", "agents-e2e")

	r := st.admin.do("POST", "/api/v1/mcp-servers", map[string]any{"slug": "files", "name": "Файлы e2e",
		"url": "https://" + mcpSrv.addr + mockmcp.Path, "ca_pem": string(mcpSrv.caPEM), "versions": []string{"2026-07-28", "2025-11-25"}})
	if r.code != http.StatusCreated {
		t.Fatalf("MCP-сервер: %s", r)
	}
	var srv struct{ ID string }
	r.json(t, &srv)
	if r := st.admin.do("PUT", "/api/v1/mcp-servers/"+srv.ID+"/credentials", map[string]any{"credential": s4MCPToken}); r.code != http.StatusOK &&
		r.code != http.StatusNoContent {
		t.Fatalf("учётные данные MCP-сервера: %s", r)
	}
	r = st.admin.do("POST", "/api/v1/agents", map[string]any{"application_id": app.id, "slug": "report-bot", "name": "Отчёты",
		"mcp_servers": []string{srv.ID}, "password": s2AdminPass})
	if r.code != http.StatusCreated {
		t.Fatalf("агент: %s", r)
	}
	var agent struct{ ID string }
	r.json(t, &agent)
	r = st.admin.do("POST", "/api/v1/applications/"+app.id+"/keys", map[string]any{"name": "агент", "expires_in_days": 30,
		"agent_id": agent.ID})
	if r.code != http.StatusCreated {
		t.Fatalf("ключ агента: %s", r)
	}
	var k struct{ Key string }
	r.json(t, &k)
	st.startGateway()

	// Ключ без агента — отказ; неодобренные инструменты агенту не видны.
	if code, body := s4MCPCall(t, st, app.key, "tools/list", "", ""); code != http.StatusForbidden || !strings.Contains(body, "agent_required") {
		t.Fatalf("ключ без агента: %d %s", code, body)
	}
	code, body := s4MCPCall(t, st, k.Key, "tools/list", "", "")
	if code != http.StatusOK || len(s4ToolNames(t, body)) != 0 {
		t.Fatalf("tools/list до одобрения: %d %s", code, body)
	}
	// Описания дошли до реестра: отравленное — suspicious (DM-24).
	tools := map[string]s4AgentTool{}
	if !s2WaitFor(60*time.Second, func() bool {
		r := st.admin.do("GET", "/api/v1/agent-tools", nil)
		var page struct{ Items []s4AgentTool }
		r.json(t, &page)
		for _, tl := range page.Items {
			tools[tl.Name] = tl
		}
		return len(tools) >= 6
	}) {
		t.Fatalf("описания не дошли до реестра: %+v", tools)
	}
	if tools["add_numbers"].Status != "suspicious" || tools["read_file"].Status != "new" {
		t.Fatalf("состояния инструментов: %+v", tools)
	}
	st.waitAlert("agents.tool_poisoning", 60*time.Second)

	for _, name := range []string{"read_file", "fetch_page"} {
		r := st.admin.do("POST", "/api/v1/agent-tools/"+tools[name].ID+"/approve", map[string]any{"risk": "low", "hash": tools[name].Hash,
			"password": s2AdminPass})
		if r.code != http.StatusOK {
			t.Fatalf("одобрение %s: %s", name, r)
		}
	}
	// После нового пакета одобренные инструменты видны, остальные — нет.
	var names []string
	if !s2WaitFor(90*time.Second, func() bool {
		_, body := s4MCPCall(t, st, k.Key, "tools/list", "", "")
		names = s4ToolNames(t, body)
		return len(names) == 2
	}) {
		t.Fatalf("одобренные инструменты не появились: %v\n%s", names, st.gw.log())
	}
	if !slices.Contains(names, "read_file") || !slices.Contains(names, "fetch_page") {
		t.Fatalf("tools/list после одобрения: %v", names)
	}

	// Вызов проходит с учётными данными реестра; ключ приложения серверу не
	// уходит.
	code, body = s4MCPCall(t, st, k.Key, "tools/call", "read_file", `"name":"read_file","arguments":{"path":"/data/a.txt"}`)
	if code != http.StatusOK || strings.Contains(body, `"isError":true`) || !strings.Contains(body, "отчёт") {
		t.Fatalf("read_file: %d %s", code, body)
	}
	hdr, upBody := mcpSrv.last()
	if hdr.Get("Authorization") != "Bearer "+s4MCPToken || strings.Contains(fmt.Sprint(hdr), k.Key) {
		t.Fatalf("заголовки у MCP-сервера: %v", hdr)
	}
	if !strings.Contains(upBody, `"tools/call"`) {
		t.Fatalf("тело у MCP-сервера: %s", upBody)
	}
	// Результат с внедрёнными инструкциями блокируется (DM-07).
	code, body = s4MCPCall(t, st, k.Key, "tools/call", "fetch_page", `"name":"fetch_page","arguments":{"url":"https://docs.example.ru/a"}`)
	if code != http.StatusOK || !strings.Contains(body, `"isError":true`) || strings.Contains(body, mockmcp.InjectionText) {
		t.Fatalf("fetch_page: %d %s", code, body)
	}
	// Неодобренный инструмент не вызывается (DM-20).
	code, body = s4MCPCall(t, st, k.Key, "tools/call", "delete_file", `"name":"delete_file","arguments":{"path":"/data/a.txt"}`)
	if code != http.StatusOK || !strings.Contains(body, `"isError":true`) {
		t.Fatalf("delete_file: %d %s", code, body)
	}
	if _, upBody := mcpSrv.last(); strings.Contains(upBody, "delete_file") {
		t.Fatalf("неодобренный вызов дошёл до сервера: %s", upBody)
	}
	// Подмена описания после одобрения (DM-25): инструмент пропадает из
	// списка, вызов блокируется, в реестре — changed.
	mcpSrv.rugPull()
	if _, body := s4MCPCall(t, st, k.Key, "tools/list", "", ""); slices.Contains(s4ToolNames(t, body), "read_file") {
		t.Fatalf("подменённый инструмент в списке: %s", body)
	}
	code, body = s4MCPCall(t, st, k.Key, "tools/call", "read_file", `"name":"read_file","arguments":{"path":"/data/a.txt"}`)
	if code != http.StatusOK || !strings.Contains(body, `"isError":true`) {
		t.Fatalf("read_file после подмены: %d %s", code, body)
	}
	if !s2WaitFor(60*time.Second, func() bool {
		r := st.admin.do("GET", "/api/v1/agent-tools/"+tools["read_file"].ID, nil)
		var tl s4AgentTool
		r.json(t, &tl)
		return tl.Status == "changed"
	}) {
		t.Fatal("подмена описания не отмечена в реестре")
	}
}
