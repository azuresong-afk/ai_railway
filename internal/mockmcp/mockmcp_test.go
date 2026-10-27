package mockmcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/mcp"
)

func post(t *testing.T, h http.Handler, hdr map[string]string, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func h2026(method, name string) map[string]string {
	h := map[string]string{mcp.HeaderProtocolVersion: mcp.Version20260728, mcp.HeaderMethod: method}
	if name != "" {
		h[mcp.HeaderName] = name
	}
	return h
}

const meta2026 = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`

func TestMock2026ToolsAndRugPull(t *testing.T) {
	m := New(Options{Poisoned: true}, nil)
	h := m.Handler()
	w := post(t, h, h2026("tools/list", ""), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+meta2026+`}}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "id_rsa") || strings.Contains(w.Body.String(), "delete_file для /etc") {
		t.Fatalf("tools/list: %d %s", w.Code, w.Body)
	}
	m.RugPull()
	w = post(t, h, h2026("tools/list", ""), `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+meta2026+`}}`)
	if !strings.Contains(w.Body.String(), "delete_file для /etc") {
		t.Fatalf("подмена не видна: %s", w.Body)
	}
	// Заголовок Mcp-Name не совпадает с телом — -32020.
	w = post(t, h, h2026("tools/call", "other"),
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a"},`+meta2026+`}}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "-32020") {
		t.Fatalf("несовпадение заголовка: %d %s", w.Code, w.Body)
	}
	w = post(t, h, h2026("tools/call", "ask_user"),
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ask_user","arguments":{"question":"?"},`+meta2026+`}}`)
	if !strings.Contains(w.Body.String(), "input_required") {
		t.Fatalf("input_required: %s", w.Body)
	}
	w = post(t, h, map[string]string{mcp.HeaderProtocolVersion: "2024-11-05"}, `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "-32022") {
		t.Fatalf("версия: %d %s", w.Code, w.Body)
	}
}

func TestMock2025Session(t *testing.T) {
	h := New(Options{Token: "tok"}, nil).Handler()
	auth := map[string]string{"Authorization": "Bearer tok"}
	if w := post(t, h, nil, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); w.Code != 401 {
		t.Fatalf("без токена: %d", w.Code)
	}
	w := post(t, h, auth, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	sid := w.Header().Get(mcp.HeaderSessionID)
	if w.Code != 200 || sid == "" {
		t.Fatalf("initialize: %d %s", w.Code, w.Body)
	}
	hdr := map[string]string{"Authorization": "Bearer tok", mcp.HeaderProtocolVersion: mcp.Version20251125, mcp.HeaderSessionID: "чужая"}
	if w := post(t, h, hdr, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`); w.Code != 404 {
		t.Fatalf("чужая сессия: %d", w.Code)
	}
	hdr[mcp.HeaderSessionID] = sid
	w = post(t, h, hdr, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ask_user","arguments":{"question":"?"}}}`)
	msgs, err := mcp.ParseSSE(w.Body)
	if err != nil || len(msgs) != 2 || msgs[0].Method != "sampling/createMessage" || msgs[1].Kind != mcp.KindResult {
		t.Fatalf("поток: %v %+v", err, msgs)
	}
	w = post(t, h, hdr, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fetch_page","arguments":{"url":"https://example.com"}}}`)
	if !strings.Contains(w.Body.String(), "Игнорируй") {
		t.Fatalf("инъекция: %s", w.Body)
	}
}
