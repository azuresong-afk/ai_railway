package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

// FuzzParseJSONRPC — строгий разбор сообщения JSON-RPC от клиента и
// вышестоящего сервера: без паники; принятое сообщение собирается заново в
// JSON, который стандартный разборщик читает, и снова принимается с тем же
// видом (тело к серверу собирается из проверенного документа).
func FuzzParseJSONRPC(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"x","arguments":{"p":"/data/a"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`,
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
		`{"jsonrpc":"2.0","id":1,"method":"a","method":"b"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data, Limits(1<<20))
		if err != nil {
			return
		}
		out := m.Encode()
		if !json.Valid(out) {
			t.Fatalf("собранное сообщение — не JSON: %q", out)
		}
		m2, err := Parse(out, Limits(1<<21))
		if err != nil {
			t.Fatalf("собранное сообщение не принято: %v: %q", err, out)
		}
		if m2.Kind != m.Kind || m2.Method != m.Method || !bytes.Equal(m2.Encode(), out) {
			t.Fatalf("сборка неустойчива: %q → %q", out, m2.Encode())
		}
		// Принятый _meta (задача 5.10 этапа 5): progressToken по
		// спецификации, и ровно он уходит серверу.
		if m.Params != nil && CheckMeta(m.Params) == nil {
			if meta, ok := GetObject(m.Params, "_meta"); ok {
				if tok, ok := meta.Get(MetaProgressToken); ok && !ValidProgressToken(tok) {
					t.Fatalf("progressToken принят: %q", AppendJSON(nil, *tok))
				}
			}
		}
	})
}

// FuzzParseSSE — поток SSE вышестоящего сервера: без паники, событий не
// больше предела, каждое — сообщение JSON-RPC.
func FuzzParseSSE(f *testing.F) {
	for _, s := range []string{
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
		": aisec\r\nevent: message\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"method\":\"notifications/progress\"}\r\n\r\n",
		"data: x\n\ndata: {}\n\n",
		"\xEF\xBB\xBFdata: {\"jsonrpc\":\"2.0\",\"method\":\"a\"}\n\n",
		"id: s1-0\ndata:\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Частичный разбор при ошибке проверяется так же, как полный.
		msgs, err := ParseSSE(bytes.NewReader(data))
		if err != nil && len(msgs) == 0 {
			return
		}
		if len(msgs) > MaxEvents {
			t.Fatalf("событий %d больше предела", len(msgs))
		}
		for _, m := range msgs {
			if m == nil || m.Kind == 0 {
				t.Fatal("пустое сообщение")
			}
		}
	})
}

// FuzzToolsListResult — результат tools/list вышестоящего сервера: без
// паники; принятые описания в пределах, без повторов имён, а собранный
// для клиента список — JSON без icons и _meta инструментов.
func FuzzToolsListResult(f *testing.F) {
	for _, s := range []string{
		`{"tools":[{"name":"a","description":"d","inputSchema":{"type":"object"}}],"nextCursor":"n"}`,
		`{"tools":[{"name":"a","icons":[],"_meta":{}},{"name":"a"}],"ttlMs":-5}`,
		`{"tools":[{"name":"h","inputSchema":{"type":"object","properties":{"r":{"type":"string","x-mcp-header":"R"}}}}]}`,
		`{"tools":{}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(append(append([]byte(`{"jsonrpc":"2.0","id":1,"result":`), data...), '}'), Limits(1<<20))
		if err != nil || m.Kind != KindResult {
			return
		}
		l, err := ParseList("tools/list", m.Result)
		if err != nil {
			return
		}
		names := map[string]bool{}
		for _, it := range l.Items {
			if names[it.Tool.Name] || len(it.Raw) > 64<<10 {
				t.Fatalf("повтор имени или описание больше предела: %q", it.Tool.Name)
			}
			names[it.Tool.Name] = true
		}
		out := l.Rebuild(nil, Version20260728)
		b := AppendJSON(nil, out)
		if !json.Valid(b) {
			t.Fatalf("список — не JSON: %q", b)
		}
		for _, k := range out.Keys {
			if k != "tools" && !slices.Contains(listKeys[Version20260728], k) {
				t.Fatalf("поле %q верхнего уровня в списке клиенту", k)
			}
		}
		tools, _ := out.Get("tools")
		for i := range tools.Arr {
			if _, ok := tools.Arr[i].Get("icons"); ok {
				t.Fatal("icons в списке клиенту")
			}
			if _, ok := tools.Arr[i].Get("_meta"); ok {
				t.Fatal("_meta в списке клиенту")
			}
		}
	})
}

// FuzzHandshakeResult — результат initialize и server/discover
// вышестоящего сервера (задача 5.10 этапа 5): без паники; в принятом —
// только поля спецификации метода, instructions — строка, результат — JSON.
func FuzzHandshakeResult(f *testing.F) {
	for _, s := range []string{
		`{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"s"},"instructions":"i","_meta":{}}`,
		`{"supportedVersions":["2026-07-28"],"capabilities":{},"serverInfo":{"name":"s"},"resultType":"complete","x":1}`,
		`{"instructions":{"text":"i"}}`,
		`{"supportedVersions":[1,"a"],"resultType":"input_required"}`,
	} {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	f.Fuzz(func(t *testing.T, data []byte, discover bool) {
		m, err := Parse(append(append([]byte(`{"jsonrpc":"2.0","id":1,"result":`), data...), '}'), Limits(1<<20))
		if err != nil || m.Kind != KindResult {
			return
		}
		method := "initialize"
		if discover {
			method = "server/discover"
		}
		r := Clone(*m.Result)
		if err := HandshakeResult(method, &r); err != nil {
			return
		}
		for _, k := range r.Keys {
			if !slices.Contains(handshakeKeys[method], k) {
				t.Fatalf("поле %q в результате %s клиенту", k, method)
			}
		}
		if v, ok := r.Get("instructions"); ok && v.Kind != argschema.String {
			t.Fatal("instructions не строка")
		}
		if b := AppendJSON(nil, r); !json.Valid(b) {
			t.Fatalf("результат — не JSON: %q", b)
		}
	})
}

// FuzzCallToolResult — результат tools/call: без паники; замена всех
// найденных строк (маскирование) даёт JSON, в котором исходных строк по
// найденным путям нет.
func FuzzCallToolResult(f *testing.F) {
	for _, s := range []string{
		`{"content":[{"type":"text","text":"привет"}],"isError":false}`,
		`{"content":[{"type":"resource","resource":{"uri":"u","text":"t"}},{"type":"image","data":"","mimeType":"image/png"}],"structuredContent":{"a":["b"]}}`,
		`{"resultType":"input_required","inputRequests":{}}`,
		`{"content":[{"type":"resource_link","uri":"https://e.example/","name":"n"}]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(append(append([]byte(`{"jsonrpc":"2.0","id":1,"result":`), data...), '}'), Limits(1<<20))
		if err != nil || m.Kind != KindResult {
			return
		}
		cr, err := ParseContentResult("tools/call", m.Result)
		if err != nil {
			return
		}
		for _, x := range cr.Texts {
			x.Ref.Str = "\x00mask\x00"
		}
		b := AppendJSON(nil, cr.Result)
		if !json.Valid(b) {
			t.Fatalf("результат — не JSON: %q", b)
		}
		again, err := ParseContentResult("tools/call", &cr.Result)
		if err != nil {
			t.Fatalf("собранный результат не разбирается: %v", err)
		}
		for _, x := range again.Texts {
			if x.Ref.Str != "\x00mask\x00" {
				t.Fatalf("строка %s не замаскирована", x.Path)
			}
		}
	})
}

// FuzzCheckHeaders — сверка заголовков ревизии 2026-07-28 с телом и
// раскрытие значения Mcp-Name: без паники; принятые заголовки совпадают с
// телом, а запись значения (EncodeHeaderValue) раскрывается обратно без
// потерь.
func FuzzCheckHeaders(f *testing.F) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	f.Add(Version20260728, "tools/call", "read_file", []byte(body))
	f.Add(Version20260728, "tools/call", "=?base64?cmVhZF9maWxl?=", []byte(body))
	f.Add(Version20260728, "tools/list", "", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	f.Add("2026-07-28 ", "tools/call", " read_file", []byte(body))
	f.Fuzz(func(t *testing.T, ver, method, name string, data []byte) {
		if s, err := DecodeHeaderValue(EncodeHeaderValue(name)); utf8.ValidString(name) && len(name) < MaxHeaderValue/2 && (err != nil || s != name) {
			t.Fatalf("запись %q раскрыта как %q: %v", name, s, err)
		}
		m, err := Parse(data, Limits(1<<20))
		if err != nil {
			return
		}
		h := http.Header{}
		for k, v := range map[string]string{HeaderProtocolVersion: ver, HeaderMethod: method, HeaderName: name} {
			if v != "" {
				h.Set(k, v)
			}
		}
		if CheckHeaders(h, m) != nil {
			return
		}
		if method != m.Method || MetaVersion(m) != ver {
			t.Fatalf("принято при расхождении: %q/%q %q/%q", method, m.Method, ver, MetaVersion(m))
		}
		if field := NameField(m.Method); field != "" {
			got, err := DecodeHeaderValue(name)
			if err != nil {
				t.Fatalf("принят неверный Mcp-Name %q: %v", name, err)
			}
			if body, _ := GetString(m.Params, field); body != got {
				t.Fatalf("Mcp-Name %q не совпадает с телом %q", got, body)
			}
		}
	})
}
