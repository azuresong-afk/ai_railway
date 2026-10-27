package mcp

import (
	"bytes"
	"encoding/json"
	"testing"
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
