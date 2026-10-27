package mcp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

func mustParse(t *testing.T, s string) *Message {
	t.Helper()
	m, err := Parse([]byte(s), Limits(1<<20))
	if err != nil {
		t.Fatalf("Parse(%s): %v", s, err)
	}
	return m
}

func TestParseKinds(t *testing.T) {
	cases := []struct {
		in   string
		kind Kind
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, KindRequest},
		{`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"x"}}`, KindRequest},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, KindNotification},
		{`{"jsonrpc":"2.0","id":1,"result":{}}`, KindResult},
		{`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}`, KindError},
		{`{"jsonrpc":"2.0","error":{"code":-32700,"message":"x"}}`, KindError},
	}
	for _, c := range cases {
		if m := mustParse(t, c.in); m.Kind != c.kind {
			t.Errorf("%s: вид %v, ждали %v", c.in, m.Kind, c.kind)
		}
	}
}

// Пакет JSON-RPC, повтор ключа, лишние поля, неверные id и method —
// отказ; пакет — отдельной ошибкой ErrBatch (ADR-0023, раздел 6).
func TestParseRejects(t *testing.T) {
	if _, err := Parse([]byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`), Limits(1<<20)); !errors.Is(err, ErrBatch) {
		t.Fatalf("пакет: %v, ждали ErrBatch", err)
	}
	bad := []string{
		`{"jsonrpc":"2.0","id":1,"method":"a","method":"b"}`,
		`{"jsonrpc":"1.0","id":1,"method":"a"}`,
		`{"id":1,"method":"a"}`,
		`{"jsonrpc":"2.0","id":1,"method":"a","extra":1}`,
		`{"jsonrpc":"2.0","id":1.5,"method":"a"}`,
		`{"jsonrpc":"2.0","id":1e3,"method":"a"}`,
		`{"jsonrpc":"2.0","id":01,"method":"a"}`,
		`{"jsonrpc":"2.0","id":null,"method":"a"}`,
		`{"jsonrpc":"2.0","id":{},"method":"a"}`,
		`{"jsonrpc":"2.0","id":"` + strings.Repeat("x", MaxIDLen+1) + `","method":"a"}`,
		`{"jsonrpc":"2.0","id":1,"method":""}`,
		`{"jsonrpc":"2.0","id":1,"method":"` + strings.Repeat("m", MaxMethodLen+1) + `"}`,
		`{"jsonrpc":"2.0","id":1,"method":"a","params":[]}`,
		`{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":""}}`,
		`{"jsonrpc":"2.0","result":{}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":""}}`,
		`{"jsonrpc":"2.0","id":1,"method":"a"} {}`,
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"a\xff\"}",
		`{"jsonrpc":"2.0","id":1,"method":"a","params":{"x":"\ud800"}}`,
		`"строка"`,
	}
	for _, s := range bad {
		if _, err := Parse([]byte(s), Limits(1<<20)); err == nil {
			t.Errorf("принято: %s", s)
		}
	}
	deep := `{"jsonrpc":"2.0","id":1,"method":"a","params":{"x":` + strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth) + `}}`
	if _, err := Parse([]byte(deep), Limits(1<<20)); err == nil {
		t.Error("вложенность глубже предела принята")
	}
	if _, err := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`), Limits(10)); err == nil {
		t.Error("сообщение больше предела принято")
	}
}

// Собранное сообщение читается стандартным разборщиком так же, как
// исходное, и снова проходит строгий разбор.
func TestEncodeRoundTrip(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"f","arguments":{"s":"<a>&\"\\\n\u0001\u007f","n":12345678901234567890,"f":1.50}}}`
	m := mustParse(t, in)
	out := m.Encode()
	if strings.Contains(string(out), "\\u003c") || !strings.Contains(string(out), "<a>&") {
		t.Errorf("экранирование HTML: %s", out)
	}
	var a, b any
	if err := json.Unmarshal([]byte(in), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatalf("собранное не читается: %v: %s", err, out)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("смысл изменился:\n%s\n%s", ja, jb)
	}
	if !strings.Contains(string(out), `12345678901234567890`) || !strings.Contains(string(out), `1.50`) {
		t.Errorf("числа не исходной записью: %s", out)
	}
	mustParse(t, string(out))
}

func TestSameID(t *testing.T) {
	a := mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	b := mustParse(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	c := mustParse(t, `{"jsonrpc":"2.0","id":"1","result":{}}`)
	if !SameID(a.ID, b.ID) || SameID(a.ID, c.ID) {
		t.Error("сравнение id")
	}
}

func TestHeaderValueEncoding(t *testing.T) {
	cases := map[string]string{
		"us-west1":            "us-west1",
		"Hello, 世界":           "=?base64?SGVsbG8sIOS4lueVjA==?=",
		" padded ":            "=?base64?IHBhZGRlZCA=?=",
		"line1\nline2":        "=?base64?bGluZTEKbGluZTI=?=",
		"=?base64?literal?=":  "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
		"file:///a/config.js": "file:///a/config.js",
	}
	for in, want := range cases {
		if got := EncodeHeaderValue(in); got != want {
			t.Errorf("EncodeHeaderValue(%q) = %q, ждали %q", in, got, want)
		}
		if got, err := DecodeHeaderValue(want); err != nil || got != in {
			t.Errorf("DecodeHeaderValue(%q) = %q, %v", want, got, err)
		}
	}
	for _, bad := range []string{"a\x01b", "=?base64?!!?=", "=?base64?/w==?=", " x"} {
		if _, err := DecodeHeaderValue(bad); err == nil {
			t.Errorf("принято %q", bad)
		}
	}
}

func headers(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

const call2026 = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`

// Несовпадение заголовков с телом — HeaderMismatch (-32020).
func TestCheckHeadersMismatch(t *testing.T) {
	m := mustParse(t, call2026)
	ok := headers(HeaderProtocolVersion, "2026-07-28", HeaderMethod, "tools/call", HeaderName, "get_weather")
	if err := CheckHeaders(ok, m); err != nil {
		t.Fatalf("верные заголовки: %v", err)
	}
	if err := CheckHeaders(headers(HeaderProtocolVersion, "2026-07-28", HeaderMethod, "tools/call",
		HeaderName, EncodeHeaderValue("get_weather\n")), m); err == nil {
		t.Error("base64 с другим именем принят")
	}
	bad := []http.Header{
		headers(HeaderMethod, "tools/call", HeaderName, "get_weather"),
		headers(HeaderProtocolVersion, "2025-11-25", HeaderMethod, "tools/call", HeaderName, "get_weather"),
		headers(HeaderProtocolVersion, "2026-07-28", HeaderMethod, "tools/list", HeaderName, "get_weather"),
		headers(HeaderProtocolVersion, "2026-07-28", HeaderMethod, "tools/call"),
		headers(HeaderProtocolVersion, "2026-07-28", HeaderMethod, "tools/call", HeaderName, "other"),
		headers(HeaderProtocolVersion, "2026-07-28", HeaderMethod, "tools/call", HeaderName, "get_weather", HeaderName, "get_weather"),
		headers(HeaderProtocolVersion, "2026-07-28", HeaderMethod, "tools/call", HeaderName, "get\x01weather"),
	}
	for i, h := range bad {
		err := CheckHeaders(h, m)
		var he *HeaderError
		if !errors.As(err, &he) {
			t.Errorf("случай %d: %v, ждали HeaderError", i, err)
		}
	}
	list := mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
	if err := CheckHeaders(headers(HeaderProtocolVersion, "2026-07-28", HeaderMethod, "tools/list", HeaderName, "x"), list); err == nil {
		t.Error("Mcp-Name у tools/list принят")
	}
}

func TestParamHeaders(t *testing.T) {
	schema := func(s string) *argschema.Value {
		v, err := argschema.ParseJSON([]byte(s), Limits(1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return &v
	}
	hs, err := ParamHeaders(schema(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},
		"o":{"type":"object","properties":{"n":{"type":"integer","x-mcp-header":"N"},"b":{"type":"boolean","x-mcp-header":"B"}}}}}`))
	if err != nil || len(hs) != 3 {
		t.Fatalf("ParamHeaders: %v, %v", hs, err)
	}
	args := schema(`{"region":"Москва","o":{"n":42,"b":true}}`)
	h, err := BuildParamHeaders(hs, args)
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Mcp-Param-Region") != EncodeHeaderValue("Москва") || h.Get("Mcp-Param-N") != "42" || h.Get("Mcp-Param-B") != "true" {
		t.Errorf("заголовки: %v", h)
	}
	if h, _ := BuildParamHeaders(hs, schema(`{"region":null}`)); len(h) != 0 {
		t.Errorf("null и отсутствие — без заголовков: %v", h)
	}
	if _, err := BuildParamHeaders(hs, schema(`{"region":1}`)); err == nil {
		t.Error("число для строкового заголовка принято")
	}
	if _, err := BuildParamHeaders(hs, schema(`{"o":{"n":9007199254740993}}`)); err == nil {
		t.Error("целое вне безопасного диапазона принято")
	}
	invalid := []string{
		`{"type":"object","properties":{"a":{"type":"number","x-mcp-header":"A"}}}`,
		`{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"A"},"b":{"type":"string","x-mcp-header":"a"}}}`,
		`{"type":"object","properties":{"a":{"type":"array","items":{"type":"string","x-mcp-header":"A"}}}}`,
		`{"type":"object","oneOf":[{"properties":{"a":{"type":"string","x-mcp-header":"A"}}}]}`,
		`{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"A B"}}}`,
		`{"type":"object","properties":{"a":{"type":"string","x-mcp-header":""}}}`,
		`{"type":"object","x-mcp-header":"Root"}`,
	}
	for _, s := range invalid {
		if _, err := ParamHeaders(schema(s)); !errors.Is(err, ErrInvalidToolHeaders) {
			t.Errorf("принято: %s", s)
		}
	}
}

func TestSessionID(t *testing.T) {
	if id, err := SessionID(headers(HeaderSessionID, "abc-123")); err != nil || id != "abc-123" {
		t.Fatal(id, err)
	}
	for _, bad := range []string{"a b", "ж", strings.Repeat("a", MaxSessionID+1)} {
		if _, err := SessionID(headers(HeaderSessionID, bad)); err == nil {
			t.Errorf("принято %q", bad)
		}
	}
}

// Лимиты числа событий и размера события SSE (ADR-0023, раздел 6).
func TestSSELimits(t *testing.T) {
	ev := "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n"
	msgs, err := ParseSSE(strings.NewReader(": keep-alive\n\n" + ev + "event: message\n" + ev))
	if err != nil || len(msgs) != 2 {
		t.Fatalf("поток: %d, %v", len(msgs), err)
	}
	if _, err := ParseSSE(strings.NewReader(strings.Repeat(ev, MaxEvents+1))); !errors.Is(err, ErrTooManyEvents) {
		t.Errorf("событий больше предела: %v", err)
	}
	big := "data: \"" + strings.Repeat("x", MaxMessage) + "\"\n\n"
	if _, err := ParseSSE(strings.NewReader(big)); err == nil {
		t.Error("событие больше предела принято")
	}
	if _, err := ParseSSE(strings.NewReader("event: other\n" + ev)); err == nil {
		t.Error("событие неизвестного типа принято")
	}
	r := NewSSEReader(strings.NewReader(strings.Repeat(ev, 10)), MaxEvents, int64(len(ev)*3))
	n := 0
	for {
		if _, err := r.Next(); err != nil {
			if !errors.Is(err, ErrStreamTooLarge) {
				t.Errorf("предел байт: %v", err)
			}
			break
		}
		n++
	}
	if n != 3 {
		t.Errorf("прочитано %d событий до предела, ждали 3", n)
	}
}

func TestMethodAllowed(t *testing.T) {
	for _, c := range []struct {
		m, v string
		ok   bool
	}{
		{"tools/call", Version20260728, true}, {"server/discover", Version20260728, true},
		{"initialize", Version20260728, false}, {"initialize", Version20251125, true},
		{"server/discover", Version20251125, false}, {"completion/complete", Version20251125, false},
		{"logging/setLevel", Version20260728, false}, {"tasks/get", Version20260728, false},
		{"sampling/createMessage", Version20251125, false},
	} {
		if MethodAllowed(c.m, c.v) != c.ok {
			t.Errorf("%s в %s: ждали %v", c.m, c.v, c.ok)
		}
	}
}

// Возможности sampling, elicitation, roots, tasks и extensions вырезаются;
// неизвестные поля params и _meta не уходят серверу.
func TestUpstreamParams(t *testing.T) {
	m := mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",
		"capabilities":{"sampling":{},"roots":{"listChanged":true},"elicitation":{},"experimental":{}},"clientInfo":{"name":"c","version":"1"},"x":1}}`)
	p, stripped := UpstreamParams(m.Method, m.Params)
	got := string(AppendJSON(nil, *p))
	if strings.Contains(got, "sampling") || strings.Contains(got, "roots") || strings.Contains(got, `"x"`) ||
		!strings.Contains(got, "experimental") {
		t.Errorf("params: %s", got)
	}
	if strings.Join(stripped, ",") != "elicitation,roots,sampling" {
		t.Errorf("вырезано: %v", stripped)
	}
	m = mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"f","task":{"ttl":1},
		"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"tasks":{},"extensions":{}},"logLevel":"debug","progressToken":5}}}`)
	p, stripped = UpstreamParams(m.Method, m.Params)
	got = string(AppendJSON(nil, *p))
	if strings.Contains(got, "task") || strings.Contains(got, "logLevel") || strings.Contains(got, "extensions") ||
		!strings.Contains(got, "progressToken") {
		t.Errorf("params: %s", got)
	}
	if strings.Join(stripped, ",") != "extensions,tasks" {
		t.Errorf("вырезано: %v", stripped)
	}
}

func resultOf(t *testing.T, s string) *argschema.Value {
	t.Helper()
	m := mustParse(t, `{"jsonrpc":"2.0","id":1,"result":`+s+`}`)
	return m.Result
}

func TestToolsList(t *testing.T) {
	r := resultOf(t, `{"tools":[
		{"name":"a","description":"Первый","icons":[{"src":"https://x/i.png"}],"_meta":{"k":1},"inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Путь"}}}},
		{"name":"a","description":"повтор"},
		{"name":"bad name"},
		{"name":"h","inputSchema":{"type":"object","properties":{"n":{"type":"number","x-mcp-header":"N"}}}},
		{"name":"b","title":"Второй"}],"nextCursor":"c2","ttlMs":300000,"cacheScope":"public"}`)
	l, err := ParseList("tools/list", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Items) != 2 || l.Invalid != 3 {
		t.Fatalf("элементов %d, исключено %d", len(l.Items), l.Invalid)
	}
	if txt := l.Items[0].Text; !strings.Contains(txt, "Первый") || !strings.Contains(txt, "Путь") || !strings.Contains(txt, "path") ||
		strings.Contains(txt, "x/i.png") {
		t.Errorf("текст описания: %q", txt)
	}
	out := string(AppendJSON(nil, l.Rebuild(func(i int) bool { return i == 0 }, Version20260728)))
	for _, want := range []string{`"nextCursor":"c2"`, `"ttlMs":60000`, `"cacheScope":"private"`} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %s: %s", want, out)
		}
	}
	if strings.Contains(out, "icons") || strings.Contains(out, `"_meta"`) || strings.Contains(out, "Второй") {
		t.Errorf("лишнее в ответе: %s", out)
	}
	if out := string(AppendJSON(nil, l.Rebuild(nil, Version20251125))); strings.Contains(out, "private") {
		t.Errorf("2025-11-25 без cacheScope шлюза: %s", out)
	}
	if _, err := ParseList("tools/list", resultOf(t, `{"tools":`+"["+strings.Repeat(`{"name":"x"},`, MaxListItems)+`{"name":"y"}]}`)); err == nil {
		t.Error("больше предела инструментов принято")
	}
}

func TestContentResult(t *testing.T) {
	r := resultOf(t, `{"resultType":"complete","content":[{"type":"text","text":"t1"},{"type":"image","data":"AA==","mimeType":"image/png"},
		{"type":"resource_link","uri":"https://x.example/a","name":"a"},{"type":"resource","resource":{"uri":"file:///r","text":"t2"}}],
		"structuredContent":{"a":["s1",{"b":"s2"}],"n":1},"isError":false}`)
	cr, err := ParseContentResult("tools/call", r)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, x := range cr.Texts {
		paths = append(paths, x.Path)
	}
	want := "content[0].text,content[2].uri,content[2].name,content[3].resource.uri,content[3].resource.text,structuredContent.a[0],structuredContent.a[1].b"
	if strings.Join(paths, ",") != want {
		t.Errorf("пути: %s", strings.Join(paths, ","))
	}
	if len(cr.Media) != 1 || cr.Links != 1 {
		t.Errorf("media %v, links %d", cr.Media, cr.Links)
	}
	cr.Texts[0].Ref.Str = "[[MASK]]"
	if out := string(AppendJSON(nil, cr.Result)); !strings.Contains(out, "[[MASK]]") || strings.Contains(out, `"t1"`) {
		t.Errorf("замена не в документе: %s", out)
	}
	if _, err := ParseContentResult("tools/call", resultOf(t, `{"resultType":"input_required","requestState":"x"}`)); !errors.Is(err, ErrInputRequired) {
		t.Errorf("input_required: %v", err)
	}
	for _, bad := range []string{`{"content":[{"type":"video"}]}`, `{"content":{}}`, `{"isError":"yes"}`, `{"resultType":"other"}`,
		`{"content":[{"type":"text","text":1}]}`, `{"content":[{"type":"resource","resource":{"text":"a","blob":"b"}}]}`} {
		if _, err := ParseContentResult("tools/call", resultOf(t, bad)); err == nil {
			t.Errorf("принято: %s", bad)
		}
	}
	rr, err := ParseContentResult("resources/read", resultOf(t, `{"contents":[{"uri":"file:///a","text":"x"},{"uri":"file:///b","blob":"AA=="}]}`))
	if err != nil || len(rr.Texts) != 3 || len(rr.Media) != 1 {
		t.Errorf("resources/read: %+v, %v", rr, err)
	}
	pr, err := ParseContentResult("prompts/get", resultOf(t, `{"description":"d","messages":[{"role":"user","content":{"type":"text","text":"p"}}]}`))
	if err != nil || len(pr.Texts) != 2 {
		t.Errorf("prompts/get: %+v, %v", pr, err)
	}
}

func TestCallParams(t *testing.T) {
	m := mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"f","arguments":{"a":"b"},"_meta":{"progressToken":"p1"}}}`)
	cp, err := ParseCallParams(m.Params)
	if err != nil || cp.Name != "f" || cp.ProgressToken == nil || len(cp.Args.Keys) != 1 {
		t.Fatalf("%+v, %v", cp, err)
	}
	for _, bad := range []string{`{"arguments":{}}`, `{"name":"f","arguments":[]}`, `{"name":"f","inputResponses":{}}`, `{"name":"f","requestState":"s"}`} {
		m := mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+bad+`}`)
		if _, err := ParseCallParams(m.Params); CodeOf(err) != CodeInvalidParams {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// Запросы сервера к клиенту и прочие уведомления клиенту не передаются;
// у progress не передаётся текст.
func TestServerMessages(t *testing.T) {
	cases := []struct {
		in             string
		normal, listen bool
	}{
		{`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":1,"message":"x"}}`, true, false},
		{`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`, true, true},
		{`{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{}}`, false, true},
		{`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"x"}}`, false, false},
		{`{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{}}`, false, false},
		{`{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"x"}}`, false, false},
	}
	for _, c := range cases {
		m := mustParse(t, c.in)
		if ServerMessageAllowed(m, false) != c.normal || ServerMessageAllowed(m, true) != c.listen {
			t.Errorf("%s", c.in)
		}
	}
	p := Sanitize(mustParse(t, cases[0].in))
	if strings.Contains(string(p.Encode()), "message") {
		t.Errorf("текст progress передан: %s", p.Encode())
	}
}

func TestErrorResult(t *testing.T) {
	d := Object()
	Set(&d, "action", String("block"))
	out := string(AppendJSON(nil, ErrorResult("Вызов отклонён", Version20260728, &d)))
	for _, want := range []string{`"isError":true`, `"resultType":"complete"`, `"ru.aisec/decision":{"action":"block"}`, "Вызов отклонён"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %s: %s", want, out)
		}
	}
	e := string(ErrorMessage(nil, CodeHeaderMismatch, "x", nil).Encode())
	if e != `{"jsonrpc":"2.0","error":{"code":-32020,"message":"x"}}` {
		t.Errorf("ошибка без id: %s", e)
	}
}
