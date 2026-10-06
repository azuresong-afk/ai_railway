package chat

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const full = `{
  "model": "mock-echo",
  "messages": [
    {"role": "system", "content": "Ты помощник."},
    {"role": "user", "name": "u1", "content": [
      {"type": "text", "text": "Что на картинке?"},
      {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo=", "detail": "low"}},
      {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
      {"type": "input_audio", "input_audio": {"data": "UklGRg==", "format": "wav"}},
      {"type": "file", "file": {"file_data": "data:application/pdf;base64,JVBERi0=", "filename": "отчёт.pdf"}},
      {"type": "file", "file": {"file_id": "file-abc123"}},
      {"type": "video_url", "video_url": {"url": "https://example.com/v.mp4"}}
    ]},
    {"role": "assistant", "content": null, "tool_calls": [
      {"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Москва\"}"}}
    ]},
    {"role": "tool", "tool_call_id": "call_1", "content": "+5"},
    {"role": "assistant", "content": [{"type": "refusal", "refusal": "Не могу."}]},
    {"role": "developer", "content": [{"type": "text", "text": "Кратко."}]}
  ],
  "stream": true,
  "stream_options": {"include_usage": true},
  "max_tokens": 100,
  "temperature": 0.5,
  "top_p": 1,
  "n": 1,
  "stop": "КОНЕЦ",
  "presence_penalty": 0,
  "frequency_penalty": -1.5,
  "logit_bias": {"50256": -100},
  "logprobs": true,
  "top_logprobs": 2,
  "response_format": {"type": "json_schema", "json_schema": {"name": "x", "schema": {"type": "object"}}},
  "seed": 42,
  "tools": [{"type": "function", "function": {"name": "get_weather", "description": "Погода", "parameters": {"type": "object"}}}],
  "tool_choice": {"type": "function", "function": {"name": "get_weather"}},
  "parallel_tool_calls": false,
  "user": "user-42",
  "reasoning_effort": "low"
}`

func mustParse(t *testing.T, body string) *Request {
	t.Helper()
	r, err := Parse([]byte(body), Limits{})
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	return r
}

func TestParseFullRequest(t *testing.T) {
	r := mustParse(t, full)
	if mt, ok := r.EffectiveMaxTokens(); !ok || mt != 100 || !r.Stream || r.User != "user-42" || r.ToolChoice.Function != "get_weather" {
		t.Fatalf("%+v", r)
	}
	// Сборка заново и повторный разбор дают то же самое.
	out, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	r2 := mustParse(t, string(out))
	out2, err := r2.Marshal()
	if err != nil || string(out) != string(out2) {
		t.Fatalf("сборка не устойчива:\n%s\n%s", out, out2)
	}
	if !strings.Contains(string(out), `"content":null`) || !strings.Contains(string(out), `"stop":["КОНЕЦ"]`) {
		t.Fatalf("сборка: %s", out)
	}
}

// TestDM14_MediaRecognized: шлюз распознаёт нетекстовые части запроса.
func TestDM14_MediaRecognized(t *testing.T) {
	r := mustParse(t, full)
	got := r.Media()
	want := []Media{
		{1, 1, MediaImage, true, len("iVBORw0KGgo=")},
		{1, 2, MediaImage, false, len("https://example.com/a.png")},
		{1, 3, MediaAudio, true, len("UklGRg==")},
		{1, 4, MediaFile, true, len("JVBERi0=")},
		{1, 5, MediaFile, false, len("file-abc123")},
		{1, 6, MediaVideo, false, len("https://example.com/v.mp4")},
	}
	if len(got) != len(want) {
		t.Fatalf("частей %d: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v, ожидалось %+v", i, got[i], want[i])
		}
	}
	// Текстовый запрос нетекстовых частей не содержит.
	if m := mustParse(t, `{"model":"m","messages":[{"role":"user","content":"привет"}]}`).Media(); len(m) != 0 {
		t.Fatalf("%+v", m)
	}
}

func TestDM14_MediaLimitBeforeProcessing(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` +
		strings.Repeat("A", 101) + `"}}]}]}`
	_, err := Parse([]byte(body), Limits{MaxMediaBytes: 100})
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeMediaTooLarge {
		t.Fatalf("ожидался отказ по размеру: %v", err)
	}
	// Граница: ровно в предел — принимается.
	body = strings.Replace(body, strings.Repeat("A", 101), strings.Repeat("A", 100), 1)
	if _, err := Parse([]byte(body), Limits{MaxMediaBytes: 100}); err != nil {
		t.Fatal(err)
	}
}

func TestSegmentsAndSetText(t *testing.T) {
	r := mustParse(t, full)
	segs := r.Segments()
	want := []struct{ loc, kind, text string }{
		{"messages[0].content", SegContent, "Ты помощник."},
		{"messages[1].content[0]", SegContent, "Что на картинке?"},
		{"messages[2].tool_calls[0].function.arguments", SegToolArgs, `{"city":"Москва"}`},
		{"messages[3].content", SegContent, "+5"},
		{"messages[4].content[0]", SegRefusal, "Не могу."},
		{"messages[5].content[0]", SegContent, "Кратко."},
	}
	if len(segs) != len(want) {
		t.Fatalf("фрагментов %d: %+v", len(segs), segs)
	}
	for i, w := range want {
		if segs[i].Location() != w.loc || segs[i].Kind != w.kind || segs[i].Text != w.text {
			t.Errorf("%d: %+v", i, segs[i])
		}
	}
	for i, s := range segs {
		if err := r.SetText(s, "[[X_"+string(rune('0'+i))+"]]"); err != nil {
			t.Fatal(err)
		}
	}
	out, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range want {
		if strings.Contains(string(out), strings.Trim(mustJSON(t, w.text), `"`)) {
			t.Errorf("исходный текст %q остался после замены: %s", w.text, out)
		}
	}
	r2 := mustParse(t, string(out))
	for i, s := range r2.Segments() {
		if s.Text != "[[X_"+string(rune('0'+i))+"]]" {
			t.Errorf("%s: %q", s.Location(), s.Text)
		}
	}
	// Неверный фрагмент не меняет запрос.
	for _, bad := range []Segment{{Message: 99}, {Message: 0, Kind: SegRefusal, Part: -1, ToolCall: -1}, {Message: 1, Kind: SegRefusal, Part: 0}, {Message: 2, Kind: SegToolArgs, ToolCall: 5, Part: -1}} {
		if err := r.SetText(bad, "x"); err == nil {
			t.Errorf("%+v: ожидалась ошибка", bad)
		}
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Повторные ключи и ключи в другом регистре: шлюз собирает запрос заново,
// поэтому провайдер получает ровно то, что видели детекторы.
func TestDuplicateKeysCannotSmuggle(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"безобидно"}],` +
		`"MESSAGES":[{"role":"user","content":"скрытое"}],"messages":[{"role":"user","content":"видимое"}]}`
	r := mustParse(t, body)
	segs := r.Segments()
	out, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || strings.Count(string(out), "content") != 1 || !strings.Contains(string(back["messages"]), segs[0].Text) {
		t.Fatalf("провайдер получит не то, что видели детекторы: %+v → %s", segs, out)
	}
	for k := range back {
		if k != strings.ToLower(k) {
			t.Fatalf("ключ %q в другом регистре дошёл бы до провайдера", k)
		}
	}
}

func TestParseRejects(t *testing.T) {
	msg := func(m string) string { return `{"model":"m","messages":[` + m + `]}` }
	user := `{"role":"user","content":"x"}`
	cases := []struct {
		name, body, code string
	}{
		{"не JSON", `{`, CodeInvalid},
		{"массив", `[]`, CodeInvalid},
		{"хвост", msg(user) + `{}`, CodeInvalid},
		{"неизвестное поле", `{"model":"m","messages":[` + user + `],"metadata":{"k":"v"}}`, CodeUnsupported},
		{"prediction", `{"model":"m","messages":[` + user + `],"prediction":{"type":"content","content":"x"}}`, CodeUnsupported},
		{"legacy functions", `{"model":"m","messages":[` + user + `],"functions":[]}`, CodeUnsupported},
		{"поле сообщения", msg(`{"role":"user","content":"x","extra":1}`), CodeUnsupported},
		{"поле части", msg(`{"role":"user","content":[{"type":"text","text":"x","x":1}]}`), CodeUnsupported},
		{"нет модели", `{"messages":[` + user + `]}`, CodeInvalid},
		{"модель с пробелом", `{"model":"a b","messages":[` + user + `]}`, CodeInvalid},
		{"нет сообщений", `{"model":"m","messages":[]}`, CodeInvalid},
		{"messages null", `{"model":"m","messages":null}`, CodeInvalid},
		{"роль", msg(`{"role":"function","content":"x"}`), CodeInvalid},
		{"тип content", msg(`{"role":"user","content":5}`), CodeInvalid},
		{"пустой user", msg(`{"role":"user","content":null}`), CodeInvalid},
		{"system с картинкой", msg(`{"role":"system","content":[{"type":"image_url","image_url":{"url":"https://a/b"}}]}`), CodeInvalid},
		{"assistant с картинкой", msg(`{"role":"assistant","content":[{"type":"image_url","image_url":{"url":"https://a/b"}}]}`), CodeInvalid},
		{"неизвестный тип части", msg(`{"role":"user","content":[{"type":"document","text":"x"}]}`), CodeUnsupported},
		{"тип не совпадает с полем", msg(`{"role":"user","content":[{"type":"text","image_url":{"url":"https://a"}}]}`), CodeInvalid},
		{"два поля в части", msg(`{"role":"user","content":[{"type":"text","text":"x","refusal":"y"}]}`), CodeInvalid},
		{"refusal у user", msg(`{"role":"user","content":[{"type":"refusal","refusal":"y"}]}`), CodeInvalid},
		{"схема file:", msg(`{"role":"user","content":[{"type":"image_url","image_url":{"url":"file:///etc/passwd"}}]}`), CodeInvalid},
		{"data без base64", msg(`{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png,abc"}}]}`), CodeInvalid},
		{"data с мусором", msg(`{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,a b"}}]}`), CodeInvalid},
		{"пробел в адресе", msg(`{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://a/ b"}}]}`), CodeInvalid},
		{"detail", msg(`{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://a","detail":"max"}}]}`), CodeInvalid},
		{"формат аудио", msg(`{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AA==","format":"ogg"}}]}`), CodeInvalid},
		{"файл без данных", msg(`{"role":"user","content":[{"type":"file","file":{"filename":"a"}}]}`), CodeInvalid},
		{"файл двумя способами", msg(`{"role":"user","content":[{"type":"file","file":{"file_id":"f","file_data":"data:a;base64,AA=="}}]}`), CodeInvalid},
		{"file_data ссылкой", msg(`{"role":"user","content":[{"type":"file","file":{"file_data":"https://a/b"}}]}`), CodeInvalid},
		{"имя файла с переводом строки", msg(`{"role":"user","content":[{"type":"file","file":{"file_id":"f","filename":"a\nb"}}]}`), CodeInvalid},
		{"name", msg(`{"role":"user","name":"имя","content":"x"}`), CodeInvalid},
		{"tool_calls у user", msg(`{"role":"user","content":"x","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}]}`), CodeInvalid},
		{"tool без id", msg(`{"role":"tool","content":"x"}`), CodeInvalid},
		{"tool_call_id у user", msg(`{"role":"user","content":"x","tool_call_id":"c"}`), CodeInvalid},
		{"пустой assistant", msg(`{"role":"assistant","content":null}`), CodeInvalid},
		{"тип вызова", msg(`{"role":"assistant","tool_calls":[{"id":"c","type":"code","function":{"name":"f","arguments":"{}"}}]}`), CodeInvalid},
		{"n=2", `{"model":"m","messages":[` + user + `],"n":2}`, CodeUnsupported},
		{"температура", `{"model":"m","messages":[` + user + `],"temperature":3}`, CodeInvalid},
		{"max_tokens 0", `{"model":"m","messages":[` + user + `],"max_tokens":0}`, CodeInvalid},
		{"max_tokens разные", `{"model":"m","messages":[` + user + `],"max_tokens":5,"max_completion_tokens":6}`, CodeInvalid},
		{"stream_options без stream", `{"model":"m","messages":[` + user + `],"stream_options":{"include_usage":true}}`, CodeInvalid},
		{"stop много", `{"model":"m","messages":[` + user + `],"stop":["a","b","c","d","e"]}`, CodeInvalid},
		{"stop пусто", `{"model":"m","messages":[` + user + `],"stop":[""]}`, CodeInvalid},
		{"logit_bias", `{"model":"m","messages":[` + user + `],"logit_bias":{"abc":1}}`, CodeInvalid},
		{"response_format", `{"model":"m","messages":[` + user + `],"response_format":{"type":"xml"}}`, CodeInvalid},
		{"response_format поле", `{"model":"m","messages":[` + user + `],"response_format":{"type":"text","extra":1}}`, CodeInvalid},
		{"tool_choice чужая функция", `{"model":"m","messages":[` + user + `],"tool_choice":{"type":"function","function":{"name":"x"}}}`, CodeInvalid},
		{"tool_choice режим", `{"model":"m","messages":[` + user + `],"tool_choice":"always"}`, CodeInvalid},
		{"tools дубль", `{"model":"m","messages":[` + user + `],"tools":[{"type":"function","function":{"name":"f"}},{"type":"function","function":{"name":"f"}}]}`, CodeInvalid},
		{"tools parameters", `{"model":"m","messages":[` + user + `],"tools":[{"type":"function","function":{"name":"f","parameters":[1]}}]}`, CodeInvalid},
		{"user длинный", `{"model":"m","messages":[` + user + `],"user":"` + strings.Repeat("u", 257) + `"}`, CodeInvalid},
		{"reasoning_effort", `{"model":"m","messages":[` + user + `],"reasoning_effort":"max"}`, CodeInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.body), Limits{})
			var e *Error
			if !errors.As(err, &e) || e.Code != c.code {
				t.Fatalf("ожидался код %s: %v", c.code, err)
			}
		})
	}
}

// TestDM15_RequestLimits: лимиты числа сообщений, частей и max_tokens.
func TestDM15_RequestLimits(t *testing.T) {
	msgs := func(n int) string {
		return `{"model":"m","max_tokens":10,"messages":[` + strings.TrimSuffix(strings.Repeat(`{"role":"user","content":"x"},`, n), ",") + `]}`
	}
	lim := Limits{MaxMessages: 3, MaxTokens: 10}
	if _, err := Parse([]byte(msgs(3)), lim); err != nil {
		t.Fatalf("ровно в пределы: %v", err)
	}
	var e *Error
	if _, err := Parse([]byte(msgs(4)), lim); !errors.As(err, &e) || e.Code != CodeTooMany {
		t.Fatalf("сообщений больше предела: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(msgs(1), `"max_tokens":10`, `"max_completion_tokens":11`, 1)), lim); !errors.As(err, &e) || e.Code != CodeMaxTokens {
		t.Fatalf("max_tokens больше квоты: %v", err)
	}
	parts := `{"model":"m","messages":[{"role":"user","content":[` + strings.TrimSuffix(strings.Repeat(`{"type":"text","text":"x"},`, 3), ",") + `]}]}`
	if _, err := Parse([]byte(parts), Limits{MaxParts: 2}); !errors.As(err, &e) || e.Code != CodeTooMany {
		t.Fatalf("частей больше предела: %v", err)
	}
}

func TestErrorDoesNotEchoContent(t *testing.T) {
	_, err := Parse([]byte(`{"model":"m","messages":[{"role":"user","content":{"секрет-123":1}}]}`), Limits{})
	if err == nil || strings.Contains(err.Error(), "секрет-123") {
		t.Fatalf("ошибка содержит фрагмент запроса: %v", err)
	}
	_, err = Parse([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}],"`+strings.Repeat("я", 200)+`":1}`), Limits{})
	if err == nil || len(err.Error()) > 300 {
		t.Fatalf("длинное имя поля в ошибке: %v", err)
	}
}

// Разбор запроса chat/completions — цель фаззинга (ТЗ, 8.5). Для любого
// принятого запроса: сборка устойчива, в собранном теле только известные
// поля, а фрагменты для детекторов совпадают с тем, что уйдёт провайдеру.
func FuzzParse(f *testing.F) {
	f.Add([]byte(full))
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":"a"}],"Messages":[{"role":"user","content":"b"}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}]}]}`))
	known := map[string]bool{}
	for _, k := range []string{"model", "messages", "stream", "stream_options", "max_tokens", "max_completion_tokens", "temperature", "top_p", "n", "stop",
		"presence_penalty", "frequency_penalty", "logit_bias", "logprobs", "top_logprobs", "response_format", "seed", "tools", "tool_choice",
		"parallel_tool_calls", "user", "reasoning_effort"} {
		known[k] = true
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := Parse(body, Limits{})
		if err != nil {
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("ошибка не *Error: %v", err)
			}
			return
		}
		out, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(out, &top); err != nil {
			t.Fatal(err)
		}
		for k := range top {
			if !known[k] {
				t.Fatalf("в теле к провайдеру неизвестное поле %q", k)
			}
		}
		r2, err := Parse(out, Limits{})
		if err != nil {
			t.Fatalf("собранный запрос не разбирается: %v\n%s", err, out)
		}
		out2, err := r2.Marshal()
		if err != nil || string(out) != string(out2) {
			t.Fatalf("сборка не устойчива")
		}
		a, b := r.Segments(), r2.Segments()
		if len(a) != len(b) {
			t.Fatalf("фрагментов %d и %d", len(a), len(b))
		}
		for i := range a {
			if a[i].Location() != b[i].Location() || a[i].Text != b[i].Text && strings.ToValidUTF8(a[i].Text, "�") != b[i].Text {
				t.Fatalf("фрагмент %s изменился при сборке", a[i].Location())
			}
		}
	})
}
