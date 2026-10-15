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
