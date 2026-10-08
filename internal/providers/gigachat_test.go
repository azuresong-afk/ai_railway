package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/fixtures/gigachat/" + name) //nolint:gosec // G304: фикстура теста из репозитория
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const gcKey = "Zml4dHVyZS1jbGllbnQtaWQ6Zml4dHVyZS1zZWNyZXQ=" // выдуманный ключ авторизации

// gcServer — фейковый GigaChat: выдача токена и chat/completions.
type gcServer struct {
	t          *testing.T
	mu         sync.Mutex
	tokenCalls int
	tokenHdr   http.Header
	tokenForm  url.Values
	chatCalls  int
	chatHdr    http.Header
	chatBody   []byte
	chatStatus []int // коды ответа по порядку вызовов; дальше — 200
	reply      []byte
	stream     bool
}

func (g *gcServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/oauth", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			g.t.Error(err)
		}
		g.mu.Lock()
		g.tokenCalls++
		g.tokenHdr, g.tokenForm = r.Header.Clone(), r.PostForm
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture(g.t, "token.json")) //nolint:errcheck,gosec // тестовый сервер
	})
	mux.HandleFunc("POST /api/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			g.t.Error(err)
		}
		g.mu.Lock()
		status := http.StatusOK
		if g.chatCalls < len(g.chatStatus) {
			status = g.chatStatus[g.chatCalls]
		}
		g.chatCalls++
		g.chatHdr, g.chatBody = r.Header.Clone(), b
		reply, stream := g.reply, g.stream
		g.mu.Unlock()
		if status != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			if status == http.StatusUnprocessableEntity {
				w.Write(fixture(g.t, "error_422.json")) //nolint:errcheck,gosec // тестовый сервер
			} else {
				io.WriteString(w, `{"status":401,"message":"Token has expired fixture-access-token-not-real-0001"}`) //nolint:errcheck,gosec // тестовый сервер
			}
			return
		}
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.Write(reply) //nolint:errcheck,gosec // тестовый сервер
	})
	return mux
}

// newGigaChat — провайдер на фейковый сервер; часы управляются тестом.
func newGigaChat(t *testing.T, g *gcServer, now *time.Time, logger *slog.Logger) *GigaChat {
	t.Helper()
	srv := httptest.NewServer(g.handler())
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL + "/api/v1")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := url.Parse(srv.URL + "/api/v2/oauth")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := cp.Random()
	if err != nil {
		t.Fatal(err)
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	p, err := NewGigaChat(GigaChatConfig{
		BaseConfig: BaseConfig{ID: "giga", External: true, Transport: &http.Transport{Proxy: nil}, Logger: logger},
		BaseURL:    base, AuthURL: auth, AuthKey: gcKey, Scope: "GIGACHAT_API_CORP", Random: rnd,
		Now: func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func gcNow() time.Time { return time.UnixMilli(1791397800000).Add(-25 * time.Minute) }

func TestGigaChatTokenLifecycle(t *testing.T) {
	g := &gcServer{t: t, reply: fixture(t, "chat.json")}
	now := gcNow()
	p := newGigaChat(t, g, &now, nil)
	req := &chat.Request{Model: "GigaChat", Messages: []chat.Message{userMsg("привет")}}
	for range 2 {
		resp, _, err := p.Chat(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if *resp.Choices[0].Message.Content != "Здравствуйте! Чем могу помочь?" || resp.Usage.TotalTokens != 27 || !strings.HasPrefix(resp.ID, "chatcmpl-") {
			t.Fatalf("%+v", resp)
		}
	}
	g.mu.Lock()
	calls, hdr, form, chatHdr := g.tokenCalls, g.tokenHdr, g.tokenForm, g.chatHdr
	g.mu.Unlock()
	// Токен получен один раз и переиспользован.
	if calls != 1 {
		t.Fatalf("получений токена: %d", calls)
	}
	uuid4Re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if hdr.Get("Authorization") != "Basic "+gcKey || !uuid4Re.MatchString(hdr.Get("RqUID")) || form.Get("scope") != "GIGACHAT_API_CORP" ||
		hdr.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("запрос токена: %v %v", hdr, form)
	}
	if chatHdr.Get("Authorization") != "Bearer fixture-access-token-not-real-0001" {
		t.Fatalf("Authorization к API: %q", chatHdr.Get("Authorization"))
	}
	// За минуту до истечения токен обновляется заранее.
	now = time.UnixMilli(1791397800000).Add(-30 * time.Second)
	if _, _, err := p.Chat(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	calls = g.tokenCalls
	g.mu.Unlock()
	if calls != 2 {
		t.Fatalf("токен не обновлён заранее: получений %d", calls)
	}
}

func userMsg(s string) chat.Message {
	return chat.Message{Role: "user", Content: chat.Content{Text: &s}}
}

// На 401 от API токен обновляется и запрос повторяется один раз; второй
// отказ — ошибка учётных данных шлюза. Текст провайдера с токеном не уходит.
func TestGigaChatRetryOn401(t *testing.T) {
	g := &gcServer{t: t, reply: fixture(t, "chat.json"), chatStatus: []int{401}}
	now := gcNow()
	p := newGigaChat(t, g, &now, nil)
	req := &chat.Request{Model: "GigaChat", Messages: []chat.Message{userMsg("x")}}
	if _, _, err := p.Chat(context.Background(), req); err != nil {
		t.Fatalf("повтор после 401: %v", err)
	}
	g.mu.Lock()
	tc, cc := g.tokenCalls, g.chatCalls
	g.chatStatus, g.chatCalls = []int{401, 401}, 0
	g.mu.Unlock()
	if tc != 2 || cc != 2 {
		t.Fatalf("токенов %d, запросов %d", tc, cc)
	}
	if _, _, err := p.Chat(context.Background(), req); !errors.Is(err, ErrAuth) {
		t.Fatalf("двойной 401: %v", err)
	}
}

func TestGigaChatProviderError(t *testing.T) {
	g := &gcServer{t: t, chatStatus: []int{422}}
	now := gcNow()
	p := newGigaChat(t, g, &now, nil)
	_, _, err := p.Chat(context.Background(), &chat.Request{Model: "GigaChat", Messages: []chat.Message{userMsg("x")}})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 422 || !strings.Contains(pe.Message, "temperature") {
		t.Fatalf("%v", err)
	}
}

func TestGigaChatRequestTranslation(t *testing.T) {
	body := `{"model":"GigaChat-Pro","temperature":0,"max_tokens":50,"messages":[
		{"role":"developer","content":"Будь краток."},
		{"role":"user","content":[{"type":"text","text":"Погода?"},{"type":"text","text":"В Москве."}]},
		{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"weather_forecast","arguments":"{\"location\": \"Москва\"}"}}]},
		{"role":"tool","tool_call_id":"call_1","content":"+5, облачно"},
		{"role":"assistant","content":"Сейчас +5."}],
		"tools":[{"type":"function","function":{"name":"weather_forecast","description":"Прогноз","parameters":{"type":"object"}}}],
		"tool_choice":{"type":"function","function":{"name":"weather_forecast"}}}`
	req, err := chat.Parse([]byte(body), chat.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := toGigaChat(req, true)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	want := `{"function_call":{"name":"weather_forecast"},"functions":[{"description":"Прогноз","name":"weather_forecast","parameters":{"type":"object"}}],` +
		`"max_tokens":50,"messages":[{"content":"Будь краток.","role":"system"},{"content":"Погода?\nВ Москве.","role":"user"},` +
		`{"content":"","function_call":{"arguments":{"location":"Москва"},"name":"weather_forecast"},"role":"assistant"},` +
		`{"content":"{\"result\":\"+5, облачно\"}","name":"weather_forecast","role":"function"},{"content":"Сейчас +5.","role":"assistant"}],` +
		`"model":"GigaChat-Pro","stream":true,"temperature":0.001}`
	norm, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(norm) != want {
		t.Fatalf("перевод запроса:\n%s\nожидалось\n%s", norm, want)
	}
}

func TestGigaChatUnsupported(t *testing.T) {
	user := `{"role":"user","content":"x"}`
	for name, body := range map[string]string{
		"stop":            `{"model":"m","stop":"END","messages":[` + user + `]}`,
		"response_format": `{"model":"m","response_format":{"type":"json_object"},"messages":[` + user + `]}`,
		"seed":            `{"model":"m","seed":1,"messages":[` + user + `]}`,
		"штраф":           `{"model":"m","frequency_penalty":0.5,"messages":[` + user + `]}`,
		"required":        `{"model":"m","tool_choice":"required","tools":[{"type":"function","function":{"name":"f"}}],"messages":[` + user + `]}`,
		"картинка":        `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://a/b.png"}}]}]}`,
		"два вызова": `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"a","type":"function","function":{"name":"f","arguments":"{}"}},` +
			`{"id":"b","type":"function","function":{"name":"g","arguments":"{}"}}]}]}`,
	} {
		req, err := chat.Parse([]byte(body), chat.Limits{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = toGigaChat(req, false)
		var pe *Error
		if !errors.As(err, &pe) || pe.Status != 400 || pe.Code != "unsupported_parameter" {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, body := range map[string]string{
		"аргументы не объект": `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"a","type":"function","function":{"name":"f","arguments":"[1]"}}]}]}`,
		"чужой tool_call_id":  `{"model":"m","messages":[{"role":"tool","tool_call_id":"zzz","content":"x"}]}`,
	} {
		req, err := chat.Parse([]byte(body), chat.Limits{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var pe *Error
		if _, err := toGigaChat(req, false); !errors.As(err, &pe) || pe.Status != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGigaChatFunctionCallResponse(t *testing.T) {
	g := &gcServer{t: t, reply: fixture(t, "chat_function_call.json")}
	now := gcNow()
	p := newGigaChat(t, g, &now, nil)
	resp, _, err := p.Chat(context.Background(), &chat.Request{Model: "GigaChat", Messages: []chat.Message{userMsg("x")}})
	if err != nil {
		t.Fatal(err)
	}
	c := resp.Choices[0]
	if c.FinishReason != "tool_calls" || c.Message.Content != nil || len(c.Message.ToolCalls) != 1 {
		t.Fatalf("%+v", c)
	}
	tc := c.Message.ToolCalls[0]
	if !strings.HasPrefix(tc.ID, "call_") || tc.Function.Name != "weather_forecast" || tc.Function.Arguments != `{"location":"Москва","num_days":1}` {
		t.Fatalf("%+v", tc)
	}
	// Причины завершения и ответ с лишним вариантом.
	for in, want := range map[string]string{"stop": "stop", "length": "length", "function_call": "tool_calls", "blacklist": "content_filter"} {
		if got, err := finishReason(in); err != nil || got != want {
			t.Errorf("%s: %s %v", in, got, err)
		}
	}
	if _, err := finishReason("error"); err == nil {
		t.Error("finish_reason error принят")
	}
	two := bytes.Replace(fixture(t, "chat.json"), []byte(`"choices":[{`), []byte(`"choices":[{"index":1,"message":{"content":"обход"}},{`), 1)
	if _, err := p.fromGigaChat(two); err == nil {
		t.Fatal("ответ с двумя вариантами принят")
	}
}

func TestGigaChatStream(t *testing.T) {
	g := &gcServer{t: t, reply: fixture(t, "stream.txt"), stream: true}
	now := gcNow()
	p := newGigaChat(t, g, &now, nil)
	st, _, err := p.Stream(context.Background(), &chat.Request{Model: "GigaChat", Messages: []chat.Message{userMsg("x")}})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close() //nolint:errcheck // тест
	a := chat.NewAssembler()
	ids := map[string]bool{}
	for {
		c, err := st.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		ids[c.ID] = true
		if err := a.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	r := a.Response()
	if len(ids) != 1 || *r.Choices[0].Message.Content != "Здравствуйте! Чем могу помочь?" || r.Choices[0].FinishReason != "stop" || r.Usage.TotalTokens != 27 {
		t.Fatalf("%+v %v", r, ids)
	}
	g.mu.Lock()
	sent := g.chatBody
	g.mu.Unlock()
	if !strings.Contains(string(sent), `"stream":true`) {
		t.Fatalf("запрос потока: %s", sent)
	}
	// Вызов функции в потоке становится tool_calls.
	c, err := gigaChatChunk(`{"choices":[{"delta":{"content":"","function_call":{"name":"f","arguments":{"a":1}}},"index":0,"finish_reason":"function_call"}]}`, "id1", "call_x")
	if err != nil || c.Choices[0].Delta.ToolCalls[0].ID != "call_x" || c.Choices[0].Delta.ToolCalls[0].Function.Arguments != `{"a":1}` || *c.Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := gigaChatChunk(`{"choices":[{"delta":{"content":"a"},"index":1}]}`, "id", "c"); err == nil {
		t.Fatal("часть с вариантом 1 принята")
	}
}

// Ключ авторизации и токен не попадают в журнал и в ответы об ошибках.
func TestGigaChatSecretsNotLeaked(t *testing.T) {
	var logs strings.Builder
	var mu sync.Mutex
	logger := slog.New(slog.NewJSONHandler(writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(b)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))
	g := &gcServer{t: t, reply: fixture(t, "chat.json"), chatStatus: []int{401, 401}}
	now := gcNow()
	p := newGigaChat(t, g, &now, logger)
	_, _, err := p.Chat(context.Background(), &chat.Request{Model: "GigaChat", Messages: []chat.Message{userMsg("x")}})
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	// Ошибка 4xx с токеном в тексте: текст заменяется.
	p.mu.Lock()
	p.token = "fixture-access-token-not-real-0001"
	p.mu.Unlock()
	resp := &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"status":400,"message":"bad token fixture-access-token-not-real-0001"}`))}
	var pe *Error
	if !errors.As(p.providerError(resp), &pe) || strings.Contains(pe.Message, "fixture-access") {
		t.Fatalf("токен в ошибке: %+v", pe)
	}
	mu.Lock()
	out := logs.String()
	mu.Unlock()
	for _, s := range []string{gcKey, "fixture-access-token"} {
		if strings.Contains(out, s) || strings.Contains(err.Error(), s) {
			t.Fatalf("в журнале или ошибке %q:\n%s", s, out)
		}
	}
}

func TestNewGigaChatValidation(t *testing.T) {
	u, err := url.Parse("https://gigachat.example/api/v1")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := cp.Random()
	if err != nil {
		t.Fatal(err)
	}
	bc := BaseConfig{ID: "g", Transport: &http.Transport{}}
	ok := GigaChatConfig{BaseConfig: bc, BaseURL: u, AuthKey: gcKey, Scope: "GIGACHAT_API_PERS", Random: rnd}
	p, err := NewGigaChat(ok)
	if err != nil || p.authURL != DefaultGigaChatAuthURL || p.endpoint != "https://gigachat.example/api/v1/chat/completions" {
		t.Fatalf("%v %s %s", err, p.authURL, p.endpoint)
	}
	for name, mod := range map[string]func(*GigaChatConfig){
		"scope":      func(c *GigaChatConfig) { c.Scope = "ALL" },
		"нет ключа":  func(c *GigaChatConfig) { c.AuthKey = "" },
		"ключ с \\r": func(c *GigaChatConfig) { c.AuthKey = "a\rb" },
		"нет адреса": func(c *GigaChatConfig) { c.BaseURL = nil },
		"нет random": func(c *GigaChatConfig) { c.Random = nil },
		"нет id":     func(c *GigaChatConfig) { c.ID = "" },
	} {
		c := ok
		mod(&c)
		if _, err := NewGigaChat(c); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// Перевод запроса и части потока — цели фаззинга (ТЗ, 8.5): для любого
// принятого шлюзом запроса перевод даёт JSON или ошибку для приложения,
// разбор части потока не паникует.
func FuzzToGigaChat(f *testing.F) {
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"a","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"a","content":"1"}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := chat.Parse(body, chat.Limits{})
		if err != nil {
			return
		}
		out, err := toGigaChat(req, false)
		if err != nil {
			var pe *Error
			if !errors.As(err, &pe) || pe.Status != 400 {
				t.Fatalf("ошибка не для приложения: %v", err)
			}
			return
		}
		if !json.Valid(out) {
			t.Fatalf("невалидный JSON: %s", out)
		}
	})
}

func FuzzGigaChatChunk(f *testing.F) {
	f.Add(`{"choices":[{"delta":{"content":"a"},"index":0}]}`)
	f.Add(`{"choices":[{"delta":{"function_call":{"name":"f","arguments":{"a":1}}},"index":0,"finish_reason":"function_call"}]}`)
	f.Fuzz(func(t *testing.T, data string) {
		c, err := gigaChatChunk(data, "id", "call")
		if err != nil {
			return
		}
		if len(c.Choices) > 1 || (len(c.Choices) == 1 && c.Choices[0].Index != 0) {
			t.Fatalf("%+v", c)
		}
	})
}
