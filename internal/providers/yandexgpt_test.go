package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func ycFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/fixtures/yandexgpt/" + name) //nolint:gosec // G304: фикстура теста из репозитория
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	ycKey    = "AQVNfixture-api-key-not-real-0001" // выдуманный API-ключ
	ycFolder = "b1gfixturefolder0001"
)

// ycServer — фейковый Foundation Models API.
type ycServer struct {
	t      *testing.T
	mu     sync.Mutex
	hdr    http.Header
	body   []byte
	status int
	reply  []byte
}

func newYandexGPT(t *testing.T, g *ycServer, logger *slog.Logger) *YandexGPT {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/foundationModels/v1/completion" {
			http.NotFound(w, r)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		g.mu.Lock()
		g.hdr, g.body = r.Header.Clone(), b
		status, reply := g.status, g.reply
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
		}
		w.Write(reply) //nolint:errcheck,gosec // тестовый сервер
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/foundationModels/v1")
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
	p, err := NewYandexGPT(YandexGPTConfig{
		BaseConfig: BaseConfig{ID: "yc", External: true, Transport: &http.Transport{Proxy: nil}, Logger: logger},
		BaseURL:    u, APIKey: ycKey, FolderID: ycFolder, Random: rnd,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestYandexGPTChat(t *testing.T) {
	g := &ycServer{t: t, reply: ycFixture(t, "completion.json")}
	p := newYandexGPT(t, g, nil)
	resp, _, err := p.Chat(context.Background(), &chat.Request{Model: "yandexgpt/latest", Messages: []chat.Message{userMsg("привет")}})
	if err != nil {
		t.Fatal(err)
	}
	c := resp.Choices[0]
	if *c.Message.Content != "Здравствуйте! Чем могу помочь?" || c.FinishReason != "stop" || resp.Usage.TotalTokens != 27 ||
		resp.Usage.PromptTokens != 18 || resp.Model != "yandexgpt/latest" || !strings.HasPrefix(resp.ID, "chatcmpl-") {
		t.Fatalf("%+v %+v", resp, c)
	}
	g.mu.Lock()
	hdr, body := g.hdr, g.body
	g.mu.Unlock()
	if hdr.Get("Authorization") != "Api-Key "+ycKey || hdr.Get("x-folder-id") != ycFolder {
		t.Fatalf("заголовки: %v", hdr)
	}
	if !strings.Contains(string(body), `"modelUri":"gpt://`+ycFolder+`/yandexgpt/latest"`) || !strings.Contains(string(body), `"stream":false`) {
		t.Fatalf("тело: %s", body)
	}
}

func TestYandexGPTRequestTranslation(t *testing.T) {
	body := `{"model":"yandexgpt/latest","temperature":0.3,"max_tokens":50,"messages":[
		{"role":"developer","content":"Будь краток."},
		{"role":"user","content":"Погода в Москве?"},
		{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"weather_forecast","arguments":"{\"location\": \"Москва\"}"}}]},
		{"role":"tool","tool_call_id":"call_1","content":"+5, облачно"}],
		"tools":[{"type":"function","function":{"name":"weather_forecast","description":"Прогноз","parameters":{"type":"object"}}}],
		"tool_choice":"auto"}`
	req, err := chat.Parse([]byte(body), chat.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := toYandexGPT(req, ycFolder, true)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	norm, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"completionOptions":{"maxTokens":"50","stream":true,"temperature":0.3},"messages":[{"role":"system","text":"Будь краток."},` +
		`{"role":"user","text":"Погода в Москве?"},{"role":"assistant","toolCallList":{"toolCalls":[{"functionCall":{"arguments":{"location":"Москва"},"name":"weather_forecast"}}]}},` +
		`{"role":"user","toolResultList":{"toolResults":[{"functionResult":{"content":"+5, облачно","name":"weather_forecast"}}]}}],` +
		`"modelUri":"gpt://` + ycFolder + `/yandexgpt/latest","tools":[{"function":{"description":"Прогноз","name":"weather_forecast","parameters":{"type":"object"}}}]}`
	if string(norm) != want {
		t.Fatalf("перевод запроса:\n%s\nожидалось\n%s", norm, want)
	}
	// tool_choice none — инструменты модели не передаются.
	req.ToolChoice = &chat.ToolChoice{Mode: "none"}
	out, err = toYandexGPT(req, ycFolder, false)
	if err != nil || strings.Contains(string(out), `"tools"`) {
		t.Fatalf("tool_choice none: %s %v", out, err)
	}
}

func TestYandexGPTUnsupported(t *testing.T) {
	user := `{"role":"user","content":"x"}`
	for name, body := range map[string]string{
		"stop":         `{"model":"m","stop":"END","messages":[` + user + `]}`,
		"top_p":        `{"model":"m","top_p":0.5,"messages":[` + user + `]}`,
		"temperature":  `{"model":"m","temperature":1.5,"messages":[` + user + `]}`,
		"seed":         `{"model":"m","seed":1,"messages":[` + user + `]}`,
		"required":     `{"model":"m","tool_choice":"required","tools":[{"type":"function","function":{"name":"f"}}],"messages":[` + user + `]}`,
		"картинка":     `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://a/b.png"}}]}]}`,
		"json_object":  `{"model":"m","response_format":{"type":"json_object"},"messages":[` + user + `]}`,
		"presence":     `{"model":"m","presence_penalty":1,"messages":[` + user + `]}`,
		"reasoning":    `{"model":"m","reasoning_effort":"low","messages":[` + user + `]}`,
		"logit_bias":   `{"model":"m","logit_bias":{"1":1},"messages":[` + user + `]}`,
		"функция явно": `{"model":"m","tool_choice":{"type":"function","function":{"name":"f"}},"tools":[{"type":"function","function":{"name":"f"}}],"messages":[` + user + `]}`,
	} {
		req, err := chat.Parse([]byte(body), chat.Limits{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = toYandexGPT(req, ycFolder, false)
		var pe *Error
		if !errors.As(err, &pe) || pe.Status != 400 || pe.Code != "unsupported_parameter" || !strings.Contains(pe.Message, "yandexgpt") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestYandexGPTToolCallResponse(t *testing.T) {
	g := &ycServer{t: t, reply: ycFixture(t, "completion_tool_calls.json")}
	p := newYandexGPT(t, g, nil)
	resp, _, err := p.Chat(context.Background(), &chat.Request{Model: "yandexgpt/latest", Messages: []chat.Message{userMsg("x")}})
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
	for in, want := range map[string]string{"ALTERNATIVE_STATUS_FINAL": "stop", "ALTERNATIVE_STATUS_TRUNCATED_FINAL": "length",
		"ALTERNATIVE_STATUS_CONTENT_FILTER": "content_filter", "ALTERNATIVE_STATUS_TOOL_CALLS": "tool_calls"} {
		if got, final, err := ycStatus(in); err != nil || !final || got != want {
			t.Errorf("%s: %s %v %v", in, got, final, err)
		}
	}
	if _, _, err := ycStatus("ALTERNATIVE_STATUS_UNSPECIFIED"); err == nil {
		t.Error("неизвестный статус принят")
	}
	// Ответ целиком со статусом PARTIAL или с двумя альтернативами — ошибка.
	for _, bad := range []string{
		strings.Replace(string(ycFixture(t, "completion.json")), "STATUS_FINAL", "STATUS_PARTIAL", 1),
		strings.Replace(string(ycFixture(t, "completion.json")), `"alternatives":[{`, `"alternatives":[{"message":{"text":"обход"},"status":"ALTERNATIVE_STATUS_FINAL"},{`, 1),
	} {
		if _, err := p.fromYandexGPT([]byte(bad), "m"); err == nil {
			t.Errorf("принят ответ: %s", bad)
		}
	}
}

func TestYandexGPTStream(t *testing.T) {
	g := &ycServer{t: t, reply: ycFixture(t, "stream.ndjson")}
	p := newYandexGPT(t, g, nil)
	st, _, err := p.Stream(context.Background(), &chat.Request{Model: "yandexgpt/latest", Messages: []chat.Message{userMsg("x")}})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close() //nolint:errcheck // тест
	a := chat.NewAssembler()
	var deltas []string
	for {
		c, err := st.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if d := c.Choices[0].Delta.Content; d != nil {
			deltas = append(deltas, *d)
		}
		if err := a.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	r := a.Response()
	// Приложению уходят приращения, а не накопленный текст.
	if strings.Join(deltas, "|") != "Здравствуйте|! Чем могу| помочь?" || *r.Choices[0].Message.Content != "Здравствуйте! Чем могу помочь?" ||
		r.Choices[0].FinishReason != "stop" || r.Usage.TotalTokens != 27 {
		t.Fatalf("%q %+v", deltas, r)
	}
}

func TestYandexGPTStreamErrors(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(string(ycFixture(t, "stream.ndjson"))), "\n")
	diverged := strings.Replace(lines[1], "Здравствуйте! Чем могу", "Добрый день! Чем могу", 1)
	for name, c := range map[string]struct {
		body string
		want error
	}{
		"обрыв без FINAL":         {lines[0] + "\n" + lines[1] + "\n", ErrTruncated},
		"текст разошёлся":         {lines[0] + "\n" + diverged + "\n", ErrBadResponse},
		"данные после завершения": {lines[0] + "\n" + lines[2] + "\n" + lines[2] + "\n", ErrBadResponse},
		"ошибка внутри потока":    {lines[0] + "\n" + string(ycFixture(t, "error.json")), nil},
	} {
		g := &ycServer{t: t, reply: []byte(c.body)}
		p := newYandexGPT(t, g, nil)
		st, _, err := p.Stream(context.Background(), &chat.Request{Model: "m", Messages: []chat.Message{userMsg("x")}})
		if err != nil {
			t.Fatal(err)
		}
		var last error
		for {
			if _, err := st.Next(); err != nil {
				last = err
				break
			}
		}
		if err := st.Close(); err != nil {
			t.Error(err)
		}
		var pe *Error
		switch {
		case c.want == nil:
			if !errors.As(last, &pe) || pe.Message != "Invalid temperature value" {
				t.Errorf("%s: %v", name, last)
			}
		case !errors.Is(last, c.want):
			t.Errorf("%s: %v", name, last)
		}
	}
}

func TestYandexGPTProviderErrorAndSecrets(t *testing.T) {
	var logs strings.Builder
	var mu sync.Mutex
	logger := slog.New(slog.NewJSONHandler(writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(b)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))
	g := &ycServer{t: t, status: 400, reply: ycFixture(t, "error.json")}
	p := newYandexGPT(t, g, logger)
	_, _, err := p.Chat(context.Background(), &chat.Request{Model: "m", Messages: []chat.Message{userMsg("x")}})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 400 || pe.Message != "Invalid temperature value" {
		t.Fatalf("%v", err)
	}
	// Ключ в тексте ошибки вырезается; 401 — без тела провайдера.
	g.mu.Lock()
	g.status, g.reply = 400, []byte(`{"error":{"message":"bad key AQVNfixture-api-key-not-real-0001"}}`)
	g.mu.Unlock()
	_, _, err = p.Chat(context.Background(), &chat.Request{Model: "m", Messages: []chat.Message{userMsg("x")}})
	if !errors.As(err, &pe) || strings.Contains(pe.Message, "AQVN") {
		t.Fatalf("ключ в ошибке: %v", err)
	}
	g.mu.Lock()
	g.status = 401
	g.mu.Unlock()
	if _, _, err := p.Chat(context.Background(), &chat.Request{Model: "m", Messages: []chat.Message{userMsg("x")}}); !errors.Is(err, ErrAuth) {
		t.Fatalf("401: %v", err)
	}
	mu.Lock()
	out := logs.String()
	mu.Unlock()
	if strings.Contains(out, "AQVN") {
		t.Fatalf("ключ в журнале:\n%s", out)
	}
}

func TestNewYandexGPTValidation(t *testing.T) {
	u, err := url.Parse("https://llm.api.cloud.yandex.net/foundationModels/v1")
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
	ok := YandexGPTConfig{BaseConfig: BaseConfig{ID: "y", Transport: &http.Transport{}}, BaseURL: u, APIKey: ycKey, FolderID: ycFolder, Random: rnd}
	p, err := NewYandexGPT(ok)
	if err != nil || p.endpoint != "https://llm.api.cloud.yandex.net/foundationModels/v1/completion" {
		t.Fatalf("%v", err)
	}
	for name, mod := range map[string]func(*YandexGPTConfig){
		"folder":     func(c *YandexGPTConfig) { c.FolderID = "b1g/../x" },
		"нет ключа":  func(c *YandexGPTConfig) { c.APIKey = "" },
		"ключ с \\n": func(c *YandexGPTConfig) { c.APIKey = "a\nb" },
		"нет адреса": func(c *YandexGPTConfig) { c.BaseURL = nil },
		"нет random": func(c *YandexGPTConfig) { c.Random = nil },
	} {
		c := ok
		mod(&c)
		if _, err := NewYandexGPT(c); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

// Перевод запроса и разбор частей потока — цели фаззинга (ТЗ, 8.5).
func FuzzToYandexGPT(f *testing.F) {
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"a","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"a","content":"1"}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := chat.Parse(body, chat.Limits{})
		if err != nil {
			return
		}
		out, err := toYandexGPT(req, ycFolder, false)
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

func FuzzYandexGPTStreamDelta(f *testing.F) {
	f.Add(`{"result":{"alternatives":[{"message":{"text":"a"},"status":"ALTERNATIVE_STATUS_PARTIAL"}]}}`, `{"result":{"alternatives":[{"message":{"text":"ab"},"status":"ALTERNATIVE_STATUS_FINAL"}]}}`)
	f.Fuzz(func(t *testing.T, a, b string) {
		d := &ycDelta{p: &YandexGPT{yc: YandexGPTConfig{Random: fixedRandom{}}}, id: "id", model: "m"}
		var text strings.Builder
		for _, line := range []string{a, b} {
			c, err := d.decode(line)
			if err != nil {
				return
			}
			if s := c.Choices[0].Delta.Content; s != nil {
				text.WriteString(*s)
			}
			// Склейка приращений всегда равна последнему накопленному тексту.
			if text.String() != d.sent {
				t.Fatalf("приращения %q, накоплено %q", text.String(), d.sent)
			}
		}
	})
}

type fixedRandom struct{}

func (fixedRandom) Read(b []byte) error {
	for i := range b {
		b[i] = byte(i)
	}
	return nil
}
