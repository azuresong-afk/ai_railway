package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

const chatBody = `{"model":"m","messages":[{"role":"user","content":"привет"}]}`

// Ответ провайдера по умолчанию.
const okResponse = `{"id":"r1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ответ"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

// upstreamRecord — что увидел провайдер.
type upstreamRecord struct {
	mu     sync.Mutex
	path   string
	query  string
	header http.Header
	body   string
	calls  int
}

func (u *upstreamRecord) get() (string, http.Header, string, int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.path, u.header, u.body, u.calls
}

// newUpstream поднимает фейкового провайдера, который записывает запрос и
// отвечает handler (если задан) или okResponse.
func newUpstream(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *upstreamRecord) {
	t.Helper()
	rec := &upstreamRecord{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		rec.mu.Lock()
		rec.path, rec.query, rec.header, rec.body = r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(b)
		rec.calls++
		rec.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=secret")
		w.Header().Set("X-Ratelimit-Remaining-Requests", "99")
		w.Header().Set("Server", "upstream/1.0")
		if _, err := io.WriteString(w, okResponse); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// gwOpts — параметры тестового шлюза.
type gwOpts struct {
	key         string // ключ провайдера
	logger      *slog.Logger
	bodyTimeout time.Duration
	maxBody     int64
	quotas      config.Quotas
	limiter     auth.LimiterConfig
	transport   http.RoundTripper
}

// newGateway — шлюз с OpenAI-совместимым провайдером на upstream и одним
// приложением: модели m и mock-echo, псевдоним default → m. Запросы без
// Authorization получают действующий ключ приложения: здесь проверяется
// обработка запроса, аутентификация — в auth_test.go.
func newGateway(t testing.TB, upstream string, mod func(*gwOpts)) http.Handler {
	t.Helper()
	o := gwOpts{logger: quiet(), maxBody: 1 << 10, transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 2 * time.Second}}
	if mod != nil {
		mod(&o)
	}
	u, err := url.Parse(upstream + "/v1")
	if err != nil {
		t.Fatal(err)
	}
	p, err := providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: providers.BaseConfig{ID: "up", External: true, Transport: o.transport, Logger: o.logger}, BaseURL: u, Key: o.key})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRouter([]config.Application{{ID: "app", Env: "test", Provider: "up", Models: []string{"m", "mock-echo", "mock-stream-slow"},
		Aliases: map[string]string{"default": "m"}, Quotas: o.quotas}}, map[string]providers.Provider{"up": p})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := NewChatHandler(ChatConfig{Router: rt, MaxBodyBytes: o.maxBody, Logger: o.logger, BodyReadTimeout: o.bodyTimeout})
	if err != nil {
		t.Fatal(err)
	}
	ta := newTestAuth(t, o.limiter)
	g := mustNew(t, Options{Logger: o.logger, Chat: ch, Router: rt, Auth: ta.cfg})
	return withKey(g, ta.key)
}

// withKey добавляет ключ приложения в запрос без Authorization.
func withKey(h http.Handler, key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		h.ServeHTTP(w, r)
	})
}

func postChat(t *testing.T, h http.Handler, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct{ Error struct{ Code string } }
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("ответ не JSON: %q", rec.Body.String())
	}
	return b.Error.Code
}

func TestChatPassesRequestAndResponse(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g := newGateway(t, up.URL, func(o *gwOpts) { o.key = "sk-provider" })
	resp := postChat(t, g, chatBody, map[string]string{
		"Cookie": "a=b", "X-Forwarded-For": "10.0.0.1", "X-Custom": "x", "X-Request-Id": "req-1", "Accept-Encoding": "br",
	})
	if resp.Code != http.StatusOK || resp.Body.String() != okResponse+"\n" {
		t.Fatalf("ответ %d %q", resp.Code, resp.Body.String())
	}
	path, hdr, body, _ := rec.get()
	if path != "/v1/chat/completions" || body != chatBody {
		t.Fatalf("провайдер получил %s %s", path, body)
	}
	if hdr.Get("Authorization") != "Bearer sk-provider" {
		t.Errorf("Authorization у провайдера: %q — должен быть ключ шлюза, а не приложения", hdr.Get("Authorization"))
	}
	for _, h := range []string{"Cookie", "X-Forwarded-For", "X-Custom", "X-Request-Id"} {
		if hdr.Get(h) != "" {
			t.Errorf("заголовок %s не должен уходить провайдеру", h)
		}
	}
	if strings.Contains(hdr.Get("Accept-Encoding"), "br") {
		t.Error("клиентский Accept-Encoding передан провайдеру")
	}
	// Приложению — только лимиты провайдера; служебные заголовки провайдера отброшены.
	if resp.Header().Get("X-Ratelimit-Remaining-Requests") != "99" || resp.Header().Get("Set-Cookie") != "" || resp.Header().Get("Server") != "" {
		t.Fatalf("заголовки ответа: %v", resp.Header())
	}
}

// Покрывает: DM-33
func TestDM33_ModelsAndAliases(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g := newGateway(t, up.URL, nil)
	// Неразрешённая модель — отказ до обращения к провайдеру.
	resp := postChat(t, g, `{"model":"gpt-secret","messages":[{"role":"user","content":"x"}]}`, nil)
	if resp.Code != http.StatusNotFound || errCode(t, resp) != "model_not_found" || strings.Contains(resp.Body.String(), "mock-echo") {
		t.Fatalf("неразрешённая модель: %d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос с неразрешённой моделью дошёл до провайдера")
	}
	// Псевдоним заменяется моделью провайдера.
	if resp := postChat(t, g, `{"model":"default","messages":[{"role":"user","content":"x"}]}`, nil); resp.Code != http.StatusOK {
		t.Fatalf("псевдоним: %d", resp.Code)
	}
	if _, _, body, _ := rec.get(); !strings.Contains(body, `"model":"m"`) {
		t.Fatalf("псевдоним не заменён: %s", body)
	}
	// Приложение видит запрошенное имя, а не модель провайдера.
	if resp := postChat(t, g, `{"model":"default","messages":[{"role":"user","content":"x"}]}`, nil); !strings.Contains(resp.Body.String(), `"model":"default"`) {
		t.Fatalf("имя модели в ответе: %s", resp.Body.String())
	}
	// GET /v1/models — только модели и псевдонимы приложения.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/models", nil)
	r := httptest.NewRecorder()
	g.ServeHTTP(r, req)
	var list struct {
		Object string
		Data   []struct{ ID, Object string }
	}
	if err := json.Unmarshal(r.Body.Bytes(), &list); err != nil || r.Code != 200 || list.Object != "list" {
		t.Fatalf("/v1/models: %d %s", r.Code, r.Body.String())
	}
	var ids []string
	for _, m := range list.Data {
		ids = append(ids, m.ID)
	}
	if strings.Join(ids, ",") != "default,m,mock-echo,mock-stream-slow" {
		t.Fatalf("/v1/models: %v", ids)
	}
	// Без ключа приложения список моделей не выдаётся.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer aisec_zzzzzzzz_"+strings.Repeat("A", 43))
	r = httptest.NewRecorder()
	g.ServeHTTP(r, req)
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("/v1/models без ключа: %d", r.Code)
	}
}

func TestChatRejectsBadInput(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g := newGateway(t, up.URL, nil)
	cases := []struct {
		name, body, ctype string
		code              int
		errCode           string
	}{
		{"большое тело", `{"x":"` + strings.Repeat("я", 1<<10) + `"}`, "application/json", 413, "request_too_large"},
		{"не json", "{", "application/json", 400, "invalid_request"},
		{"массив", "[1]", "application/json", 400, "invalid_request"},
		{"пусто", "", "application/json", 400, "invalid_request"},
		{"не запрос chat", `{"x":1}`, "application/json", 400, "unsupported_parameter"},
		{"нет сообщений", `{"model":"m","messages":[]}`, "application/json", 400, "invalid_request"},
		{"тип", chatBody, "text/plain", 415, "unsupported_media_type"},
		{"без типа", chatBody, "", 415, "unsupported_media_type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(c.body))
			if c.ctype != "" {
				req.Header.Set("Content-Type", c.ctype)
			}
			resp := httptest.NewRecorder()
			g.ServeHTTP(resp, req)
			if resp.Code != c.code || errCode(t, resp) != c.errCode {
				t.Fatalf("%d %q, ожидалось %d %q", resp.Code, errCode(t, resp), c.code, c.errCode)
			}
		})
	}
	// Граница: тело ровно в предел проходит.
	prefix := `{"model":"m","messages":[{"role":"user","content":"`
	exact := prefix + strings.Repeat("a", (1<<10)-len(prefix)-4) + `"}]}`
	if resp := postChat(t, g, exact, nil); resp.Code != http.StatusOK {
		t.Fatalf("тело ровно в предел: %d", resp.Code)
	}
	if _, _, _, calls := rec.get(); calls != 1 {
		t.Fatalf("отклонённые запросы дошли до провайдера: вызовов %d", calls)
	}
	// Charset в Content-Type допустим.
	if resp := postChat(t, g, chatBody, map[string]string{"Content-Type": "application/json; charset=utf-8"}); resp.Code != 200 {
		t.Fatalf("charset: %d", resp.Code)
	}
}

// Покрывает: DM-15
func TestDM15_AppQuotaLimits(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g := newGateway(t, up.URL, func(o *gwOpts) { o.quotas = config.Quotas{MaxMessages: 1, MaxTokens: 10}; o.maxBody = 1 << 12 })
	two := `{"model":"m","messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}`
	if resp := postChat(t, g, two, nil); resp.Code != 400 || errCode(t, resp) != "request_too_large" {
		t.Fatalf("сообщений больше квоты: %d %s", resp.Code, resp.Body.String())
	}
	big := `{"model":"m","max_tokens":11,"messages":[{"role":"user","content":"a"}]}`
	if resp := postChat(t, g, big, nil); resp.Code != 400 || errCode(t, resp) != "max_tokens_exceeded" {
		t.Fatalf("max_tokens больше квоты: %d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос сверх квоты дошёл до провайдера")
	}
}

func TestChatUpstreamErrors(t *testing.T) {
	// Провайдер недоступен.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	resp := postChat(t, newGateway(t, deadURL, nil), chatBody, nil)
	if resp.Code != 502 || errCode(t, resp) != "upstream_unavailable" || strings.Contains(resp.Body.String(), deadURL) {
		t.Fatalf("недоступный провайдер: %d %s", resp.Code, resp.Body.String())
	}
	// Провайдер завис — таймаут до заголовков ответа.
	hang, _ := newUpstream(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	start := time.Now()
	resp = postChat(t, newGateway(t, hang.URL, func(o *gwOpts) {
		o.transport = &http.Transport{Proxy: nil, ResponseHeaderTimeout: 300 * time.Millisecond}
	}), chatBody, nil)
	if resp.Code != 504 || errCode(t, resp) != "upstream_timeout" || time.Since(start) > 3*time.Second {
		t.Fatalf("зависший провайдер: %d %s за %s", resp.Code, resp.Body.String(), time.Since(start))
	}
	// Ошибка провайдера: код, тип и текст в формате OpenAI, Retry-After.
	errUp, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":{"message":"Rate limit\nreached","type":"requests","code":"rate_limit_exceeded"}}`) //nolint:errcheck // тестовый провайдер
	})
	resp = postChat(t, newGateway(t, errUp.URL, nil), chatBody, nil)
	if resp.Code != 429 || errCode(t, resp) != "rate_limit_exceeded" || resp.Header().Get("Retry-After") != "7" || strings.Contains(resp.Body.String(), `\n`) {
		t.Fatalf("ошибка провайдера: %d %s", resp.Code, resp.Body.String())
	}
	// Ответ 200, но не ответ модели; перенаправление не выполняется.
	for name, h := range map[string]http.HandlerFunc{
		"не JSON": func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "<html>") }, //nolint:errcheck // тестовый провайдер
		"перенаправление": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example/collect", http.StatusTemporaryRedirect)
		},
	} {
		bad, _ := newUpstream(t, h)
		resp := postChat(t, newGateway(t, bad.URL, nil), chatBody, nil)
		if resp.Code != 502 || strings.Contains(resp.Body.String(), "evil") {
			t.Fatalf("%s: %d %s", name, resp.Code, resp.Body.String())
		}
	}
}

func TestChatHidesUpstreamAuthErrorBody(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			if _, err := io.WriteString(w, `{"error":{"message":"Incorrect API key provided: sk-...abcd"}}`); err != nil {
				t.Error(err)
			}
		})
		resp := postChat(t, newGateway(t, up.URL, func(o *gwOpts) { o.key = "sk-provider-abcd" }), chatBody, nil)
		if resp.Code != http.StatusBadGateway || errCode(t, resp) != "upstream_auth_error" || strings.Contains(resp.Body.String(), "abcd") {
			t.Fatalf("%d от провайдера: %d %s", code, resp.Code, resp.Body.String())
		}
	}
}

// Провайдер получает запрос, собранный заново: повторный ключ messages не
// протащит текст, который не видели проверки; строка запроса не передаётся.
func TestChatSendsRebuiltBody(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g := newGateway(t, up.URL, func(o *gwOpts) { o.maxBody = 1 << 12 })
	body := `{"model":"m",  "messages":[{"role":"user","content":"скрытое"}],"Messages":[{"role":"user","content":"видимое"}]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions?api_key=secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	g.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	_, _, got, _ := rec.get()
	if got != `{"model":"m","messages":[{"role":"user","content":"видимое"}]}` {
		t.Fatalf("провайдер получил %s", got)
	}
	rec.mu.Lock()
	q := rec.query
	rec.mu.Unlock()
	if q != "" {
		t.Fatalf("строка запроса ушла провайдеру: %q", q)
	}
}

// Идентификатор пользователя внешнему провайдеру не передаётся.
func TestChatDropsUserForExternalProvider(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g := newGateway(t, up.URL, nil)
	if resp := postChat(t, g, `{"model":"m","user":"ivanov@example.com","messages":[{"role":"user","content":"x"}]}`, nil); resp.Code != 200 {
		t.Fatal(resp.Code)
	}
	if _, _, body, _ := rec.get(); strings.Contains(body, "ivanov") {
		t.Fatalf("user ушёл внешнему провайдеру: %s", body)
	}
}

// Ответ провайдера собирается заново: неизвестные поля (здесь — reasoning)
// приложению не уходят.
func TestChatResponseRebuilt(t *testing.T) {
	up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"r","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ок","reasoning_content":"скрытое"},"finish_reason":"stop","logprobs":{"content":[{"token":"скрытое"}]}}],"extra":"скрытое"}`) //nolint:errcheck // тестовый провайдер
	})
	resp := postChat(t, newGateway(t, up.URL, nil), chatBody, nil)
	if resp.Code != 200 || strings.Contains(resp.Body.String(), "скрытое") || !strings.Contains(resp.Body.String(), `"content":"ок"`) {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
}

// sseUpstream отдаёт части потока; после первой ждёт release.
func sseUpstream(t *testing.T, parts []string, release <-chan struct{}) *httptest.Server {
	t.Helper()
	up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("нет Flusher")
			return
		}
		for i, p := range parts {
			fmt.Fprint(w, p) //nolint:errcheck // тестовый провайдер
			fl.Flush()
			if i == 0 && release != nil {
				<-release
			}
		}
	})
	return up
}

func chunk(content string) string {
	return `data: {"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"` + content + `","reasoning_content":"скрытое"},"finish_reason":null}]}` + "\n\n"
}

func streamReq(t *testing.T, gw *httptest.Server) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := gw.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// Поток SSE приходит клиенту по частям, пока провайдер ещё отвечает; части
// собраны заново (без неизвестных полей). Проверяется через настоящий
// HTTP-сервер: httptest.ResponseRecorder не показывает сброс буфера.
func TestChatStreamsIncrementally(t *testing.T) {
	release := make(chan struct{})
	up := sseUpstream(t, []string{chunk("раз"), ": keep-alive\n\n" + chunk(" два") + "data: [DONE]\n\n"}, release)
	gw := httptest.NewServer(newGateway(t, up.URL, nil))
	defer gw.Close()
	resp := streamReq(t, gw)
	defer resp.Body.Close() //nolint:errcheck // тело читается ниже
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("Content-Type: %s", resp.Header.Get("Content-Type"))
	}
	br := bufio.NewReader(resp.Body)
	got := make(chan string, 1)
	go func() {
		line, err := br.ReadString('\n')
		if err != nil {
			line = "ошибка: " + err.Error()
		}
		got <- line
	}()
	select {
	case line := <-got:
		if !strings.Contains(line, `"content":"раз"`) || strings.Contains(line, "скрытое") {
			t.Fatalf("первая часть: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("первая часть потока не пришла до завершения ответа провайдера — шлюз буферизует SSE")
	}
	close(release)
	rest, err := io.ReadAll(br)
	if err != nil || !strings.HasSuffix(string(rest), "data: [DONE]\n\n") || strings.Contains(string(rest), "скрытое") || strings.Contains(string(rest), "keep-alive") {
		t.Fatalf("остаток потока: %q %v", rest, err)
	}
}

// Оборванный поток и ошибка внутри потока: событие с error, без [DONE].
func TestChatStreamErrors(t *testing.T) {
	for name, parts := range map[string][]string{
		"обрыв":           {chunk("раз")},
		"ошибка в потоке": {chunk("раз"), `data: {"error":{"message":"overloaded","type":"server_error"}}` + "\n\n"},
		"мусор в потоке":  {chunk("раз"), "data: {не json\n\n"},
	} {
		up := sseUpstream(t, parts, nil)
		gw := httptest.NewServer(newGateway(t, up.URL, nil))
		resp := streamReq(t, gw)
		b, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); err != nil || cerr != nil {
			t.Fatal(err, cerr)
		}
		gw.Close()
		if !strings.Contains(string(b), `"error"`) || strings.Contains(string(b), "[DONE]") {
			t.Fatalf("%s: %q", name, b)
		}
	}
	// Провайдер ответил не потоком SSE — обычная ошибка до начала потока.
	notSSE, _ := newUpstream(t, nil)
	gw := httptest.NewServer(newGateway(t, notSSE.URL, nil))
	defer gw.Close()
	resp := streamReq(t, gw)
	defer resp.Body.Close() //nolint:errcheck // тест проверяет только код
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("не SSE: %d", resp.StatusCode)
	}
}

// Разрыв соединения клиентом отменяет запрос к провайдеру.
func TestChatClientCancelPropagates(t *testing.T) {
	cancelled := make(chan struct{})
	up, _ := newUpstream(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-time.After(5 * time.Second):
		}
	})
	g := newGateway(t, up.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(chatBody))
	req.Header.Set("Content-Type", "application/json")
	done := make(chan struct{})
	go func() {
		g.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("запрос к провайдеру не отменён после разрыва клиентом")
	}
	<-done
}

// Медленная передача тела не занимает соединение дольше предела.
func TestChatSlowBodyTimesOut(t *testing.T) {
	up, rec := newUpstream(t, nil)
	gw := httptest.NewServer(newGateway(t, up.URL, func(o *gwOpts) { o.bodyTimeout = 200 * time.Millisecond }))
	defer gw.Close()
	pr, pw := io.Pipe()
	go func() {
		if _, err := io.WriteString(pw, `{"model":`); err != nil {
			return
		}
		time.Sleep(2 * time.Second)
		pw.Close() //nolint:errcheck,gosec // конец медленного тела; ошибка в тесте не важна
	}()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.URL+"/v1/chat/completions", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := gw.Client().Do(req)
	if err == nil {
		defer resp.Body.Close() //nolint:errcheck // тест проверяет только код
		if resp.StatusCode != http.StatusRequestTimeout {
			t.Fatalf("медленное тело: код %d", resp.StatusCode)
		}
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("соединение занято %s", time.Since(start))
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("недочитанный запрос дошёл до провайдера")
	}
}

// В журнал шлюза не попадают промпт, ключи провайдера и приложения, строка
// запроса (ТЗ: логи без содержимого и секретов).
func TestChatLogsHaveNoSecrets(t *testing.T) {
	var logs strings.Builder
	var mu sync.Mutex
	logger := slog.New(slog.NewJSONHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	for _, target := range []string{deadURL, up.URL} {
		g := newGateway(t, target, func(o *gwOpts) { o.key = "sk-provider-secret"; o.logger = logger; o.maxBody = 1 << 12 })
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions?token=query-secret",
			strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"промпт-секрет"}]}`))
		req.Header.Set("Content-Type", "application/json")
		g.ServeHTTP(httptest.NewRecorder(), req) // с действующим ключом приложения (withKey)
		bad := req.Clone(context.Background())
		bad.Header.Set("Authorization", "Bearer client-secret")
		g.ServeHTTP(httptest.NewRecorder(), bad)
	}
	mu.Lock()
	out := logs.String()
	mu.Unlock()
	if out == "" {
		t.Fatal("журнал пуст — тест ничего не проверяет")
	}
	for _, secret := range []string{"промпт-секрет", "sk-provider-secret", "client-secret", "query-secret", "aisec_", "192.0.2.1"} {
		if strings.Contains(out, secret) {
			t.Errorf("в журнал попало %q:\n%s", secret, out)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// Обработчик входящих HTTP-запросов шлюза — цель фаззинга (ТЗ, 8.5).
// Перебираются метод, путь со строкой запроса, тело, Content-Type и
// произвольный заголовок; провайдеру уходят только собранный заново запрос
// chat/completions, заголовки шлюза и никакой строки запроса.
func FuzzProxyHandler(f *testing.F) {
	f.Add("POST", "/v1/chat/completions", []byte(chatBody), "application/json", "X-Custom", "v")
	f.Add("POST", "/v1/chat/completions?k=v", []byte("{"), "application/json", "Authorization", "Bearer x")
	f.Add("GET", "/v1/models", []byte(`{"a":1}`), "text/plain", "Cookie", "a=b")
	f.Add("POST", "/v1/chat/completions", []byte(strings.Repeat("{", 2000)), "application/json; charset=utf-8", "X-Forwarded-For", "1.2.3.4")
	var mu sync.Mutex
	var seen http.Header
	var seenQuery, seenBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		mu.Lock()
		seen, seenQuery, seenBody = r.Header.Clone(), r.URL.RawQuery, string(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, okResponse) //nolint:errcheck,gosec // тестовый провайдер
	}))
	defer up.Close()
	// Порог неудач не достижим: иначе после первых отказов фаззинг упёрся бы в 429.
	g := newGateway(f, up.URL, func(o *gwOpts) { o.limiter = auth.LimiterConfig{MaxFailures: 1 << 30}; o.maxBody = 1 << 12 })
	// Что может прийти провайдеру: заголовки шлюза и то, что добавляет сам транспорт Go.
	allowedUp := map[string]bool{"Content-Type": true, "Accept": true, "User-Agent": true, "Content-Length": true, "Accept-Encoding": true}
	allowedCodes := map[int]bool{200: true, 400: true, 401: true, 404: true, 405: true, 413: true, 415: true}
	f.Fuzz(func(t *testing.T, method, target string, body []byte, ctype, hName, hValue string) {
		if !strings.HasPrefix(target, "/") {
			return
		}
		req, err := http.NewRequestWithContext(context.Background(), method, "http://gw"+target, strings.NewReader(string(body)))
		if err != nil {
			return // такой запрос не построить и клиенту
		}
		req.Header.Set("Content-Type", ctype)
		if hName != "" {
			req.Header.Set(hName, hValue)
		}
		mu.Lock()
		seen, seenQuery, seenBody = nil, "", ""
		mu.Unlock()
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)
		if !allowedCodes[rec.Code] {
			t.Fatalf("неожиданный код %d: %q", rec.Code, rec.Body.String())
		}
		mu.Lock()
		defer mu.Unlock()
		if seen == nil {
			return // до провайдера запрос не дошёл
		}
		if !isJSONObject([]byte(seenBody)) || seenBody == string(body) && strings.Contains(string(body), " ") {
			t.Fatalf("провайдеру ушло не собранное заново тело: %q", seenBody)
		}
		if seenQuery != "" {
			t.Fatalf("провайдеру ушла строка запроса %q", seenQuery)
		}
		for h := range seen {
			if !allowedUp[h] {
				t.Fatalf("провайдеру ушёл заголовок %s", h)
			}
		}
	})
}
