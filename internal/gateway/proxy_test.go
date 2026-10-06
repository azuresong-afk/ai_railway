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
)

const chatBody = `{"model":"m","messages":[{"role":"user","content":"привет"}]}`

// upstreamRecord — что увидел провайдер.
type upstreamRecord struct {
	mu     sync.Mutex
	path   string
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
// отвечает handler (если задан) или эхом тела.
func newUpstream(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *upstreamRecord) {
	t.Helper()
	rec := &upstreamRecord{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		rec.mu.Lock()
		rec.path, rec.header, rec.body = r.URL.Path, r.Header.Clone(), string(b)
		rec.calls++
		rec.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=secret")
		w.Header().Set("Server", "upstream/1.0")
		w.Header().Set("Retry-After", "3")
		if _, err := w.Write(b); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// newGateway — шлюз с прокси на upstream. Запросы без Authorization получают
// действующий ключ приложения: здесь проверяется прокси, аутентификация —
// в auth_test.go.
func newGateway(t *testing.T, upstream string, mod func(*ProxyConfig)) http.Handler {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ProxyConfig{
		Upstream: u, MaxBodyBytes: 1 << 10, Logger: quiet(),
		Transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 2 * time.Second},
	}
	if mod != nil {
		mod(&cfg)
	}
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ta := newTestAuth(t, auth.LimiterConfig{})
	g := mustNew(t, Options{Logger: quiet(), Proxy: p, Auth: ta.cfg})
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

func TestProxyPassesRequestAndResponse(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g := newGateway(t, up.URL+"/base", nil)
	resp := postChat(t, g, chatBody, map[string]string{"X-Request-Id": "req-1"})
	if resp.Code != http.StatusOK || resp.Body.String() != chatBody {
		t.Fatalf("ответ %d %q", resp.Code, resp.Body.String())
	}
	path, hdr, body, _ := rec.get()
	if path != "/base/v1/chat/completions" || body != chatBody || hdr.Get("X-Request-Id") != "req-1" {
		t.Fatalf("провайдер получил %s %q %v", path, body, hdr)
	}
	if resp.Header().Get("Retry-After") != "3" {
		t.Error("Retry-After провайдера не передан")
	}
	for _, h := range []string{"Set-Cookie", "Server"} {
		if resp.Header().Get(h) != "" {
			t.Errorf("заголовок провайдера %s дошёл до приложения", h)
		}
	}
}

func TestProxyRequestHeaderAllowlist(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g := newGateway(t, up.URL, func(c *ProxyConfig) {
		c.UpstreamKey = "sk-provider"
		c.ForwardHeaders = []string{"X-Mock-Scenario"}
	})
	postChat(t, g, chatBody, map[string]string{
		"Cookie": "a=b", "X-Forwarded-For": "10.0.0.1", // Authorization с ключом приложения добавляет withKey
		"X-Mock-Scenario": "echo", "X-Custom": "x", "Accept-Encoding": "br",
	})
	_, hdr, _, _ := rec.get()
	if hdr.Get("Authorization") != "Bearer sk-provider" {
		t.Errorf("Authorization у провайдера: %q — должен быть ключ шлюза, а не приложения", hdr.Get("Authorization"))
	}
	for _, h := range []string{"Cookie", "X-Custom"} {
		if hdr.Get(h) != "" {
			t.Errorf("заголовок %s не должен уходить провайдеру", h)
		}
	}
	if strings.Contains(hdr.Get("X-Forwarded-For"), "10.0.0.1") {
		t.Error("клиентский X-Forwarded-For ушёл провайдеру")
	}
	if hdr.Get("X-Mock-Scenario") != "echo" {
		t.Error("разрешённый дополнительный заголовок не передан")
	}
	if strings.Contains(hdr.Get("Accept-Encoding"), "br") {
		t.Error("клиентский Accept-Encoding передан провайдеру")
	}
}

func TestProxyNoKeyNoAuthorization(t *testing.T) {
	up, rec := newUpstream(t, nil)
	postChat(t, newGateway(t, up.URL, nil), chatBody, map[string]string{"Authorization": "Bearer client"})
	if _, hdr, _, _ := rec.get(); hdr.Get("Authorization") != "" {
		t.Fatal("без ключа шлюза Authorization не должен уходить провайдеру")
	}
}

func TestProxyRejectsBadInput(t *testing.T) {
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
	exact := `{"x":"` + strings.Repeat("a", (1<<10)-8) + `"}`
	if resp := postChat(t, g, exact, nil); resp.Code != http.StatusOK {
		t.Fatalf("тело ровно в предел: %d", resp.Code)
	}
	if _, _, _, calls := rec.get(); calls != 1 {
		t.Fatalf("отклонённые запросы дошли до провайдера: вызовов %d", calls)
	}
	// Charset в Content-Type допустим.
	if resp := postChat(t, g, chatBody, map[string]string{"Content-Type": "application/json; charset=utf-8"}); resp.Code != 200 {
		t.Fatalf("application/json; charset=utf-8: %d", resp.Code)
	}
}

func TestProxyUpstreamErrors(t *testing.T) {
	// Провайдер недоступен.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	if resp := postChat(t, newGateway(t, deadURL, nil), chatBody, nil); resp.Code != 502 || errCode(t, resp) != "upstream_unavailable" {
		t.Fatalf("недоступный провайдер: %d %s", resp.Code, resp.Body.String())
	}
	// Провайдер завис.
	hang, _ := newUpstream(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	g := newGateway(t, hang.URL, func(c *ProxyConfig) {
		c.Transport = &http.Transport{Proxy: nil, ResponseHeaderTimeout: 200 * time.Millisecond}
	})
	start := time.Now()
	resp := postChat(t, g, chatBody, nil)
	if resp.Code != 504 || errCode(t, resp) != "upstream_timeout" || time.Since(start) > 3*time.Second {
		t.Fatalf("зависший провайдер: %d %s за %s", resp.Code, resp.Body.String(), time.Since(start))
	}
	// Ошибка провайдера передаётся как есть (в формате провайдера).
	errUp, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":{"code":"rate_limit_exceeded"}}`) //nolint:errcheck // тестовый провайдер
	})
	if resp := postChat(t, newGateway(t, errUp.URL, nil), chatBody, nil); resp.Code != 429 || errCode(t, resp) != "rate_limit_exceeded" {
		t.Fatalf("ошибка провайдера: %d %s", resp.Code, resp.Body.String())
	}
	// В тексте ошибки нет внутренних подробностей (адреса провайдера).
	if resp := postChat(t, newGateway(t, deadURL, nil), chatBody, nil); strings.Contains(resp.Body.String(), deadURL) {
		t.Fatal("ошибка раскрывает адрес провайдера")
	}
}

// Поток SSE приходит клиенту по частям, пока провайдер ещё отвечает.
// Проверяется через настоящий HTTP-сервер: httptest.ResponseRecorder не показывает сброс буфера.
func TestProxyStreamsIncrementally(t *testing.T) {
	release := make(chan struct{})
	up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("нет Flusher")
			return
		}
		fmt.Fprint(w, "data: {\"n\":1}\n\n") //nolint:errcheck // тестовый провайдер
		fl.Flush()
		<-release
		fmt.Fprint(w, "data: {\"n\":2}\n\ndata: [DONE]\n\n") //nolint:errcheck // тестовый провайдер
		fl.Flush()
	})
	gw := httptest.NewServer(newGateway(t, up.URL, nil))
	defer gw.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.URL+"/v1/chat/completions", strings.NewReader(chatBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := gw.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
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
		if line != "data: {\"n\":1}\n" {
			t.Fatalf("первая часть: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("первая часть потока не пришла до завершения ответа провайдера — шлюз буферизует SSE")
	}
	close(release)
	rest, err := io.ReadAll(br)
	if err != nil || !strings.Contains(string(rest), "[DONE]") {
		t.Fatalf("остаток потока: %q %v", rest, err)
	}
}

// Разрыв соединения клиентом отменяет запрос к провайдеру.
func TestProxyClientCancelPropagates(t *testing.T) {
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

func TestNewProxyErrors(t *testing.T) {
	u, err := url.Parse("https://h")
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{}
	cases := map[string]ProxyConfig{
		"нет upstream":    {Transport: tr, MaxBodyBytes: 1},
		"нет транспорта":  {Upstream: u, MaxBodyBytes: 1},
		"нет предела":     {Upstream: u, Transport: tr},
		"ключ с \\n":      {Upstream: u, Transport: tr, MaxBodyBytes: 1, UpstreamKey: "a\nX-Evil: 1"},
		"ключ с пробелом": {Upstream: u, Transport: tr, MaxBodyBytes: 1, UpstreamKey: "a b"},
	}
	for name, c := range cases {
		if _, err := NewProxy(c); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

// Обработчик входящих HTTP-запросов шлюза — цель фаззинга (ТЗ, 8.5).
// Перебираются метод, путь со строкой запроса, тело, Content-Type и
// произвольный заголовок; провайдеру должны уходить только заголовки из
// allowlist и только объект JSON без строки запроса.
func FuzzProxyHandler(f *testing.F) {
	f.Add("POST", "/v1/chat/completions", []byte(chatBody), "application/json", "X-Custom", "v")
	f.Add("POST", "/v1/chat/completions?k=v", []byte("{"), "application/json", "Authorization", "Bearer x")
	f.Add("GET", "/v1/models", []byte(`{"a":1}`), "text/plain", "Cookie", "a=b")
	f.Add("POST", "/v1/chat/completions", []byte(strings.Repeat("{", 2000)), "application/json; charset=utf-8", "X-Forwarded-For", "1.2.3.4")
	var mu sync.Mutex
	var seen http.Header
	var seenQuery string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen, seenQuery = r.Header.Clone(), r.URL.RawQuery
		mu.Unlock()
		if _, err := io.Copy(w, r.Body); err != nil {
			return
		}
	}))
	defer up.Close()
	u, err := url.Parse(up.URL)
	if err != nil {
		f.Fatal(err)
	}
	p, err := NewProxy(ProxyConfig{Upstream: u, Transport: &http.Transport{Proxy: nil}, MaxBodyBytes: 1 << 12, Logger: quiet()})
	if err != nil {
		f.Fatal(err)
	}
	// Порог неудач не достижим: иначе после первых отказов фаззинг упёрся бы в 429.
	ta := newTestAuth(f, auth.LimiterConfig{MaxFailures: 1 << 30})
	g := withKey(mustNew(f, Options{Logger: quiet(), Proxy: p, Auth: ta.cfg}), ta.key)
	// Что может прийти провайдеру: allowlist шлюза и то, что добавляет сам транспорт Go.
	allowedUp := map[string]bool{"Content-Type": true, "Accept": true, "User-Agent": true, "X-Request-Id": true,
		"Content-Length": true, "Accept-Encoding": true}
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
		seen, seenQuery = nil, ""
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
		if !isJSONObject(body) {
			t.Fatalf("провайдеру ушло тело, которое не объект JSON: %q", body)
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

func TestProxyDropsQueryString(t *testing.T) {
	var gotQuery string
	up, _ := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	})
	g := newGateway(t, up.URL, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions?api_key=secret&x=1", strings.NewReader(chatBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotQuery != "" {
		t.Fatalf("строка запроса ушла провайдеру: %q (код %d)", gotQuery, rec.Code)
	}
}

func TestProxyDropsTrailers(t *testing.T) {
	up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Secret-Trailer")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "{}"); err != nil {
			t.Error(err)
		}
		w.Header().Set("X-Secret-Trailer", "secret")
	})
	gw := httptest.NewServer(newGateway(t, up.URL, nil))
	defer gw.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.URL+"/v1/chat/completions", strings.NewReader(chatBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := gw.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // тело читается ниже
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.Trailer.Get("X-Secret-Trailer") != "" {
		t.Fatal("трейлер провайдера дошёл до приложения")
	}
}

func TestProxyHidesUpstreamAuthErrorBody(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			if _, err := io.WriteString(w, `{"error":{"message":"Incorrect API key provided: sk-...abcd"}}`); err != nil {
				t.Error(err)
			}
		})
		resp := postChat(t, newGateway(t, up.URL, func(c *ProxyConfig) { c.UpstreamKey = "sk-provider-abcd" }), chatBody, nil)
		if resp.Code != http.StatusBadGateway || errCode(t, resp) != "upstream_auth_error" || strings.Contains(resp.Body.String(), "abcd") {
			t.Fatalf("%d от провайдера: %d %s", code, resp.Code, resp.Body.String())
		}
	}
}

// Медленная передача тела не занимает соединение дольше предела.
func TestProxySlowBodyTimesOut(t *testing.T) {
	up, rec := newUpstream(t, nil)
	gw := httptest.NewServer(newGateway(t, up.URL, func(c *ProxyConfig) { c.BodyReadTimeout = 200 * time.Millisecond }))
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
		t.Fatalf("медленное тело держало соединение %s", time.Since(start))
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("медленный запрос дошёл до провайдера")
	}
}

// В журнал шлюза не попадают содержимое запроса, ключ провайдера и
// клиентский Authorization (ТЗ: логи без содержимого и секретов).
func TestProxyLogsHaveNoSecrets(t *testing.T) {
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
		g := newGateway(t, target, func(c *ProxyConfig) { c.UpstreamKey = "sk-provider-secret"; c.Logger = logger })
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
	for _, secret := range []string{"промпт-секрет", "sk-provider-secret", "client-secret", "query-secret", "aisec_"} {
		if strings.Contains(out, secret) {
			t.Errorf("в журнал попало %q:\n%s", secret, out)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
