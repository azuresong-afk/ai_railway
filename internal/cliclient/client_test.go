package cliclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
)

// Сетевой клиент aisec-cli (ADR-0029, дополнение 1): только https, корень
// доверия из файла, без прокси из окружения и перенаправлений, срок и
// предел ответа, токен из файла с правами 0600/0400.

const testToken = "aisec_pat_synthetic_0123456789abcdef" //nolint:gosec // G101: синтетический токен теста

type testServer struct {
	url, ca, token string
	ca2            string
}

// startServer — сервер с сертификатом тестового УЦ на 127.0.0.1.
func startServer(t *testing.T, h http.Handler) testServer {
	t.Helper()
	p := profile(t)
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := aisecCrypto.NewCA("cli-test", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := aisecCrypto.NewCA("other", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv, err := httpserver.New(ctx, httpserver.Config{Addr: "127.0.0.1:0", Handler: h, TLS: tp, CertPEM: cert, KeyPEM: key,
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	dir := t.TempDir()
	s := testServer{url: "https://" + srv.Addr(), ca: filepath.Join(dir, "ca.pem"), ca2: filepath.Join(dir, "other.pem"),
		token: filepath.Join(dir, "token")}
	write(t, s.ca, ca.CertPEM(), 0o644)
	write(t, s.ca2, other.CertPEM(), 0o644)
	write(t, s.token, []byte(testToken+"\n"), 0o600)
	return s
}

func write(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func profile(t *testing.T) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (s testServer) client(t *testing.T, mut func(*Options)) *Client {
	t.Helper()
	o := Options{Server: s.url, CAFile: s.ca, TokenFile: s.token, Provider: profile(t)}
	if mut != nil {
		mut(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseServer(t *testing.T) {
	for _, ok := range []string{"https://srv.example.ru", "https://srv.example.ru:8443", "https://127.0.0.1:8443/", "https://[::1]:443"} {
		u, err := ParseServer(ok)
		if err != nil || u.Scheme != "https" || u.Path != "" {
			t.Errorf("%s: %v %v", ok, u, err)
		}
	}
	for _, bad := range []string{"", "http://srv.example.ru", "srv.example.ru", "https://", "https://user:pw@srv", "https://srv/api",
		"https://srv?x=1", "https://srv#f", "https://srv:0", "https://srv:65536", "https://srv:08443", "https://srv:abc", "ftp://srv",
		"https:opaque"} {
		if _, err := ParseServer(bad); !errors.Is(err, ErrServerURL) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t")
	write(t, p, []byte(testToken+"\r\n"), 0o600)
	if tok, err := ReadToken(p); err != nil || tok != testToken {
		t.Fatalf("0600: %q %v", tok, err)
	}
	write(t, p, []byte(testToken), 0o400)
	if _, err := ReadToken(p); err != nil {
		t.Fatalf("0400: %v", err)
	}
	write(t, p, []byte(testToken), 0o644)
	if _, err := ReadToken(p); err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("0644: %v", err)
	}
	for name, body := range map[string]string{
		"короткий":     "abc",
		"пробел":       "aisec_pat_synthetic 0123456789",
		"две строки":   testToken + "\n" + testToken,
		"кириллица":    "токен_токен_токен_токен",
		"пустой":       "",
		"длинный":      strings.Repeat("a", maxToken+1),
		"управляющий":  testToken + "\x00",
		"только конец": "\n",
	} {
		write(t, p, []byte(body), 0o600)
		if _, err := ReadToken(p); !errors.Is(err, ErrToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ReadToken(filepath.Join(dir, "нет")); err == nil {
		t.Fatal("нет файла")
	}
}

func TestNewRejects(t *testing.T) {
	s := startServer(t, http.NotFoundHandler())
	for name, mut := range map[string]func(*Options){
		"http":          func(o *Options) { o.Server = strings.Replace(s.url, "https", "http", 1) },
		"нет корня":     func(o *Options) { o.CAFile = "" },
		"корень не PEM": func(o *Options) { o.CAFile = s.token },
		"нет токена":    func(o *Options) { o.TokenFile = filepath.Join(t.TempDir(), "x") },
		"нет профиля":   func(o *Options) { o.Provider = nil },
	} {
		o := Options{Server: s.url, CAFile: s.ca, TokenFile: s.token, Provider: profile(t)}
		mut(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestDo(t *testing.T) {
	var redirected bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/ok", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:gosec // G104: тестовый сервер
		if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Content-Type") != "application/json" || string(body) != `{"a":1}` {
			http.Error(w, "заголовки", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"r1"}`)) //nolint:gosec // G104: ответ тестового сервера
	})
	mux.HandleFunc("GET /api/v1/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/v1/target", http.StatusFound)
	})
	mux.HandleFunc("GET /api/v1/target", func(http.ResponseWriter, *http.Request) { redirected = true })
	mux.HandleFunc("GET /api/v1/big", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`"` + strings.Repeat("a", 2048) + `"`)) //nolint:gosec // G104: ответ тестового сервера
	})
	mux.HandleFunc("GET /api/v1/problem", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"invalid_request","detail":"Отчёт не прошёл проверку.\u001b[31m","errors":[` + //nolint:gosec // G104: ответ тестового сервера
			strings.Repeat(`{"field":"files[0].path","detail":"путь"},`, 7) + `{"field":"x","detail":"последний"}]}`))
	})
	mux.HandleFunc("GET /api/v1/html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html></html>`)) //nolint:gosec // G104: ответ тестового сервера
	})
	mux.HandleFunc("GET /api/v1/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	s := startServer(t, mux)
	// Прокси из окружения не используется (см. проверку транспорта ниже).
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	c := s.client(t, func(o *Options) { o.MaxResponse = 1024; o.Timeout = 500 * time.Millisecond })
	ctx := context.Background()
	var out struct{ ID string }
	if err := c.Do(ctx, "POST", "/api/v1/ok", []byte(`{"a":1}`), "application/json", &out); err != nil || out.ID != "r1" {
		t.Fatalf("запрос: %+v %v", out, err)
	}
	if err := c.Do(ctx, "GET", "/api/v1/redirect", nil, "", nil); !errors.Is(err, ErrRedirect) || redirected {
		t.Fatalf("перенаправление: %v, выполнено %v", err, redirected)
	}
	if err := c.Do(ctx, "GET", "/api/v1/big", nil, "", &out); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("предел ответа: %v", err)
	}
	err := c.Do(ctx, "GET", "/api/v1/problem", nil, "", nil)
	var p *Problem
	if !errors.As(err, &p) || p.Status != 400 || p.Code != "invalid_request" || !strings.Contains(p.Detail, "и ещё ошибок: 3") ||
		strings.ContainsRune(p.Detail, 0x1b) || strings.Contains(p.Detail, testToken) {
		t.Fatalf("отказ: %#v", err)
	}
	if err := c.Do(ctx, "GET", "/api/v1/html", nil, "", &out); !errors.Is(err, ErrContentType) {
		t.Fatalf("не JSON: %v", err)
	}
	if err := c.Do(ctx, "GET", "/api/v1/slow", nil, "", nil); err == nil {
		t.Fatal("срок запроса не сработал")
	}
	for _, bad := range []string{"/v1/ok", "api/v1/ok", "/api/v1/ok?x=1", "/api/v1/ok#f"} {
		if err := c.Do(ctx, "GET", bad, nil, "", nil); err == nil {
			t.Errorf("путь %q принят", bad)
		}
	}
	// Чужой корень доверия — отказ рукопожатия, токен не отправлен.
	other := s.client(t, func(o *Options) { o.CAFile = s.ca2 })
	if err := other.Do(ctx, "POST", "/api/v1/ok", []byte(`{"a":1}`), "application/json", nil); err == nil ||
		strings.Contains(err.Error(), testToken) {
		t.Fatalf("чужой корень: %v", err)
	}
	// Прокси из окружения: Go и так не проксирует 127.0.0.1, поэтому
	// проверяется сам транспорт — функции прокси нет.
	if tr, ok := c.http.Transport.(*http.Transport); !ok || tr.Proxy != nil || !tr.DisableCompression {
		t.Fatal("транспорт клиента берёт прокси из окружения")
	}
	if c.Server() != s.url {
		t.Fatalf("адрес: %s", c.Server())
	}
}

func TestClean(t *testing.T) {
	if got := clean("а\x07б\u0085в", 100); got != "абв" {
		t.Fatalf("управляющие: %q", got)
	}
	if got := clean(strings.Repeat("я", 10), 5); got != "яя" {
		t.Fatalf("обрезка по символу: %q", got)
	}
}
