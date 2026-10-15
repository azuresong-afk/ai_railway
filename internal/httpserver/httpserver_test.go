package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

type pair struct {
	tls           aisecCrypto.TLSProvider
	ca, cert, key []byte
}

func newPair(t *testing.T) pair {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := aisecCrypto.NewCA("test", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	return pair{tp, ca.CertPEM(), cert, key}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func client(t *testing.T, p pair) *http.Client {
	t.Helper()
	cfg, err := p.tls.ClientConfig(p.ca)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func TestServeAndGracefulShutdown(t *testing.T) {
	p := newPair(t)
	release := make(chan struct{})
	started := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(started)
			<-release
		}
		if _, err := io.WriteString(w, "ok"); err != nil {
			t.Error(err)
		}
	})
	srv, err := New(context.Background(), Config{Addr: "127.0.0.1:0", Handler: h, TLS: p.tls, CertPEM: p.cert, KeyPEM: p.key, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	c := client(t, p)
	get := func(path string) (string, error) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+srv.Addr()+path, nil)
		if err != nil {
			return "", err
		}
		resp, err := c.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close() //nolint:errcheck // тело прочитано ниже; ошибка закрытия в тесте не важна
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	if body, err := get("/"); err != nil || body != "ok" {
		t.Fatalf("запрос: %q %v", body, err)
	}

	// Активный запрос дорабатывает после начала завершения.
	slow := make(chan string, 1)
	go func() {
		body, err := get("/slow")
		if err != nil {
			body = "ошибка: " + err.Error()
		}
		slow <- body
	}()
	<-started
	cancel()
	time.Sleep(100 * time.Millisecond)
	close(release)
	if body := <-slow; body != "ok" {
		t.Fatalf("активный запрос прерван при завершении: %q", body)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := get("/"); err == nil {
		t.Fatal("сервер принимает запросы после завершения")
	}
}

func TestPlainHTTPRejected(t *testing.T) {
	p := newPair(t)
	srv, err := New(context.Background(), Config{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), TLS: p.tls, CertPEM: p.cert, KeyPEM: p.key, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := srv.Run(ctx); err != nil {
			t.Error(err)
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+srv.Addr()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err == nil {
		defer resp.Body.Close() //nolint:errcheck // тест проверяет только код ответа
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("HTTP без TLS: код %d, ожидался отказ", resp.StatusCode)
		}
	}
}

func TestNewErrors(t *testing.T) {
	p := newPair(t)
	cases := map[string]Config{
		"нет обработчика": {Addr: "127.0.0.1:0", TLS: p.tls, CertPEM: p.cert, KeyPEM: p.key},
		"нет TLS":         {Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), CertPEM: p.cert, KeyPEM: p.key},
		"нет сертификата": {Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), TLS: p.tls},
		"плохой ключ":     {Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), TLS: p.tls, CertPEM: p.cert, KeyPEM: []byte("x")},
		"плохой адрес":    {Addr: "256.0.0.1:0", Handler: http.NotFoundHandler(), TLS: p.tls, CertPEM: p.cert, KeyPEM: p.key},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(context.Background(), cfg); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
	_, err := New(context.Background(), cases["нет сертификата"])
	if err == nil || !strings.Contains(err.Error(), "без TLS") {
		t.Fatalf("ошибка должна объяснять, что без TLS нельзя: %v", err)
	}
}
