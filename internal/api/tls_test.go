package api_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/api"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
)

// Сквозная проверка: каркас по настоящему TLS отвечает Problem Details на
// защищённый маршрут без входа и заголовками безопасности.
func TestOverRealTLS(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := p.Hasher()
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, _, err := api.New(api.Options{Logger: logger, Hasher: hasher, Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	srv, err := httpserver.New(ctx, httpserver.Config{Addr: "127.0.0.1:0", Handler: h, TLS: tp, CertPEM: cert, KeyPEM: key, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	cc, err := tp.ClientConfig(ca.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cc}, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+srv.Addr()+"/api/v1/system/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 || resp.Header.Get("Content-Type") != api.ContentTypeProblem || resp.Header.Get("Content-Security-Policy") != api.DefaultCSP {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
