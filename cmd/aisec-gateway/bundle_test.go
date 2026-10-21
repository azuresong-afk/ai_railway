package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

// Сборка обработчика шлюза из пакета конфигурации (задача 2.13).

type nopSink struct{}

func (nopSink) Send(context.Context, []events.Event) error { return nil }

type bundleBuild struct {
	fx  *bundletest.Fixture
	hb  *handlerBuilder
	tp  aisecCrypto.TLSProvider
	rnd aisecCrypto.Random
	ca  string
}

func newBundleBuild(t *testing.T) *bundleBuild {
	t.Helper()
	fx := bundletest.New(t)
	p := fx.Provider
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("AISec test provider CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	queue := events.NewQueue(nopSink{}, events.QueueConfig{Logger: logger})
	t.Cleanup(func() { _ = queue.Close(context.Background()) })
	authBase := &gateway.AuthConfig{Limiter: auth.NewFailureLimiter(auth.LimiterConfig{}), Events: queue,
		IDs: ids.NewGenerator(rnd), Logger: logger}
	hb := &handlerBuilder{cfg: &config.Gateway{MaxBodyBytes: config.DefaultMaxBodyBytes}, logger: logger, hasher: h,
		auth: authBase, events: queue, quotas: gateway.NewLimiter(nil)}
	return &bundleBuild{fx: fx, hb: hb, tp: tp, rnd: rnd, ca: string(ca.CertPEM())}
}

// open подписывает содержимое и открывает пакет, как это делает шлюз.
func (b *bundleBuild) open(t *testing.T, c *bundle.Content) *bundle.Bundle {
	t.Helper()
	for i := range c.Providers {
		c.Providers[i].CAPEM = b.ca
	}
	bd, err := b.fx.Opener(t).Open(b.fx.Seal(t, c, 1), 0)
	if err != nil {
		t.Fatal(err)
	}
	return bd
}

func TestBuildFromBundle(t *testing.T) {
	b := newBundleBuild(t)
	h, err := buildFromBundle(b.open(t, b.fx.Content(t)), b.tp, b.rnd, b.hb, b.hb.logger)
	if err != nil {
		t.Fatal(err)
	}
	// Ключ приложения из пакета принимается, модели — из пакета.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+bundletest.Key)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK || len(resp.Data) != 1 || resp.Data[0].ID != "gpt-4o" {
		t.Fatalf("модели: %d %s", w.Code, w.Body)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer aisec_abcd1234_wrong")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("чужой ключ: %d", w.Code)
	}
}

// Пакет, где политика ссылается на словарь, которого у приложения нет, не
// собирается: шлюз отклоняет его (invalid_content) и работает на прежнем.
func TestBuildFromBundleMissingDictionary(t *testing.T) {
	b := newBundleBuild(t)
	c := b.fx.Content(t)
	c.Applications[0].Lists = nil
	if _, err := buildFromBundle(b.open(t, c), b.tp, b.rnd, b.hb, b.hb.logger); err == nil || !strings.Contains(err.Error(), "codename") {
		t.Fatalf("политика без словаря собрана: %v", err)
	}
}

func TestBuildFromBundleRejects(t *testing.T) {
	b := newBundleBuild(t)
	c := b.fx.Content(t)
	c.Applications[0].UserFrom = "header"
	if _, err := buildFromBundle(b.open(t, c), b.tp, b.rnd, b.hb, b.hb.logger); err == nil {
		t.Fatal("user_from без ключа псевдонимов собран")
	}
	bd := b.open(t, b.fx.Content(t))
	bd.Content.Providers[0].CAPEM = "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"
	if _, err := buildFromBundle(bd, b.tp, b.rnd, b.hb, b.hb.logger); err == nil {
		t.Fatal("провайдер с неверным корнем собран")
	}
}
