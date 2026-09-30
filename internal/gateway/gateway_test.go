package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func do(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, nil))
	return rec
}

func TestHealth(t *testing.T) {
	g := New(Options{Logger: quiet()})
	for _, p := range []string{"/healthz", "/readyz"} {
		rec := do(t, g, http.MethodGet, p)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}

func TestUnknownRoutesInOpenAIFormat(t *testing.T) {
	g := New(Options{Logger: quiet(), Proxy: http.NotFoundHandler()})
	cases := []struct {
		method, path string
		code         int
		errCode      string
	}{
		{http.MethodGet, "/v1/models", http.StatusNotFound, "not_found"},
		{http.MethodPost, "/v1/embeddings", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/v1/chat/completions", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodDelete, "/healthz", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodGet, "/../etc/passwd", http.StatusNotFound, "not_found"},
	}
	for _, c := range cases {
		rec := do(t, g, c.method, c.path)
		var body struct{ Error struct{ Code string } }
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: ответ не JSON: %q", c.method, c.path, rec.Body.String())
		}
		if rec.Code != c.code || body.Error.Code != c.errCode {
			t.Errorf("%s %s: %d %q, ожидалось %d %q", c.method, c.path, rec.Code, body.Error.Code, c.code, c.errCode)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := do(t, New(Options{Logger: quiet()}), http.MethodGet, "/healthz")
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"} {
		if rec.Header().Get(k) != v {
			t.Errorf("%s = %q", k, rec.Header().Get(k))
		}
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("нет Strict-Transport-Security")
	}
}

func TestProxyRouteNotMountedWithoutProxy(t *testing.T) {
	rec := do(t, New(Options{Logger: quiet()}), http.MethodPost, "/v1/chat/completions")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("без прокси маршрут должен отсутствовать: %d", rec.Code)
	}
}
