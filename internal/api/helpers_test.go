package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func testHasher(t testing.TB) aisecCrypto.Hasher {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// allowPerm разрешает только перечисленные права.
type allowPerm map[string]bool

func (a allowPerm) Authorize(_ *http.Request, perm string) (Principal, Decision) {
	if a[perm] {
		return Principal{ID: "u1"}, Allow
	}
	return Principal{ID: "u1"}, Forbidden
}

func newHandler(t testing.TB, o Options) (http.Handler, *Router) {
	t.Helper()
	o.Hasher = testHasher(t)
	o.Logger = quiet()
	h, rt, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return h, rt
}

func do(h http.Handler, method, target, body string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:1234"
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func mustProblem(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("статус %d, ожидался %d; тело %s", w.Code, status, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != ContentTypeProblem {
		t.Fatalf("Content-Type %q", ct)
	}
	if !strings.Contains(w.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("нет кода %s: %s", code, w.Body.String())
	}
}

var errTest = errors.New("база недоступна: secret-dsn")

func okReady(context.Context) error { return nil }
