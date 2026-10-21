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

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
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

// allowPerm разрешает только перечисленные права. Субъект — сессия
// консоли синтетического пользователя, которого нет в хранилище.
type allowPerm map[string]bool

func (a allowPerm) Authorize(_ *http.Request, perm string) (Principal, Decision) {
	c := &auth.Caller{User: auth.User{ID: "01900000-0000-7000-8000-0000000000f1", Login: "u1", Role: auth.RoleSecurityAdmin},
		Session: auth.Session{ID: "01900000-0000-7000-8000-0000000000f2", State: auth.SessionActive}}
	g := auth.Grants{}
	for p, ok := range a {
		if ok {
			g[p] = auth.ScopeAll
		}
	}
	if a[perm] {
		return Principal{ID: "u1", Caller: c, Grants: g}, Allow
	}
	return Principal{ID: "u1", Caller: c, Grants: g}, Forbidden
}

// testAuth — сервис входа на хранилище в памяти, быстром хешере и ключе
// данных в памяти (второй фактор).
func testAuth(t testing.TB, mem *authtest.Memory, opts ...auth.Option) *auth.Service {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	key, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := p.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	opts = append([]auth.Option{auth.WithPasswordHasher(&authtest.Hasher{}), auth.WithRoleStore(mem),
		auth.WithSecretBox(keyring.NewStatic("01900000-0000-7000-8000-0000000000d1", aead))}, opts...)
	svc, err := auth.NewService(context.Background(), mem, mem, p, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func newHandler(t testing.TB, o Options) (http.Handler, *Router) {
	t.Helper()
	o.Hasher = testHasher(t)
	o.Logger = quiet()
	if o.Auth == nil {
		o.Auth = testAuth(t, authtest.NewMemory())
		// Без явного Authorizer тесты каркаса ждут DenyAll, а не сессии.
		if o.Authorizer == nil {
			o.Authorizer = DenyAll{}
		}
	}
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
