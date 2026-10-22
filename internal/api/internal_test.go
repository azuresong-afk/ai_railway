package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// Внутренний API шлюзов (задача 2.14). Сквозные проверки на настоящем mTLS —
// internal/gateway/control_test.go; здесь — контракт, отказы без TLS и fuzz.

type nopAudit struct{}

func (nopAudit) Record(context.Context, audit.Entry) error { return nil }

// asGateway — субъект запроса: шлюз с заданным ID (вместо проверки сертификата).
type asGateway string

func (g asGateway) Authorize(_ *http.Request, perm string) (Principal, Decision) {
	if perm != PermGatewayInternal {
		return Principal{ID: string(g)}, Forbidden
	}
	return Principal{ID: string(g), Grants: auth.Grants{PermGatewayInternal: auth.ScopeAll}}, Allow
}

// newGatewayEnv — реестр в памяти с УЦ и одним зарегистрированным шлюзом.
func newGatewayEnv(t testing.TB) (*gwregistry.Service, gwregistry.Gateway) {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("AISec test CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := gwregistry.New(gwregistry.Options{Store: gwregistry.NewMemory(), Provider: p, CA: ca, Audit: nopAudit{}, Logger: quiet(),
		HeartbeatMinInterval: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tok, _, err := svc.IssueToken(ctx, gwregistry.TokenInput{Name: "gw-1", Actor: audit.Actor{Type: audit.ActorCLI, ID: "uid:0"}})
	if err != nil {
		t.Fatal(err)
	}
	_, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := svc.Register(ctx, gwregistry.RegisterInput{Token: tok, CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	return svc, reg.Gateway
}

func newInternalHandler(t testing.TB, authz Authorizer) (http.Handler, *Router) {
	t.Helper()
	svc, _ := newGatewayEnv(t)
	h, rt, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Authorizer: authz,
		Events: events.NewMemory(), RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}},
		Extra: BundleRoutes(newBundleEnv(t, true).svc, quiet())})
	if err != nil {
		t.Fatal(err)
	}
	return h, rt
}

func TestInternalRoutesMatchSpec(t *testing.T) {
	raw, err := os.ReadFile("../../api/internal-openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var s spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	_, rt := newInternalHandler(t, nil)
	registered := map[string]bool{}
	for _, r := range rt.Routes() {
		registered[strings.ToLower(r.Method)+" "+r.Path] = true
		if r.Public || !strings.HasPrefix(r.Path, "/internal/v1/") {
			t.Errorf("%s %s: на внутреннем порту только защищённые маршруты /internal/v1/", r.Method, r.Path)
		}
		op, ok := s.Paths[r.Path][strings.ToLower(r.Method)]
		if !ok {
			t.Errorf("маршрут %s %s не описан в internal-openapi.yaml", r.Method, r.Path)
			continue
		}
		for _, code := range []string{"401", "403", "429"} {
			if _, ok := op.Responses[code]; !ok {
				t.Errorf("%s %s: не описан ответ %s", r.Method, r.Path, code)
			}
		}
	}
	for path, ops := range s.Paths {
		for method := range ops {
			if !registered[method+" "+path] {
				t.Errorf("в internal-openapi.yaml есть %s %s, а обработчика нет", strings.ToUpper(method), path)
			}
		}
	}
}

// Без проверенного клиентского сертификата (r.TLS нет) — 401; к маршрутам
// консоли внутренний порт не пускает.
func TestInternalRequiresGatewayCert(t *testing.T) {
	h, _ := newInternalHandler(t, nil)
	w := do(h, http.MethodPost, "/internal/v1/heartbeat", `{"version":"1"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("без сертификата: %d", w.Code)
	}
	for _, path := range []string{"/api/v1/gateways/register", "/api/v1/auth/login", "/healthz", "/"} {
		if w := do(h, http.MethodPost, path, `{}`); w.Code != http.StatusNotFound {
			t.Errorf("%s на внутреннем порту: %d", path, w.Code)
		}
	}
	// Запрос без TLS и без реестра — отказ «не аутентифицирован», а не паника.
	if _, d := (GatewayAuthorizer{}).Authorize(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil), "users.read"); d != Unauthenticated {
		t.Fatalf("без TLS и реестра: %v", d)
	}
}

func TestHeartbeatHandler(t *testing.T) {
	svc, gw := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Authorizer: asGateway(gw.ID)})
	if err != nil {
		t.Fatal(err)
	}
	w := do(h, http.MethodPost, "/internal/v1/heartbeat", `{"version":"2.0.0","bundle_etag":"\"abc\""}`, "Content-Type", "application/json")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"interval_seconds":30`) {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body)
	}
	// stopping без started_at — 400 (В27 ревью 2.r5).
	if w := do(h, http.MethodPost, "/internal/v1/heartbeat", `{"version":"1","stopping":true}`, "Content-Type", "application/json"); w.Code != http.StatusBadRequest {
		t.Fatalf("stopping без started_at: %d %s", w.Code, w.Body)
	}
	// Шлюз, которого нет в реестре (отозван между проверками), — 401.
	h2, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Authorizer: asGateway("nope")})
	if err != nil {
		t.Fatal(err)
	}
	if w := do(h2, http.MethodPost, "/internal/v1/heartbeat", `{"version":"1"}`, "Content-Type", "application/json"); w.Code != http.StatusUnauthorized {
		t.Fatalf("неизвестный шлюз: %d", w.Code)
	}
	if _, _, err := NewInternal(InternalOptions{Hasher: testHasher(t)}); err == nil {
		t.Fatal("внутренний API без реестра")
	}
}

// FuzzHeartbeatRequest: любое тело heartbeat — 200 или ошибка клиента в
// формате Problem Details, без паники и 500.
func FuzzHeartbeatRequest(f *testing.F) {
	svc, gw := newGatewayEnv(f)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(f), Gateways: svc, Authorizer: asGateway(gw.ID),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}})
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{`{"version":"1"}`, `{"version":"1","bundle_etag":"x"}`, `{}`, `[]`, `{"version":1}`, "\x00", `{"version":"1"}{}`,
		`{"version":"1","selftest":{"ok":true,"checked_at":"2026-10-21T10:00:00Z","failed":0}}`,
		`{"version":"1","integrity":{"ok":false,"checked_at":"2026-10-21T10:00:00Z","reason":"files_mismatch","failed":2}}`,
		`{"version":"1","selftest":{"ok":"да"}}`, `{"version":"1","integrity":null}`, `{"version":"1","selftest":[]}`,
		`{"version":"1","started_at":"2026-10-21T10:00:00.123456789Z","stopping":true}`, `{"version":"1","stopping":true}`} {
		f.Add(s, "application/json")
	}
	f.Add(`{"version":"1"}`, "text/plain")
	f.Fuzz(func(t *testing.T, body, ctype string) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/internal/v1/heartbeat", strings.NewReader(body))
		req.Header.Set("Content-Type", ctype)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		switch w.Code {
		case http.StatusOK, http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusTooManyRequests:
		default:
			t.Fatalf("код %d: %s", w.Code, w.Body)
		}
		if w.Code != http.StatusOK && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
			t.Fatalf("ошибка не в формате Problem Details: %q", w.Header().Get("Content-Type"))
		}
	})
}

// FuzzRegisterGatewayRequest: любое тело регистрации — 201 или ошибка
// клиента; без верного токена сертификат не выпускается.
func FuzzRegisterGatewayRequest(f *testing.F) {
	svc, _ := newGatewayEnv(f)
	h, _, err := New(Options{Logger: quiet(), Hasher: testHasher(f), Gateways: svc,
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}})
	if err != nil {
		f.Fatal(err)
	}
	_, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(`{"token":"aisec_gwreg_AAAA","csr":"x"}`)
	f.Add(`{"token":"","csr":""}`)
	f.Add(`{"token":"aisec_gwreg_` + strings.Repeat("A", 43) + `","csr":` + jsonString(string(csr)) + `}`)
	f.Add(`{"csr":` + jsonString(string(csr)) + `}`)
	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/gateways/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		switch w.Code {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusRequestEntityTooLarge:
		default:
			// 201 невозможен: действующего токена фаззер не знает.
			t.Fatalf("код %d: %s", w.Code, w.Body)
		}
	})
}

func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
