package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// eventLog — приёмник событий для тестов.
type eventLog struct {
	mu  sync.Mutex
	evs []events.Event
}

func (l *eventLog) Enqueue(e events.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evs = append(l.evs, e)
	return nil
}

func (l *eventLog) all() []events.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]events.Event(nil), l.evs...)
}

// testAuth — аутентификация с одним действующим ключом приложения app.
type testAuth struct {
	cfg *AuthConfig
	key string
	log *eventLog
}

func newTestAuth(t testing.TB, lc auth.LimiterConfig, extra ...auth.KeyRecord) testAuth {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
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
	key, prefix, hash, err := auth.NewAppKey(rnd, h)
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.NewAuthenticator(h, append([]auth.KeyRecord{{AppID: "app", Env: "test", Prefix: prefix, SHA256: hash}}, extra...))
	if err != nil {
		t.Fatal(err)
	}
	log := &eventLog{}
	return testAuth{
		cfg: &AuthConfig{Authenticator: a, Limiter: auth.NewFailureLimiter(lc), Events: log, IDs: ids.NewGenerator(rnd), Logger: quiet()},
		key: key, log: log,
	}
}

// echoIdentity отвечает идентификатором приложения из контекста.
var echoIdentity = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	id, ok := IdentityFrom(r.Context())
	if !ok {
		http.Error(w, "нет приложения", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"app": id.AppID, "prefix": id.KeyPrefix})
})

func authReq(remote string, authz ...string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(chatBody))
	req.RemoteAddr = remote
	for _, v := range authz {
		req.Header.Add("Authorization", v)
	}
	return req
}

func TestDM38_GatewayAuthFailures(t *testing.T) {
	ta := newTestAuth(t, auth.LimiterConfig{MaxFailures: 100})
	h, err := RequireAppKey(*ta.cfg, echoIdentity)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authReq("192.0.2.10:5000", "Bearer "+ta.key))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"app":"app"`) {
		t.Fatalf("действующий ключ: %d %s", rec.Code, rec.Body.String())
	}
	if n := len(ta.log.all()); n != 0 {
		t.Fatalf("успешный вход создал %d событий", n)
	}
	cases := []struct {
		name   string
		authz  []string
		reason string
	}{
		{"нет заголовка", nil, auth.ReasonMissing},
		{"другая схема", []string{"Basic " + ta.key}, auth.ReasonMalformed},
		{"два заголовка", []string{"Bearer " + ta.key, "Bearer " + ta.key}, auth.ReasonMalformed},
		{"чужой формат", []string{"Bearer sk-proj-1234"}, auth.ReasonMalformed},
		{"подменён секрет", []string{"Bearer " + ta.key[:len(ta.key)-1] + flip(ta.key[len(ta.key)-1])}, auth.ReasonInvalid},
	}
	for i, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authReq("192.0.2.10:5000", c.authz...))
		if rec.Code != http.StatusUnauthorized || errCode(t, rec) != "invalid_api_key" || rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s: %d %q", c.name, rec.Code, rec.Body.String())
		}
		// Ответ одинаков при любой причине: подробности — только в событии.
		if !strings.Contains(rec.Body.String(), "ключ приложения не принят") || strings.Contains(rec.Body.String(), `"`+c.reason+`"`) {
			t.Fatalf("%s: в ответе подробности: %q", c.name, rec.Body.String())
		}
		evs := ta.log.all()
		if len(evs) != i+1 {
			t.Fatalf("%s: событий %d", c.name, len(evs))
		}
		e := evs[i]
		if e.Type != events.TypeAuthFailure || e.AuthFailure.Reason != c.reason || e.AuthFailure.RemoteAddr != "192.0.2.10" ||
			len(e.Threats) != 1 || e.Threats[0] != "DM-38" {
			t.Fatalf("%s: событие %+v %+v", c.name, e, e.AuthFailure)
		}
		// Сам ключ в событие не попадает ни целиком, ни секретной частью.
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), ta.key[len("aisec_12345678_"):len("aisec_12345678_")+20]) {
			t.Fatalf("%s: секрет ключа в событии: %s", c.name, b)
		}
	}
	if p := ta.log.all()[4].AuthFailure.KeyPrefix; p != ta.key[:len("aisec_12345678")] {
		t.Fatalf("префикс в событии: %q", p)
	}
	if a := ta.log.all()[4].App; a != "app" {
		t.Fatalf("приложение в событии: %q", a)
	}
}

func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func TestDM38_GatewayRateLimitsFailures(t *testing.T) {
	ta := newTestAuth(t, auth.LimiterConfig{MaxFailures: 3, Block: time.Minute})
	clock := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	ta.cfg.Now = func() time.Time { return clock }
	h, err := RequireAppKey(*ta.cfg, echoIdentity)
	if err != nil {
		t.Fatal(err)
	}
	attacker := "198.51.100.5:4444"
	for i := range 3 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authReq(attacker, "Bearer aisec_zzzzzzzz_"+strings.Repeat("A", 43)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("попытка %d: %d", i, rec.Code)
		}
	}
	evs := ta.log.all()
	if len(evs) != 4 || evs[3].AuthFailure.Reason != auth.ReasonRateLimited {
		t.Fatalf("ожидалось три отказа и одно событие о блокировке: %d", len(evs))
	}
	// Во время блокировки неудачи получают 429 без событий.
	for range 5 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authReq(attacker, "Bearer "+ta.key[:len(ta.key)-1]+flip(ta.key[len(ta.key)-1])))
		if rec.Code != http.StatusTooManyRequests || errCode(t, rec) != "auth_rate_limited" || rec.Header().Get("Retry-After") != "60" {
			t.Fatalf("при блокировке: %d %s %q", rec.Code, rec.Body.String(), rec.Header().Get("Retry-After"))
		}
	}
	if len(ta.log.all()) != 4 {
		t.Fatal("отклонённые при блокировке запросы создали события")
	}
	// Действующий ключ проходит и с заблокированного адреса: соседи по NAT
	// не отключаются из-за чужого недействующего ключа.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authReq(attacker, "Bearer "+ta.key))
	if rec.Code != http.StatusOK {
		t.Fatalf("действующий ключ с заблокированного адреса: %d", rec.Code)
	}
	// Другой адрес не заблокирован: его неудача — 401, а не 429.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authReq("198.51.100.6:1", "Bearer aisec_zzzzzzzz_"+strings.Repeat("A", 43)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("соседний адрес: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authReq("198.51.100.6:1", "Bearer "+ta.key))
	if rec.Code != http.StatusOK {
		t.Fatalf("соседний адрес: %d", rec.Code)
	}
	// После блокировки неудача снова получает 401 и событие.
	clock = clock.Add(time.Minute)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authReq(attacker, "Bearer aisec_zzzzzzzz_"+strings.Repeat("A", 43)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("после блокировки: %d", rec.Code)
	}
	if n := len(ta.log.all()); n != 6 {
		t.Fatalf("событий %d, ожидалось 6", n)
	}
}

func TestDM38_GatewayIgnoresForwardedFor(t *testing.T) {
	ta := newTestAuth(t, auth.LimiterConfig{})
	// Ключ, привязанный к подсети 10.0.0.0/8.
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	hs, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	key, prefix, hash, err := auth.NewAppKey(rnd, hs)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := KeyRecords([]config.Application{{ID: "bound", Env: "prod", Keys: []config.AppKey{{Prefix: prefix, SHA256: hash, AllowedCIDRs: []string{"10.0.0.0/8"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.NewAuthenticator(hs, recs)
	if err != nil {
		t.Fatal(err)
	}
	ta.cfg.Authenticator = a
	h, err := RequireAppKey(*ta.cfg, echoIdentity)
	if err != nil {
		t.Fatal(err)
	}
	req := authReq("203.0.113.1:1", "Bearer "+key)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Real-Ip", "10.0.0.1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || ta.log.all()[0].AuthFailure.Reason != auth.ReasonAddress {
		t.Fatalf("X-Forwarded-For обошёл allowed_cidrs: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authReq("10.20.30.40:1", "Bearer "+key))
	if rec.Code != http.StatusOK {
		t.Fatalf("адрес из подсети: %d", rec.Code)
	}
}

func TestKeyRecords(t *testing.T) {
	recs, err := KeyRecords([]config.Application{{ID: "a", Env: "test", Keys: []config.AppKey{
		{Prefix: "aisec_abcd1234", SHA256: strings.Repeat("0", 64), Expires: "2027-01-01", Revoked: true, AllowedCIDRs: []string{"10.1.2.3/8"}},
		{Prefix: "aisec_abcd1235", SHA256: strings.Repeat("1", 64)},
	}}})
	if err != nil || len(recs) != 2 {
		t.Fatal(recs, err)
	}
	r := recs[0]
	if !r.Expires.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) || !r.Revoked || r.AllowedCIDRs[0].String() != "10.0.0.0/8" || r.Env != "test" {
		t.Fatalf("%+v", r)
	}
	if !recs[1].Expires.IsZero() || recs[1].AllowedCIDRs != nil {
		t.Fatalf("%+v", recs[1])
	}
	for _, bad := range []config.AppKey{{Expires: "01.01.2027"}, {AllowedCIDRs: []string{"10.0.0.1"}}} {
		if _, err := KeyRecords([]config.Application{{ID: "a", Keys: []config.AppKey{bad}}}); err == nil {
			t.Errorf("%+v: ожидалась ошибка", bad)
		}
	}
}

func TestRequireAppKeyNeedsDependencies(t *testing.T) {
	if _, err := RequireAppKey(AuthConfig{}, echoIdentity); err == nil {
		t.Fatal("собран обработчик без зависимостей")
	}
	if _, err := New(Options{Chat: echoIdentity}); err == nil {
		t.Fatal("маршрут приложений подключён без аутентификации")
	}
}
