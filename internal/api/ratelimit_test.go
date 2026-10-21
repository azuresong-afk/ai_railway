package api

import (
	"net/netip"
	"testing"
	"time"
)

func TestRateLimiterWindowAndRules(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewRateLimiter(RateConfig{
		Rules: []RateRule{{Prefix: "/", Max: 3, Window: time.Minute}, {Prefix: "/api/v1/auth/", Max: 1, Window: time.Minute}, {Prefix: "/free", Max: 0}},
		Now:   func() time.Time { return now },
	})
	c := netip.MustParsePrefix("192.0.2.1/32")
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("GET", "/api/v1/x", c); !ok {
			t.Fatalf("запрос %d", i)
		}
	}
	ok, wait := l.Allow("GET", "/api/v1/x", c)
	if ok || wait <= 0 || wait > time.Minute {
		t.Fatalf("ожидался отказ: %v %v", ok, wait)
	}
	if ok, _ := l.Allow("GET", "/api/v1/auth/login", c); !ok {
		t.Fatal("у входа свой счётчик")
	}
	if ok, _ := l.Allow("GET", "/api/v1/auth/login", c); ok {
		t.Fatal("вход строже")
	}
	if ok, _ := l.Allow("GET", "/free", c); !ok {
		t.Fatal("Max=0 — без предела")
	}
	now = now.Add(time.Minute)
	if ok, _ := l.Allow("GET", "/api/v1/x", c); !ok {
		t.Fatal("окно сброшено")
	}
}

func TestRateLimiterBoundedMemory(t *testing.T) {
	l := NewRateLimiter(RateConfig{Rules: []RateRule{{Prefix: "/", Max: 2, Window: time.Minute}}, MaxEntries: 2, Now: func() time.Time { return time.Unix(0, 0) }})
	for _, a := range []string{"192.0.2.1/32", "192.0.2.2/32"} {
		l.Allow("GET", "/x", netip.MustParsePrefix(a))
	}
	// Таблица полна: новые клиенты делят общий счётчик и всё равно ограничены.
	denied := false
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("GET", "/x", netip.MustParsePrefix("198.51.100.0/24")); !ok {
			denied = true
		}
	}
	if !denied || len(l.entries) != 2 {
		t.Fatalf("denied=%v entries=%d", denied, len(l.entries))
	}
}

func TestClientPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.9":         "192.0.2.9/32",
		"2001:db8::1:2:3:4": "2001:db8::/64",
		"::ffff:192.0.2.9":  "192.0.2.9/32",
	} {
		if got := clientPrefix(netip.MustParseAddr(in)); got.String() != want {
			t.Errorf("%s: %s, ожидалось %s", in, got, want)
		}
	}
	if clientPrefix(netip.Addr{}).IsValid() {
		t.Error("пустой адрес принят")
	}
}

// В3 ревью 2.r1: строгий предел — только у POST, которые проверяют пароль
// или код; выход, чтение настройки и прочее — по общему правилу.
func TestDefaultRateRulesAuth(t *testing.T) {
	l := NewRateLimiter(RateConfig{Now: func() time.Time { return time.Unix(0, 0) }})
	c := netip.MustParsePrefix("192.0.2.1/32")
	for _, tc := range []struct {
		method, path string
		strict       bool
	}{
		{"POST", "/api/v1/auth/login", true},
		{"POST", "/api/v1/auth/setup", true},
		{"POST", "/api/v1/auth/mfa/verify", true},
		{"POST", "/api/v1/auth/mfa/setup/confirm", true},
		{"POST", "/api/v1/auth/password", true},
		{"GET", "/api/v1/auth/setup", false},
		{"POST", "/api/v1/auth/logout", false},
		{"GET", "/api/v1/auth/policy", false},
	} {
		i := l.ruleFor(tc.method, tc.path)
		if got := l.cfg.Rules[i].Max == 10; got != tc.strict {
			t.Errorf("%s %s: строгий %v, ожидалось %v", tc.method, tc.path, got, tc.strict)
		}
	}
	// Выход не съедает предел входа.
	for range 20 {
		l.Allow("POST", "/api/v1/auth/logout", c)
	}
	if ok, _ := l.Allow("POST", "/api/v1/auth/login", c); !ok {
		t.Fatal("выход исчерпал предел входа")
	}
}

func TestRateLimitMiddlewareResponse(t *testing.T) {
	h, _ := newHandler(t, Options{RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 1, Window: time.Minute}}}})
	if w := do(h, "GET", "/healthz", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	w := do(h, "GET", "/healthz", "")
	mustProblem(t, w, 429, CodeRateLimited)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("нет Retry-After")
	}
	// X-Forwarded-For клиента игнорируется.
	if w := do(h, "GET", "/healthz", "", "X-Forwarded-For", "203.0.113.5"); w.Code != 429 {
		t.Fatalf("заголовок подменил клиента: %d", w.Code)
	}
}
