package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// В3 ревью 2.r1: адрес клиента за доверенным прокси — из X-Forwarded-For
// справа налево; без доверенного прокси заголовок не действует.
func TestResolveClient(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("2001:db8:1::/48")}
	for _, tc := range []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"без прокси заголовок игнорируется", "192.0.2.7:5000", []string{"203.0.113.5"}, "192.0.2.7"},
		{"доверенный прокси", "10.0.0.5:443", []string{"203.0.113.5"}, "203.0.113.5"},
		{"подделка слева отбрасывается", "10.0.0.5:443", []string{"198.51.100.1, 203.0.113.5"}, "203.0.113.5"},
		{"цепочка прокси", "10.0.0.5:443", []string{"203.0.113.5, 10.0.0.9"}, "203.0.113.5"},
		{"несколько заголовков", "10.0.0.5:443", []string{"198.51.100.1", "203.0.113.5, 10.0.0.9"}, "203.0.113.5"},
		{"все доверенные — самый левый", "10.0.0.5:443", []string{"10.0.0.7, 10.0.0.9"}, "10.0.0.7"},
		{"мусор — последний доверенный узел", "10.0.0.5:443", []string{"203.0.113.5, мусор, 10.0.0.9"}, "10.0.0.9"},
		{"без заголовка — прокси", "10.0.0.5:443", nil, "10.0.0.5"},
		{"пустой заголовок — прокси", "10.0.0.5:443", []string{""}, "10.0.0.5"},
		{"IPv6 и отображённый IPv4", "[2001:db8:1::2]:443", []string{"::ffff:203.0.113.5"}, "203.0.113.5"},
		{"зона интерфейса не принимается", "10.0.0.5:443", []string{"fe80::1%eth0"}, "10.0.0.5"},
		{"адрес с портом не принимается", "10.0.0.5:443", []string{"203.0.113.5:1234"}, "10.0.0.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := resolveClient(r, trusted); got.String() != tc.want {
				t.Fatalf("%s, ожидалось %s", got, tc.want)
			}
		})
	}
}

// Длинная цепочка разбирается только справа, не дальше maxForwardedHops.
func TestResolveClientLongChain(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.5:443"
	r.Header.Set("X-Forwarded-For", "203.0.113.5,"+strings.Repeat("10.1.1.1,", 100)+"10.1.1.2")
	if got := resolveClient(r, trusted); got.String() != "10.1.1.1" {
		t.Fatalf("%s", got)
	}
	if hops := lastHops([]string{strings.Repeat("a,", 1000)}, maxForwardedHops); len(hops) != maxForwardedHops {
		t.Fatalf("разобрано %d адресов", len(hops))
	}
}

// Обработчики (аудит, сессии) видят тот же адрес, что и ограничитель.
func TestClientAddrInHandlers(t *testing.T) {
	h, _ := newHandler(t, Options{
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		Extra: []Route{{Method: http.MethodGet, Path: "/api/v1/test-addr", Public: true,
			Handler: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(clientAddr(r).String())) }}}, //nolint:gosec // G104: тестовый обработчик
	})
	if w := do(h, "GET", "/api/v1/test-addr", "", "X-Forwarded-For", "203.0.113.5"); w.Body.String() != "203.0.113.5" {
		t.Fatalf("адрес в обработчике: %q", w.Body.String())
	}
	h, _ = newHandler(t, Options{Extra: []Route{{Method: http.MethodGet, Path: "/api/v1/test-addr", Public: true,
		Handler: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(clientAddr(r).String())) }}}}) //nolint:gosec // G104: тестовый обработчик
	if w := do(h, "GET", "/api/v1/test-addr", "", "X-Forwarded-For", "203.0.113.5"); w.Body.String() != "192.0.2.1" {
		t.Fatalf("без доверенных прокси: %q", w.Body.String())
	}
}

// Ограничитель считает клиентов за доверенным прокси по отдельности: офис
// за одним адресом прокси не упирается в общий предел.
func TestRateLimitBehindTrustedProxy(t *testing.T) {
	h, _ := newHandler(t, Options{
		RateLimit:      RateConfig{Rules: []RateRule{{Prefix: "/", Max: 1, Window: time.Minute}}},
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	})
	// do() отправляет запросы с адреса 192.0.2.1 (см. helpers_test.go).
	for _, client := range []string{"203.0.113.5", "203.0.113.6"} {
		if w := do(h, "GET", "/healthz", "", "X-Forwarded-For", client); w.Code != http.StatusOK {
			t.Fatalf("%s: %d", client, w.Code)
		}
	}
	mustProblem(t, do(h, "GET", "/healthz", "", "X-Forwarded-For", "203.0.113.5"), http.StatusTooManyRequests, CodeRateLimited)
}

// Разбор X-Forwarded-For — вход от клиента: без паники, не дальше
// maxForwardedHops, итог — адрес соединения или адрес из заголовка.
func FuzzResolveClient(f *testing.F) {
	for _, s := range []string{"203.0.113.5", "198.51.100.1, 203.0.113.5, 10.0.0.9", "", ",,,", "fe80::1%eth0", "::ffff:10.0.0.1", "мусор", strings.Repeat("10.0.0.1,", 40)} {
		f.Add(s)
	}
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	f.Fuzz(func(t *testing.T, xff string) {
		if hops := lastHops([]string{xff}, maxForwardedHops); len(hops) > maxForwardedHops {
			t.Fatalf("разобрано %d адресов", len(hops))
		}
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.5:443"
		r.Header.Set("X-Forwarded-For", xff)
		got := resolveClient(r, trusted)
		if !got.IsValid() || got.Zone() != "" || got.Is4In6() {
			t.Fatalf("адрес %v из %q", got, xff)
		}
		if got.String() == "10.0.0.5" {
			return
		}
		for _, hop := range strings.Split(xff, ",") {
			if a, err := netip.ParseAddr(strings.TrimSpace(hop)); err == nil && a.Unmap() == got {
				return
			}
		}
		t.Fatalf("адрес %v не из заголовка %q", got, xff)
	})
}
