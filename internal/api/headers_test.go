package api

import (
	"strings"
	"testing"
)

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h, _ := newHandler(t, Options{})
	for _, target := range []string{"/healthz", "/api/v1/system/info", "/api/v1/nope", "/other"} {
		hd := do(h, "GET", target, "").Header()
		if hd.Get("Content-Security-Policy") != DefaultCSP {
			t.Errorf("%s: CSP %q", target, hd.Get("Content-Security-Policy"))
		}
		for k, want := range map[string]string{
			"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
			"Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
		} {
			if hd.Get(k) != want {
				t.Errorf("%s: %s=%q", target, k, hd.Get(k))
			}
		}
		if !strings.Contains(hd.Get("Strict-Transport-Security"), "max-age=") {
			t.Errorf("%s: нет HSTS", target)
		}
	}
	if hd := do(h, "GET", "/api/v1/system/info", "").Header(); hd.Get("Cache-Control") != "no-store" {
		t.Errorf("API кэшируется: %q", hd.Get("Cache-Control"))
	}
}

// CSP из ТЗ 6.9 не должна ослабляться: нет unsafe-*, внешних источников и подстановок.
func TestCSPIsStrict(t *testing.T) {
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:", "*", "data: ;"} {
		if strings.Contains(DefaultCSP, bad) {
			t.Errorf("CSP содержит %q", bad)
		}
	}
	for _, need := range []string{"default-src 'self'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
		if !strings.Contains(DefaultCSP, need) {
			t.Errorf("в CSP нет %q", need)
		}
	}
}
