package config

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var required = []string{"-config", "gateway.yaml", "-tls-cert", "c.pem", "-tls-key", "k.pem", "-upstream-url", "https://mock-llm:9443", "-upstream-ca", "ca.pem"}

func TestLoadGatewayDefaults(t *testing.T) {
	cfg, err := LoadGateway(required, env(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultGatewayListen || cfg.MaxBodyBytes != DefaultMaxBodyBytes ||
		cfg.UpstreamConnectTimeout != DefaultConnectTimeout || cfg.UpstreamHeaderTimeout != DefaultHeaderTimeout ||
		cfg.UpstreamURL.String() != "https://mock-llm:9443" || len(cfg.ForwardHeaders) != 0 || cfg.ConfigFile != "gateway.yaml" {
		t.Fatalf("значения по умолчанию: %+v", cfg)
	}
}

func TestLoadGatewayEnvAndFlagPrecedence(t *testing.T) {
	e := env(map[string]string{
		"AISEC_GATEWAY_CONFIG":          "env-gateway.yaml",
		"AISEC_GATEWAY_TLS_CERT":        "env-c.pem",
		"AISEC_GATEWAY_TLS_KEY":         "env-k.pem",
		"AISEC_GATEWAY_UPSTREAM_URL":    "https://env.example/base/",
		"AISEC_GATEWAY_UPSTREAM_CA":     "env-ca.pem",
		"AISEC_GATEWAY_MAX_BODY_BYTES":  "2048",
		"AISEC_GATEWAY_FORWARD_HEADERS": "x-mock-scenario, X-Trace",
		"AISEC_GATEWAY_LISTEN":          "0.0.0.0:9000",
	})
	cfg, err := LoadGateway([]string{"-listen", "127.0.0.1:1", "-upstream-header-timeout", "5s"}, e, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:1" {
		t.Errorf("флаг должен быть важнее окружения: %s", cfg.Listen)
	}
	if cfg.ConfigFile != "env-gateway.yaml" || cfg.TLSCertFile != "env-c.pem" || cfg.MaxBodyBytes != 2048 || cfg.UpstreamHeaderTimeout != 5*time.Second {
		t.Errorf("значения из окружения: %+v", cfg)
	}
	if cfg.UpstreamURL.Path != "/base" {
		t.Errorf("завершающий / в пути не отрезан: %q", cfg.UpstreamURL.Path)
	}
	if strings.Join(cfg.ForwardHeaders, ",") != "X-Mock-Scenario,X-Trace" {
		t.Errorf("заголовки: %v", cfg.ForwardHeaders)
	}
}

func TestLoadGatewayErrors(t *testing.T) {
	with := func(extra ...string) []string { return append(append([]string{}, required...), extra...) }
	cases := map[string][]string{
		"нет обязательных": {},
		"нет config":       required[2:],
		"http":             with("-upstream-url", "http://mock-llm"),
		"без хоста":        with("-upstream-url", "https:///v1"),
		"учётные данные в адресе": with("-upstream-url", "https://user:secret@host"),
		"параметры в адресе":      with("-upstream-url", "https://host/?key=1"),
		"тело мало":               with("-max-body-bytes", "10"),
		"тело велико":             with("-max-body-bytes", "999999999"),
		"тело не число":           with("-max-body-bytes", "1MB"),
		"таймаут":                 with("-upstream-connect-timeout", "0s"),
		"таймаут велик":           with("-upstream-header-timeout", "1h"),
		"адрес":                   with("-listen", "8443"),
		"Authorization":           with("-forward-headers", "authorization"),
		"Cookie":                  with("-forward-headers", "Cookie"),
		"X-Forwarded-For":         with("-forward-headers", "x-forwarded-for"),
		"Accept-Encoding":         with("-forward-headers", "accept-encoding"),
		"имя заголовка":           with("-forward-headers", "X Bad"),
		"лишний аргумент":         with("лишнее"),
		"неизвестный флаг":        with("-debug"),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadGateway(args, env(nil), io.Discard); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

func TestHelpDoesNotPrintEnvironment(t *testing.T) {
	var out strings.Builder
	_, err := LoadGateway([]string{"-h"}, env(map[string]string{"AISEC_GATEWAY_UPSTREAM_URL": "https://user:s3cr3t@host"}), &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("ожидался flag.ErrHelp, получено %v", err)
	}
	if strings.Contains(out.String(), "s3cr3t") {
		t.Fatal("справка печатает значение из окружения")
	}
	if !strings.Contains(out.String(), "AISEC_GATEWAY_UPSTREAM_URL") {
		t.Fatal("справка не называет переменные окружения")
	}
}

func TestEnvNames(t *testing.T) {
	if got := envName("upstream-key-file"); got != "AISEC_GATEWAY_UPSTREAM_KEY_FILE" {
		t.Fatal(got)
	}
}

func TestErrorDoesNotLeakUpstreamSecret(t *testing.T) {
	_, err := LoadGateway(append(append([]string{}, required...), "-upstream-url", "https://user:s3cr3t@host"), env(nil), io.Discard)
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("ошибка раскрывает секрет из адреса: %v", err)
	}
}

func TestParseHeaderListLimit(t *testing.T) {
	many := make([]string, maxForwardHeaders+1)
	for i := range many {
		many[i] = "X-H" + strings.Repeat("a", i+1)
	}
	if _, err := parseHeaderList(strings.Join(many, ",")); err == nil {
		t.Fatal("ожидалась ошибка числа заголовков")
	}
	if _, err := parseHeaderList(strings.Repeat("a", 65)); err == nil {
		t.Fatal("ожидалась ошибка длины имени")
	}
}

func FuzzParseUpstreamURL(f *testing.F) {
	for _, s := range []string{"https://h:1/p/", "http://h", "https://u:p@h", "https://h/?q=1", "::"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseUpstreamURL(s)
		if err != nil {
			return
		}
		if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Hostname() == "" {
			t.Fatalf("принят недопустимый адрес %q", s)
		}
	})
}
