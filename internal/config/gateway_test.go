package config

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var required = []string{"-config", "gateway.yaml", "-tls-cert", "c.pem", "-tls-key", "k.pem"}

func TestLoadGatewayDefaults(t *testing.T) {
	cfg, err := LoadGateway(required, env(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultGatewayListen || cfg.MaxBodyBytes != DefaultMaxBodyBytes || cfg.ConfigFile != "gateway.yaml" || cfg.TLSKeyFile != "k.pem" {
		t.Fatalf("значения по умолчанию: %+v", cfg)
	}
}

func TestLoadGatewayEnvAndFlagPrecedence(t *testing.T) {
	e := env(map[string]string{
		"AISEC_GATEWAY_CONFIG":         "env-gateway.yaml",
		"AISEC_GATEWAY_TLS_CERT":       "env-c.pem",
		"AISEC_GATEWAY_TLS_KEY":        "env-k.pem",
		"AISEC_GATEWAY_MAX_BODY_BYTES": "2048",
		"AISEC_GATEWAY_LISTEN":         "0.0.0.0:9000",
	})
	cfg, err := LoadGateway([]string{"-listen", "127.0.0.1:1"}, e, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:1" {
		t.Errorf("флаг должен быть важнее окружения: %s", cfg.Listen)
	}
	if cfg.ConfigFile != "env-gateway.yaml" || cfg.TLSCertFile != "env-c.pem" || cfg.MaxBodyBytes != 2048 {
		t.Errorf("значения из окружения: %+v", cfg)
	}
}

func TestLoadGatewayErrors(t *testing.T) {
	with := func(extra ...string) []string { return append(append([]string{}, required...), extra...) }
	cases := map[string][]string{
		"нет обязательных": {},
		"нет config":       required[2:],
		"тело мало":        with("-max-body-bytes", "10"),
		"тело велико":      with("-max-body-bytes", "999999999"),
		"тело не число":    with("-max-body-bytes", "1MB"),
		"адрес":            with("-listen", "8443"),
		"лишний аргумент":  with("лишнее"),
		"неизвестный флаг": with("-debug"),
		// Провайдер задаётся только в файле конфигурации.
		"флаг upstream этапа 0": with("-upstream-url", "https://h"),
		"флаг forward-headers":  with("-forward-headers", "X-A"),
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
	_, err := LoadGateway([]string{"-h"}, env(map[string]string{"AISEC_GATEWAY_CONFIG": "/secret/path-from-env.yaml"}), &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("ожидался flag.ErrHelp, получено %v", err)
	}
	if strings.Contains(out.String(), "path-from-env") {
		t.Fatal("справка печатает значение из окружения")
	}
	if !strings.Contains(out.String(), "AISEC_GATEWAY_CONFIG") {
		t.Fatal("справка не называет переменные окружения")
	}
}

func TestEnvNames(t *testing.T) {
	if got := envName("max-body-bytes"); got != "AISEC_GATEWAY_MAX_BODY_BYTES" {
		t.Fatal(got)
	}
}

func TestUpstreamURLErrorDoesNotLeakSecret(t *testing.T) {
	_, err := ParseUpstreamURL("https://user:s3cr3t@host")
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("ошибка раскрывает секрет из адреса: %v", err)
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
