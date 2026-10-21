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

func TestLoadGatewayIntegrity(t *testing.T) {
	cfg, err := LoadGateway(required, env(nil), io.Discard)
	if err != nil || cfg.Manifest != "" || cfg.IntegrityAction != IntegrityAlert || cfg.IntegrityInterval != DefaultIntegrityInterval {
		t.Fatalf("по умолчанию: %+v %v", cfg, err)
	}
	e := env(map[string]string{"AISEC_GATEWAY_MANIFEST": "/opt/aisec/aisec-manifest.json",
		"AISEC_GATEWAY_INTEGRITY_ACTION": "stop", "AISEC_GATEWAY_INTEGRITY_INTERVAL": "10m"})
	cfg, err = LoadGateway(required, e, io.Discard)
	if err != nil || cfg.Manifest != "/opt/aisec/aisec-manifest.json" || cfg.IntegrityAction != IntegrityStop || cfg.IntegrityInterval.Minutes() != 10 {
		t.Fatalf("из окружения: %+v %v", cfg, err)
	}
	for _, extra := range [][]string{{"-integrity-action", "ignore"}, {"-integrity-interval", "59s"}, {"-integrity-interval", "-1h"}} {
		if _, err := LoadGateway(append(append([]string{}, required...), extra...), env(nil), io.Discard); err == nil {
			t.Errorf("%v: принято", extra)
		}
	}
}

func TestLoadGatewaySelftest(t *testing.T) {
	cfg, err := LoadGateway(required, env(nil), io.Discard)
	if err != nil || cfg.SelftestAction != IntegrityAlert {
		t.Fatalf("по умолчанию: %+v %v", cfg, err)
	}
	cfg, err = LoadGateway(required, env(map[string]string{"AISEC_GATEWAY_SELFTEST_ACTION": "stop"}), io.Discard)
	if err != nil || cfg.SelftestAction != IntegrityStop {
		t.Fatalf("из окружения: %+v %v", cfg, err)
	}
	if _, err := LoadGateway(append(append([]string{}, required...), "-selftest-action", "off"), env(nil), io.Discard); err == nil {
		t.Error("неизвестная реакция принята")
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

func TestLoadGatewayServer(t *testing.T) {
	tls := []string{"-tls-cert", "c.pem", "-tls-key", "k.pem"}
	with := func(extra ...string) []string { return append(append([]string{}, tls...), extra...) }
	srv := []string{"-server", "https://server.example:8445", "-server-ca", "ca.crt", "-client-cert", "gw.crt", "-client-key", "gw.key",
		"-bundle-pub", "bundle-signing.pub", "-state-dir", "state"}
	cfg, err := LoadGateway(with(srv...), env(nil), io.Discard)
	if err != nil || cfg.Server == nil || cfg.Server.Host != "server.example:8445" || cfg.ClientKeyFile != "gw.key" ||
		cfg.StateDir != "state" || len(cfg.BundlePubFiles) != 1 || cfg.ConfigFile != "" {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = LoadGateway(with(append(srv, "-bundle-pub", "old.pub,new.pub", "-user-hmac-key", "user.key")...), env(nil), io.Discard)
	if err != nil || len(cfg.BundlePubFiles) != 2 || cfg.BundlePubFiles[1] != "new.pub" || cfg.UserHMACKeyFile != "user.key" {
		t.Fatalf("ротация ключа: %+v %v", cfg, err)
	}
	cfg, err = LoadGateway(tls, env(map[string]string{
		"AISEC_GATEWAY_SERVER": "https://s:8445", "AISEC_GATEWAY_SERVER_CA": "ca", "AISEC_GATEWAY_CLIENT_CERT": "c", "AISEC_GATEWAY_CLIENT_KEY": "k",
		"AISEC_GATEWAY_BUNDLE_PUB": "b.pub", "AISEC_GATEWAY_STATE_DIR": "st",
	}), io.Discard)
	if err != nil || cfg.Server == nil || cfg.ServerCAFile != "ca" || cfg.StateDir != "st" {
		t.Fatalf("из окружения: %+v %v", cfg, err)
	}
	if cfg, err := LoadGateway(required, env(nil), io.Discard); err != nil || cfg.Server != nil {
		t.Fatalf("без сервера: %+v %v", cfg, err)
	}
	base := func(drop string, extra ...string) []string {
		var out []string
		for i := 0; i < len(srv); i += 2 {
			if srv[i] != drop {
				out = append(out, srv[i], srv[i+1])
			}
		}
		return with(append(out, extra...)...)
	}
	for name, args := range map[string][]string{
		"без корня":                    base("-server-ca"),
		"без сертификата":              base("-client-cert"),
		"без ключа":                    base("-client-key"),
		"без ключа пакетов":            base("-bundle-pub"),
		"без каталога":                 base("-state-dir"),
		"с файлом":                     base("", "-config", "gateway.yaml"),
		"три ключа пакетов":            base("", "-bundle-pub", "a,b,c"),
		"пустой ключ пакетов":          base("", "-bundle-pub", "a,"),
		"http":                         base("", "-server", "http://s:8445"),
		"путь":                         base("", "-server", "https://s:8445/api"),
		"учётные данные":               base("", "-server", "https://u:p@s:8445"),
		"без сервера и файла":          tls,
		"ключ пакетов без сервера":     append(append([]string{}, required...), "-bundle-pub", "b.pub"),
		"каталог без сервера":          append(append([]string{}, required...), "-state-dir", "st"),
		"ключ псевдонимов без сервера": append(append([]string{}, required...), "-user-hmac-key", "u.key"),
	} {
		if _, err := LoadGateway(args, env(nil), io.Discard); err == nil {
			t.Errorf("%s: принято", name)
		} else if strings.Contains(err.Error(), "u:p") {
			t.Errorf("%s: учётные данные в тексте ошибки", name)
		}
	}
}

func FuzzParseServerURL(f *testing.F) {
	for _, s := range []string{"https://h:8445", "https://h:8445/", "http://h", "https://u:p@h", "https://h/p", "https://h?q", "::", "https:opaque"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseServerURL(s)
		if err != nil {
			return
		}
		if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Hostname() == "" {
			t.Fatalf("принят недопустимый адрес %q", s)
		}
	})
}
