package main

import (
	"io"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadConfigDefaultsAndEnv(t *testing.T) {
	e := env(map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d"})
	cfg, err := loadConfig(nil, e, io.Discard)
	if err != nil || cfg.Listen != defaultListen || cfg.TLSCertFile != "c" || cfg.KeysDir != "/keys" || cfg.DatabaseURL == "" {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = loadConfig([]string{"-listen", "0.0.0.0:9000", "-tls-cert", "c2"}, e, io.Discard)
	if err != nil || cfg.Listen != "0.0.0.0:9000" || cfg.TLSCertFile != "c2" {
		t.Fatalf("флаг важнее окружения: %+v %v", cfg, err)
	}
	if cfg.AuditSigningPub != "" {
		t.Fatalf("ключ аудита по умолчанию: %q", cfg.AuditSigningPub)
	}
	e = env(map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d",
		"AISEC_SERVER_AUDIT_SIGNING_PUB": "/keys/audit-signing.pub"})
	if cfg, err = loadConfig(nil, e, io.Discard); err != nil || cfg.AuditSigningPub != "/keys/audit-signing.pub" {
		t.Fatalf("ключ аудита из окружения: %+v %v", cfg, err)
	}
	// Ключ псевдонимов для теневого ИИ (ADR-0027, п. 6) — необязательный.
	if cfg.UserHMACKey != "" {
		t.Fatalf("ключ псевдонимов по умолчанию: %q", cfg.UserHMACKey)
	}
	e = env(map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d",
		"AISEC_SERVER_USER_HMAC_KEY": "/keys/user-hmac.key"})
	if cfg, err = loadConfig(nil, e, io.Discard); err != nil || cfg.UserHMACKey != "/keys/user-hmac.key" {
		t.Fatalf("ключ псевдонимов из окружения: %+v %v", cfg, err)
	}
	if cfg, err = loadConfig([]string{"-user-hmac-key", "/k2"}, e, io.Discard); err != nil || cfg.UserHMACKey != "/k2" {
		t.Fatalf("ключ псевдонимов из флага: %+v %v", cfg, err)
	}
	// Правила ML-детекторов в шаблонах (compose.ml.yaml, ADR-0024) — только явно.
	if cfg.MLTemplates {
		t.Fatal("ml-templates по умолчанию включён")
	}
	e = env(map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d",
		"AISEC_SERVER_ML_TEMPLATES": "true"})
	if cfg, err = loadConfig(nil, e, io.Discard); err != nil || !cfg.MLTemplates {
		t.Fatalf("ml-templates из окружения: %+v %v", cfg, err)
	}
	if cfg, err = loadConfig([]string{"-ml-templates", "false"}, e, io.Discard); err != nil || cfg.MLTemplates {
		t.Fatalf("ml-templates: флаг важнее окружения: %+v %v", cfg, err)
	}
}

func TestLoadConfigIntegrity(t *testing.T) {
	base := map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d"}
	cfg, err := loadConfig(nil, env(base), io.Discard)
	if err != nil || cfg.Manifest != "" || cfg.IntegrityAction != integrity.ActionAlert || cfg.IntegrityInterval != time.Hour {
		t.Fatalf("по умолчанию: %+v %v", cfg, err)
	}
	base["AISEC_SERVER_MANIFEST"] = "/opt/aisec/aisec-manifest.json"
	base["AISEC_SERVER_INTEGRITY_ACTION"] = "stop"
	base["AISEC_SERVER_INTEGRITY_INTERVAL"] = "15m"
	cfg, err = loadConfig(nil, env(base), io.Discard)
	if err != nil || cfg.Manifest != "/opt/aisec/aisec-manifest.json" || cfg.IntegrityAction != integrity.ActionStop || cfg.IntegrityInterval != 15*time.Minute {
		t.Fatalf("из окружения: %+v %v", cfg, err)
	}
	cfg, err = loadConfig([]string{"-integrity-action", "alert", "-integrity-interval", "2h"}, env(base), io.Discard)
	if err != nil || cfg.IntegrityAction != integrity.ActionAlert || cfg.IntegrityInterval != 2*time.Hour {
		t.Fatalf("флаг важнее окружения: %+v %v", cfg, err)
	}
	for _, args := range [][]string{
		{"-integrity-action", "ignore"}, {"-integrity-interval", "30s"}, {"-integrity-interval", "час"},
	} {
		if _, err := loadConfig(args, env(base), io.Discard); err == nil {
			t.Errorf("%v: принято", args)
		}
	}
}

func TestLoadConfigRejects(t *testing.T) {
	full := map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d"}
	without := func(k string) map[string]string {
		m := map[string]string{}
		for a, b := range full {
			if a != k {
				m[a] = b
			}
		}
		return m
	}
	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"нет сертификата":                 {nil, without("AISEC_SERVER_TLS_CERT")},
		"нет ключа":                       {nil, without("AISEC_SERVER_TLS_KEY")},
		"нет БД":                          {nil, without("AISEC_DATABASE_URL")},
		"нет ключей":                      {nil, without("AISEC_SERVER_KEYS_DIR")},
		"плохой адрес":                    {[]string{"-listen", "8444"}, full},
		"лишний аргумент":                 {[]string{"x"}, full},
		"неизвестный флаг":                {[]string{"-database-url", "postgres://u:p@h/d"}, full},
		"УЦ без ключа":                    {[]string{"-ca-cert", "ca.crt"}, full},
		"ключ УЦ без сертификата":         {[]string{"-ca-key", "ca.key"}, full},
		"внутренний порт = консоль":       {[]string{"-internal-listen", "127.0.0.1:8444"}, full},
		"плохой внутренний адрес":         {[]string{"-internal-listen", "8445"}, full},
		"внутренний сертификат без ключа": {[]string{"-internal-tls-cert", "i.crt"}, full},
		"ml-templates не true/false":      {[]string{"-ml-templates", "1"}, full},
	} {
		if _, err := loadConfig(tc.args, env(tc.env), io.Discard); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestLoadConfigInternalAPI(t *testing.T) {
	e := env(map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d",
		"AISEC_SERVER_CA_CERT": "/keys/ca.crt", "AISEC_SERVER_CA_KEY": "/keys/ca.key"})
	cfg, err := loadConfig(nil, e, io.Discard)
	if err != nil || cfg.InternalListen != defaultInternalListen || cfg.CACert != "/keys/ca.crt" || cfg.CAKey != "/keys/ca.key" ||
		cfg.InternalTLSCertFile != "" {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = loadConfig([]string{"-internal-listen", "0.0.0.0:9445", "-internal-tls-cert", "i.crt", "-internal-tls-key", "i.key"}, e, io.Discard)
	if err != nil || cfg.InternalListen != "0.0.0.0:9445" || cfg.InternalTLSKeyFile != "i.key" {
		t.Fatalf("%+v %v", cfg, err)
	}
}

// Настройки «Состояния системы» (задача 2.20, РСБ.5): умолчания, окружение,
// флаг важнее окружения, отказ на неверных значениях. Флага -timezone нет:
// часовой пояс — в настройках установки (H-Р10, В26 ревью 2.r5).
func TestLoadConfigStatus(t *testing.T) {
	base := map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d"}
	cfg, err := loadConfig(nil, env(base), io.Discard)
	if err != nil || cfg.AuditStorageLimit != 20<<30 || cfg.AuditStorageWarnPercent != 80 {
		t.Fatalf("умолчания: %+v %v", cfg, err)
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{k: v}
		for a, b := range base {
			m[a] = b
		}
		return m
	}
	cfg, err = loadConfig([]string{"-audit-storage-limit", "1073741824", "-audit-storage-warn-percent", "90"},
		env(with("AISEC_SERVER_AUDIT_STORAGE_WARN_PERCENT", "50")), io.Discard)
	if err != nil || cfg.AuditStorageLimit != 1<<30 || cfg.AuditStorageWarnPercent != 90 {
		t.Fatalf("флаги: %+v %v", cfg, err)
	}
	for name, args := range map[string][]string{
		"флаг часового пояса удалён": {"-timezone", "Europe/Moscow"},
		"предел не число":            {"-audit-storage-limit", "много"},
		"предел мал":                 {"-audit-storage-limit", "1024"},
		"предел отрицателен":         {"-audit-storage-limit", "-1"},
		"порог ноль":                 {"-audit-storage-warn-percent", "0"},
		"порог больше 100":           {"-audit-storage-warn-percent", "101"},
		"порог не число":             {"-audit-storage-warn-percent", "x"},
	} {
		if _, err := loadConfig(args, env(base), io.Discard); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// В1 и В3 ревью 2.r1: период проверки цепочки аудита и доверенные прокси.
func TestLoadConfigAuditVerifyAndProxies(t *testing.T) {
	base := map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d"}
	cfg, err := loadConfig(nil, env(base), io.Discard)
	if err != nil || cfg.AuditVerifyInterval != time.Hour || cfg.TrustedProxies != nil {
		t.Fatalf("по умолчанию: %+v %v", cfg, err)
	}
	base["AISEC_SERVER_AUDIT_VERIFY_INTERVAL"] = "10m"
	base["AISEC_SERVER_TRUSTED_PROXIES"] = "10.0.0.5, 192.0.2.0/24,2001:db8::/48"
	base["AISEC_SERVER_NOTIFY_ALLOWED_NETWORKS"] = "127.0.0.1"
	cfg, err = loadConfig(nil, env(base), io.Discard)
	if err != nil || len(cfg.NotifyAllowedNetworks) != 1 || cfg.NotifyAllowedNetworks[0].String() != "127.0.0.1/32" {
		t.Fatalf("сети уведомлений (3Н31 ревью 3.r2): %+v %v", cfg, err)
	}
	if err != nil || cfg.AuditVerifyInterval != 10*time.Minute || len(cfg.TrustedProxies) != 3 ||
		cfg.TrustedProxies[0].String() != "10.0.0.5/32" || cfg.TrustedProxies[2].String() != "2001:db8::/48" {
		t.Fatalf("из окружения: %+v %v", cfg, err)
	}
	for _, args := range [][]string{
		{"-audit-verify-interval", "30s"}, {"-audit-verify-interval", "час"},
		{"-trusted-proxies", "0.0.0.0/0"}, {"-trusted-proxies", "::/0"}, {"-trusted-proxies", "прокси"},
		{"-trusted-proxies", "10.0.0.1,"}, {"-trusted-proxies", "fe80::1%eth0"}, {"-trusted-proxies", "::ffff:10.0.0.0/104"},
		{"-notify-allowed-networks", "0.0.0.0/0"}, {"-notify-allowed-networks", "сеть"},
	} {
		if _, err := loadConfig(args, env(base), io.Discard); err == nil {
			t.Errorf("%v: принято", args)
		}
	}
}

// Приём syslog теневого ИИ (задача 4.23): по умолчанию выключен; TLS
// обязателен, без него — только явным флагом и из разрешённых сетей;
// отдельный порт; пределы — в разумных границах.
func TestLoadConfigShadowSyslog(t *testing.T) {
	base := map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_SERVER_KEYS_DIR": "/keys", "AISEC_DATABASE_URL": "postgres://u@h/d"}
	cfg, err := loadConfig(nil, env(base), io.Discard)
	if err != nil || cfg.ShadowAISyslog.Listen != "" {
		t.Fatalf("по умолчанию выключен: %+v %v", cfg.ShadowAISyslog, err)
	}
	// Без адреса прочие флаги не действуют и не проверяются.
	if _, err := loadConfig([]string{"-shadow-ai-syslog-format", "xml"}, env(base), io.Discard); err != nil {
		t.Fatalf("формат без адреса: %v", err)
	}
	withTLS := map[string]string{}
	for k, v := range base {
		withTLS[k] = v
	}
	withTLS["AISEC_SERVER_SHADOW_AI_SYSLOG_LISTEN"] = "0.0.0.0:6514"
	withTLS["AISEC_SERVER_SHADOW_AI_SYSLOG_FORMAT"] = "cef"
	withTLS["AISEC_SERVER_SHADOW_AI_SYSLOG_TLS_CERT"] = "/keys/syslog.crt"
	withTLS["AISEC_SERVER_SHADOW_AI_SYSLOG_TLS_KEY"] = "/keys/syslog.key"
	withTLS["AISEC_SERVER_SHADOW_AI_SYSLOG_CLIENT_CA"] = "/keys/sources-ca.crt"
	withTLS["AISEC_SERVER_SHADOW_AI_SYSLOG_ALLOWED_NETWORKS"] = "10.0.0.0/8"
	withTLS["AISEC_SERVER_SHADOW_AI_SYSLOG_MAX_CONNECTIONS"] = "64"
	cfg, err = loadConfig(nil, env(withTLS), io.Discard)
	s := cfg.ShadowAISyslog
	if err != nil || s.Listen != "0.0.0.0:6514" || s.Format != "cef" || s.TLSKeyFile != "/keys/syslog.key" || s.ClientCAFile != "/keys/sources-ca.crt" ||
		s.Insecure || len(s.AllowedNetworks) != 1 || s.MaxConns != 64 || s.MaxConnsPerIP != 16 || s.LinesPerSecond != 5000 {
		t.Fatalf("из окружения: %+v %v", s, err)
	}
	cfg, err = loadConfig([]string{"-shadow-ai-syslog-format", "squid", "-shadow-ai-syslog-lines-per-second", "100"}, env(withTLS), io.Discard)
	if err != nil || cfg.ShadowAISyslog.Format != "squid" || cfg.ShadowAISyslog.LinesPerSecond != 100 {
		t.Fatalf("флаг важнее окружения: %+v %v", cfg.ShadowAISyslog, err)
	}
	insecure := []string{"-shadow-ai-syslog-listen", "127.0.0.1:5514", "-shadow-ai-syslog-format", "squid",
		"-shadow-ai-syslog-insecure", "true", "-shadow-ai-syslog-allowed-networks", "127.0.0.1"}
	cfg, err = loadConfig(insecure, env(base), io.Discard)
	if err != nil || !cfg.ShadowAISyslog.Insecure || cfg.ShadowAISyslog.AllowedNetworks[0].String() != "127.0.0.1/32" {
		t.Fatalf("без TLS из разрешённой сети: %+v %v", cfg.ShadowAISyslog, err)
	}
	listen := []string{"-shadow-ai-syslog-listen", "0.0.0.0:6514", "-shadow-ai-syslog-format", "cef"}
	tls := append(append([]string{}, listen...), "-shadow-ai-syslog-tls-cert", "s.crt", "-shadow-ai-syslog-tls-key", "s.key")
	for name, args := range map[string][]string{
		"нет сертификата":         listen,
		"нет ключа":               append(append([]string{}, listen...), "-shadow-ai-syslog-tls-cert", "s.crt"),
		"нет формата":             {"-shadow-ai-syslog-listen", "0.0.0.0:6514", "-shadow-ai-syslog-tls-cert", "s.crt", "-shadow-ai-syslog-tls-key", "s.key"},
		"чужой формат":            append(append([]string{}, tls...), "-shadow-ai-syslog-format", "json"),
		"адрес без порта":         append(append([]string{}, tls...), "-shadow-ai-syslog-listen", "6514"),
		"порт консоли":            append(append([]string{}, tls...), "-shadow-ai-syslog-listen", defaultListen),
		"порт шлюзов":             append(append([]string{}, tls...), "-shadow-ai-syslog-listen", defaultInternalListen),
		"без TLS без сетей":       append(append([]string{}, listen...), "-shadow-ai-syslog-insecure", "true"),
		"без TLS с сертификатом":  append(append([]string{}, tls...), "-shadow-ai-syslog-insecure", "true", "-shadow-ai-syslog-allowed-networks", "10.0.0.0/8"),
		"insecure не логическое":  append(append([]string{}, tls...), "-shadow-ai-syslog-insecure", "да"),
		"сеть /0":                 append(append([]string{}, tls...), "-shadow-ai-syslog-allowed-networks", "0.0.0.0/0"),
		"соединений ноль":         append(append([]string{}, tls...), "-shadow-ai-syslog-max-connections", "0"),
		"с адреса не число":       append(append([]string{}, tls...), "-shadow-ai-syslog-max-connections-per-address", "x"),
		"строк в секунду слишком": append(append([]string{}, tls...), "-shadow-ai-syslog-lines-per-second", "2000000"),
	} {
		if _, err := loadConfig(args, env(base), io.Discard); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}
