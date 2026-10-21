package main

import (
	"io"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadConfigDefaultsAndEnv(t *testing.T) {
	e := env(map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_DATABASE_URL": "postgres://u@h/d"})
	cfg, err := loadConfig(nil, e, io.Discard)
	if err != nil || cfg.Listen != defaultListen || cfg.TLSCertFile != "c" || cfg.DatabaseURL == "" {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = loadConfig([]string{"-listen", "0.0.0.0:9000", "-tls-cert", "c2"}, e, io.Discard)
	if err != nil || cfg.Listen != "0.0.0.0:9000" || cfg.TLSCertFile != "c2" {
		t.Fatalf("флаг важнее окружения: %+v %v", cfg, err)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	full := map[string]string{"AISEC_SERVER_TLS_CERT": "c", "AISEC_SERVER_TLS_KEY": "k", "AISEC_DATABASE_URL": "postgres://u@h/d"}
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
		"нет сертификата":  {nil, without("AISEC_SERVER_TLS_CERT")},
		"нет ключа":        {nil, without("AISEC_SERVER_TLS_KEY")},
		"нет БД":           {nil, without("AISEC_DATABASE_URL")},
		"плохой адрес":     {[]string{"-listen", "8444"}, full},
		"лишний аргумент":  {[]string{"x"}, full},
		"неизвестный флаг": {[]string{"-database-url", "postgres://u:p@h/d"}, full},
	} {
		if _, err := loadConfig(tc.args, env(tc.env), io.Discard); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}
