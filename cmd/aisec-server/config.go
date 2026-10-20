package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
)

// Значения по умолчанию.
const defaultListen = "127.0.0.1:8444"

// serverConfig — параметры запуска сервера управления.
type serverConfig struct {
	Listen      string
	TLSCertFile string
	TLSKeyFile  string
	// DatabaseURL содержит пароль, поэтому берётся только из окружения, не из
	// аргументов командной строки (их видно в списке процессов).
	DatabaseURL string
}

// loadConfig разбирает аргументы и окружение. Флаг важнее переменной окружения.
func loadConfig(args []string, getenv func(string) string, errOut io.Writer) (*serverConfig, error) {
	fs := flag.NewFlagSet("aisec-server", flag.ContinueOnError)
	fs.SetOutput(errOut)
	listen := fs.String("listen", defaultListen, "адрес и порт сервера (AISEC_SERVER_LISTEN)")
	cert := fs.String("tls-cert", "", "сертификат TLS сервера, PEM (AISEC_SERVER_TLS_CERT)")
	key := fs.String("tls-key", "", "закрытый ключ TLS сервера, PEM, права 0600 (AISEC_SERVER_TLS_KEY)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, dst := range map[string]*string{"listen": listen, "tls-cert": cert, "tls-key": key} {
		if set[name] {
			continue
		}
		if v := getenv("AISEC_SERVER_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); v != "" {
			*dst = v
		}
	}
	cfg := &serverConfig{Listen: *listen, TLSCertFile: *cert, TLSKeyFile: *key, DatabaseURL: getenv("AISEC_DATABASE_URL")}
	var errs []error
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		errs = append(errs, errors.New("listen: ожидается адрес:порт"))
	}
	if cfg.TLSCertFile == "" {
		errs = append(errs, errors.New("tls-cert: обязательный параметр"))
	}
	if cfg.TLSKeyFile == "" {
		errs = append(errs, errors.New("tls-key: обязательный параметр"))
	}
	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("AISEC_DATABASE_URL: обязательная переменная (postgres://пользователь@хост:порт/база)"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("конфигурация сервера: %w", err)
	}
	return cfg, nil
}
