package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// Значения по умолчанию.
const defaultListen = "127.0.0.1:8444"

// serverConfig — параметры запуска сервера управления.
type serverConfig struct {
	Listen      string
	TLSCertFile string
	TLSKeyFile  string
	// AuditSigningPub — открытый ключ подписи контрольных точек архивации
	// аудита (audit-signing.pub, ADR-0008); пусто — подписи точек не
	// проверяются, только их связность.
	AuditSigningPub string
	// KeysDir — каталог ключей aisec-cli init (master.key, ADR-0007): мастер-ключ
	// расшифровывает ключ данных для секретов в БД (TOTP, ИАФ.5).
	KeysDir string
	// Manifest — манифест целостности (ОЦЛ.1); пусто — aisec-manifest.json
	// в корне установки, над каталогом bin/ с исполняемым файлом.
	Manifest string
	// IntegrityAction — реакция на нарушение целостности: alert или stop.
	IntegrityAction integrity.Action
	// IntegrityInterval — период проверки целостности (ОЦЛ.2).
	IntegrityInterval time.Duration
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
	auditPub := fs.String("audit-signing-pub", "", "открытый ключ проверки контрольных точек аудита audit-signing.pub (AISEC_SERVER_AUDIT_SIGNING_PUB)")
	keysDir := fs.String("keys-dir", "", "каталог ключей aisec-cli init с master.key, права 0700 (AISEC_SERVER_KEYS_DIR)")
	manifest := fs.String("manifest", "", "манифест целостности; по умолчанию ../aisec-manifest.json от каталога бинарника (AISEC_SERVER_MANIFEST)")
	action := fs.String("integrity-action", string(integrity.ActionAlert), "реакция на нарушение целостности: alert или stop (AISEC_SERVER_INTEGRITY_ACTION)")
	interval := fs.String("integrity-interval", integrity.DefaultInterval.String(), "период проверки целостности, не меньше 1m (AISEC_SERVER_INTEGRITY_INTERVAL)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, dst := range map[string]*string{"listen": listen, "tls-cert": cert, "tls-key": key, "audit-signing-pub": auditPub, "keys-dir": keysDir,
		"manifest": manifest, "integrity-action": action, "integrity-interval": interval} {
		if set[name] {
			continue
		}
		if v := getenv("AISEC_SERVER_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); v != "" {
			*dst = v
		}
	}
	cfg := &serverConfig{Listen: *listen, TLSCertFile: *cert, TLSKeyFile: *key, AuditSigningPub: *auditPub, KeysDir: *keysDir, Manifest: *manifest, DatabaseURL: getenv("AISEC_DATABASE_URL")}
	var errs []error
	var err error
	if cfg.IntegrityAction, err = integrity.ParseAction(*action); err != nil {
		errs = append(errs, fmt.Errorf("integrity-action: %w", err))
	}
	if cfg.IntegrityInterval, err = time.ParseDuration(*interval); err != nil || cfg.IntegrityInterval < integrity.MinInterval {
		errs = append(errs, fmt.Errorf("integrity-interval: длительность не меньше %s, например 1h", integrity.MinInterval))
	}
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		errs = append(errs, errors.New("listen: ожидается адрес:порт"))
	}
	if cfg.TLSCertFile == "" {
		errs = append(errs, errors.New("tls-cert: обязательный параметр"))
	}
	if cfg.TLSKeyFile == "" {
		errs = append(errs, errors.New("tls-key: обязательный параметр"))
	}
	if cfg.KeysDir == "" {
		errs = append(errs, errors.New("keys-dir: обязательный параметр (каталог ключей aisec-cli init)"))
	}
	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("AISEC_DATABASE_URL: обязательная переменная (postgres://пользователь@хост:порт/база)"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("конфигурация сервера: %w", err)
	}
	return cfg, nil
}
