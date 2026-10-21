package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
)

// Значения по умолчанию.
const (
	defaultListen         = "127.0.0.1:8444"
	defaultInternalListen = "127.0.0.1:8445"
)

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
	// CACert и CAKey — внутренний УЦ (ca.crt, ca.key из aisec-cli init,
	// Р8): им проверяются клиентские сертификаты шлюзов и выпускаются
	// сертификаты при регистрации. Пусто — внутренний порт не открывается.
	CACert string
	CAKey  string
	// InternalListen — порт внутреннего API шлюзов (mTLS, ИАФ.10).
	InternalListen string
	// InternalTLSCertFile и InternalTLSKeyFile — сертификат внутреннего
	// порта; пусто — тот же, что у консоли.
	InternalTLSCertFile string
	InternalTLSKeyFile  string
	// Timezone — часовой пояс для показа времени в консоли (ВРМ.2); хранение
	// всегда в UTC.
	Timezone *time.Location
	// AuditStorageLimit — предел размера журнала аудита в байтах, при котором
	// заполнение равно 100% (РСБ.5); AuditStorageWarnPercent — порог
	// предупреждения.
	AuditStorageLimit       int64
	AuditStorageWarnPercent int
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
	caCert := fs.String("ca-cert", "", "сертификат внутреннего УЦ ca.crt для mTLS шлюзов; без него внутренний порт закрыт (AISEC_SERVER_CA_CERT)")
	caKey := fs.String("ca-key", "", "закрытый ключ внутреннего УЦ ca.key, права 0400 или 0600 (AISEC_SERVER_CA_KEY)")
	internalListen := fs.String("internal-listen", defaultInternalListen, "адрес и порт внутреннего API шлюзов, mTLS (AISEC_SERVER_INTERNAL_LISTEN)")
	internalCert := fs.String("internal-tls-cert", "", "сертификат TLS внутреннего порта; по умолчанию — tls-cert (AISEC_SERVER_INTERNAL_TLS_CERT)")
	internalKey := fs.String("internal-tls-key", "", "закрытый ключ TLS внутреннего порта; по умолчанию — tls-key (AISEC_SERVER_INTERNAL_TLS_KEY)")
	tz := fs.String("timezone", "UTC", "часовой пояс для показа времени, имя IANA, например Europe/Moscow (AISEC_SERVER_TIMEZONE)")
	storageLimit := fs.String("audit-storage-limit", strconv.FormatInt(sysstatus.DefaultStorageLimit, 10), "предел размера журнала аудита в байтах для расчёта заполнения (AISEC_SERVER_AUDIT_STORAGE_LIMIT)")
	storageWarn := fs.String("audit-storage-warn-percent", strconv.Itoa(sysstatus.DefaultWarnPercent), "порог предупреждения о заполнении журнала аудита, 1–100 процентов (AISEC_SERVER_AUDIT_STORAGE_WARN_PERCENT)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, dst := range map[string]*string{"listen": listen, "tls-cert": cert, "tls-key": key, "audit-signing-pub": auditPub, "keys-dir": keysDir,
		"manifest": manifest, "integrity-action": action, "integrity-interval": interval,
		"ca-cert": caCert, "ca-key": caKey, "internal-listen": internalListen, "internal-tls-cert": internalCert, "internal-tls-key": internalKey,
		"timezone": tz, "audit-storage-limit": storageLimit, "audit-storage-warn-percent": storageWarn} {
		if set[name] {
			continue
		}
		if v := getenv("AISEC_SERVER_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); v != "" {
			*dst = v
		}
	}
	cfg := &serverConfig{Listen: *listen, TLSCertFile: *cert, TLSKeyFile: *key, AuditSigningPub: *auditPub, KeysDir: *keysDir,
		Manifest: *manifest, CACert: *caCert, CAKey: *caKey, InternalListen: *internalListen,
		InternalTLSCertFile: *internalCert, InternalTLSKeyFile: *internalKey, DatabaseURL: getenv("AISEC_DATABASE_URL")}
	var errs []error
	var err error
	if cfg.Timezone, err = time.LoadLocation(*tz); err != nil || *tz == "" || *tz == "Local" {
		errs = append(errs, errors.New("timezone: имя часового пояса IANA, например UTC или Europe/Moscow"))
	}
	if cfg.AuditStorageLimit, err = strconv.ParseInt(*storageLimit, 10, 64); err != nil || cfg.AuditStorageLimit < 1<<20 {
		errs = append(errs, errors.New("audit-storage-limit: целое число байт, не меньше 1 МиБ"))
	}
	if cfg.AuditStorageWarnPercent, err = strconv.Atoi(*storageWarn); err != nil || cfg.AuditStorageWarnPercent < 1 || cfg.AuditStorageWarnPercent > 100 {
		errs = append(errs, errors.New("audit-storage-warn-percent: целое число от 1 до 100"))
	}
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
	if (cfg.CACert == "") != (cfg.CAKey == "") {
		errs = append(errs, errors.New("ca-cert и ca-key задаются вместе"))
	}
	if (cfg.InternalTLSCertFile == "") != (cfg.InternalTLSKeyFile == "") {
		errs = append(errs, errors.New("internal-tls-cert и internal-tls-key задаются вместе"))
	}
	if _, _, err := net.SplitHostPort(cfg.InternalListen); err != nil {
		errs = append(errs, errors.New("internal-listen: ожидается адрес:порт"))
	} else if cfg.InternalListen == cfg.Listen {
		errs = append(errs, errors.New("internal-listen: внутренний API — на отдельном порту, не на порту консоли"))
	}
	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("AISEC_DATABASE_URL: обязательная переменная (postgres://пользователь@хост:порт/база)"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("конфигурация сервера: %w", err)
	}
	return cfg, nil
}
