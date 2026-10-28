package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
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
	// аудита (audit-signing.pub, ADR-0008). Пусто допустимо только пока в
	// журнале нет контрольных точек: иначе сервер не запускается.
	AuditSigningPub string
	// AuditVerifyInterval — период фоновой проверки цепочки журнала аудита
	// (РСБ.4, DM-43); первая проверка — при запуске.
	AuditVerifyInterval time.Duration
	// TrustedProxies — сети обратных прокси (TLS-шлюз ГОСТ и т. п., ТЗ 10.3),
	// от которых принимается X-Forwarded-For; пусто — заголовку не доверяем.
	TrustedProxies []netip.Prefix
	// NotifyAllowedNetworks — сети, в которые разрешена доставка
	// уведомлений, хотя по умолчанию они запрещены: loopback, link-local и
	// т. п. (3Н31 ревью 3.r2); пусто — только умолчания.
	NotifyAllowedNetworks []netip.Prefix
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
	// AuditStorageLimit — предел размера журнала аудита в байтах, при котором
	// заполнение равно 100% (РСБ.5); AuditStorageWarnPercent — порог
	// предупреждения.
	AuditStorageLimit       int64
	AuditStorageWarnPercent int
	// UserHMACKey — ключ псевдонимов пользователей (тот же файл, что
	// -user-hmac-key у шлюзов; ADR-0027, п. 6): им теневой ИИ заменяет
	// логины и адреса из журналов прокси псевдонимами, как в событиях.
	// Пусто — пользователи из журналов не учитываются.
	UserHMACKey string
	// ShadowAISyslog — приём журналов прокси по syslog (теневой ИИ, задача
	// 4.23); Listen пусто — выключен (по умолчанию).
	ShadowAISyslog shadowSyslogConfig
	// DatabaseURL содержит пароль, поэтому берётся только из окружения, не из
	// аргументов командной строки (их видно в списке процессов).
	DatabaseURL string
}

// shadowSyslogConfig — флаги слушателя syslog теневого ИИ.
type shadowSyslogConfig struct {
	Listen string
	// Format — тело сообщений: cef или squid.
	Format string
	// TLSCertFile и TLSKeyFile — свой сертификат слушателя (RFC 5425).
	TLSCertFile string
	TLSKeyFile  string
	// ClientCAFile — корень, которым проверяются клиентские сертификаты
	// источников; пусто — клиентский сертификат не требуется.
	ClientCAFile string
	// Insecure — приём без TLS; только вместе с AllowedNetworks.
	Insecure        bool
	AllowedNetworks []netip.Prefix
	MaxConns        int
	MaxConnsPerIP   int
	LinesPerSecond  int
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
	storageLimit := fs.String("audit-storage-limit", strconv.FormatInt(sysstatus.DefaultStorageLimit, 10), "предел размера журнала аудита в байтах для расчёта заполнения (AISEC_SERVER_AUDIT_STORAGE_LIMIT)")
	storageWarn := fs.String("audit-storage-warn-percent", strconv.Itoa(sysstatus.DefaultWarnPercent), "порог предупреждения о заполнении журнала аудита, 1–100 процентов (AISEC_SERVER_AUDIT_STORAGE_WARN_PERCENT)")
	verifyInterval := fs.String("audit-verify-interval", audit.DefaultVerifyInterval.String(), "период проверки цепочки журнала аудита, не меньше 1m (AISEC_SERVER_AUDIT_VERIFY_INTERVAL)")
	proxies := fs.String("trusted-proxies", "", "сети доверенных обратных прокси через запятую, например 10.0.0.5/32; от них принимается X-Forwarded-For (AISEC_SERVER_TRUSTED_PROXIES)")
	notifyNets := fs.String("notify-allowed-networks", "", "сети через запятую, куда разрешены каналы уведомлений, хотя по умолчанию запрещены (loopback, link-local), например 127.0.0.1/32 для локального приёмника syslog (AISEC_SERVER_NOTIFY_ALLOWED_NETWORKS)")
	userKey := fs.String("user-hmac-key", "", "ключ псевдонимов пользователей шлюзов, права 0600; для теневого ИИ, без него пользователи из журналов прокси не учитываются (AISEC_SERVER_USER_HMAC_KEY)")
	syslogListen := fs.String("shadow-ai-syslog-listen", "", "адрес и порт приёма журналов прокси по syslog для теневого ИИ; пусто — выключен (AISEC_SERVER_SHADOW_AI_SYSLOG_LISTEN)")
	syslogFormat := fs.String("shadow-ai-syslog-format", "", "формат сообщений syslog: cef (NGFW, UserGate) или squid (AISEC_SERVER_SHADOW_AI_SYSLOG_FORMAT)")
	syslogCert := fs.String("shadow-ai-syslog-tls-cert", "", "сертификат TLS слушателя syslog, PEM (AISEC_SERVER_SHADOW_AI_SYSLOG_TLS_CERT)")
	syslogKey := fs.String("shadow-ai-syslog-tls-key", "", "закрытый ключ TLS слушателя syslog, PEM, права 0600 (AISEC_SERVER_SHADOW_AI_SYSLOG_TLS_KEY)")
	syslogCA := fs.String("shadow-ai-syslog-client-ca", "", "корневой сертификат для проверки клиентских сертификатов источников syslog; пусто — не требуются (AISEC_SERVER_SHADOW_AI_SYSLOG_CLIENT_CA)")
	syslogInsecure := fs.String("shadow-ai-syslog-insecure", "false", "приём syslog без TLS, только из -shadow-ai-syslog-allowed-networks: true или false (AISEC_SERVER_SHADOW_AI_SYSLOG_INSECURE)")
	syslogNets := fs.String("shadow-ai-syslog-allowed-networks", "", "сети источников syslog через запятую; пусто — любые (только с TLS) (AISEC_SERVER_SHADOW_AI_SYSLOG_ALLOWED_NETWORKS)")
	syslogConns := fs.String("shadow-ai-syslog-max-connections", strconv.Itoa(shadowai.DefaultSyslogMaxConns), "предел соединений syslog всего (AISEC_SERVER_SHADOW_AI_SYSLOG_MAX_CONNECTIONS)")
	syslogPerIP := fs.String("shadow-ai-syslog-max-connections-per-address", strconv.Itoa(shadowai.DefaultSyslogMaxConnsPerIP), "предел соединений syslog с одного адреса (AISEC_SERVER_SHADOW_AI_SYSLOG_MAX_CONNECTIONS_PER_ADDRESS)")
	syslogRate := fs.String("shadow-ai-syslog-lines-per-second", strconv.Itoa(shadowai.DefaultSyslogLinesPerSecond), "предел строк syslog в секунду на все соединения (AISEC_SERVER_SHADOW_AI_SYSLOG_LINES_PER_SECOND)")
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
		"audit-storage-limit": storageLimit, "audit-storage-warn-percent": storageWarn,
		"audit-verify-interval": verifyInterval, "trusted-proxies": proxies, "notify-allowed-networks": notifyNets,
		"user-hmac-key": userKey, "shadow-ai-syslog-listen": syslogListen, "shadow-ai-syslog-format": syslogFormat,
		"shadow-ai-syslog-tls-cert": syslogCert, "shadow-ai-syslog-tls-key": syslogKey, "shadow-ai-syslog-client-ca": syslogCA,
		"shadow-ai-syslog-insecure": syslogInsecure, "shadow-ai-syslog-allowed-networks": syslogNets,
		"shadow-ai-syslog-max-connections": syslogConns, "shadow-ai-syslog-max-connections-per-address": syslogPerIP,
		"shadow-ai-syslog-lines-per-second": syslogRate} {
		if set[name] {
			continue
		}
		if v := getenv("AISEC_SERVER_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); v != "" {
			*dst = v
		}
	}
	cfg := &serverConfig{Listen: *listen, TLSCertFile: *cert, TLSKeyFile: *key, AuditSigningPub: *auditPub, KeysDir: *keysDir,
		Manifest: *manifest, CACert: *caCert, CAKey: *caKey, InternalListen: *internalListen,
		InternalTLSCertFile: *internalCert, InternalTLSKeyFile: *internalKey, UserHMACKey: *userKey, DatabaseURL: getenv("AISEC_DATABASE_URL")}
	var errs []error
	var err error
	if cfg.AuditStorageLimit, err = strconv.ParseInt(*storageLimit, 10, 64); err != nil || cfg.AuditStorageLimit < 1<<20 {
		errs = append(errs, errors.New("audit-storage-limit: целое число байт, не меньше 1 МиБ"))
	}
	if cfg.AuditStorageWarnPercent, err = strconv.Atoi(*storageWarn); err != nil || cfg.AuditStorageWarnPercent < 1 || cfg.AuditStorageWarnPercent > 100 {
		errs = append(errs, errors.New("audit-storage-warn-percent: целое число от 1 до 100"))
	}
	if cfg.AuditVerifyInterval, err = time.ParseDuration(*verifyInterval); err != nil || cfg.AuditVerifyInterval < audit.MinVerifyInterval {
		errs = append(errs, fmt.Errorf("audit-verify-interval: длительность не меньше %s, например 1h", audit.MinVerifyInterval))
	}
	if cfg.TrustedProxies, err = parsePrefixes(*proxies); err != nil {
		errs = append(errs, fmt.Errorf("trusted-proxies: %w", err))
	}
	if cfg.NotifyAllowedNetworks, err = parsePrefixes(*notifyNets); err != nil {
		errs = append(errs, fmt.Errorf("notify-allowed-networks: %w", err))
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
	if cfg.ShadowAISyslog, err = parseShadowSyslog(cfg, shadowSyslogFlags{listen: *syslogListen, format: *syslogFormat,
		cert: *syslogCert, key: *syslogKey, ca: *syslogCA, insecure: *syslogInsecure, nets: *syslogNets, conns: *syslogConns,
		perIP: *syslogPerIP, rate: *syslogRate}); err != nil {
		errs = append(errs, err)
	}
	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("AISEC_DATABASE_URL: обязательная переменная (postgres://пользователь@хост:порт/база)"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("конфигурация сервера: %w", err)
	}
	return cfg, nil
}

// maxTrustedProxies — предел числа сетей в -trusted-proxies.
const maxTrustedProxies = 64

// parsePrefixes разбирает список сетей через запятую; адрес без маски —
// одна машина (/32 или /128).
func parsePrefixes(s string) ([]netip.Prefix, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) > maxTrustedProxies {
		return nil, fmt.Errorf("не больше %d сетей", maxTrustedProxies)
	}
	out := make([]netip.Prefix, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if !strings.Contains(p, "/") {
			a, err := netip.ParseAddr(p)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("%q: ожидается адрес или сеть CIDR", p)
			}
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("%q: ожидается адрес или сеть CIDR", p)
		}
		if pr.Addr().Is4In6() || pr.Addr().Zone() != "" {
			return nil, fmt.Errorf("%q: сеть IPv4 записывается без ::ffff:, без зоны интерфейса", p)
		}
		if pr.Bits() == 0 {
			return nil, fmt.Errorf("%q: сеть /0 — это любой адрес; укажите конкретные сети", p)
		}
		out = append(out, pr.Masked())
	}
	return out, nil
}

// shadowSyslogFlags — строковые значения флагов слушателя syslog.
type shadowSyslogFlags struct {
	listen, format, cert, key, ca, insecure, nets, conns, perIP, rate string
}

// parseShadowSyslog проверяет флаги приёма по syslog (задача 4.23). Без
// адреса слушатель выключен, остальные флаги не действуют. Без TLS — только
// явным флагом и только из разрешённых сетей.
func parseShadowSyslog(cfg *serverConfig, f shadowSyslogFlags) (shadowSyslogConfig, error) {
	c := shadowSyslogConfig{Listen: strings.TrimSpace(f.listen)}
	if c.Listen == "" {
		return c, nil
	}
	var errs []error
	c.Format, c.TLSCertFile, c.TLSKeyFile, c.ClientCAFile = f.format, f.cert, f.key, f.ca
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, errors.New("shadow-ai-syslog-listen: ожидается адрес:порт"))
	} else if c.Listen == cfg.Listen || c.Listen == cfg.InternalListen {
		errs = append(errs, errors.New("shadow-ai-syslog-listen: приём syslog — на отдельном порту, не на порту консоли или шлюзов"))
	}
	if c.Format != shadowai.FormatCEF && c.Format != shadowai.FormatSquid {
		errs = append(errs, errors.New("shadow-ai-syslog-format: cef или squid"))
	}
	var err error
	if c.Insecure, err = strconv.ParseBool(f.insecure); err != nil {
		errs = append(errs, errors.New("shadow-ai-syslog-insecure: true или false"))
	}
	if c.AllowedNetworks, err = parsePrefixes(f.nets); err != nil {
		errs = append(errs, fmt.Errorf("shadow-ai-syslog-allowed-networks: %w", err))
	}
	switch {
	case c.Insecure && (c.TLSCertFile != "" || c.TLSKeyFile != "" || c.ClientCAFile != ""):
		errs = append(errs, errors.New("shadow-ai-syslog-insecure: приём без TLS не сочетается с сертификатами слушателя"))
	case c.Insecure && len(c.AllowedNetworks) == 0:
		errs = append(errs, errors.New("shadow-ai-syslog-insecure: приём без TLS — только из сетей shadow-ai-syslog-allowed-networks"))
	case !c.Insecure && (c.TLSCertFile == "" || c.TLSKeyFile == ""):
		errs = append(errs, errors.New("shadow-ai-syslog-tls-cert и shadow-ai-syslog-tls-key: обязательны (или явный приём без TLS)"))
	}
	for _, v := range []struct {
		name string
		s    string
		dst  *int
	}{{"shadow-ai-syslog-max-connections", f.conns, &c.MaxConns}, {"shadow-ai-syslog-max-connections-per-address", f.perIP, &c.MaxConnsPerIP},
		{"shadow-ai-syslog-lines-per-second", f.rate, &c.LinesPerSecond}} {
		n, err := strconv.Atoi(v.s)
		if err != nil || n < 1 || n > 1_000_000 {
			errs = append(errs, fmt.Errorf("%s: целое число от 1 до 1000000", v.name))
			continue
		}
		*v.dst = n
	}
	return c, errors.Join(errs...)
}
