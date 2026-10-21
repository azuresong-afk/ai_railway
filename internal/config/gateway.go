package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Gateway — параметры запуска шлюза. Значения берутся из флагов, затем из
// переменных окружения AISEC_GATEWAY_*, затем из значений по умолчанию.
// Приложения, ключи, провайдеры и приёмник событий — в файле конфигурации
// (-config, gwfile.go).
type Gateway struct {
	// ConfigFile — файл конфигурации шлюза.
	ConfigFile   string
	Listen       string
	TLSCertFile  string
	TLSKeyFile   string
	MaxBodyBytes int64
	// Manifest — манифест целостности (ОЦЛ.1); пусто — aisec-manifest.json
	// в корне установки, над каталогом bin/ с исполняемым файлом.
	Manifest string
	// IntegrityAction — реакция на нарушение целостности: alert или stop.
	IntegrityAction string
	// IntegrityInterval — период проверки целостности (ОЦЛ.2).
	IntegrityInterval time.Duration
	// SelftestAction — реакция на провал самотеста детекторов (ОЦЛ.5):
	// alert или stop; провал криптопрофиля останавливает запуск всегда.
	SelftestAction string
	// Server — адрес внутреннего API сервера управления (mTLS, ИАФ.10);
	// пусто — режим «без сервера» (только файл конфигурации).
	Server *url.URL
	// ServerCAFile — корень, которому шлюз доверяет при обращении к серверу.
	ServerCAFile string
	// ClientCertFile и ClientKeyFile — сертификат шлюза от внутреннего УЦ
	// (aisec-gateway register) и его закрытый ключ (0600).
	ClientCertFile string
	ClientKeyFile  string
}

// Границы и значения по умолчанию.
const (
	DefaultGatewayListen  = "127.0.0.1:8443"
	DefaultMaxBodyBytes   = 1 << 20
	MinBodyBytes          = 1 << 10
	MaxBodyBytesLimit     = 32 << 20
	DefaultConnectTimeout = 10 * time.Second
	DefaultHeaderTimeout  = 60 * time.Second
	MaxUpstreamTimeout    = 10 * time.Minute
	envPrefix             = "AISEC_GATEWAY_"
	// Контроль целостности: значения совпадают с internal/integrity
	// (DefaultInterval, MinInterval, ActionAlert, ActionStop); пакет config
	// не зависит от integrity, сверка — в тесте.
	DefaultIntegrityInterval = time.Hour
	MinIntegrityInterval     = time.Minute
	IntegrityAlert           = "alert"
	IntegrityStop            = "stop"
)

// LoadGateway разбирает аргументы командной строки и окружение. getenv
// передаётся явно, чтобы конфигурацию можно было проверить в тестах.
func LoadGateway(args []string, getenv func(string) string, errOut io.Writer) (*Gateway, error) {
	fs := flag.NewFlagSet("aisec-gateway", flag.ContinueOnError)
	fs.SetOutput(errOut)
	// Значения окружения применяются после разбора флагов, а не через
	// значения по умолчанию: справка (-h) не должна печатать то, что задано
	// в окружении.
	configFile := fs.String("config", "", "файл конфигурации шлюза: приложения, ключи, провайдеры, события (AISEC_GATEWAY_CONFIG)")
	listen := fs.String("listen", DefaultGatewayListen, "адрес и порт шлюза (AISEC_GATEWAY_LISTEN)")
	cert := fs.String("tls-cert", "", "сертификат TLS шлюза, PEM (AISEC_GATEWAY_TLS_CERT)")
	key := fs.String("tls-key", "", "закрытый ключ TLS шлюза, PEM, права 0600 (AISEC_GATEWAY_TLS_KEY)")
	maxBody := fs.String("max-body-bytes", strconv.Itoa(DefaultMaxBodyBytes), "предел размера тела запроса, байт (AISEC_GATEWAY_MAX_BODY_BYTES)")
	manifest := fs.String("manifest", "", "манифест целостности; по умолчанию ../aisec-manifest.json от каталога бинарника (AISEC_GATEWAY_MANIFEST)")
	action := fs.String("integrity-action", IntegrityAlert, "реакция на нарушение целостности: alert или stop (AISEC_GATEWAY_INTEGRITY_ACTION)")
	interval := fs.String("integrity-interval", DefaultIntegrityInterval.String(), "период проверки целостности, не меньше 1m (AISEC_GATEWAY_INTEGRITY_INTERVAL)")
	selftestAction := fs.String("selftest-action", IntegrityAlert, "реакция на провал самотеста детекторов: alert или stop; сбой криптопрофиля всегда останавливает (AISEC_GATEWAY_SELFTEST_ACTION)")
	server := fs.String("server", "", "адрес внутреннего API сервера управления, https://хост:8445; пусто — без сервера (AISEC_GATEWAY_SERVER)")
	serverCA := fs.String("server-ca", "", "корневой сертификат для проверки сервера, PEM (AISEC_GATEWAY_SERVER_CA)")
	clientCert := fs.String("client-cert", "", "сертификат шлюза от внутреннего УЦ, PEM (AISEC_GATEWAY_CLIENT_CERT)")
	clientKey := fs.String("client-key", "", "закрытый ключ сертификата шлюза, права 0600 (AISEC_GATEWAY_CLIENT_KEY)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, dst := range map[string]*string{
		"config": configFile, "listen": listen, "tls-cert": cert, "tls-key": key, "max-body-bytes": maxBody,
		"manifest": manifest, "integrity-action": action, "integrity-interval": interval, "selftest-action": selftestAction,
		"server": server, "server-ca": serverCA, "client-cert": clientCert, "client-key": clientKey,
	} {
		if set[name] {
			continue // флаг важнее окружения
		}
		if v := getenv(envName(name)); v != "" {
			*dst = v
		}
	}

	cfg := &Gateway{ConfigFile: *configFile, Listen: *listen, TLSCertFile: *cert, TLSKeyFile: *key,
		Manifest: *manifest, IntegrityAction: *action, SelftestAction: *selftestAction,
		ServerCAFile: *serverCA, ClientCertFile: *clientCert, ClientKeyFile: *clientKey}
	var errs []error
	if cfg.IntegrityAction != IntegrityAlert && cfg.IntegrityAction != IntegrityStop {
		errs = append(errs, fmt.Errorf("integrity-action: ожидается %s или %s", IntegrityAlert, IntegrityStop))
	}
	if cfg.SelftestAction != IntegrityAlert && cfg.SelftestAction != IntegrityStop {
		errs = append(errs, fmt.Errorf("selftest-action: ожидается %s или %s", IntegrityAlert, IntegrityStop))
	}
	iv, err := time.ParseDuration(*interval)
	if err != nil || iv < MinIntegrityInterval {
		errs = append(errs, fmt.Errorf("integrity-interval: длительность не меньше %s, например 1h", MinIntegrityInterval))
	}
	cfg.IntegrityInterval = iv
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		errs = append(errs, errors.New("listen: ожидается адрес:порт"))
	}
	for name, v := range map[string]string{"config": cfg.ConfigFile, "tls-cert": cfg.TLSCertFile, "tls-key": cfg.TLSKeyFile} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s: обязательный параметр", name))
		}
	}
	n, err := strconv.ParseInt(*maxBody, 10, 64)
	if err != nil || n < MinBodyBytes || n > MaxBodyBytesLimit {
		errs = append(errs, fmt.Errorf("max-body-bytes: число от %d до %d", MinBodyBytes, MaxBodyBytesLimit))
	}
	cfg.MaxBodyBytes = n
	if *server != "" {
		if cfg.Server, err = ParseServerURL(*server); err != nil {
			errs = append(errs, err)
		}
		for name, v := range map[string]string{"server-ca": cfg.ServerCAFile, "client-cert": cfg.ClientCertFile, "client-key": cfg.ClientKeyFile} {
			if v == "" {
				errs = append(errs, fmt.Errorf("%s: обязателен вместе с server", name))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("конфигурация шлюза: %w", err)
	}
	return cfg, nil
}

// envName — имя переменной окружения для флага: max-body-bytes → AISEC_GATEWAY_MAX_BODY_BYTES.
func envName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// ParseServerURL проверяет адрес сервера управления для шлюза: только https,
// хост, без учётных данных, пути, параметров и фрагмента.
func ParseServerURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return nil, errors.New("server: не разобран адрес")
	case u.Scheme != "https":
		return nil, errors.New("server: только https")
	case u.Host == "" || u.Hostname() == "":
		return nil, errors.New("server: не указан хост")
	case u.User != nil:
		return nil, errors.New("server: учётные данные в адресе запрещены")
	case (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return nil, errors.New("server: только схема, хост и порт, без пути и параметров")
	}
	u.Path = ""
	return u, nil
}

// ParseUpstreamURL проверяет базовый адрес провайдера: только https, без
// учётных данных, запроса и фрагмента. Адрес включает версию API
// (https://llm.example/v1); путь метода (/chat/completions) добавляет адаптер.
func ParseUpstreamURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("base_url: не разобран адрес")
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("base_url: только https")
	case u.Host == "" || u.Hostname() == "":
		return nil, errors.New("base_url: не указан хост")
	case u.User != nil:
		// Учётные данные в адресе попали бы в логи; ключ задаётся файлом.
		return nil, errors.New("base_url: учётные данные в адресе запрещены, используйте key_file")
	case u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("base_url: адрес без параметров запроса и фрагмента")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}
