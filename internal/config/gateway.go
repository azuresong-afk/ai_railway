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
	} {
		if set[name] {
			continue // флаг важнее окружения
		}
		if v := getenv(envName(name)); v != "" {
			*dst = v
		}
	}

	cfg := &Gateway{ConfigFile: *configFile, Listen: *listen, TLSCertFile: *cert, TLSKeyFile: *key}
	var errs []error
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
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("конфигурация шлюза: %w", err)
	}
	return cfg, nil
}

// envName — имя переменной окружения для флага: max-body-bytes → AISEC_GATEWAY_MAX_BODY_BYTES.
func envName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
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
