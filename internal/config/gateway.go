package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Gateway — конфигурация шлюза этапа 0: прозрачный прокси на один upstream.
// Значения берутся из флагов, затем из переменных окружения AISEC_GATEWAY_*,
// затем из значений по умолчанию.
type Gateway struct {
	Listen         string
	TLSCertFile    string
	TLSKeyFile     string
	UpstreamURL    *url.URL
	UpstreamCAFile string
	// UpstreamKeyFile — файл с ключом API провайдера (права 0600). Шлюз
	// подставляет его сам; клиентский Authorization к провайдеру не уходит.
	UpstreamKeyFile        string
	MaxBodyBytes           int64
	UpstreamConnectTimeout time.Duration
	UpstreamHeaderTimeout  time.Duration
	// ForwardHeaders — дополнительные заголовки запроса, которые можно
	// передать провайдеру (сверх встроенного allowlist).
	ForwardHeaders []string
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
	maxForwardHeaders     = 16
	envPrefix             = "AISEC_GATEWAY_"
)

// LoadGateway разбирает аргументы командной строки и окружение. getenv
// передаётся явно, чтобы конфигурацию можно было проверить в тестах.
func LoadGateway(args []string, getenv func(string) string, errOut io.Writer) (*Gateway, error) {
	fs := flag.NewFlagSet("aisec-gateway", flag.ContinueOnError)
	fs.SetOutput(errOut)
	// Значения окружения применяются после разбора флагов, а не через
	// значения по умолчанию: справка (-h) не должна печатать то, что задано
	// в окружении, — там может оказаться, например, адрес с учётными данными.
	listen := fs.String("listen", DefaultGatewayListen, "адрес и порт шлюза (AISEC_GATEWAY_LISTEN)")
	cert := fs.String("tls-cert", "", "сертификат TLS шлюза, PEM (AISEC_GATEWAY_TLS_CERT)")
	key := fs.String("tls-key", "", "закрытый ключ TLS шлюза, PEM, права 0600 (AISEC_GATEWAY_TLS_KEY)")
	upstream := fs.String("upstream-url", "", "базовый адрес провайдера https://хост[:порт] (AISEC_GATEWAY_UPSTREAM_URL)")
	upstreamCA := fs.String("upstream-ca", "", "корневые сертификаты провайдера, PEM (AISEC_GATEWAY_UPSTREAM_CA)")
	upstreamKey := fs.String("upstream-key-file", "", "файл с ключом API провайдера, права 0600 (AISEC_GATEWAY_UPSTREAM_KEY_FILE)")
	maxBody := fs.String("max-body-bytes", strconv.Itoa(DefaultMaxBodyBytes), "предел размера тела запроса, байт (AISEC_GATEWAY_MAX_BODY_BYTES)")
	connect := fs.String("upstream-connect-timeout", DefaultConnectTimeout.String(), "таймаут соединения с провайдером (AISEC_GATEWAY_UPSTREAM_CONNECT_TIMEOUT)")
	header := fs.String("upstream-header-timeout", DefaultHeaderTimeout.String(), "таймаут до заголовков ответа провайдера (AISEC_GATEWAY_UPSTREAM_HEADER_TIMEOUT)")
	forward := fs.String("forward-headers", "", "дополнительные заголовки запроса для провайдера, через запятую (AISEC_GATEWAY_FORWARD_HEADERS)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, dst := range map[string]*string{
		"listen": listen, "tls-cert": cert, "tls-key": key, "upstream-url": upstream, "upstream-ca": upstreamCA,
		"upstream-key-file": upstreamKey, "max-body-bytes": maxBody, "upstream-connect-timeout": connect,
		"upstream-header-timeout": header, "forward-headers": forward,
	} {
		if set[name] {
			continue // флаг важнее окружения
		}
		if v := getenv(envName(name)); v != "" {
			*dst = v
		}
	}

	cfg := &Gateway{
		Listen: *listen, TLSCertFile: *cert, TLSKeyFile: *key,
		UpstreamCAFile: *upstreamCA, UpstreamKeyFile: *upstreamKey,
	}
	var errs []error
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		errs = append(errs, errors.New("listen: ожидается адрес:порт"))
	}
	for name, v := range map[string]string{"tls-cert": cfg.TLSCertFile, "tls-key": cfg.TLSKeyFile, "upstream-url": *upstream, "upstream-ca": cfg.UpstreamCAFile} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s: обязательный параметр", name))
		}
	}
	if *upstream != "" {
		u, err := ParseUpstreamURL(*upstream)
		if err != nil {
			errs = append(errs, err)
		}
		cfg.UpstreamURL = u
	}
	n, err := strconv.ParseInt(*maxBody, 10, 64)
	if err != nil || n < MinBodyBytes || n > MaxBodyBytesLimit {
		errs = append(errs, fmt.Errorf("max-body-bytes: число от %d до %d", MinBodyBytes, MaxBodyBytesLimit))
	}
	cfg.MaxBodyBytes = n
	cfg.UpstreamConnectTimeout, err = parseTimeout("upstream-connect-timeout", *connect)
	if err != nil {
		errs = append(errs, err)
	}
	cfg.UpstreamHeaderTimeout, err = parseTimeout("upstream-header-timeout", *header)
	if err != nil {
		errs = append(errs, err)
	}
	cfg.ForwardHeaders, err = parseHeaderList(*forward)
	if err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("конфигурация шлюза: %w", err)
	}
	return cfg, nil
}

// envName — имя переменной окружения для флага: upstream-url → AISEC_GATEWAY_UPSTREAM_URL.
func envName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// ParseUpstreamURL проверяет базовый адрес провайдера: только https, без
// учётных данных, запроса и фрагмента. Путь запроса приложения
// (/v1/chat/completions) добавляется к пути адреса.
func ParseUpstreamURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("upstream-url: не разобран адрес")
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("upstream-url: только https")
	case u.Host == "" || u.Hostname() == "":
		return nil, errors.New("upstream-url: не указан хост")
	case u.User != nil:
		// Учётные данные в адресе попали бы в логи; ключ задаётся файлом.
		return nil, errors.New("upstream-url: учётные данные в адресе запрещены, используйте upstream-key-file")
	case u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("upstream-url: адрес без параметров запроса и фрагмента")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

func parseTimeout(name, s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 || d > MaxUpstreamTimeout {
		return 0, fmt.Errorf("%s: длительность от 0 до %s, например 30s", name, MaxUpstreamTimeout)
	}
	return d, nil
}

// запрещено пробрасывать: учётные данные и служебные заголовки соединения.
var neverForward = map[string]bool{
	"Authorization": true, "Proxy-Authorization": true, "Cookie": true, "Host": true,
	"Accept-Encoding": true, "Content-Encoding": true, "Expect": true,
	"Connection": true, "Transfer-Encoding": true, "Content-Length": true, "Upgrade": true,
	"Te": true, "Trailer": true, "Keep-Alive": true, "Proxy-Connection": true, "Forwarded": true,
	"X-Forwarded-For": true, "X-Forwarded-Host": true, "X-Forwarded-Proto": true, "X-Real-Ip": true,
}

func parseHeaderList(s string) ([]string, error) {
	var out []string
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if !validHeaderName(h) {
			return nil, fmt.Errorf("forward-headers: недопустимое имя заголовка %q", h)
		}
		h = http.CanonicalHeaderKey(h)
		if neverForward[h] {
			return nil, fmt.Errorf("forward-headers: заголовок %s пробрасывать нельзя", h)
		}
		out = append(out, h)
	}
	if len(out) > maxForwardHeaders {
		return nil, fmt.Errorf("forward-headers: не больше %d заголовков", maxForwardHeaders)
	}
	return out, nil
}

func validHeaderName(h string) bool {
	if len(h) > 64 {
		return false
	}
	for _, r := range h {
		ok := r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}
