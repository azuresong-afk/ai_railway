package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Заголовки запроса, которые шлюз всегда передаёт провайдеру. Остальные
// (в том числе клиентские Authorization, Cookie, X-Forwarded-*) отбрасываются:
// учётные данные провайдера подставляет шлюз (ТЗ, 5.1).
var defaultRequestHeaders = []string{"Content-Type", "Accept", "User-Agent", "X-Request-Id"}

// Заголовки ответа провайдера, которые передаются приложению. Остальные
// (Set-Cookie, Server, служебные заголовки провайдера) отбрасываются.
var responseHeaders = []string{"Content-Type", "Retry-After", "X-Request-Id",
	"X-Ratelimit-Limit-Requests", "X-Ratelimit-Limit-Tokens",
	"X-Ratelimit-Remaining-Requests", "X-Ratelimit-Remaining-Tokens",
	"X-Ratelimit-Reset-Requests", "X-Ratelimit-Reset-Tokens"}

// ProxyConfig — параметры прозрачного прокси этапа 0.
type ProxyConfig struct {
	Upstream       *url.URL
	Transport      http.RoundTripper
	UpstreamKey    string // ключ API провайдера; пусто — не подставляется
	MaxBodyBytes   int64
	ForwardHeaders []string // дополнительные заголовки запроса
	Logger         *slog.Logger
	// BodyReadTimeout — предел времени на чтение тела запроса: медленная
	// передача тела не должна занимать соединения. Ноль — DefaultBodyReadTimeout.
	BodyReadTimeout time.Duration
}

// DefaultBodyReadTimeout — время на чтение тела запроса по умолчанию.
const DefaultBodyReadTimeout = 30 * time.Second

// Proxy проксирует POST /v1/chat/completions на один upstream.
type Proxy struct {
	cfg     ProxyConfig
	allowed []string
	rp      *httputil.ReverseProxy
	logger  *slog.Logger
}

// NewProxy проверяет параметры и собирает прокси.
func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	if cfg.Upstream == nil || cfg.Transport == nil {
		return nil, errors.New("прокси: не заданы upstream или транспорт")
	}
	if cfg.MaxBodyBytes <= 0 {
		return nil, errors.New("прокси: не задан предел размера тела")
	}
	if err := validateKey(cfg.UpstreamKey); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.BodyReadTimeout <= 0 {
		cfg.BodyReadTimeout = DefaultBodyReadTimeout
	}
	p := &Proxy{cfg: cfg, logger: logger}
	p.allowed = append(append([]string{}, defaultRequestHeaders...), cfg.ForwardHeaders...)
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      cfg.Transport,
		FlushInterval:  -1, // SSE: каждая часть уходит клиенту сразу
		ModifyResponse: p.filterResponse,
		ErrorHandler:   p.upstreamError,
		ErrorLog:       slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	return p, nil
}

// validateKey не даёт подставить в заголовок ключ с управляющими символами.
func validateKey(key string) error {
	for i := 0; i < len(key); i++ {
		if c := key[i]; c < 0x21 || c > 0x7e {
			return errors.New("прокси: ключ провайдера содержит недопустимые символы")
		}
	}
	return nil
}

// NewTransport — транспорт к провайдеру: доверие только корневым
// сертификатам rootsPEM, только заданный адрес (переменные HTTP_PROXY не
// используются — ЗИ.3), таймауты на соединение, TLS и заголовки ответа.
func NewTransport(tp aisecCrypto.TLSProvider, rootsPEM []byte, connectTimeout, headerTimeout time.Duration) (*http.Transport, error) {
	tlsCfg, err := tp.ClientConfig(rootsPEM)
	if err != nil {
		return nil, fmt.Errorf("TLS к провайдеру: %w", err)
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: headerTimeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}, nil
}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(p.cfg.Upstream)
	// Строка запроса клиента провайдеру не передаётся: её содержимое не
	// проходит проверки и могло бы унести данные мимо allowlist.
	pr.Out.URL.RawQuery = ""
	out := http.Header{}
	for _, h := range p.allowed {
		if v := pr.In.Header.Values(h); len(v) > 0 {
			out[h] = append([]string(nil), v...)
		}
	}
	if p.cfg.UpstreamKey != "" {
		out.Set("Authorization", "Bearer "+p.cfg.UpstreamKey)
	}
	pr.Out.Header = out
}

func (p *Proxy) filterResponse(resp *http.Response) error {
	// Ошибка аутентификации у провайдера относится к ключу шлюза, а не к
	// приложению; тело провайдера может содержать часть ключа — не передаём.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		p.logger.Warn("провайдер отклонил учётные данные шлюза", "status", resp.StatusCode)
		if err := resp.Body.Close(); err != nil {
			p.logger.Warn("закрытие ответа провайдера", "error", errorClass(err))
		}
		body := []byte(`{"error":{"message":"провайдер модели отклонил учётные данные шлюза","type":"upstream_error","code":"upstream_auth_error"}}` + "\n")
		resp.StatusCode = http.StatusBadGateway
		resp.Status = http.StatusText(http.StatusBadGateway)
		resp.Header = http.Header{"Content-Type": {"application/json"}}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Trailer = nil
		return nil
	}
	out := http.Header{}
	for _, h := range responseHeaders {
		if v := resp.Header.Values(h); len(v) > 0 {
			out[h] = v
		}
	}
	resp.Header = out
	// Трейлеры провайдера не передаются: allowlist относится и к ним.
	// Транспорт заполняет resp.Trailer при чтении конца тела, поэтому они
	// удаляются в этот момент, а не здесь.
	resp.Trailer = nil
	resp.Body = &trailerStripper{ReadCloser: resp.Body, resp: resp}
	return nil
}

// trailerStripper удаляет трейлеры ответа, как только транспорт их прочитал.
type trailerStripper struct {
	io.ReadCloser
	resp *http.Response
}

func (t *trailerStripper) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	if err != nil {
		t.resp.Trailer = nil
	}
	return n, err
}

// errorClass — описание ошибки без адреса и строки запроса: в *url.Error они
// есть, а в журнал попадать не должны.
func errorClass(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + errorClass(ue.Err)
	}
	return err.Error()
}

func (p *Proxy) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		// Клиент закрыл соединение: запрос к провайдеру уже отменён.
		p.logger.Info("клиент прервал запрос", "path", r.URL.Path)
		return
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		p.logger.Warn("провайдер не ответил вовремя", "error", errorClass(err))
		WriteError(w, http.StatusGatewayTimeout, "провайдер модели не ответил вовремя", "upstream_error", "upstream_timeout")
		return
	}
	p.logger.Warn("провайдер недоступен", "error", errorClass(err))
	WriteError(w, http.StatusBadGateway, "провайдер модели недоступен", "upstream_error", "upstream_unavailable")
}

// ServeHTTP проверяет запрос и передаёт его провайдеру.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		WriteError(w, http.StatusUnsupportedMediaType, "ожидается Content-Type: application/json", "invalid_request_error", "unsupported_media_type")
		return
	}
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(p.cfg.BodyReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		p.logger.Warn("не удалось ограничить время чтения тела", "error", err)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.cfg.MaxBodyBytes))
	// После чтения тела срок снимается: дальше соединение нужно для ответа,
	// в том числе долгого потокового.
	if derr := rc.SetReadDeadline(time.Time{}); derr != nil && !errors.Is(derr, http.ErrNotSupported) {
		p.logger.Warn("не удалось снять срок чтения", "error", derr)
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			WriteError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("тело запроса больше %d байт", p.cfg.MaxBodyBytes), "invalid_request_error", "request_too_large")
			return
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			WriteError(w, http.StatusRequestTimeout, "тело запроса передавалось слишком долго", "invalid_request_error", "request_timeout")
			return
		}
		WriteError(w, http.StatusBadRequest, "не удалось прочитать тело запроса", "invalid_request_error", "invalid_request")
		return
	}
	if !isJSONObject(body) {
		WriteError(w, http.StatusBadRequest, "тело запроса — не объект JSON", "invalid_request_error", "invalid_request")
		return
	}
	// Провайдеру уходит запрос, собранный заново из проверенной модели, а не
	// исходные байты (см. пакет chat).
	req, err := chat.Parse(body, chat.Limits{})
	if err != nil {
		var ce *chat.Error
		if !errors.As(err, &ce) {
			ce = &chat.Error{Code: chat.CodeInvalid, Message: "неверный запрос"}
		}
		WriteError(w, http.StatusBadRequest, ce.Message, "invalid_request_error", ce.Code)
		return
	}
	if body, err = req.Marshal(); err != nil {
		p.logger.Error("сборка запроса к провайдеру", "error", err)
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	p.rp.ServeHTTP(w, r)
}

func isJSONObject(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '{' && json.Valid(b)
}
