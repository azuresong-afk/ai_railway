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
}

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
	p := &Proxy{cfg: cfg, logger: logger}
	p.allowed = append(append([]string{}, defaultRequestHeaders...), cfg.ForwardHeaders...)
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      cfg.Transport,
		FlushInterval:  -1, // SSE: каждая часть уходит клиенту сразу
		ModifyResponse: filterResponse,
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

func filterResponse(resp *http.Response) error {
	out := http.Header{}
	for _, h := range responseHeaders {
		if v := resp.Header.Values(h); len(v) > 0 {
			out[h] = v
		}
	}
	resp.Header = out
	return nil
}

func (p *Proxy) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		// Клиент закрыл соединение: запрос к провайдеру уже отменён.
		p.logger.Info("клиент прервал запрос", "path", r.URL.Path)
		return
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		p.logger.Warn("провайдер не ответил вовремя", "error", err)
		WriteError(w, http.StatusGatewayTimeout, "провайдер модели не ответил вовремя", "upstream_error", "upstream_timeout")
		return
	}
	p.logger.Warn("провайдер недоступен", "error", err)
	WriteError(w, http.StatusBadGateway, "провайдер модели недоступен", "upstream_error", "upstream_unavailable")
}

// ServeHTTP проверяет запрос и передаёт его провайдеру.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		WriteError(w, http.StatusUnsupportedMediaType, "ожидается Content-Type: application/json", "invalid_request_error", "unsupported_media_type")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.cfg.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			WriteError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("тело запроса больше %d байт", p.cfg.MaxBodyBytes), "invalid_request_error", "request_too_large")
			return
		}
		WriteError(w, http.StatusBadRequest, "не удалось прочитать тело запроса", "invalid_request_error", "invalid_request")
		return
	}
	if !isJSONObject(body) {
		WriteError(w, http.StatusBadRequest, "тело запроса — не объект JSON", "invalid_request_error", "invalid_request")
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
