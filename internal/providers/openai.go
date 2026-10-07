package providers

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
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/sse"
)

// OpenAIConfig — параметры OpenAI-совместимого провайдера (vLLM, Ollama,
// llama.cpp server, облачные сервисы с совместимым API).
type OpenAIConfig struct {
	ID string
	// BaseURL — базовый адрес вместе с версией API, например
	// https://llm.example/v1; запрос идёт на BaseURL + /chat/completions.
	BaseURL   *url.URL
	Key       string // ключ API провайдера; пусто — не передаётся
	External  bool
	Transport http.RoundTripper
	Logger    *slog.Logger
	// ResponseTimeout — общий срок ответа, в том числе потокового; ноль —
	// DefaultResponseTimeout.
	ResponseTimeout time.Duration
	// StreamIdleTimeout — наибольшая пауза между событиями потока; ноль —
	// DefaultStreamIdleTimeout.
	StreamIdleTimeout time.Duration
}

// Сроки ответа провайдера по умолчанию (план этапа 1, Р11).
const (
	DefaultResponseTimeout   = 10 * time.Minute
	DefaultStreamIdleTimeout = 60 * time.Second
)

// OpenAI — OpenAI-совместимый провайдер.
type OpenAI struct {
	cfg      OpenAIConfig
	endpoint string
	client   *http.Client
	logger   *slog.Logger
}

// NewOpenAI проверяет параметры и создаёт провайдера.
func NewOpenAI(cfg OpenAIConfig) (*OpenAI, error) {
	if cfg.ID == "" || cfg.BaseURL == nil || cfg.Transport == nil {
		return nil, errors.New("провайдер openai: не заданы id, base_url или транспорт")
	}
	for i := 0; i < len(cfg.Key); i++ {
		// Ключ с управляющими символами позволил бы внедрить заголовок.
		if c := cfg.Key[i]; c < 0x21 || c > 0x7e {
			return nil, fmt.Errorf("провайдер %s: ключ содержит недопустимые символы", cfg.ID)
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ResponseTimeout <= 0 {
		cfg.ResponseTimeout = DefaultResponseTimeout
	}
	if cfg.StreamIdleTimeout <= 0 {
		cfg.StreamIdleTimeout = DefaultStreamIdleTimeout
	}
	u := *cfg.BaseURL
	u.Path = strings.TrimSuffix(u.Path, "/") + "/chat/completions"
	u.RawQuery, u.Fragment = "", ""
	// Перенаправления не выполняются: иначе запрос с ключом мог бы уйти на
	// другой адрес, чем разрешил администратор (ЗИ.3).
	client := &http.Client{Transport: cfg.Transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &OpenAI{cfg: cfg, endpoint: u.String(), client: client, logger: cfg.Logger}, nil
}

// ID — идентификатор провайдера в конфигурации.
func (p *OpenAI) ID() string { return p.cfg.ID }

// External — провайдер вне контура заказчика.
func (p *OpenAI) External() bool { return p.cfg.External }

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

// do отправляет запрос и возвращает ответ с кодом 200 или ошибку по классам.
// Meta возвращается и с ошибкой провайдера: Retry-After нужен приложению
// именно при 429 и 503.
// ctx — контекст запроса к провайдеру (со сроком ответа), clientCtx —
// контекст клиента: по нему отличается уход клиента от таймаута.
func (p *OpenAI) do(ctx, clientCtx context.Context, req *chat.Request, stream bool) (*http.Response, Meta, error) {
	out := *req
	out.Stream = stream
	if !stream {
		out.StreamOptions = nil
	}
	body, err := out.Marshal()
	if err != nil {
		return nil, Meta{}, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, Meta{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("User-Agent", "aisec-gateway")
	if stream {
		hr.Header.Set("Accept", "text/event-stream")
	} else {
		hr.Header.Set("Accept", "application/json")
	}
	if p.cfg.Key != "" {
		hr.Header.Set("Authorization", "Bearer "+p.cfg.Key)
	}
	resp, err := p.client.Do(hr)
	if err != nil {
		return nil, Meta{}, p.transportError(clientCtx, err)
	}
	meta := metaFrom(resp.Header)
	if resp.StatusCode == http.StatusOK {
		return resp, meta, nil
	}
	defer resp.Body.Close() //nolint:errcheck // тело ошибки прочитано ниже; ошибка закрытия не важна
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Тело провайдера может содержать часть ключа — не читаем и не передаём.
		p.logger.Warn("провайдер отклонил учётные данные шлюза", "provider", p.cfg.ID, "status", resp.StatusCode)
		return nil, Meta{}, ErrAuth
	}
	return nil, meta, p.providerError(resp)
}

// keyLeaks сообщает, что в тексте есть ключ провайдера или его фрагмент
// длиной от 8 символов (провайдеры бывает цитируют неверный ключ в ошибке).
func (p *OpenAI) keyLeaks(text string) bool {
	k := p.cfg.Key
	if k == "" {
		return false
	}
	if len(k) <= 8 {
		return strings.Contains(text, k)
	}
	for i := 0; i+8 <= len(k); i++ {
		if strings.Contains(text, k[i:i+8]) {
			return true
		}
	}
	return false
}

// providerError разбирает ошибку провайдера в формате OpenAI.
func (p *OpenAI) providerError(resp *http.Response) error {
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &Error{Status: resp.StatusCode, Type: "upstream_error", Code: "upstream_error", Message: "ошибка провайдера модели"}
	if resp.StatusCode < 400 || resp.StatusCode > 599 {
		// Перенаправления и прочие коды — не ответ модели.
		e.Status = http.StatusBadGateway
		return e
	}
	if err != nil {
		return e
	}
	var body struct {
		Error struct {
			Message string          `json:"message"`
			Type    string          `json:"type"`
			Code    json.RawMessage `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &body) != nil {
		return e
	}
	if m := cleanText(body.Error.Message, maxErrorMessage); m != "" && !p.keyLeaks(body.Error.Message) {
		e.Message = m
	}
	if t := body.Error.Type; validCode(t) {
		e.Type = t
	}
	var code string
	if json.Unmarshal(body.Error.Code, &code) == nil && validCode(code) {
		e.Code = code
	}
	return e
}

// validCode — короткий идентификатор вроде rate_limit_exceeded.
func validCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// transportError классифицирует ошибку связи. Отмена запроса клиентом
// возвращается как есть (ctx.Err()).
func (p *OpenAI) transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		p.logger.Warn("провайдер не ответил вовремя", "provider", p.cfg.ID, "error", ErrorClass(err))
		return ErrTimeout
	}
	p.logger.Warn("провайдер недоступен", "provider", p.cfg.ID, "error", ErrorClass(err))
	return ErrUnavailable
}

// ErrorClass — описание ошибки без адреса и строки запроса: в *url.Error они
// есть, а в журнал попадать не должны.
func ErrorClass(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + ErrorClass(ue.Err)
	}
	return err.Error()
}

// Chat — ответ целиком.
func (p *OpenAI) Chat(ctx context.Context, req *chat.Request) (*chat.Response, Meta, error) {
	// Общий срок покрывает и чтение тела: провайдер, отдающий тело по байту,
	// не удержит соединение дольше.
	rctx, cancel := context.WithTimeout(ctx, p.cfg.ResponseTimeout)
	defer cancel()
	resp, meta, err := p.do(rctx, ctx, req, false)
	if err != nil {
		return nil, meta, err
	}
	defer resp.Body.Close() //nolint:errcheck // тело прочитано; ошибка закрытия не важна
	b, err := io.ReadAll(io.LimitReader(resp.Body, chat.MaxResponseBytes+1))
	if err != nil {
		return nil, meta, p.transportError(ctx, err)
	}
	if len(b) > chat.MaxResponseBytes {
		p.logger.Warn("ответ провайдера больше предела", "provider", p.cfg.ID)
		return nil, meta, ErrBadResponse
	}
	r, err := chat.ParseResponse(b)
	if err != nil {
		p.logger.Warn("ответ провайдера не разобран", "provider", p.cfg.ID)
		return nil, meta, ErrBadResponse
	}
	return r, meta, nil
}

// Stream — потоковый ответ.
func (p *OpenAI) Stream(ctx context.Context, req *chat.Request) (Stream, Meta, error) {
	// Общий срок потока и срок простоя между событиями (Р11): зависший или
	// бесконечный поток не держит соединение и горутину.
	rctx, cancel := context.WithTimeout(ctx, p.cfg.ResponseTimeout)
	resp, meta, err := p.do(rctx, ctx, req, true)
	if err != nil {
		cancel()
		return nil, meta, err
	}
	if mt, _, perr := mime.ParseMediaType(resp.Header.Get("Content-Type")); perr != nil || mt != "text/event-stream" {
		p.logger.Warn("провайдер ответил не потоком SSE", "provider", p.cfg.ID)
		if cerr := resp.Body.Close(); cerr != nil {
			p.logger.Warn("закрытие ответа провайдера", "error", ErrorClass(cerr))
		}
		cancel()
		return nil, meta, ErrBadResponse
	}
	s := &openAIStream{p: p, ctx: ctx, cancel: cancel, body: resp.Body, r: sse.NewReader(resp.Body, sse.Limits{})}
	s.idle = time.AfterFunc(p.cfg.StreamIdleTimeout, func() {
		s.idleExpired.Store(true)
		cancel()
	})
	return s, meta, nil
}

type openAIStream struct {
	p           *OpenAI
	ctx         context.Context // контекст клиента
	cancel      context.CancelFunc
	idle        *time.Timer
	idleExpired atomic.Bool
	body        io.ReadCloser
	r           *sse.Reader
	size        int
	done        bool
}

func (s *openAIStream) Next() (*chat.Chunk, error) {
	if s.done {
		return nil, io.EOF
	}
	for {
		ev, err := s.r.Next()
		switch {
		case err != nil && s.idleExpired.Load():
			s.p.logger.Warn("поток провайдера: превышен простой между событиями", "provider", s.p.cfg.ID)
			return nil, ErrTimeout
		case errors.Is(err, io.EOF):
			return nil, ErrTruncated
		case errors.Is(err, sse.ErrLineTooLong), errors.Is(err, sse.ErrEventTooLarge):
			s.p.logger.Warn("поток провайдера: событие больше предела", "provider", s.p.cfg.ID)
			return nil, ErrBadResponse
		case err != nil:
			return nil, s.p.transportError(s.ctx, err)
		}
		s.idle.Reset(s.p.cfg.StreamIdleTimeout)
		if s.size += len(ev.Data); s.size > chat.MaxResponseBytes {
			s.p.logger.Warn("поток провайдера больше предела", "provider", s.p.cfg.ID)
			return nil, ErrBadResponse
		}
		if ev.Event != "" && ev.Event != "message" && ev.Event != "error" {
			continue // служебные события провайдера не передаются
		}
		if ev.Data == chat.Done {
			s.done = true
			return nil, io.EOF
		}
		if msg, ok := streamErrorMessage(ev.Data); ok {
			return nil, s.p.streamError(msg)
		}
		c, err := chat.ParseChunk(ev.Data)
		if err != nil {
			s.p.logger.Warn("часть потока провайдера не разобрана", "provider", s.p.cfg.ID)
			return nil, ErrBadResponse
		}
		return c, nil
	}
}

// streamErrorMessage распознаёт ошибку внутри потока: data: {"error": {...}}
// и возвращает её текст. Данные, которые не разбираются как объект ошибки, —
// обычная часть потока (ok = false).
func streamErrorMessage(data string) (msg string, ok bool) {
	if !strings.Contains(data, `"error"`) {
		return "", false
	}
	var body struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal([]byte(data), &body) != nil || len(body.Error) == 0 || string(body.Error) == "null" {
		return "", false
	}
	// Ошибка — объект с message или просто строка; иное — без текста.
	var obj struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body.Error, &obj) == nil {
		return obj.Message, true
	}
	var str string
	if json.Unmarshal(body.Error, &str) == nil {
		return str, true
	}
	return "", true
}

func (p *OpenAI) streamError(msg string) *Error {
	e := &Error{Status: http.StatusBadGateway, Type: "upstream_error", Code: "upstream_error", Message: "ошибка провайдера модели"}
	if m := cleanText(msg, maxErrorMessage); m != "" && !p.keyLeaks(msg) {
		e.Message = m
	}
	return e
}

func (s *openAIStream) Close() error {
	s.idle.Stop()
	s.cancel()
	return s.body.Close()
}
