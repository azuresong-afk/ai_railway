package providers

import (
	"bufio"
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

// Общее ядро HTTP-провайдеров: отправка запроса, классы ошибок, сроки ответа,
// разбор потока SSE. Адаптеры (OpenAI, GigaChat, YandexGPT) отличаются только
// форматом тела и способом авторизации.

// BaseConfig — общие параметры провайдера.
type BaseConfig struct {
	ID        string
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

type base struct {
	cfg    BaseConfig
	client *http.Client
	logger *slog.Logger
	// secrets — учётные данные, фрагменты которых не должны уйти приложению
	// в тексте ошибки провайдера; dynSecrets — меняющиеся (токен доступа).
	secrets    []string
	dynSecrets func() []string
}

func newBase(cfg BaseConfig, secrets ...string) (base, error) {
	if cfg.ID == "" || cfg.Transport == nil {
		return base{}, errors.New("провайдер: не заданы id или транспорт")
	}
	for _, s := range secrets {
		if err := validateSecret(s); err != nil {
			return base{}, fmt.Errorf("провайдер %s: %w", cfg.ID, err)
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
	// Перенаправления не выполняются: иначе запрос с ключом мог бы уйти на
	// другой адрес, чем разрешил администратор (ЗИ.3).
	client := &http.Client{Transport: cfg.Transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return base{cfg: cfg, client: client, logger: cfg.Logger, secrets: secrets}, nil
}

// validateSecret не даёт подставить в заголовок значение с управляющими
// символами (внедрение заголовка).
func validateSecret(s string) error {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return errors.New("учётные данные содержат недопустимые символы")
		}
	}
	return nil
}

// ID — идентификатор провайдера в конфигурации.
func (b *base) ID() string { return b.cfg.ID }

// External — провайдер вне контура заказчика.
func (b *base) External() bool { return b.cfg.External }

// endpoint — базовый адрес и путь метода без строки запроса и фрагмента.
func endpoint(baseURL *url.URL, path string) string {
	u := *baseURL
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery, u.Fragment = "", ""
	return u.String()
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

// post отправляет JSON и возвращает ответ с кодом 200 или ошибку по классам.
// Meta возвращается и с ошибкой провайдера: Retry-After нужен приложению
// именно при 429 и 503. ctx — контекст запроса к провайдеру (со сроком
// ответа), clientCtx — контекст клиента: по нему уход клиента отличается от
// таймаута. auth — значение заголовка Authorization (пусто — без него).
func (b *base) post(ctx, clientCtx context.Context, url string, body []byte, stream bool, auth string) (*http.Response, Meta, error) {
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
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
	if auth != "" {
		hr.Header.Set("Authorization", auth)
	}
	return b.do(hr, clientCtx)
}

// do выполняет подготовленный запрос: ответ 200 или ошибка по классам.
func (b *base) do(hr *http.Request, clientCtx context.Context) (*http.Response, Meta, error) {
	resp, err := b.client.Do(hr)
	if err != nil {
		return nil, Meta{}, b.transportError(clientCtx, err)
	}
	meta := metaFrom(resp.Header)
	if resp.StatusCode == http.StatusOK {
		return resp, meta, nil
	}
	defer resp.Body.Close() //nolint:errcheck // тело ошибки прочитано ниже; ошибка закрытия не важна
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Тело провайдера может содержать часть ключа — не читаем и не передаём.
		b.logger.Warn("провайдер отклонил учётные данные шлюза", "provider", b.cfg.ID, "status", resp.StatusCode)
		return nil, Meta{}, ErrAuth
	}
	return nil, meta, b.providerError(resp)
}

// keyLeaks сообщает, что в тексте есть учётные данные провайдера или их
// фрагмент длиной от 8 символов (провайдеры бывает цитируют неверный ключ).
func (b *base) keyLeaks(text string) bool {
	all := b.secrets
	if b.dynSecrets != nil {
		all = append(append([]string(nil), all...), b.dynSecrets()...)
	}
	for _, k := range all {
		if k == "" {
			continue
		}
		if len(k) <= 8 {
			if strings.Contains(text, k) {
				return true
			}
			continue
		}
		for i := 0; i+8 <= len(k); i++ {
			if strings.Contains(text, k[i:i+8]) {
				return true
			}
		}
	}
	return false
}

// providerError разбирает ошибку провайдера: формат OpenAI
// ({"error": {...}}) или GigaChat ({"status": N, "message": "..."}).
func (b *base) providerError(resp *http.Response) error {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
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
		Error *struct {
			Message string          `json:"message"`
			Type    string          `json:"type"`
			Code    json.RawMessage `json:"code"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return e
	}
	msg := body.Message
	if body.Error != nil {
		msg = body.Error.Message
		if t := body.Error.Type; validCode(t) {
			e.Type = t
		}
		var code string
		if json.Unmarshal(body.Error.Code, &code) == nil && validCode(code) {
			e.Code = code
		}
	}
	if m := cleanText(msg, maxErrorMessage); m != "" && !b.keyLeaks(msg) {
		e.Message = m
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
func (b *base) transportError(clientCtx context.Context, err error) error {
	if clientCtx.Err() != nil {
		return clientCtx.Err()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		b.logger.Warn("провайдер не ответил вовремя", "provider", b.cfg.ID, "error", ErrorClass(err))
		return ErrTimeout
	}
	b.logger.Warn("провайдер недоступен", "provider", b.cfg.ID, "error", ErrorClass(err))
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

// readBody читает тело ответа без потока с пределом размера. Срок задан
// контекстом запроса: провайдер, отдающий тело по байту, не удержит
// соединение дольше общего срока ответа.
func (b *base) readBody(clientCtx context.Context, resp *http.Response) ([]byte, error) {
	defer resp.Body.Close() //nolint:errcheck // тело прочитано; ошибка закрытия не важна
	raw, err := io.ReadAll(io.LimitReader(resp.Body, chat.MaxResponseBytes+1))
	if err != nil {
		return nil, b.transportError(clientCtx, err)
	}
	if len(raw) > chat.MaxResponseBytes {
		b.logger.Warn("ответ провайдера больше предела", "provider", b.cfg.ID)
		return nil, ErrBadResponse
	}
	return raw, nil
}

// openStream проверяет, что ответ — поток SSE, и запускает учёт простоя.
// decode переводит данные события в часть ответа (nil — пропустить).
func (b *base) openStream(clientCtx context.Context, cancel context.CancelFunc, resp *http.Response,
	decode func(data string) (*chat.Chunk, error)) (Stream, error) {
	if mt, _, perr := mime.ParseMediaType(resp.Header.Get("Content-Type")); perr != nil || mt != "text/event-stream" {
		b.logger.Warn("провайдер ответил не потоком SSE", "provider", b.cfg.ID)
		if cerr := resp.Body.Close(); cerr != nil {
			b.logger.Warn("закрытие ответа провайдера", "error", ErrorClass(cerr))
		}
		cancel()
		return nil, ErrBadResponse
	}
	r := sse.NewReader(resp.Body, sse.Limits{})
	next := func() (frame, error) {
		ev, err := r.Next()
		switch {
		case errors.Is(err, io.EOF):
			return frame{}, ErrTruncated // поток SSE штатно кончается событием [DONE]
		case errors.Is(err, sse.ErrLineTooLong), errors.Is(err, sse.ErrEventTooLarge):
			return frame{}, errFrameTooLarge
		case err != nil:
			return frame{}, err
		}
		if ev.Event != "" && ev.Event != "message" && ev.Event != "error" {
			return frame{data: ev.Data, skip: true}, nil // служебные события провайдера не передаются
		}
		if ev.Data == chat.Done {
			return frame{done: true}, nil
		}
		return frame{data: ev.Data}, nil
	}
	s := b.newFrameStream(clientCtx, cancel, resp.Body, next, decode)
	s.countFrames = true
	return s, nil
}

// openNDJSON — поток строк JSON (YandexGPT). Строка — до MaxResponseBytes.
// Конец потока без ошибки — штатный, если final сообщает, что последняя
// часть получена; иначе поток оборван. Объём считает decode: в строках
// YandexGPT текст накопленный, и сумма длин строк не отражает размер ответа.
func (b *base) openNDJSON(clientCtx context.Context, cancel context.CancelFunc, resp *http.Response,
	decode func(data string) (*chat.Chunk, error), final func() bool) Stream {
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	var line []byte
	next := func() (frame, error) {
		line = line[:0]
		for {
			chunk, err := br.ReadSlice('\n')
			if len(line)+len(chunk) > chat.MaxResponseBytes {
				return frame{}, errFrameTooLarge
			}
			line = append(line, chunk...)
			switch {
			case err == nil:
				t := strings.TrimSpace(string(line))
				if t == "" {
					return frame{skip: true}, nil
				}
				return frame{data: t}, nil
			case errors.Is(err, bufio.ErrBufferFull):
				continue
			case errors.Is(err, io.EOF):
				if t := strings.TrimSpace(string(line)); t != "" {
					return frame{data: t}, nil // последняя строка без перевода строки
				}
				if final() {
					return frame{done: true}, nil
				}
				return frame{}, ErrTruncated
			default:
				return frame{}, err
			}
		}
	}
	return b.newFrameStream(clientCtx, cancel, resp.Body, next, decode)
}

// closeBody закрывает тело ответа провайдера, ошибку — в журнал.
func (b *base) closeBody(resp *http.Response) {
	if cerr := resp.Body.Close(); cerr != nil {
		b.logger.Warn("закрытие ответа провайдера", "error", ErrorClass(cerr))
	}
}

// frame — кадр потока: данные части, служебный кадр или конец потока.
type frame struct {
	data string
	skip bool
	done bool
}

var errFrameTooLarge = errors.New("кадр потока больше предела")

func (b *base) newFrameStream(clientCtx context.Context, cancel context.CancelFunc, body io.ReadCloser,
	next func() (frame, error), decode func(string) (*chat.Chunk, error)) *frameStream {
	s := &frameStream{b: b, ctx: clientCtx, cancel: cancel, body: body, next: next, decode: decode}
	s.idle = time.AfterFunc(b.cfg.StreamIdleTimeout, func() {
		s.idleExpired.Store(true)
		cancel()
	})
	return s
}

// frameStream — поток частей ответа с общим сроком (контекст запроса),
// сроком простоя между кадрами и пределом объёма.
type frameStream struct {
	b           *base
	ctx         context.Context // контекст клиента
	cancel      context.CancelFunc
	idle        *time.Timer
	idleExpired atomic.Bool
	body        io.ReadCloser
	next        func() (frame, error)
	decode      func(string) (*chat.Chunk, error)
	size        int
	countFrames bool // считать объём по кадрам (SSE)
	done        bool
}

func (s *frameStream) Next() (*chat.Chunk, error) {
	if s.done {
		return nil, io.EOF
	}
	for {
		f, err := s.next()
		switch {
		case err != nil && s.idleExpired.Load():
			s.b.logger.Warn("поток провайдера: превышен простой между событиями", "provider", s.b.cfg.ID)
			return nil, ErrTimeout
		case errors.Is(err, ErrTruncated):
			return nil, ErrTruncated
		case errors.Is(err, errFrameTooLarge):
			s.b.logger.Warn("поток провайдера: событие больше предела", "provider", s.b.cfg.ID)
			return nil, ErrBadResponse
		case err != nil:
			return nil, s.b.transportError(s.ctx, err)
		}
		s.idle.Reset(s.b.cfg.StreamIdleTimeout)
		if s.countFrames {
			s.size += len(f.data)
		}
		if s.size > chat.MaxResponseBytes {
			s.b.logger.Warn("поток провайдера больше предела", "provider", s.b.cfg.ID)
			return nil, ErrBadResponse
		}
		if f.done {
			s.done = true
			return nil, io.EOF
		}
		if f.skip {
			continue
		}
		if msg, ok := streamErrorMessage(f.data); ok {
			return nil, s.b.streamError(msg)
		}
		c, err := s.decode(f.data)
		if err != nil {
			s.b.logger.Warn("часть потока провайдера не разобрана", "provider", s.b.cfg.ID)
			return nil, ErrBadResponse
		}
		if c != nil {
			return c, nil
		}
	}
}

func (s *frameStream) Close() error {
	s.idle.Stop()
	s.cancel()
	return s.body.Close()
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

func (b *base) streamError(msg string) *Error {
	e := &Error{Status: http.StatusBadGateway, Type: "upstream_error", Code: "upstream_error", Message: "ошибка провайдера модели"}
	if m := cleanText(msg, maxErrorMessage); m != "" && !b.keyLeaks(msg) {
		e.Message = m
	}
	return e
}
