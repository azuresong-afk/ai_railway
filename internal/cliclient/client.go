// Package cliclient — сетевой клиент aisec-cli к API сервера управления
// (задачи 5.21 и 5.22 этапа 5, ADR-0029, дополнение 1): отчёт сканера
// моделей и эталонные хеши с узла заказчика, где лежат файлы модели; а
// также Check API шлюза для проверки документов RAG до индексации (задача
// 5.25, aisec-cli rag check): адрес шлюза и ключ приложения — по тем же
// правилам.
// Первый исходящий вызов CLI, поэтому клиент узкий:
//   - адрес сервера — только из флага команды и только https;
//   - TLS — из internal/crypto (криптопрофиль), корень доверия — из файла,
//     системное хранилище сертификатов не используется;
//   - прокси из окружения (HTTPS_PROXY и т. п.) не используется,
//     перенаправления не выполняются;
//   - у каждого запроса — срок, у ответа — предел размера;
//   - токен API — из файла, недоступного группе и остальным (0600 или
//     0400), не из флага и не из окружения; в текстах ошибок его нет.
package cliclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Пределы по умолчанию.
const (
	// DefaultTimeout — срок одного запроса целиком (с отправкой отчёта).
	DefaultTimeout = 60 * time.Second
	// DefaultMaxResponse — предел тела ответа.
	DefaultMaxResponse = 4 << 20
	// dialTimeout и tlsTimeout — установка соединения и рукопожатие TLS.
	dialTimeout = 10 * time.Second
	tlsTimeout  = 10 * time.Second
	// maxHeaderBytes — заголовки ответа.
	maxHeaderBytes = 64 << 10
	// minToken и maxToken — длина токена API в файле.
	minToken = 16
	maxToken = 512
)

// Ошибки клиента. Тексты не содержат токена и тела ответа.
var (
	ErrServerURL   = errors.New("адрес сервера: только https://хост[:порт] без пути, параметров и учётных данных")
	ErrToken       = errors.New("файл токена: одна строка из печатных символов ASCII без пробелов, от 16 до 512 символов")
	ErrRedirect    = errors.New("сервер ответил перенаправлением: перенаправления не выполняются, укажите точный адрес сервера")
	ErrTooLarge    = errors.New("ответ сервера больше допустимого размера")
	ErrContentType = errors.New("ответ сервера не в формате JSON")
)

// Options — параметры клиента.
type Options struct {
	// Server — адрес сервера управления: https://хост[:порт].
	Server string
	// CAFile — корневые сертификаты (PEM), которым доверяет клиент.
	CAFile string
	// TokenFile — файл с токеном API (права 0600 или 0400).
	TokenFile string
	// Provider — криптопрофиль: настройки TLS — его.
	Provider aisecCrypto.Provider
	// Timeout — срок запроса; 0 — DefaultTimeout.
	Timeout time.Duration
	// MaxResponse — предел тела ответа; 0 — DefaultMaxResponse.
	MaxResponse int64
}

// Client — клиент API сервера управления.
type Client struct {
	base    *url.URL
	token   string
	http    *http.Client
	timeout time.Duration
	max     int64
}

// Problem — отказ сервера (application/problem+json): код ответа, код и
// текст для людей.
type Problem struct {
	Status int
	Code   string
	Detail string
}

func (p *Problem) Error() string {
	if p.Detail == "" {
		return fmt.Sprintf("сервер ответил %d", p.Status)
	}
	return fmt.Sprintf("сервер ответил %d: %s", p.Status, p.Detail)
}

// ParseServer проверяет адрес сервера: только https, хост обязателен, без
// учётных данных, пути, параметров и фрагмента.
func ParseServer(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, ErrServerURL
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 || strings.HasPrefix(p, "0") {
			return nil, ErrServerURL
		}
	}
	return &url.URL{Scheme: "https", Host: u.Host}, nil
}

// ReadToken читает токен из файла: права 0600 или 0400, обычный файл,
// одна строка (перевод строки в конце допустим).
func ReadToken(path string) (string, error) {
	data, err := aisecCrypto.ReadKeyFile(path)
	if err != nil {
		return "", fmt.Errorf("файл токена: %w", err)
	}
	t := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if len(t) < minToken || len(t) > maxToken {
		return "", ErrToken
	}
	for i := 0; i < len(t); i++ {
		if t[i] <= ' ' || t[i] > '~' {
			return "", ErrToken
		}
	}
	return t, nil
}

// New проверяет параметры, читает корень доверия и токен.
func New(o Options) (*Client, error) {
	if o.Provider == nil {
		return nil, errors.New("клиент API: не задан криптопрофиль")
	}
	base, err := ParseServer(o.Server)
	if err != nil {
		return nil, err
	}
	if o.CAFile == "" {
		return nil, errors.New("корневой сертификат: укажите файл -ca")
	}
	roots, err := aisecCrypto.ReadPEMFile(o.CAFile)
	if err != nil {
		return nil, fmt.Errorf("корневой сертификат: %w", err)
	}
	tp, err := o.Provider.TLS()
	if err != nil {
		return nil, err
	}
	cfg, err := tp.ClientConfig(roots)
	if err != nil {
		return nil, err
	}
	token, err := ReadToken(o.TokenFile)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.MaxResponse <= 0 {
		o.MaxResponse = DefaultMaxResponse
	}
	tr := &http.Transport{
		// Прокси из окружения не используется: адрес — только из флага.
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSClientConfig:        cfg,
		TLSHandshakeTimeout:    tlsTimeout,
		ResponseHeaderTimeout:  o.Timeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableCompression:     true,
		DisableKeepAlives:      true,
	}
	hc := &http.Client{Transport: tr, Timeout: o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect }}
	return &Client{base: base, token: token, http: hc, timeout: o.Timeout, max: o.MaxResponse}, nil
}

// Server — адрес сервера (без пути).
func (c *Client) Server() string { return c.base.String() }

// Do выполняет запрос к пути API (начинается с «/api/» — сервер управления
// — или с «/guard/» — Check API шлюза): тело body с типом contentType (nil —
// без тела), ответ JSON — в out (nil — не разбирается). Отказ сервера —
// *Problem.
func (c *Client) Do(ctx context.Context, method, path string, body []byte, contentType string, out any) error {
	if (!strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/guard/")) || strings.ContainsAny(path, "?#") {
		return errors.New("клиент API: неверный путь запроса")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, rd)
	if err != nil {
		return fmt.Errorf("клиент API: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return ErrRedirect
		}
		// Текст ошибки net/http содержит метод и адрес, но не заголовки.
		return fmt.Errorf("запрос к серверу: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // тело прочитано или не нужно
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.max+1))
	if err != nil {
		return fmt.Errorf("ответ сервера: %w", err)
	}
	if int64(len(data)) > c.max {
		return ErrTooLarge
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return ErrRedirect
	}
	if resp.StatusCode >= 400 {
		return problemOf(resp.StatusCode, data)
	}
	if out == nil {
		return nil
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return ErrContentType
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("ответ сервера: некорректный JSON")
	}
	return nil
}

// maxDetail — текст отказа сервера в сообщении CLI; maxFieldErrors — ошибок
// полей в нём.
const (
	maxDetail      = 2048
	maxFieldErrors = 5
)

// problemOf — отказ сервера: код и текст из problem+json сервера управления
// или из ошибки шлюза ({"error":{"code","message"}}), без тела ответа
// целиком (оно может быть страницей посредника).
func problemOf(status int, data []byte) *Problem {
	p := &Problem{Status: status}
	var body struct {
		Code   string `json:"code"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Errors []struct {
			Field  string `json:"field"`
			Detail string `json:"detail"`
		} `json:"errors"`
		Gateway *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &body) != nil {
		return p
	}
	if g := body.Gateway; g != nil && body.Code == "" && body.Detail == "" {
		body.Code, body.Detail = g.Code, g.Message
	}
	detail := body.Detail
	if detail == "" {
		detail = body.Title
	}
	// Ошибки полей (отчёт не прошёл проверку) — первые несколько.
	for i, e := range body.Errors {
		if i == maxFieldErrors {
			detail += fmt.Sprintf("; и ещё ошибок: %d", len(body.Errors)-i)
			break
		}
		detail += "; " + e.Detail
	}
	p.Code, p.Detail = clean(body.Code, 64), clean(detail, maxDetail)
	return p
}

// clean — строка без управляющих символов и не длиннее n байт (текст
// ответа выводится в терминал).
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
