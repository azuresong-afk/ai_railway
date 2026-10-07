package providers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode"

	"github.com/azuresong-afk/ai_railway/internal/chat"
)

// Provider — провайдер модели за общим интерфейсом (ТЗ, 5.1). Запрос и ответ
// — в модели пакета chat: адаптер переводит их в формат провайдера и обратно,
// поэтому шлюз и проверки не зависят от провайдера.
type Provider interface {
	ID() string
	// External — провайдер вне контура заказчика (ТЗ, 5.4).
	External() bool
	// Chat — ответ целиком (stream: false).
	Chat(ctx context.Context, req *chat.Request) (*chat.Response, Meta, error)
	// Stream — потоковый ответ (stream: true). Поток закрывает вызывающий.
	Stream(ctx context.Context, req *chat.Request) (Stream, Meta, error)
}

// Stream — части потокового ответа. Next возвращает io.EOF после штатного
// завершения потока; поток, оборванный без завершения, — ErrTruncated.
type Stream interface {
	Next() (*chat.Chunk, error)
	Close() error
}

// Meta — сведения из ответа провайдера, которые можно передать приложению:
// только заголовки из allowlist (лимиты провайдера).
type Meta struct {
	Header http.Header
}

// Заголовки ответа провайдера, которые передаются приложению.
var passHeaders = []string{"Retry-After",
	"X-Ratelimit-Limit-Requests", "X-Ratelimit-Limit-Tokens",
	"X-Ratelimit-Remaining-Requests", "X-Ratelimit-Remaining-Tokens",
	"X-Ratelimit-Reset-Requests", "X-Ratelimit-Reset-Tokens"}

func metaFrom(h http.Header) Meta {
	out := http.Header{}
	for _, k := range passHeaders {
		if v := h.Get(k); v != "" && len(v) <= 128 && !strings.ContainsFunc(v, unicode.IsControl) {
			out.Set(k, v)
		}
	}
	return Meta{Header: out}
}

// Классы ошибок обращения к провайдеру. Шлюз отвечает по ним приложению без
// внутренних подробностей (адреса, ключа, текста провайдера при 401/403).
var (
	// ErrAuth — провайдер отклонил учётные данные шлюза (401, 403).
	ErrAuth = errors.New("провайдер отклонил учётные данные шлюза")
	// ErrTimeout — провайдер не ответил вовремя.
	ErrTimeout = errors.New("провайдер не ответил вовремя")
	// ErrUnavailable — нет связи с провайдером.
	ErrUnavailable = errors.New("провайдер недоступен")
	// ErrBadResponse — ответ провайдера не разобран или больше пределов.
	ErrBadResponse = errors.New("ответ провайдера не разобран")
	// ErrTruncated — поток оборван без завершающего события.
	ErrTruncated = errors.New("поток провайдера оборван")
)

// Error — ошибка, которую вернул провайдер (код HTTP и тело в формате
// OpenAI). Текст очищен от управляющих символов и ограничен по длине.
type Error struct {
	Status     int
	Type, Code string
	Message    string
}

func (e *Error) Error() string { return "провайдер: " + e.Message }

// maxErrorMessage — предел длины текста ошибки провайдера, рун.
const maxErrorMessage = 500

// cleanText убирает управляющие символы и ограничивает длину.
func cleanText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit]) + "…"
	}
	return s
}
