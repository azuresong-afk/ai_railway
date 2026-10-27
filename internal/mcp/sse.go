package mcp

import (
	"errors"
	"io"

	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
	"github.com/azuresong-afk/ai_railway/internal/sse"
)

// Пределы потока SSE вышестоящего сервера (ADR-0023, раздел 6).
const (
	// MaxEvents — событий SSE на один запрос.
	MaxEvents = 1024
	// MaxStream — байт потока ответа на запрос (и потока
	// subscriptions/listen: у него ещё и предел времени).
	MaxStream = 16 << 20
)

// ErrTooManyEvents — в потоке больше MaxEvents событий.
var ErrTooManyEvents = errors.New("поток SSE: больше допустимого числа событий")

// ErrStreamTooLarge — поток больше предела байт.
var ErrStreamTooLarge = errors.New("поток SSE больше предела")

// SSEReader читает сообщения JSON-RPC из потока SSE вышестоящего сервера:
// событие — до MaxMessage байт, событий — до maxEvents, всего — до
// maxBytes (0 — без предела байт). Событие без данных пропускается, но
// считается в пределе событий. Событие с
// типом, отличным от message, — ошибка: в MCP других типов нет.
type SSEReader struct {
	r         *sse.Reader
	count     *countingReader
	events    int
	maxEvents int
}

// NewSSEReader — чтение потока r с пределами.
func NewSSEReader(r io.Reader, maxEvents int, maxBytes int64) *SSEReader {
	cr := &countingReader{r: r, max: maxBytes}
	return &SSEReader{r: sse.NewReader(cr, sse.Limits{MaxLine: MaxMessage, MaxEvent: MaxMessage}), count: cr,
		maxEvents: maxEvents}
}

// Next — следующее сообщение потока; конец потока — io.EOF.
func (s *SSEReader) Next() (*Message, error) {
	for {
		ev, err := s.r.Next()
		if err != nil {
			if s.count.over {
				return nil, ErrStreamTooLarge
			}
			return nil, err
		}
		s.events++
		if s.events > s.maxEvents {
			return nil, ErrTooManyEvents
		}
		if ev.Event != "" && ev.Event != "message" {
			return nil, invalid("событие SSE неизвестного типа")
		}
		if ev.Data == "" {
			// Событие без данных (priming-событие 2025-11-25 с одним id для
			// возобновления потока) — не сообщение; в предел событий входит.
			continue
		}
		return Parse([]byte(ev.Data), Limits(MaxMessage))
	}
}

// Events — прочитано событий.
func (s *SSEReader) Events() int { return s.events }

type countingReader struct {
	r    io.Reader
	n    int64
	max  int64
	over bool
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.max > 0 {
		if c.n >= c.max {
			c.over = true
			return 0, ErrStreamTooLarge
		}
		if rest := c.max - c.n; int64(len(p)) > rest {
			p = p[:rest]
		}
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ParseSSE читает поток целиком (тесты и fuzz): сообщения по порядку.
func ParseSSE(data io.Reader) ([]*Message, error) {
	r := NewSSEReader(data, MaxEvents, MaxStream)
	var out []*Message
	for {
		m, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, m)
	}
}

// SSEData — сообщение для поля data события SSE: компактная запись без
// переводов строки (AppendJSON экранирует их в строках).
func SSEData(v argschema.Value) string { return string(AppendJSON(nil, v)) }
