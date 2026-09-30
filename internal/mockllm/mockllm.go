// Пакет mockllm — OpenAI-совместимый мок провайдера LLM для разработки и
// e2e-тестов (ТЗ, 11.5). В поставку не входит.
//
// Сценарий выбирается заголовком X-Mock-Scenario или именем модели
// «mock-<сценарий>»:
//   - echo (по умолчанию) — ответ повторяет последнее сообщение пользователя;
//   - fixed — постоянный ответ;
//   - stream-slow — как echo, но при потоковой передаче с паузами между частями;
//   - error-500, error-429 — ошибка провайдера в формате OpenAI;
//   - hang — не отвечает, пока клиент не закроет соединение (проверка таймаутов).
//
// «Вредоносные» сценарии (канарейка, exfil-ссылки, tool_calls) появляются на
// этапе 1 вместе с детекторами.
package mockllm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Ограничения.
const (
	MaxBodyBytes   = 1 << 20
	MaxMessages    = 256
	HangLimit      = 5 * time.Minute
	FixedAnswer    = "Это постоянный ответ mock-llm."
	ScenarioHeader = "X-Mock-Scenario"
)

// Сценарии.
const (
	ScenarioEcho       = "echo"
	ScenarioFixed      = "fixed"
	ScenarioStreamSlow = "stream-slow"
	ScenarioError500   = "error-500"
	ScenarioError429   = "error-429"
	ScenarioHang       = "hang"
)

var scenarios = []string{ScenarioEcho, ScenarioFixed, ScenarioStreamSlow, ScenarioError500, ScenarioError429, ScenarioHang}

// Server — обработчик mock-llm.
type Server struct {
	logger *slog.Logger
	now    func() time.Time
	// ChunkDelay — пауза между частями в сценарии stream-slow.
	ChunkDelay time.Duration
	seq        atomic.Uint64
}

// New создаёт обработчик.
func New(logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{logger: logger, now: time.Now, ChunkDelay: 50 * time.Millisecond}
}

// Handler возвращает маршруты mock-llm.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/models", s.models)
	mux.HandleFunc("POST /v1/chat/completions", s.chat)
	return mux
}

type model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

func (s *Server) models(w http.ResponseWriter, _ *http.Request) {
	data := make([]model, 0, len(scenarios))
	for _, sc := range scenarios {
		data = append(data, model{ID: "mock-" + sc, Object: "model", Created: 0, OwnedBy: "aisec-mock"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// ChatRequest — нужная моку часть запроса OpenAI.
type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

// Message — сообщение диалога; content — строка или массив частей.
type Message struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type contentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Text извлекает текст сообщения: строку или текстовые части массива.
func (m Message) Text() (string, error) {
	if len(m.Content) == 0 || string(m.Content) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil {
		return s, nil
	}
	var parts []contentPart
	if err := json.Unmarshal(m.Content, &parts); err != nil {
		return "", errors.New("content — строка или массив частей")
	}
	var b strings.Builder
	for _, p := range parts {
		if p.Type == "text" {
			b.WriteString(p.Text)
		}
	}
	return b.String(), nil
}

// ParseChatRequest разбирает и проверяет тело запроса.
func ParseChatRequest(body []byte) (*ChatRequest, error) {
	var req ChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errors.New("тело запроса — не JSON объекта запроса")
	}
	if req.Model == "" {
		return nil, errors.New("не указана модель")
	}
	if len(req.Messages) == 0 || len(req.Messages) > MaxMessages {
		return nil, fmt.Errorf("число сообщений должно быть от 1 до %d", MaxMessages)
	}
	for i, m := range req.Messages {
		switch m.Role {
		case "system", "user", "assistant", "tool", "developer":
		default:
			return nil, fmt.Errorf("messages[%d]: неизвестная роль", i)
		}
		if _, err := m.Text(); err != nil {
			return nil, fmt.Errorf("messages[%d]: %w", i, err)
		}
	}
	return &req, nil
}

// scenarioOf выбирает сценарий по заголовку или имени модели.
func scenarioOf(r *http.Request, req *ChatRequest) (string, bool) {
	sc := r.Header.Get(ScenarioHeader)
	if sc == "" {
		sc = strings.TrimPrefix(req.Model, "mock-")
		if sc == req.Model {
			sc = ScenarioEcho // любая другая модель — эхо
		}
	}
	for _, known := range scenarios {
		if sc == known {
			return sc, true
		}
	}
	return "", false
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(w, r)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "тело запроса больше допустимого", "invalid_request_error", "request_too_large")
			return
		}
		writeError(w, http.StatusBadRequest, "не удалось прочитать тело запроса", "invalid_request_error", "invalid_request")
		return
	}
	req, err := ParseChatRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_request")
		return
	}
	sc, ok := scenarioOf(r, req)
	if !ok {
		writeError(w, http.StatusBadRequest, "неизвестный сценарий mock-llm", "invalid_request_error", "unknown_scenario")
		return
	}
	// Содержимое сообщений в лог не пишется — только метаданные.
	s.logger.Info("запрос", "scenario", sc, "stream", req.Stream, "messages", len(req.Messages))

	switch sc {
	case ScenarioError500:
		writeError(w, http.StatusInternalServerError, "внутренняя ошибка провайдера (mock)", "server_error", "internal_error")
		return
	case ScenarioError429:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "превышен лимит запросов (mock)", "rate_limit_error", "rate_limit_exceeded")
		return
	case ScenarioHang:
		select {
		case <-r.Context().Done():
		case <-time.After(HangLimit):
		}
		return
	}

	answer := FixedAnswer
	if sc != ScenarioFixed {
		answer = lastUserText(req.Messages)
	}
	id := fmt.Sprintf("chatcmpl-mock-%d", s.seq.Add(1))
	if req.Stream {
		delay := time.Duration(0)
		if sc == ScenarioStreamSlow {
			delay = s.ChunkDelay
		}
		s.stream(w, r, id, req.Model, answer, delay)
		return
	}
	prompt := 0
	for _, m := range req.Messages {
		prompt += countTokens(textOrEmpty(m))
	}
	completion := countTokens(answer)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "object": "chat.completion", "created": s.now().Unix(), "model": req.Model,
		"choices": []map[string]any{{
			"index": 0, "finish_reason": "stop",
			"message": map[string]string{"role": "assistant", "content": answer},
		}},
		"usage": map[string]int{"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion},
	})
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request, id, modelName, answer string, delay time.Duration) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "потоковая передача не поддерживается", "server_error", "no_streaming")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	created := s.now().Unix()
	send := func(delta map[string]string, finish any) bool {
		chunk := map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created, "model": modelName,
			"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": finish}},
		}
		b, err := json.Marshal(chunk)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !send(map[string]string{"role": "assistant"}, nil) {
		return
	}
	for _, part := range SplitChunks(answer) {
		if delay > 0 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(delay):
			}
		}
		if !send(map[string]string{"content": part}, nil) {
			return
		}
	}
	if !send(map[string]string{}, "stop") {
		return
	}
	if _, err := fmt.Fprint(w, "data: [DONE]\n\n"); err == nil {
		flusher.Flush()
	}
}

// SplitChunks делит ответ на части по словам, сохраняя пробелы: склейка
// частей даёт исходный текст.
func SplitChunks(s string) []string {
	var out []string
	start := 0
	for i, r := range s {
		if r == ' ' && i > start {
			out = append(out, s[start:i])
			start = i
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func lastUserText(msgs []Message) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return textOrEmpty(msgs[i])
		}
	}
	return ""
}

// textOrEmpty — текст сообщения, уже проверенного ParseChatRequest.
func textOrEmpty(m Message) string {
	t, err := m.Text()
	if err != nil {
		return ""
	}
	return t
}

// countTokens — грубая оценка: число слов. Моку точность не нужна.
func countTokens(s string) int { return len(strings.Fields(s)) }

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return // клиент ушёл; писать больше некуда
	}
}

// writeError отвечает ошибкой в формате OpenAI.
func writeError(w http.ResponseWriter, status int, msg, typ, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"message": msg, "type": typ, "code": code}})
}
