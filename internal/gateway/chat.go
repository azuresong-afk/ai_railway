package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/providers"
	"github.com/azuresong-afk/ai_railway/internal/sse"
)

// ChatConfig — параметры обработчика POST /v1/chat/completions.
type ChatConfig struct {
	Router       *Router
	MaxBodyBytes int64
	Logger       *slog.Logger
	// BodyReadTimeout — предел времени на чтение тела запроса: медленная
	// передача тела не должна занимать соединения. Ноль — DefaultBodyReadTimeout.
	BodyReadTimeout time.Duration
}

// DefaultBodyReadTimeout — время на чтение тела запроса по умолчанию.
const DefaultBodyReadTimeout = 30 * time.Second

// ChatHandler разбирает запрос приложения, выбирает провайдера и модель и
// отдаёт ответ. И запрос, и ответ собираются заново из разобранной модели:
// провайдер и приложение получают только то, что видели проверки.
type ChatHandler struct {
	cfg    ChatConfig
	logger *slog.Logger
}

// NewChatHandler проверяет параметры.
func NewChatHandler(cfg ChatConfig) (*ChatHandler, error) {
	if cfg.Router == nil || cfg.MaxBodyBytes <= 0 {
		return nil, errors.New("chat: не заданы маршруты или предел размера тела")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.BodyReadTimeout <= 0 {
		cfg.BodyReadTimeout = DefaultBodyReadTimeout
	}
	return &ChatHandler{cfg: cfg, logger: cfg.Logger}, nil
}

// readBody читает тело с пределом размера и времени. При ошибке ответ уже
// записан.
func (h *ChatHandler) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		WriteError(w, http.StatusUnsupportedMediaType, "ожидается Content-Type: application/json", "invalid_request_error", "unsupported_media_type")
		return nil, false
	}
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(h.cfg.BodyReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		h.logger.Warn("не удалось ограничить время чтения тела", "error", err)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes))
	// После чтения тела срок снимается: дальше соединение нужно для ответа,
	// в том числе долгого потокового.
	if derr := rc.SetReadDeadline(time.Time{}); derr != nil && !errors.Is(derr, http.ErrNotSupported) {
		h.logger.Warn("не удалось снять срок чтения", "error", derr)
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		var ne net.Error
		switch {
		case errors.As(err, &tooLarge):
			WriteError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("тело запроса больше %d байт", h.cfg.MaxBodyBytes), "invalid_request_error", "request_too_large")
		case errors.As(err, &ne) && ne.Timeout():
			WriteError(w, http.StatusRequestTimeout, "тело запроса передавалось слишком долго", "invalid_request_error", "request_timeout")
		default:
			WriteError(w, http.StatusBadRequest, "не удалось прочитать тело запроса", "invalid_request_error", "invalid_request")
		}
		return nil, false
	}
	if !isJSONObject(body) {
		WriteError(w, http.StatusBadRequest, "тело запроса — не объект JSON", "invalid_request_error", "invalid_request")
		return nil, false
	}
	return body, true
}

func isJSONObject(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '{' && json.Valid(b)
}

// ServeHTTP обрабатывает POST /v1/chat/completions.
func (h *ChatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	app, ok := h.cfg.Router.app(r)
	if !ok {
		WriteError(w, http.StatusForbidden, "приложение не настроено", "invalid_request_error", "app_not_configured")
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	req, err := chat.Parse(body, app.Limits)
	if err != nil {
		var ce *chat.Error
		if !errors.As(err, &ce) {
			ce = &chat.Error{Code: chat.CodeInvalid, Message: "неверный запрос"}
		}
		WriteError(w, http.StatusBadRequest, ce.Message, "invalid_request_error", ce.Code)
		return
	}
	requested := req.Model
	model, ok := app.Resolve(requested)
	if !ok {
		// Неразрешённая модель (DM-33): список разрешённых — в GET /v1/models.
		WriteError(w, http.StatusNotFound, "модель недоступна для приложения", "invalid_request_error", "model_not_found")
		return
	}
	req.Model = model
	if app.Provider.External() {
		// Идентификатор пользователя (часто e-mail или ФИО) внешнему
		// провайдеру не передаётся (ТЗ, 5.4).
		req.User = ""
	}
	if req.Stream {
		h.stream(w, r, app, req, requested)
		return
	}
	resp, meta, err := app.Provider.Chat(r.Context(), req)
	copyMeta(w, meta)
	if err != nil {
		h.providerError(w, r, err)
		return
	}
	// Приложение видит то имя модели, которое запросило (в том числе
	// псевдоним), а не имя у провайдера (DM-33).
	resp.Model = requested
	writeJSON(w, http.StatusOK, resp)
}

func copyMeta(w http.ResponseWriter, m providers.Meta) {
	for k, v := range m.Header {
		w.Header()[k] = v
	}
}

// providerError отвечает приложению по классу ошибки провайдера.
func (h *ChatHandler) providerError(w http.ResponseWriter, r *http.Request, err error) {
	var pe *providers.Error
	switch {
	case r.Context().Err() != nil:
		h.logger.Info("клиент прервал запрос", "path", r.URL.Path)
	case errors.As(err, &pe):
		WriteError(w, pe.Status, pe.Message, pe.Type, pe.Code)
	case errors.Is(err, providers.ErrAuth):
		WriteError(w, http.StatusBadGateway, "провайдер модели отклонил учётные данные шлюза", "upstream_error", "upstream_auth_error")
	case errors.Is(err, providers.ErrTimeout):
		WriteError(w, http.StatusGatewayTimeout, "провайдер модели не ответил вовремя", "upstream_error", "upstream_timeout")
	case errors.Is(err, providers.ErrBadResponse):
		WriteError(w, http.StatusBadGateway, "ответ провайдера модели не разобран", "upstream_error", "upstream_bad_response")
	default:
		WriteError(w, http.StatusBadGateway, "провайдер модели недоступен", "upstream_error", "upstream_unavailable")
	}
}

// stream передаёт потоковый ответ: каждая часть разбирается и собирается
// заново, неизвестные поля провайдера приложению не уходят.
func (h *ChatHandler) stream(w http.ResponseWriter, r *http.Request, app *App, req *chat.Request, requested string) {
	st, meta, err := app.Provider.Stream(r.Context(), req)
	copyMeta(w, meta)
	if err != nil {
		h.providerError(w, r, err)
		return
	}
	defer func() {
		if cerr := st.Close(); cerr != nil {
			h.logger.Debug("закрытие потока провайдера", "error", providers.ErrorClass(cerr))
		}
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	send := func(data []byte) bool {
		if err := sse.Write(w, sse.Event{Data: string(data)}); err != nil {
			return false // клиент ушёл
		}
		return rc.Flush() == nil
	}
	for {
		c, err := st.Next()
		if errors.Is(err, io.EOF) {
			send([]byte(chat.Done))
			return
		}
		if err != nil {
			if r.Context().Err() != nil {
				h.logger.Info("клиент прервал поток", "path", r.URL.Path)
				return
			}
			h.logger.Warn("поток провайдера прерван", "provider", app.Provider.ID(), "error", errorKind(err))
			// Ошибка внутри потока — событием с объектом error, как у OpenAI;
			// завершающего [DONE] нет: приложение видит, что ответ неполный.
			send(streamErrorBody(err))
			return
		}
		c.Model = requested
		data, err := json.Marshal(c)
		if err != nil || !send(data) {
			return
		}
	}
}

func errorKind(err error) string {
	var pe *providers.Error
	if errors.As(err, &pe) {
		return fmt.Sprintf("ошибка провайдера %d", pe.Status)
	}
	return providers.ErrorClass(err)
}

func streamErrorBody(err error) []byte {
	msg, code := "поток провайдера модели прерван", "upstream_stream_error"
	var pe *providers.Error
	if errors.As(err, &pe) {
		msg, code = pe.Message, pe.Code
	}
	b, merr := json.Marshal(map[string]any{"error": map[string]any{"message": msg, "type": "upstream_error", "code": code}})
	if merr != nil {
		return []byte(`{"error":{"message":"поток прерван","type":"upstream_error","code":"upstream_stream_error"}}`)
	}
	return b
}
