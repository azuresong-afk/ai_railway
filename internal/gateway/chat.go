package gateway

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/policy"
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
	// Events и IDs — события gateway_request (ТЗ, 5.5); обязательны.
	Events EventSink
	IDs    *ids.Generator
	// Quotas — квоты приложений (DM-15, DM-36); nil — без квот.
	Quotas *Limiter
	// UserMAC — имитовставка для псевдонима пользователя в событиях и
	// квотах (ТЗ, 5.5); nil — пользователь не учитывается.
	UserMAC aisecCrypto.MAC
	// DetectorTimeout — срок детектора на короткий текст; ноль —
	// DefaultDetectorTimeout. Срок растёт с длиной текста (pipeline.go).
	DetectorTimeout time.Duration
	// Now — часы для задержек в событии; по умолчанию time.Now.
	Now func() time.Time
}

// Заголовки шлюза (ТЗ, 5.1 и 4.3).
const (
	HeaderEventID  = "X-AISec-Event-Id"
	HeaderDecision = "X-AISec-Decision"
	HeaderUser     = "X-AISec-User"
)

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
	if cfg.Events == nil || cfg.IDs == nil {
		return nil, errors.New("chat: не заданы события: запрос без события не обрабатывается")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
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

// ServeHTTP обрабатывает POST /v1/chat/completions по шагам ТЗ, 4.3:
// пользователь, модель, квоты, входные детекторы и решение, провайдер.
// Событие gateway_request создаётся для каждого запроса, прошедшего разбор
// и проверку X-AISec-User; ошибки разбора событий не создают.
func (h *ChatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.cfg.Now()
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
	user, ok := h.user(w, r, app, req)
	if !ok {
		return
	}
	rec, ok := h.newRecord(w, app, req, user, start)
	if !ok {
		return
	}
	defer h.emit(rec)
	requested := req.Model
	model, ok := app.Resolve(requested)
	if !ok {
		// Неразрешённая модель (DM-33): список разрешённых — в GET /v1/models.
		rec.reject(ruleModel, "DM-33")
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusNotFound, "модель недоступна для приложения", "invalid_request_error", "model_not_found")
		return
	}
	req.Model = model
	rec.ev.Model = model
	texts, segs := requestTexts(req)
	if !h.admit(w, r, rec, req, user, texts) {
		return
	}
	checkStart := h.cfg.Now()
	in, err := app.inspect(r.Context(), inspectRequest{
		Endpoint: policy.EndpointChat, External: app.Provider.External(), Texts: texts, Media: policyMedia(req.Media()),
		Mask: app.Storage == events.StorageMasked, Timeout: h.cfg.DetectorTimeout,
	})
	rec.ev.LatencyMS["input_check"] = h.cfg.Now().Sub(checkStart).Milliseconds()
	switch {
	case err != nil && r.Context().Err() != nil:
		// Клиент ушёл до решения: отвечать некому, решения нет.
		rec.skip = true
		h.logger.Info("клиент прервал запрос во время проверки", "path", r.URL.Path)
		return
	case err != nil:
		// Ошибка сборки конвейера (детектор политики не найден) — запрос не
		// проверен и не уходит, независимо от fail_mode.
		h.logger.Error("проверка запроса не выполнена", "app", app.ID, "event_id", rec.ev.ID, "error", err)
		rec.failClosed()
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
		return
	}
	rec.in, rec.texts = in, texts
	if len(in.Failures) > 0 {
		h.logger.Warn("сбой детекторов при проверке запроса", "app", app.ID, "event_id", rec.ev.ID,
			"failures", len(in.Failures), "fail_open", app.FailOpen)
	}
	w.Header().Set(HeaderDecision, in.headerDecision())
	switch {
	case in.FailBlock:
		WriteError(w, http.StatusServiceUnavailable, "запрос не удалось проверить, повторите позже", "service_unavailable", "check_unavailable")
		return
	case in.Decision.Block:
		// Какие детекторы сработали, приложению не сообщается (ТЗ, 5.1).
		WriteError(w, http.StatusBadRequest, in.Decision.Message, "invalid_request_error", "policy_violation")
		return
	}
	for i, changed := range in.Changed {
		if !changed {
			continue
		}
		if err := req.SetText(segs[i], in.Texts[i]); err != nil {
			// Не удалось применить маскирование — запрос не уходит.
			h.logger.Error("маскирование не применено", "app", app.ID, "event_id", rec.ev.ID, "error", err)
			rec.failClosed()
			w.Header().Set(HeaderDecision, string(policy.Block))
			WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
			return
		}
	}
	if app.Provider.External() {
		// Идентификатор пользователя (часто e-mail или ФИО) внешнему
		// провайдеру не передаётся (ТЗ, 5.4).
		req.User = ""
	}
	rec.sent = true
	providerStart := h.cfg.Now()
	defer func() { rec.ev.LatencyMS["provider"] = h.cfg.Now().Sub(providerStart).Milliseconds() }()
	if req.Stream {
		h.stream(w, r, app, req, requested, rec)
		return
	}
	resp, meta, err := app.Provider.Chat(r.Context(), req)
	copyMeta(w, meta)
	if err != nil {
		h.providerError(w, r, err)
		return
	}
	rec.usage(resp.Usage)
	// Приложение видит то имя модели, которое запросило (в том числе
	// псевдоним), а не имя у провайдера (DM-33).
	resp.Model = requested
	writeJSON(w, http.StatusOK, resp)
}

// user — псевдоним конечного пользователя (ТЗ, 4.3, шаг 2; 5.5): HMAC
// идентификатора на ключе установки. Исходный идентификатор нигде не
// сохраняется. При ошибке ответ уже записан.
func (h *ChatHandler) user(w http.ResponseWriter, r *http.Request, app *App, req *chat.Request) (string, bool) {
	var id string
	switch app.UserFrom {
	case userFromHeader:
		vals := r.Header.Values(HeaderUser)
		if len(vals) > 1 {
			WriteError(w, http.StatusBadRequest, "заголовок X-AISec-User указан несколько раз", "invalid_request_error", "invalid_user")
			return "", false
		}
		if len(vals) == 1 {
			id = vals[0]
			if len(id) > maxUserIDLength || !utf8.ValidString(id) || strings.ContainsFunc(id, unicode.IsControl) {
				WriteError(w, http.StatusBadRequest, fmt.Sprintf("X-AISec-User — до %d байт без управляющих символов", maxUserIDLength),
					"invalid_request_error", "invalid_user")
				return "", false
			}
		}
	case userFromField:
		id = req.User // длину и состав проверил chat.Parse
	}
	if id == "" || h.cfg.UserMAC == nil {
		return "", true
	}
	return hex.EncodeToString(h.cfg.UserMAC.Sum([]byte(id))[:16]), true
}

// admit проверяет квоты (ТЗ, 4.3, шаг 3). При отказе ответ уже записан.
func (h *ChatHandler) admit(w http.ResponseWriter, r *http.Request, rec *record, req *chat.Request, user string, texts []inspectText) bool {
	if h.cfg.Quotas == nil {
		return true
	}
	// Размер входа — проверяемый текст и описания инструментов: они
	// тоже уходят модели (до 16 КиБ на инструмент).
	size := 0
	for _, t := range texts {
		size += len(t.Text)
	}
	for _, tl := range req.Tools {
		size += len(tl.Function.Description) + len(tl.Function.Parameters)
	}
	maxOut, _ := req.EffectiveMaxTokens()
	qr := QuotaRequest{App: rec.app.ID, User: user, InputBytes: size, Tokens: estimateTokens(size) + max(maxOut, 0)}
	if id, ok := IdentityFrom(r.Context()); ok {
		qr.Key = id.KeyPrefix
	}
	res, err := h.cfg.Quotas.Admit(qr)
	var ex *Exceeded
	switch {
	case err == nil:
		rec.res = res
		return true
	case errors.As(err, &ex):
		rec.reject(ruleQuotaPrefix+ex.Rule, ex.Threat)
		w.Header().Set(HeaderDecision, string(policy.Block))
		if ex.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((ex.RetryAfter+time.Second-1)/time.Second), 10))
		}
		WriteError(w, http.StatusTooManyRequests, "превышена квота приложения", "rate_limit_error", "quota_exceeded")
	default:
		// Приложения нет в квотах — ошибка сборки шлюза; не пропускаем.
		h.logger.Error("квоты не проверены", "app", rec.app.ID, "error", err)
		rec.failClosed()
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
	}
	return false
}

// estimateTokens — оценка токенов входа сверху для резерва квоты: около
// трёх байт на токен (русский текст в UTF-8 даёт больше байт на токен).
// После ответа резерв заменяется расходом из usage.
func estimateTokens(inputBytes int) int { return (inputBytes + 2) / 3 }

// requestTexts — текстовые фрагменты запроса для детекторов. Сообщения
// с ролью tool — источник tool (ответы инструментов, DM-07), остальное —
// user: системный промпт и история тоже приходят от приложения.
func requestTexts(req *chat.Request) ([]inspectText, []chat.Segment) {
	segs := req.Segments()
	texts := make([]inspectText, len(segs))
	for i, s := range segs {
		src := detect.SourceUser
		if s.Role == "tool" {
			src = detect.SourceTool
		}
		texts[i] = inspectText{Text: s.Text, Source: src, Location: s.Location()}
	}
	return texts, segs
}

// policyMedia — нетекстовые части для non_text. Ссылкой считается адрес
// изображения или видео, который загрузит провайдер; идентификатор файла у
// провайдера — нет.
func policyMedia(ms []chat.Media) []policy.MediaPart {
	out := make([]policy.MediaPart, 0, len(ms))
	for _, m := range ms {
		out = append(out, policy.MediaPart{Kind: m.Kind, URL: !m.Inline && (m.Kind == chat.MediaImage || m.Kind == chat.MediaVideo)})
	}
	return out
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
func (h *ChatHandler) stream(w http.ResponseWriter, r *http.Request, app *App, req *chat.Request, requested string, rec *record) {
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
		rec.usage(c.Usage)
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
