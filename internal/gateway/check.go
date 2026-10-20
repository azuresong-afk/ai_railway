package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Check API — POST /guard/v1/check (ТЗ, 5.1): проверка текста по политике
// приложения без обращения к модели. Нужен приложениям, которые ходят к
// модели напрямую, и для документов RAG и ответов инструментов (DM-07).
// Проверка идёт тем же конвейером, что и чат (inspect), с endpoint=check.

// CheckHandler обслуживает POST /guard/v1/check. Зависимости — те же, что у
// чата: события, квоты, ключ псевдонима пользователя.
type CheckHandler struct{ h *ChatHandler }

// NewCheckHandler проверяет параметры (те же, что у NewChatHandler).
func NewCheckHandler(cfg ChatConfig) (*CheckHandler, error) {
	h, err := NewChatHandler(cfg)
	if err != nil {
		return nil, err
	}
	return &CheckHandler{h: h}, nil
}

// checkRequest — тело запроса. Ровно одно из text и messages.
type checkRequest struct {
	Direction string         `json:"direction"`
	Source    string         `json:"source,omitempty"`
	Text      *string        `json:"text,omitempty"`
	Messages  []checkMessage `json:"messages,omitempty"`
	User      string         `json:"user,omitempty"`
}

// checkMessage — сообщение для проверки; содержимое — только строка.
type checkMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// checkFinding — находка в ответе: без найденного значения, только место.
type checkFinding struct {
	Detector string  `json:"detector"`
	Category string  `json:"category"`
	Score    float64 `json:"score"`
	Start    int     `json:"start"`
	End      int     `json:"end"`
	Location string  `json:"location"`
	Threat   string  `json:"threat,omitempty"`
}

// checkResponse — ответ Check API.
type checkResponse struct {
	// ID — идентификатор события check.
	ID string `json:"id"`
	// Decision — что сделано с текстом: allow, log, redact, pseudonymize, block.
	// Action — решение политики как в режиме enforce (в monitor может
	// отличаться от Decision). Blocked — текст использовать нельзя.
	Decision string `json:"decision"`
	Action   string `json:"action"`
	Blocked  bool   `json:"blocked"`
	Message  string `json:"message,omitempty"`
	// Incomplete — часть детекторов не дала результата, а приложение
	// настроено на fail_open: проверка неполная.
	Incomplete bool `json:"incomplete,omitempty"`
	// Unchecked — у политики нет ни одного правила для этого направления:
	// ни один детектор не запускался, «allow» не означает «проверено».
	Unchecked bool           `json:"unchecked,omitempty"`
	Findings  []checkFinding `json:"findings"`
	Truncated bool           `json:"findings_truncated,omitempty"`
	// Text и Messages — преобразованный вход (после redact); при блокировке
	// не возвращаются.
	Text     *string        `json:"text,omitempty"`
	Messages []checkMessage `json:"messages,omitempty"`
}

var checkRoles = map[string]bool{"system": true, "user": true, "assistant": true, "tool": true}

// parseCheck разбирает тело запроса и сводит его к фрагментам.
func parseCheck(body []byte, maxMessages int) (*checkRequest, detect.Direction, []inspectText, *chat.Error) {
	var r checkRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, "", nil, &chat.Error{Code: chat.CodeInvalid, Message: "тело запроса — не объект запроса Check API"}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, "", nil, &chat.Error{Code: chat.CodeInvalid, Message: "данные после объекта JSON"}
	}
	var dir detect.Direction
	switch r.Direction {
	case string(detect.Input):
		dir = detect.Input
	case string(detect.Output):
		dir = detect.Output
	default:
		return nil, "", nil, &chat.Error{Code: chat.CodeInvalid, Message: "direction: input или output"}
	}
	src := detect.Source(r.Source)
	switch {
	case src == "image" || src == "audio":
		return nil, "", nil, &chat.Error{Code: chat.CodeUnsupported, Message: "source: изображения и аудио Check API пока не принимает"}
	case src == "":
	case dir == detect.Input && (src == detect.SourceUser || src == detect.SourceRAG || src == detect.SourceTool):
	case dir == detect.Output && src == detect.SourceOutput:
	default:
		return nil, "", nil, &chat.Error{Code: chat.CodeInvalid, Message: "source: user, rag или tool для input, output для output"}
	}
	if (r.Text == nil) == (len(r.Messages) == 0) {
		return nil, "", nil, &chat.Error{Code: chat.CodeInvalid, Message: "нужно ровно одно из text и messages"}
	}
	if len(r.User) > 256 {
		return nil, "", nil, &chat.Error{Code: chat.CodeInvalid, Message: "user: не длиннее 256 байт"}
	}
	pick := func(role string) detect.Source {
		switch {
		case src != "":
			return src
		case dir == detect.Output:
			return detect.SourceOutput
		case role == "tool":
			return detect.SourceTool
		}
		return detect.SourceUser
	}
	if r.Text != nil {
		if *r.Text == "" || !utf8.ValidString(*r.Text) {
			return nil, "", nil, &chat.Error{Code: chat.CodeInvalid, Message: "text: непустая строка UTF-8"}
		}
		return &r, dir, []inspectText{{Text: *r.Text, Source: pick(""), Location: "text"}}, nil
	}
	if maxMessages <= 0 {
		maxMessages = chat.DefaultLimits.MaxMessages
	}
	if len(r.Messages) > maxMessages {
		return nil, "", nil, &chat.Error{Code: chat.CodeTooMany, Message: fmt.Sprintf("messages: больше %d сообщений", maxMessages)}
	}
	texts := make([]inspectText, len(r.Messages))
	for i, m := range r.Messages {
		if !checkRoles[m.Role] || m.Content == "" || !utf8.ValidString(m.Content) {
			return nil, "", nil, &chat.Error{Code: chat.CodeInvalid, Message: fmt.Sprintf("messages[%d]: role system, user, assistant или tool и непустая строка content", i)}
		}
		texts[i] = inspectText{Text: m.Content, Source: pick(m.Role), Location: fmt.Sprintf("messages[%d].content", i)}
	}
	return &r, dir, texts, nil
}

// ServeHTTP проверяет текст по политике приложения. Блокировка политикой —
// ответ 200 с blocked: true (Check API — вопрос о тексте, а не прокси);
// сбой проверки при fail_closed — 503, как в чате.
func (c *CheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := c.h
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
	req, dir, texts, cerr := parseCheck(body, app.Limits.MaxMessages)
	if cerr != nil {
		WriteError(w, http.StatusBadRequest, cerr.Message, "invalid_request_error", cerr.Code)
		return
	}
	user, ok := h.user(w, r, app, req.User)
	if !ok {
		return
	}
	rec, ok := h.newEventRecord(w, app, events.TypeCheck, "", false, user, start)
	if !ok {
		return
	}
	defer h.emit(rec)
	rec.output = dir == detect.Output
	rec.ev.Source = req.Source
	switch {
	case rec.ev.Source != "":
	case dir == detect.Output:
		rec.ev.Source = string(detect.SourceOutput)
	default:
		rec.ev.Source = string(detect.SourceUser)
	}
	size := 0
	for _, t := range texts {
		size += len(t.Text)
	}
	// Токены модели Check API не тратит: учитываются частота и размер.
	if !h.admitSize(w, r, rec, user, size, 0) {
		return
	}
	checkStart := h.cfg.Now()
	in, err := app.inspect(r.Context(), inspectRequest{
		Endpoint: policy.EndpointCheck, Direction: dir, External: app.Provider.External(), Texts: texts,
		Mask: app.Storage == events.StorageMasked, Timeout: h.cfg.DetectorTimeout,
	})
	rec.ev.LatencyMS["input_check"] = h.cfg.Now().Sub(checkStart).Milliseconds()
	switch {
	case err != nil && r.Context().Err() != nil:
		rec.skip = true
		h.logger.Info("клиент прервал запрос во время проверки", "path", r.URL.Path)
		return
	case err != nil:
		h.logger.Error("проверка текста не выполнена", "app", app.ID, "event_id", rec.ev.ID, "error", err)
		rec.failClosed()
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
		return
	}
	rec.in, rec.texts = in, texts
	if len(in.Failures) > 0 {
		h.logger.Warn("сбой детекторов при проверке текста", "app", app.ID, "event_id", rec.ev.ID,
			"failures", len(in.Failures), "fail_open", app.FailOpen)
	}
	w.Header().Set(HeaderDecision, in.headerDecision())
	if in.FailBlock {
		WriteError(w, http.StatusServiceUnavailable, "текст не удалось проверить, повторите позже", "service_unavailable", "check_unavailable")
		return
	}
	resp := checkResponse{
		ID: rec.ev.ID, Decision: in.headerDecision(), Action: string(in.Decision.Action), Blocked: in.Decision.Block,
		Incomplete: len(in.Failures) > 0, Findings: []checkFinding{},
		Unchecked: len(app.Policy.Detectors(dir)) == 0,
	}
	for i, f := range in.Findings {
		if i >= maxEventFindings {
			resp.Truncated = true
			break
		}
		resp.Findings = append(resp.Findings, checkFinding{Detector: f.Detector, Category: f.Category, Score: f.Score,
			Start: f.Start, End: f.End, Location: texts[f.Text].Location, Threat: f.Threat})
	}
	if resp.Blocked {
		resp.Message = in.Decision.Message
		writeJSON(w, http.StatusOK, resp)
		return
	}
	out := make([]string, len(texts))
	for i, t := range texts {
		out[i] = t.Text
		if i < len(in.Changed) && in.Changed[i] {
			out[i] = in.Texts[i]
		}
	}
	if req.Text != nil {
		resp.Text = &out[0]
	} else {
		resp.Messages = make([]checkMessage, len(out))
		for i, m := range req.Messages {
			resp.Messages[i] = checkMessage{Role: m.Role, Content: out[i]}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
