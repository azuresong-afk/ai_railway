package gateway

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// EmbeddingsHandler обслуживает POST /v1/embeddings (ТЗ, 5.1): входной
// текст проходит тот же конвейер, что и чат, но допустимы только redact и
// block — из вектора псевдоним не восстановить, поэтому pseudonymize
// выполняется как redact (policy.EndpointEmbeddings, видно в трассировке).
type EmbeddingsHandler struct{ h *ChatHandler }

// NewEmbeddingsHandler проверяет параметры (те же, что у NewChatHandler).
func NewEmbeddingsHandler(cfg ChatConfig) (*EmbeddingsHandler, error) {
	h, err := NewChatHandler(cfg)
	if err != nil {
		return nil, err
	}
	return &EmbeddingsHandler{h: h}, nil
}

// ServeHTTP: пользователь, модель, квоты, входные детекторы и решение,
// провайдер — по шагам ТЗ, 4.3.
func (e *EmbeddingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := e.h
	start := h.cfg.Now()
	app, ok := h.cfg.Router.app(r)
	if !ok {
		h.cfg.Router.noApp(w, r)
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	req, err := chat.ParseEmbeddings(body)
	if err != nil {
		var ce *chat.Error
		if !errors.As(err, &ce) {
			ce = &chat.Error{Code: chat.CodeInvalid, Message: "неверный запрос"}
		}
		WriteError(w, http.StatusBadRequest, ce.Message, "invalid_request_error", ce.Code)
		return
	}
	emb, ok := app.Provider.(providers.Embedder)
	if !ok {
		WriteError(w, http.StatusNotImplemented, "провайдер приложения не поддерживает эмбеддинги", "invalid_request_error", "embeddings_not_supported")
		return
	}
	user, ok := h.user(w, r, app, req.User)
	if !ok {
		return
	}
	requested := req.Model
	model, allowed := app.Resolve(requested)
	rec, ok := h.newEventRecord(w, app, events.TypeGatewayRequest, model, false, user, start)
	if !ok {
		return
	}
	defer h.emit(rec)
	if !allowed {
		rec.ev.Model = requested
		rec.reject(ruleModel, "DM-33")
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusNotFound, "модель недоступна для приложения", "invalid_request_error", "model_not_found")
		return
	}
	req.Model = model
	texts := make([]inspectText, len(req.Input))
	size := 0
	for i, s := range req.Input {
		texts[i] = inspectText{Text: s, Source: detect.SourceUser, Location: fmt.Sprintf("input[%d]", i)}
		size += len(s)
	}
	if !h.admitSize(w, r, rec, user, size, estimateTokens(size)) {
		return
	}
	checkStart := h.cfg.Now()
	in, err := app.inspect(r.Context(), inspectRequest{
		Endpoint: policy.EndpointEmbeddings, External: app.Provider.External(), Texts: texts, User: user,
		Mask: app.Storage == events.StorageMasked, Timeout: h.cfg.DetectorTimeout,
	})
	rec.ev.LatencyMS["input_check"] = h.cfg.Now().Sub(checkStart).Milliseconds()
	switch {
	case err != nil && r.Context().Err() != nil:
		rec.skip = true
		h.logger.Info("клиент прервал запрос во время проверки", "path", r.URL.Path)
		return
	case err != nil:
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
		WriteError(w, http.StatusBadRequest, in.Decision.Message, "invalid_request_error", "policy_violation")
		return
	}
	for i, changed := range in.Changed {
		if changed {
			req.Input[i] = in.Texts[i]
		}
	}
	if app.Provider.External() {
		req.User = "" // идентификатор пользователя внешнему провайдеру не передаётся (ТЗ, 5.4)
	}
	rec.sent = true
	providerStart := h.cfg.Now()
	defer func() { rec.ev.LatencyMS["provider"] = h.cfg.Now().Sub(providerStart).Milliseconds() }()
	resp, meta, err := emb.Embeddings(r.Context(), req)
	copyMeta(w, meta)
	if err != nil {
		h.providerError(w, r, err)
		return
	}
	if u := resp.Usage; u != nil && max(u.PromptTokens, u.TotalTokens) > 0 {
		// Часть серверов заполняет только total_tokens: у эмбеддингов это вход.
		rec.usage(&chat.Usage{PromptTokens: max(u.PromptTokens, u.TotalTokens), TotalTokens: u.TotalTokens})
	} else {
		// Без usage или с нулями расход оценивается по размеру входа (задача 3.18).
		rec.inTokens = estimateTokens(size)
		rec.outBytes = func() int { return 0 }
	}
	resp.Model = requested
	writeJSON(w, http.StatusOK, resp)
}
