package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

const promptBaselineNotFound = "Эталон системного промпта не задан."

// promptBaselineRoutes — эталон системного промпта приложения (ТЗ 5.4,
// DM-26; задача 4.14 этапа 4). Всё — под правом applications.policy: текст
// эталона показывается и меняется только им, понижение режима и снятие —
// ослабление с повторной проверкой (пароль или код в теле запроса).
func promptBaselineRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/applications/{id}/prompt-baseline", Permission: auth.PermApplicationsPolicy,
			Handler: needApps(d, d.getPromptBaseline)},
		{Method: http.MethodPut, Path: "/api/v1/applications/{id}/prompt-baseline", Permission: auth.PermApplicationsPolicy,
			MaxBody: appMaxBody, Handler: needApps(d, d.setPromptBaseline)},
		{Method: http.MethodDelete, Path: "/api/v1/applications/{id}/prompt-baseline", Permission: auth.PermApplicationsPolicy,
			MaxBody: smallMaxBody, Handler: needApps(d, d.deletePromptBaseline)},
	}
}

// PromptBaselineView — эталон системного промпта. Configured = false —
// эталона нет.
type PromptBaselineView struct {
	Configured bool `json:"configured"`
	// Mode — off, alert или block.
	Mode string `json:"mode,omitempty"`
	// Hash — хеш нормализованного текста: он же в пакете конфигурации.
	Hash      string     `json:"hash,omitempty"`
	Bytes     int        `json:"bytes,omitempty"`
	Text      string     `json:"text,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func promptBaselineView(b apps.PromptBaseline, text string) PromptBaselineView {
	up := b.UpdatedAt.UTC()
	return PromptBaselineView{Configured: true, Mode: b.Mode, Hash: b.Hash, Bytes: b.Size, Text: text, UpdatedAt: &up}
}

// promptBaselineProblem — ошибки эталона; остальное — appsProblem.
func (d Deps) promptBaselineProblem(err error) *Problem {
	switch {
	case errors.Is(err, apps.ErrNoPromptBaseline):
		return NewProblem(http.StatusNotFound, CodeNotFound, promptBaselineNotFound)
	case errors.Is(err, apps.ErrNoDataKey):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Ключ данных не подключён: эталон системного промпта недоступен. Выполните aisec-cli init и перезапустите сервер.")
	case errors.Is(err, apps.ErrArchived):
		return NewProblem(http.StatusConflict, CodeConflict, "Приложение в архиве: эталон ему задать нельзя.")
	}
	return appsProblem(d.Logger, err, appNotFound)
}

func (d Deps) getPromptBaseline(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	b, err := d.Apps.PromptBaseline(r.Context(), id)
	switch {
	case errors.Is(err, apps.ErrNoPromptBaseline):
		WriteJSON(w, http.StatusOK, PromptBaselineView{})
		return
	case err != nil:
		WriteProblem(w, d.promptBaselineProblem(err))
		return
	}
	text, err := d.Apps.OpenPromptText(r.Context(), b)
	if err != nil {
		WriteProblem(w, d.promptBaselineProblem(err))
		return
	}
	WriteJSON(w, http.StatusOK, promptBaselineView(b, text))
}

// PromptBaselineRequest — тело PUT: text не задан — текст прежний (смена
// режима).
type PromptBaselineRequest struct {
	Text *string `json:"text"`
	Mode string  `json:"mode"`
	reauthFields
}

func (d Deps) setPromptBaseline(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	var req PromptBaselineRequest
	if p := DecodeJSON(w, r, &req, appMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by = d.withConfirm(r, by, req.reauthFields, "application.prompt_baseline_set")
	b, err := d.Apps.SetPromptBaseline(r.Context(), by, id, apps.PromptBaselineInput{Text: req.Text, Mode: req.Mode})
	if err != nil {
		WriteProblem(w, d.promptBaselineProblem(err))
		return
	}
	text, err := d.Apps.OpenPromptText(r.Context(), b)
	if err != nil {
		WriteProblem(w, d.promptBaselineProblem(err))
		return
	}
	WriteJSON(w, http.StatusOK, promptBaselineView(b, text))
}

func (d Deps) deletePromptBaseline(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	// Тело необязательно: пароль или код нужны, только если эталон
	// действует (снятие — ослабление).
	var re reauthFields
	if r.ContentLength != 0 {
		if p := DecodeJSON(w, r, &re, smallMaxBody); p != nil {
			WriteProblem(w, p)
			return
		}
	}
	by = d.withConfirm(r, by, re, "application.prompt_baseline_removed")
	if _, err := d.Apps.DeletePromptBaseline(r.Context(), by, id); err != nil {
		WriteProblem(w, d.promptBaselineProblem(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
