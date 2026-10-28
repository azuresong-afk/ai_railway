package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/quotalease"
)

// quotaSettingsRoutes — режим квот при нескольких шлюзах (ADR-0021, п. 2,
// задача 4.29): local — счётчики в памяти каждого шлюза, leased — аренда
// у сервера. Переход на local, когда на связи больше одного шлюза, —
// ослабление (DM-40): повторная проверка паролем или кодом и weakening в
// аудите.
func quotaSettingsRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/quota-settings", Permission: auth.PermBudgetsRead,
			Handler: needQuotas(d, d.getQuotaSettings)},
		{Method: http.MethodPut, Path: "/api/v1/quota-settings", Permission: auth.PermQuotaModeManage,
			MaxBody: smallMaxBody, Handler: needQuotas(d, d.putQuotaSettings)},
	}
}

func needQuotas(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Quotas == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Распределённые квоты не подключены."))
			return
		}
		h(w, r)
	}
}

func (d Deps) getQuotaSettings(w http.ResponseWriter, r *http.Request) {
	st, err := d.Quotas.Settings(r.Context())
	if err != nil {
		WriteProblem(w, quotaProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, st)
}

type quotaSettingsRequest struct {
	Mode string `json:"mode"`
	reauthFields
}

func (d Deps) putQuotaSettings(w http.ResponseWriter, r *http.Request) {
	a, ok := d.alertsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req quotaSettingsRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by := quotalease.By{Actor: a.Actor, IP: a.IP,
		Confirm: d.confirmFunc(r, req.reauthFields, "install.quota_mode_changed", quotalease.ErrConfirmRequired)}
	st, err := d.Quotas.SetMode(r.Context(), by, req.Mode)
	if err != nil {
		WriteProblem(w, quotaProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, st)
}

func quotaProblem(logger *slog.Logger, err error) *Problem {
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.Is(err, quotalease.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Переход на режим local при нескольких шлюзах на связи ослабляет квоты: выполните его в консоли с вводом текущего пароля или кода.")
	case errors.Is(err, quotalease.ErrInvalidMode):
		return Invalid("Проверьте введённые данные.", FieldError{"mode", "mode: local или leased"})
	case errors.Is(err, quotalease.ErrNotSetUp):
		return NewProblem(http.StatusConflict, CodeConflict, "Первичная настройка не выполнена: режим квот пока не меняется.")
	}
	logger.Error("режим квот", "class", "db", "error", err)
	return errInternal()
}
