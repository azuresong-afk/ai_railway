package api

import (
	"errors"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// alertSettingsRoutes — срок хранения закрытых оповещений (решение волны B
// этапа 3, ADR-0020). Сокращение необратимо удаляет оповещения: повторная
// проверка паролем или кодом и weakening в аудите (DM-40).
func alertSettingsRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/alert-settings", Permission: auth.PermAlertRulesRead,
			Handler: needAlerts(d, d.getAlertSettings)},
		{Method: http.MethodPut, Path: "/api/v1/alert-settings", Permission: auth.PermAlertRulesManage, MaxBody: smallMaxBody,
			Handler: needAlerts(d, d.putAlertSettings)},
	}
}

func (d Deps) getAlertSettings(w http.ResponseWriter, r *http.Request) {
	st, err := d.Alerts.Retention(r.Context())
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, ruleNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, st)
}

type alertSettingsRequest struct {
	RetentionDays int `json:"retention_days"`
	reauthFields
}

func (d Deps) putAlertSettings(w http.ResponseWriter, r *http.Request) {
	by, ok := d.alertsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req alertSettingsRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by.Confirm = d.confirmFunc(r, req.reauthFields, "alert.settings_changed", alerting.ErrConfirmRequired)
	st, err := d.Alerts.SetRetention(r.Context(), by, req.RetentionDays)
	if errors.Is(err, alerting.ErrNotSetUp) {
		WriteProblem(w, NewProblem(http.StatusConflict, CodeConflict, "Первичная настройка не выполнена: срок хранения пока не меняется."))
		return
	}
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, ruleNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, st)
}
