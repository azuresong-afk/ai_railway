package api

import (
	"errors"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
)

// incidentSettingsRoutes — срок хранения закрытых инцидентов (3Н37 ревью
// 3.r2, ADR-0020, п. 5). Сокращение необратимо удаляет инциденты вместе с
// оповещениями и комментариями: повторная проверка паролем или кодом и
// weakening в аудите (DM-40), как у оповещений.
func incidentSettingsRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/incident-settings", Permission: auth.PermIncidentsRead,
			Handler: needIncidents(d, d.getIncidentSettings)},
		{Method: http.MethodPut, Path: "/api/v1/incident-settings", Permission: auth.PermIncidentCategoriesManage,
			MaxBody: smallMaxBody, Handler: needIncidents(d, d.putIncidentSettings)},
	}
}

func (d Deps) getIncidentSettings(w http.ResponseWriter, r *http.Request) {
	st, err := d.Incidents.Retention(r.Context())
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, st)
}

type incidentSettingsRequest struct {
	RetentionDays int `json:"retention_days"`
	reauthFields
}

func (d Deps) putIncidentSettings(w http.ResponseWriter, r *http.Request) {
	by, ok := d.incidentsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req incidentSettingsRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by.Confirm = d.confirmFunc(r, req.reauthFields, "incident.settings_changed", incidents.ErrConfirmRequired)
	st, err := d.Incidents.SetRetention(r.Context(), by, req.RetentionDays)
	if errors.Is(err, incidents.ErrNotSetUp) {
		WriteProblem(w, NewProblem(http.StatusConflict, CodeConflict, "Первичная настройка не выполнена: срок хранения пока не меняется."))
		return
	}
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, st)
}
