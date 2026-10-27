package api

import (
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// userAccessRoutes — пользователь приложения по JWT корпоративного IdP и
// доступ к моделям по группам (ТЗ 4.3, 7.3 УПД.9, DM-33; задача 4.21 этапа
// 4, ADR-0025, раздел 4). Чтение — право applications.read (секретов в
// настройке нет; владелец — только своих приложений), изменение — applications.policy: это функция
// безопасности, ослабление — с повторной проверкой (пароль или код в теле).
func userAccessRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/applications/{id}/user-access", Permission: auth.PermApplicationsRead, Scoped: true,
			Handler: needApps(d, d.getUserAccess)},
		{Method: http.MethodPut, Path: "/api/v1/applications/{id}/user-access", Permission: auth.PermApplicationsPolicy,
			MaxBody: appMaxBody, Handler: needApps(d, d.setUserAccess)},
	}
}

// UserAccessView — настройка пользователя приложения. Configured = false —
// настройки нет, значения по умолчанию (режим off).
type UserAccessView struct {
	Configured bool `json:"configured"`
	// Mode — off (только X-AISec-User), optional (JWT или X-AISec-User),
	// required (JWT обязателен).
	Mode        string              `json:"mode"`
	Issuer      string              `json:"issuer"`
	Audience    string              `json:"audience"`
	GroupsClaim string              `json:"groups_claim"`
	Leeway      int                 `json:"leeway"`
	ModelGroups map[string][]string `json:"model_groups"`
	UpdatedAt   *time.Time          `json:"updated_at,omitempty"`
}

func userAccessView(u apps.UserAccess) UserAccessView {
	v := UserAccessView{Configured: u.Configured, Mode: u.Mode, Issuer: u.Issuer, Audience: u.Audience, GroupsClaim: u.GroupsClaim,
		Leeway: u.Leeway, ModelGroups: u.ModelGroups}
	if v.ModelGroups == nil {
		v.ModelGroups = map[string][]string{}
	}
	if u.Configured {
		up := u.UpdatedAt.UTC()
		v.UpdatedAt = &up
	}
	return v
}

func (d Deps) getUserAccess(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermApplicationsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	// Чужое приложение для владельца — как несуществующее.
	if _, err := d.Apps.Application(r.Context(), id, owner); err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	u, err := d.Apps.UserAccess(r.Context(), id)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, userAccessView(u))
}

// UserAccessRequest — тело PUT: настройка целиком; leeway не задан — 60 с,
// groups_claim пуст — groups.
type UserAccessRequest struct {
	Mode        string              `json:"mode"`
	Issuer      string              `json:"issuer"`
	Audience    string              `json:"audience"`
	GroupsClaim string              `json:"groups_claim"`
	Leeway      *int                `json:"leeway"`
	ModelGroups map[string][]string `json:"model_groups"`
	reauthFields
}

func (d Deps) setUserAccess(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	var req UserAccessRequest
	if p := DecodeJSON(w, r, &req, appMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by = d.withConfirm(r, by, req.reauthFields, "application.user_access_set")
	u, err := d.Apps.SetUserAccess(r.Context(), by, id, apps.UserAccessInput{Mode: req.Mode, Issuer: req.Issuer, Audience: req.Audience,
		GroupsClaim: req.GroupsClaim, Leeway: req.Leeway, ModelGroups: req.ModelGroups})
	if err != nil {
		WriteProblem(w, d.promptBaselineProblem(err))
		return
	}
	WriteJSON(w, http.StatusOK, userAccessView(u))
}
