package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Настройки входа через каталог LDAP (ИАФ.7; ADR-0025, задача 4.16). Сам
// вход — обычный POST /api/v1/auth/login: при отсутствии локальной записи
// с таким логином сервер проверяет пароль в каталоге.

func ldapRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/auth/ldap", Permission: auth.PermAuthIdPRead, Handler: needAuth(d, d.getLDAP)},
		{Method: http.MethodPut, Path: "/api/v1/auth/ldap", Permission: auth.PermAuthIdPManage, MaxBody: idpMaxBody,
			Handler: needAuth(d, d.putLDAP)},
		{Method: http.MethodDelete, Path: "/api/v1/auth/ldap", Permission: auth.PermAuthIdPManage, MaxBody: authMaxBody,
			Handler: needAuth(d, d.deleteLDAP)},
	}
}

// LDAPView — настройки каталога без пароля сервисной учётной записи.
type LDAPView struct {
	Configured       bool            `json:"configured"`
	Enabled          bool            `json:"enabled"`
	URL              string          `json:"url"`
	CAPEM            string          `json:"ca_pem"`
	BindDN           string          `json:"bind_dn"`
	UserBaseDN       string          `json:"user_base_dn"`
	UserFilter       string          `json:"user_filter"`
	IDAttribute      string          `json:"id_attribute"`
	DisplayAttribute string          `json:"display_attribute"`
	GroupMode        string          `json:"group_mode"`
	GroupBaseDN      string          `json:"group_base_dn"`
	GroupRoles       []GroupRoleView `json:"group_roles"`
	Version          int             `json:"version,omitempty"`
	UpdatedAt        *time.Time      `json:"updated_at,omitempty"`
}

func ldapView(st auth.LDAPSettings) LDAPView {
	v := LDAPView{Configured: true, Enabled: st.Enabled, URL: st.URL, CAPEM: st.CAPEM, BindDN: st.BindDN,
		UserBaseDN: st.UserBaseDN, UserFilter: st.UserFilter, IDAttribute: st.IDAttribute,
		DisplayAttribute: st.DisplayAttribute, GroupMode: st.GroupMode, GroupBaseDN: st.GroupBaseDN,
		GroupRoles: []GroupRoleView{}, Version: st.Version}
	if !st.UpdatedAt.IsZero() {
		t := st.UpdatedAt
		v.UpdatedAt = &t
	}
	for _, g := range st.GroupRoles {
		v.GroupRoles = append(v.GroupRoles, GroupRoleView{Group: g.Group, Role: string(g.Role)})
	}
	return v
}

// ldapProblem — ответы для ошибок настроек каталога.
func ldapProblem(d Deps, err error) *Problem {
	switch {
	case errors.Is(err, auth.ErrLDAPNotConfigured):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Вход через каталог LDAP не настроен.")
	case errors.Is(err, auth.ErrLDAPUnavailable):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Вход через каталог LDAP недоступен: на сервере не загружен ключ данных. Обратитесь к администратору системы.")
	case errors.Is(err, auth.ErrExternalUser):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Настройки входа через каталог меняет только локальная учётная запись с паролем.")
	case errors.Is(err, auth.ErrRoleNotFound):
		return Invalid("Проверьте сопоставление групп.", FieldError{"group_roles", "Одной из ролей нет."})
	}
	return authProblem(d.Logger, err)
}

func (d Deps) getLDAP(w http.ResponseWriter, r *http.Request) {
	st, err := d.Auth.LDAP(r.Context())
	if errors.Is(err, auth.ErrLDAPNotConfigured) {
		WriteJSON(w, http.StatusOK, LDAPView{GroupRoles: []GroupRoleView{}})
		return
	}
	if err != nil {
		WriteProblem(w, ldapProblem(d, err))
		return
	}
	WriteJSON(w, http.StatusOK, ldapView(st))
}

type ldapRequest struct {
	Enabled          *bool           `json:"enabled"`
	URL              string          `json:"url"`
	CAPEM            string          `json:"ca_pem"`
	BindDN           string          `json:"bind_dn"`
	BindPassword     string          `json:"bind_password"`
	UserBaseDN       string          `json:"user_base_dn"`
	UserFilter       string          `json:"user_filter"`
	IDAttribute      string          `json:"id_attribute"`
	DisplayAttribute string          `json:"display_attribute"`
	GroupMode        string          `json:"group_mode"`
	GroupBaseDN      string          `json:"group_base_dn"`
	GroupRoles       []GroupRoleView `json:"group_roles"`
	reauthFields
}

func (d Deps) putLDAP(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req ldapRequest
	if p := DecodeJSON(w, r, &req, idpMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if req.Enabled == nil {
		WriteProblem(w, Invalid("Укажите, включён ли вход через каталог.", FieldError{"enabled", "Поле обязательно."}))
		return
	}
	in := auth.LDAPInput{Enabled: *req.Enabled, URL: req.URL, CAPEM: req.CAPEM, BindDN: req.BindDN,
		BindPassword: req.BindPassword, UserBaseDN: req.UserBaseDN, UserFilter: req.UserFilter,
		IDAttribute: req.IDAttribute, DisplayAttribute: req.DisplayAttribute, GroupMode: req.GroupMode,
		GroupBaseDN: req.GroupBaseDN}
	for _, g := range req.GroupRoles {
		in.GroupRoles = append(in.GroupRoles, auth.GroupRole{Group: g.Group, Role: auth.Role(g.Role)})
	}
	st, err := d.Auth.SetLDAP(r.Context(), c, in, req.Password, req.Code)
	if err != nil {
		WriteProblem(w, ldapProblem(d, err))
		return
	}
	WriteJSON(w, http.StatusOK, ldapView(st))
}

func (d Deps) deleteLDAP(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req reauthFields
	if p := DecodeJSON(w, r, &req, authMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if err := d.Auth.DeleteLDAP(r.Context(), c, req.Password, req.Code); err != nil {
		WriteProblem(w, ldapProblem(d, err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
