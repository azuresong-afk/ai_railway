package api

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// roleMaxBody — предел тела запросов ролей: каталог разрешений невелик.
const roleMaxBody = 16 << 10

// roleRoutes — роли и разрешения (УПД.1–2; задача 2.9).
func roleRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/permissions", Permission: auth.PermRolesRead, Handler: needAuth(d, d.listPermissions)},
		{Method: http.MethodGet, Path: "/api/v1/roles", Permission: auth.PermRolesRead, Handler: needAuth(d, d.listRoles)},
		{Method: http.MethodPost, Path: "/api/v1/roles", Permission: auth.PermRolesManage, MaxBody: roleMaxBody, Handler: needAuth(d, d.createRole)},
		{Method: http.MethodGet, Path: "/api/v1/roles/{id}", Permission: auth.PermRolesRead, Handler: needAuth(d, d.getRole)},
		{Method: http.MethodPut, Path: "/api/v1/roles/{id}", Permission: auth.PermRolesManage, MaxBody: roleMaxBody, Handler: needAuth(d, d.updateRole)},
		{Method: http.MethodDelete, Path: "/api/v1/roles/{id}", Permission: auth.PermRolesManage, Handler: needAuth(d, d.deleteRole)},
		{Method: http.MethodPut, Path: "/api/v1/users/{id}/role", Permission: auth.PermRolesManage, MaxBody: roleMaxBody, Handler: needAuth(d, d.assignRole)},
	}
}

// roleProblem переводит ошибки ролей; nil — ошибка не из ролей.
func roleProblem(err error) *Problem {
	switch {
	case errors.Is(err, auth.ErrRoleNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Роль не найдена.")
	case errors.Is(err, auth.ErrRoleTaken):
		return NewProblem(http.StatusConflict, CodeConflict, "Роль с таким ID уже есть: выберите другой ID.")
	case errors.Is(err, auth.ErrRoleInUse):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Роль назначена пользователям, в том числе деактивированным: сначала назначьте им другую роль.")
	case errors.Is(err, auth.ErrRoleBuiltin):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Предустановленную роль нельзя изменить или удалить: создайте свою роль на её основе.")
	case errors.Is(err, auth.ErrOwnRole):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Свою роль нельзя изменить или удалить: попросите другого администратора безопасности.")
	case errors.Is(err, auth.ErrTooManyRoles):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Достигнут предел своих ролей: удалите неиспользуемые.")
	}
	return nil
}

// PermissionView — разрешение каталога.
type PermissionView struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Group    string `json:"group"`
	Security bool   `json:"security"`
	Ownable  bool   `json:"ownable"`
}

// GrantView — разрешение роли с областью.
type GrantView struct {
	Permission string `json:"permission"`
	Scope      string `json:"scope"`
}

// RoleView — роль в ответах API.
type RoleView struct {
	ID          string      `json:"id"`
	DisplayName string      `json:"display_name"`
	Description string      `json:"description"`
	Builtin     bool        `json:"builtin"`
	MFARequired bool        `json:"mfa_required"`
	Permissions []GrantView `json:"permissions"`
	Users       int         `json:"users"`
	CreatedAt   *time.Time  `json:"created_at,omitempty"`
	UpdatedAt   *time.Time  `json:"updated_at,omitempty"`
}

func roleView(r auth.RoleDef, users int) RoleView {
	v := RoleView{ID: string(r.ID), DisplayName: r.DisplayName, Description: r.Description, Builtin: r.Builtin,
		MFARequired: r.MFARequired, Permissions: []GrantView{}, Users: users,
		CreatedAt: optTime(r.CreatedAt), UpdatedAt: optTime(r.UpdatedAt)}
	for _, p := range r.Grants.Names() {
		v.Permissions = append(v.Permissions, GrantView{Permission: p, Scope: r.Grants.Scope(p).String()})
	}
	return v
}

// pathRoleID — ID роли из пути; недопустимый — 404, как и отсутствующая роль.
func pathRoleID(w http.ResponseWriter, r *http.Request) (auth.Role, bool) {
	id := auth.Role(r.PathValue("id"))
	if !id.Valid() {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Роль не найдена."))
		return "", false
	}
	return id, true
}

func (d Deps) listPermissions(w http.ResponseWriter, _ *http.Request) {
	perms := auth.Permissions()
	resp := struct {
		Items []PermissionView `json:"items"`
	}{Items: make([]PermissionView, 0, len(perms))}
	for _, p := range perms {
		resp.Items = append(resp.Items, PermissionView{Name: p.Name, Title: p.Title, Group: p.Group, Security: p.Security, Ownable: p.Ownable})
	}
	WriteJSON(w, http.StatusOK, resp)
}

// RoleList — список ролей; все роли помещаются на одну страницу (их не больше
// предустановленных и auth.MaxCustomRoles).
type RoleList struct {
	Items []RoleView `json:"items"`
}

func (d Deps) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := d.Auth.Roles(r.Context())
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	auth.SortRoles(roles)
	resp := RoleList{Items: make([]RoleView, 0, len(roles))}
	for _, x := range roles {
		resp.Items = append(resp.Items, roleView(x.RoleDef, x.Users))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) writeRole(w http.ResponseWriter, r *http.Request, status int, id auth.Role) {
	roles, err := d.Auth.Roles(r.Context())
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	for _, x := range roles {
		if x.ID == id {
			WriteJSON(w, status, roleView(x.RoleDef, x.Users))
			return
		}
	}
	WriteProblem(w, roleProblem(auth.ErrRoleNotFound))
}

func (d Deps) getRole(w http.ResponseWriter, r *http.Request) {
	id, ok := pathRoleID(w, r)
	if !ok {
		return
	}
	d.writeRole(w, r, http.StatusOK, id)
}

// roleRequest — тело создания и изменения своей роли.
type roleRequest struct {
	ID          string      `json:"id,omitempty"`
	DisplayName string      `json:"display_name"`
	Description string      `json:"description"`
	MFARequired bool        `json:"mfa_required"`
	Permissions []GrantView `json:"permissions"`
}

func (q roleRequest) input() auth.RoleInput {
	in := auth.RoleInput{ID: q.ID, DisplayName: q.DisplayName, Description: q.Description, MFARequired: q.MFARequired}
	for _, g := range q.Permissions {
		in.Permissions = append(in.Permissions, auth.GrantInput{Permission: g.Permission, Scope: g.Scope})
	}
	return in
}

func (d Deps) createRole(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req roleRequest
	if p := DecodeJSON(w, r, &req, roleMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	role, err := d.Auth.CreateRole(r.Context(), c, req.input())
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	w.Header().Set("Location", "/api/v1/roles/"+string(role.ID))
	WriteJSON(w, http.StatusCreated, roleView(role, 0))
}

func (d Deps) updateRole(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathRoleID(w, r)
	if !ok {
		return
	}
	var req roleRequest
	if p := DecodeJSON(w, r, &req, roleMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if req.ID != "" && req.ID != string(id) {
		WriteProblem(w, Invalid("ID роли не меняется.", FieldError{"id", "ID роли не меняется: создайте новую роль."}))
		return
	}
	if _, err := d.Auth.UpdateRole(r.Context(), c, id, req.input()); err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	d.writeRole(w, r, http.StatusOK, id)
}

func (d Deps) deleteRole(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathRoleID(w, r)
	if !ok {
		return
	}
	if err := d.Auth.DeleteRole(r.Context(), c, id); err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type assignRoleRequest struct {
	Role string `json:"role"`
}

// AssignedRole — ответ на назначение роли.
type AssignedRole struct {
	User            UserView `json:"user"`
	RevokedSessions int      `json:"revoked_sessions"`
}

func (d Deps) assignRole(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathUserID(w, r)
	if !ok {
		return
	}
	var req assignRoleRequest
	if p := DecodeJSON(w, r, &req, roleMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	n, err := d.Auth.AssignRole(r.Context(), c, id, auth.Role(req.Role))
	if errors.Is(err, auth.ErrRoleNotFound) {
		WriteProblem(w, Invalid("Проверьте введённые данные.", FieldError{"role", "Неизвестная роль."}))
		return
	}
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	u, err := d.Auth.User(r.Context(), id)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, AssignedRole{User: userView(u, time.Now()), RevokedSessions: n})
}

// auditDenied — запись отказа в доступе в журнал аудита (УПД.6, DM-39).
// Отказ без аутентификации не пишется: его поток ограничен ЗИ.6, а
// неудачные входы уже в журнале.
func auditDenied(svc *auth.Service, logger *slog.Logger) func(*http.Request, Denial) {
	return func(r *http.Request, d Denial) {
		if d.Decision != Forbidden || d.Principal.Caller == nil {
			return
		}
		if err := svc.AccessDenied(r.Context(), *d.Principal.Caller, d.Method, d.Path, d.Permission, d.Reason); err != nil {
			logger.Error("отказ в доступе не записан в журнал аудита", "error", err)
		}
	}
}
