package api

import (
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// userRoutes — учётные записи и их сессии (ИАФ.1, ИАФ.3, УПД.4–5; задача
// 2.7). Удаления нет: записи деактивируются (УПД.5).
//
// POST /api/v1/users намеренно без Idempotency-Key: хранилище повторов
// запомнило бы ответ с временным паролем; повтор и так отклоняется по
// занятому логину.
func userRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/users", Permission: auth.PermUsersRead, Handler: needAuth(d, d.listUsers)},
		{Method: http.MethodPost, Path: "/api/v1/users", Permission: auth.PermUsersManage, SecretOnce: true, MaxBody: authMaxBody, Handler: needAuth(d, d.createUser)},
		{Method: http.MethodGet, Path: "/api/v1/users/{id}", Permission: auth.PermUsersRead, Handler: needAuth(d, d.getUser)},
		{Method: http.MethodPost, Path: "/api/v1/users/{id}/deactivate", Permission: auth.PermUsersManage, Handler: needAuth(d, d.setStatus(auth.StatusDeactivated))},
		{Method: http.MethodPost, Path: "/api/v1/users/{id}/activate", Permission: auth.PermUsersManage, Handler: needAuth(d, d.setStatus(auth.StatusActive))},
		{Method: http.MethodPost, Path: "/api/v1/users/{id}/password-reset", Permission: auth.PermUsersManage, SecretOnce: true, Handler: needAuth(d, d.resetPassword)},
		{Method: http.MethodGet, Path: "/api/v1/users/{id}/sessions", Permission: auth.PermSessionsRead, Handler: needAuth(d, d.listSessions)},
		{Method: http.MethodDelete, Path: "/api/v1/users/{id}/sessions", Permission: auth.PermSessionsManage, Handler: needAuth(d, d.revokeSessions)},
	}
}

// UserView — учётная запись в ответах API. Хеш пароля не выдаётся.
type UserView struct {
	ID                 string     `json:"id"`
	Login              string     `json:"login"`
	DisplayName        string     `json:"display_name"`
	Role               string     `json:"role"`
	Status             string     `json:"status"`
	Locked             bool       `json:"locked"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	MustChangePassword bool       `json:"must_change_password"`
	PasswordChangedAt  time.Time  `json:"password_changed_at"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	DeactivatedAt      *time.Time `json:"deactivated_at,omitempty"`
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func userView(u auth.User, now time.Time) UserView {
	v := UserView{
		ID: u.ID, Login: u.Login, DisplayName: u.DisplayName, Role: string(u.Role), Status: string(u.Status),
		Locked: u.Locked(now), MustChangePassword: u.MustChangePassword,
		PasswordChangedAt: u.PasswordChangedAt.UTC(), CreatedAt: u.CreatedAt.UTC(),
		LastLoginAt: optTime(u.LastLoginAt), DeactivatedAt: optTime(u.DeactivatedAt),
	}
	if v.Locked {
		v.LockedUntil = optTime(u.LockedUntil)
	}
	return v
}

// pathUserID — ID из пути; неверный UUID — 404, как и отсутствующая запись.
func pathUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, err := store.ParseUUID(r.PathValue("id"))
	if err != nil {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Учётная запись не найдена."))
		return "", false
	}
	return string(id), true
}

func (d Deps) listUsers(w http.ResponseWriter, r *http.Request) {
	page, p := ParsePage(r)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	var after *auth.UserCursor
	if page.Cursor != nil {
		after = &auth.UserCursor{CreatedAt: time.UnixMicro(page.Cursor.TimeMicro), ID: page.Cursor.ID}
	}
	users, err := d.Auth.Users(r.Context(), after, page.Limit+1)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	resp := PageResponse[UserView]{Items: make([]UserView, 0, min(len(users), page.Limit))}
	now := time.Now()
	for i, u := range users {
		if i == page.Limit {
			last := users[i-1]
			resp.NextCursor = Cursor{TimeMicro: last.CreatedAt.UnixMicro(), ID: last.ID}.Encode()
			break
		}
		resp.Items = append(resp.Items, userView(u, now))
	}
	WriteJSON(w, http.StatusOK, resp)
}

type createUserRequest struct {
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

// CreatedUser — ответ на создание учётной записи и сброс пароля: временный
// пароль показывается один раз (ИАФ.3).
type CreatedUser struct {
	User              UserView `json:"user"`
	TemporaryPassword string   `json:"temporary_password"`
}

func (d Deps) createUser(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req createUserRequest
	if p := DecodeJSON(w, r, &req, authMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	u, temp, err := d.Auth.CreateUser(r.Context(), c, auth.NewUser{Login: req.Login, DisplayName: req.DisplayName, Role: auth.Role(req.Role)})
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	w.Header().Set("Location", "/api/v1/users/"+u.ID)
	WriteJSON(w, http.StatusCreated, CreatedUser{User: userView(u, time.Now()), TemporaryPassword: temp})
}

func (d Deps) getUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUserID(w, r)
	if !ok {
		return
	}
	u, err := d.Auth.User(r.Context(), id)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, userView(u, time.Now()))
}

func (d Deps) setStatus(st auth.Status) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := callerFrom(r)
		if !ok {
			WriteProblem(w, errForbidden())
			return
		}
		id, ok := pathUserID(w, r)
		if !ok {
			return
		}
		if err := d.Auth.SetStatus(r.Context(), c, id, st); err != nil {
			WriteProblem(w, authProblem(d.Logger, err))
			return
		}
		u, err := d.Auth.User(r.Context(), id)
		if err != nil {
			WriteProblem(w, authProblem(d.Logger, err))
			return
		}
		WriteJSON(w, http.StatusOK, userView(u, time.Now()))
	}
}

func (d Deps) resetPassword(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathUserID(w, r)
	if !ok {
		return
	}
	temp, err := d.Auth.ResetPassword(r.Context(), c, id)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	u, err := d.Auth.User(r.Context(), id)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, CreatedUser{User: userView(u, time.Now()), TemporaryPassword: temp})
}

// SessionView — сессия пользователя в ответах API (токены не выдаются).
type SessionView struct {
	ID         string    `json:"id"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	SourceIP   string    `json:"source_ip,omitempty"`
	UserAgent  string    `json:"user_agent"`
}

// SessionList — список сессий; все незавершённые сессии помещаются на одну страницу.
type SessionList struct {
	Items []SessionView `json:"items"`
}

func (d Deps) listSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUserID(w, r)
	if !ok {
		return
	}
	list, err := d.Auth.Sessions(r.Context(), id)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	resp := SessionList{Items: make([]SessionView, 0, len(list))}
	for _, s := range list {
		v := SessionView{ID: s.ID, State: string(s.State), CreatedAt: s.CreatedAt.UTC(), LastSeenAt: s.LastSeenAt.UTC(),
			ExpiresAt: s.ExpiresAt.UTC(), UserAgent: s.UserAgent}
		if s.SourceIP.IsValid() {
			v.SourceIP = s.SourceIP.String()
		}
		resp.Items = append(resp.Items, v)
	}
	WriteJSON(w, http.StatusOK, resp)
}

// RevokedSessions — число завершённых сессий.
type RevokedSessions struct {
	Revoked int `json:"revoked"`
}

func (d Deps) revokeSessions(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathUserID(w, r)
	if !ok {
		return
	}
	n, err := d.Auth.RevokeSessions(r.Context(), c, id)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, RevokedSessions{Revoked: n})
}
