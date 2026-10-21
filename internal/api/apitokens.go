package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// apiTokenMaxBody — предел тела выпуска токена.
const apiTokenMaxBody = 16 << 10

// apiTokenRoutes — токены API (ИАФ.9; задача 2.10). Все маршруты со Scoped:
// при области own обработчик отбирает только свои токены (УПД.8). Выпуск
// без Idempotency-Key: сохранённый ответ содержал бы сам токен.
func apiTokenRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/api-tokens", Permission: auth.PermAPITokensRead, Scoped: true, Handler: needAuth(d, d.listAPITokens)},
		{Method: http.MethodPost, Path: "/api/v1/api-tokens", Permission: auth.PermAPITokensManage, Scoped: true,
			MaxBody: apiTokenMaxBody, Handler: needAuth(d, d.createAPIToken)},
		{Method: http.MethodGet, Path: "/api/v1/api-tokens/{id}", Permission: auth.PermAPITokensRead, Scoped: true, Handler: needAuth(d, d.getAPIToken)},
		{Method: http.MethodDelete, Path: "/api/v1/api-tokens/{id}", Permission: auth.PermAPITokensManage, Scoped: true, Handler: needAuth(d, d.revokeAPIToken)},
	}
}

// apiTokenProblem переводит ошибки токенов; nil — ошибка не из токенов.
func apiTokenProblem(err error) *Problem {
	switch {
	case errors.Is(err, auth.ErrAPITokenNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Токен API не найден.")
	case errors.Is(err, auth.ErrAPITokenRevoked):
		return NewProblem(http.StatusConflict, CodeConflict, "Токен API уже отозван.")
	case errors.Is(err, auth.ErrTooManyAPITokens):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"У вас уже 20 действующих токенов API: отзовите неиспользуемые.")
	}
	return nil
}

// APITokenView — токен API в ответах; секрета в нём нет.
type APITokenView struct {
	ID          string      `json:"id"`
	UserID      string      `json:"user_id"`
	Name        string      `json:"name"`
	Prefix      string      `json:"prefix"`
	Permissions []GrantView `json:"permissions"`
	// Status — active, expired или revoked.
	Status       string     `json:"status"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP   string     `json:"last_used_ip,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`
}

func apiTokenView(t auth.APIToken, now time.Time) APITokenView {
	v := APITokenView{ID: t.ID, UserID: t.UserID, Name: t.Name, Prefix: t.Prefix, Permissions: []GrantView{},
		Status: "active", ExpiresAt: t.ExpiresAt.UTC(), CreatedAt: t.CreatedAt.UTC(),
		LastUsedAt: optTime(t.LastUsedAt), RevokedAt: optTime(t.RevokedAt), RevokeReason: t.RevokeReason}
	switch {
	case t.Revoked():
		v.Status = "revoked"
	case !now.Before(t.ExpiresAt):
		v.Status = "expired"
	}
	if t.LastUsedIP.IsValid() {
		v.LastUsedIP = t.LastUsedIP.String()
	}
	for _, p := range t.Grants.Names() {
		v.Permissions = append(v.Permissions, GrantView{Permission: p, Scope: t.Grants.Scope(p).String()})
	}
	return v
}

// pathTokenID — ID токена из пути; недопустимый — 404, как и отсутствующий.
func pathTokenID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, err := store.ParseUUID(r.PathValue("id"))
	if err != nil {
		WriteProblem(w, apiTokenProblem(auth.ErrAPITokenNotFound))
		return "", false
	}
	return string(id), true
}

func (d Deps) listAPITokens(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	page, p := ParsePage(r)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	var after *auth.UserCursor
	if page.Cursor != nil {
		after = &auth.UserCursor{CreatedAt: time.UnixMicro(page.Cursor.TimeMicro), ID: page.Cursor.ID}
	}
	tokens, err := d.Auth.APITokens(r.Context(), c, after, page.Limit+1)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	resp := PageResponse[APITokenView]{Items: make([]APITokenView, 0, min(len(tokens), page.Limit))}
	now := time.Now()
	for i, t := range tokens {
		if i == page.Limit {
			last := tokens[i-1]
			resp.NextCursor = Cursor{TimeMicro: last.CreatedAt.UnixMicro(), ID: last.ID}.Encode()
			break
		}
		resp.Items = append(resp.Items, apiTokenView(t, now))
	}
	WriteJSON(w, http.StatusOK, resp)
}

type createAPITokenRequest struct {
	Name          string      `json:"name"`
	ExpiresInDays int         `json:"expires_in_days"`
	Permissions   []GrantView `json:"permissions"`
}

// CreatedAPIToken — ответ на выпуск: токен показывается один раз (ИАФ.9).
type CreatedAPIToken struct {
	APIToken APITokenView `json:"api_token"`
	Token    string       `json:"token"`
}

func (d Deps) createAPIToken(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req createAPITokenRequest
	if p := DecodeJSON(w, r, &req, apiTokenMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	in := auth.APITokenInput{Name: req.Name, ExpiresInDays: req.ExpiresInDays}
	for _, g := range req.Permissions {
		in.Permissions = append(in.Permissions, auth.GrantInput{Permission: g.Permission, Scope: g.Scope})
	}
	t, raw, err := d.Auth.CreateAPIToken(r.Context(), c, in)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	w.Header().Set("Location", "/api/v1/api-tokens/"+t.ID)
	WriteJSON(w, http.StatusCreated, CreatedAPIToken{APIToken: apiTokenView(t, time.Now()), Token: raw})
}

func (d Deps) getAPIToken(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathTokenID(w, r)
	if !ok {
		return
	}
	t, err := d.Auth.APITokenByID(r.Context(), c, id)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, apiTokenView(t, time.Now()))
}

func (d Deps) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathTokenID(w, r)
	if !ok {
		return
	}
	t, err := d.Auth.RevokeAPIToken(r.Context(), c, id)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, apiTokenView(t, time.Now()))
}
