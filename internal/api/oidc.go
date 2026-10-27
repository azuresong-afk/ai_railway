package api

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
)

// Вход через внешний IdP по OpenID Connect и его настройки (ИАФ.7;
// ADR-0025, задача 4.17).

const (
	// OIDCCookie — одноразовое значение незавершённого входа через IdP.
	// SameSite=Lax: возврат от IdP — переход с чужого сайта, cookie со
	// Strict браузер бы не прислал. Сессионные cookie остаются Strict.
	OIDCCookie = "__Host-aisec_oidc"
	// idpMaxBody — предел тела настроек IdP (PEM корней до 64 КиБ).
	idpMaxBody = 128 << 10
	// maxOIDCCookie, maxCallbackQuery — пределы cookie и строки возврата.
	maxOIDCCookie    = 64
	maxCallbackQuery = 8 << 10
)

func oidcRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/auth/oidc", Public: true, Handler: needAuth(d, d.oidcOption)},
		{Method: http.MethodGet, Path: "/api/v1/auth/oidc/start", Public: true, Handler: needAuth(d, d.oidcStart)},
		{Method: http.MethodGet, Path: oidc.CallbackPath, Public: true, Handler: needAuth(d, d.oidcCallback)},
		{Method: http.MethodGet, Path: "/api/v1/auth/idp", Permission: auth.PermAuthIdPRead, Handler: needAuth(d, d.getIdP)},
		{Method: http.MethodPut, Path: "/api/v1/auth/idp", Permission: auth.PermAuthIdPManage, MaxBody: idpMaxBody,
			Handler: needAuth(d, d.putIdP)},
		{Method: http.MethodDelete, Path: "/api/v1/auth/idp", Permission: auth.PermAuthIdPManage, MaxBody: authMaxBody,
			Handler: needAuth(d, d.deleteIdP)},
	}
}

// OIDCOption — кнопка «Войти через …» на экране входа.
type OIDCOption struct {
	Enabled     bool   `json:"enabled"`
	DisplayName string `json:"display_name,omitempty"`
}

func (d Deps) oidcOption(w http.ResponseWriter, r *http.Request) {
	opt, err := d.Auth.IdPLoginOption(r.Context())
	if err != nil {
		// Экран входа работает и без кнопки; причина — в журнале.
		d.Logger.Warn("настройки входа через IdP не прочитаны", "error", err)
		opt = auth.LoginOption{}
	}
	resp := OIDCOption{Enabled: opt.Enabled}
	if opt.Enabled {
		resp.DisplayName = opt.DisplayName
	}
	WriteJSON(w, http.StatusOK, resp)
}

// oidcFailRedirect — возврат на экран входа с кодом отказа (без причины:
// она в журнале аудита).
func oidcFailRedirect(w http.ResponseWriter, r *http.Request, code string) {
	clearOIDCCookie(w)
	http.Redirect(w, r, "/?oidc="+url.QueryEscape(code), http.StatusSeeOther)
}

func clearOIDCCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: OIDCCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// oidcCode — код отказа для пользователя по ошибке входа через IdP.
func (d Deps) oidcCode(err error) string {
	var oe *auth.OIDCError
	switch {
	case errors.As(err, &oe):
		return oe.Code
	case errors.Is(err, auth.ErrIdPNotConfigured), errors.Is(err, auth.ErrIdPUnavailable),
		errors.Is(err, auth.ErrTooManyLogins):
		return auth.OIDCUnavailable
	}
	d.Logger.Error("ошибка входа через IdP", "error", err)
	return auth.OIDCUnavailable
}

func (d Deps) oidcStart(w http.ResponseWriter, r *http.Request) {
	res, err := d.Auth.StartOIDC(r.Context())
	if err != nil {
		oidcFailRedirect(w, r, d.oidcCode(err))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: OIDCCookie, Value: res.Cookie, Path: "/",
		MaxAge: int(auth.OIDCLoginTTL / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, res.RedirectURL, http.StatusSeeOther)
}

func (d Deps) oidcCallback(w http.ResponseWriter, r *http.Request) {
	in := auth.OIDCCallbackInput{SourceIP: clientAddr(r), UserAgent: r.UserAgent()}
	if c, err := r.Cookie(OIDCCookie); err == nil && len(c.Value) <= maxOIDCCookie {
		in.Cookie = c.Value
	}
	if len(r.URL.RawQuery) <= maxCallbackQuery {
		if q, err := url.ParseQuery(r.URL.RawQuery); err == nil {
			in.State, in.Code, in.Error = q.Get("state"), q.Get("code"), q.Get("error")
		}
	}
	res, err := d.Auth.FinishOIDC(r.Context(), in)
	if err != nil {
		oidcFailRedirect(w, r, d.oidcCode(err))
		return
	}
	clearOIDCCookie(w)
	setSessionCookies(w, res.Token, res.CSRF)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// GroupRoleView — строка сопоставления «группа IdP → роль».
type GroupRoleView struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

// IdPView — настройки входа через IdP без секрета клиента.
type IdPView struct {
	Configured  bool            `json:"configured"`
	Enabled     bool            `json:"enabled"`
	DisplayName string          `json:"display_name"`
	Issuer      string          `json:"issuer"`
	ClientID    string          `json:"client_id"`
	ConsoleURL  string          `json:"console_url"`
	RedirectURI string          `json:"redirect_uri,omitempty"`
	CAPEM       string          `json:"ca_pem"`
	Scopes      []string        `json:"scopes"`
	GroupsClaim string          `json:"groups_claim"`
	RequiredACR []string        `json:"required_acr"`
	RequiredAMR []string        `json:"required_amr"`
	GroupRoles  []GroupRoleView `json:"group_roles"`
	Version     int             `json:"version,omitempty"`
	UpdatedAt   *time.Time      `json:"updated_at,omitempty"`
}

func idpView(st auth.IdPSettings) IdPView {
	v := IdPView{Configured: true, Enabled: st.Enabled, DisplayName: st.DisplayName, Issuer: st.Issuer,
		ClientID: st.ClientID, ConsoleURL: st.ConsoleURL, CAPEM: st.CAPEM, Scopes: nonNil(st.Scopes),
		GroupsClaim: st.GroupsClaim, RequiredACR: nonNil(st.RequiredACR), RequiredAMR: nonNil(st.RequiredAMR),
		GroupRoles: []GroupRoleView{}, Version: st.Version}
	if st.ConsoleURL != "" {
		v.RedirectURI = st.ConsoleURL + oidc.CallbackPath
	}
	if !st.UpdatedAt.IsZero() {
		t := st.UpdatedAt
		v.UpdatedAt = &t
	}
	for _, g := range st.GroupRoles {
		v.GroupRoles = append(v.GroupRoles, GroupRoleView{Group: g.Group, Role: string(g.Role)})
	}
	return v
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// idpProblem — ответы для ошибок настроек IdP.
func idpProblem(d Deps, err error) *Problem {
	switch {
	case errors.Is(err, auth.ErrIdPNotConfigured):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Вход через IdP не настроен.")
	case errors.Is(err, auth.ErrIdPUnavailable):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Вход через IdP недоступен: на сервере не загружен ключ данных. Обратитесь к администратору системы.")
	case errors.Is(err, auth.ErrExternalUser):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Настройки входа через IdP меняет только локальная учётная запись с паролем.")
	case errors.Is(err, auth.ErrRoleNotFound):
		return Invalid("Проверьте сопоставление групп.", FieldError{"group_roles", "Одной из ролей нет."})
	}
	return authProblem(d.Logger, err)
}

func (d Deps) getIdP(w http.ResponseWriter, r *http.Request) {
	st, err := d.Auth.IdP(r.Context())
	if errors.Is(err, auth.ErrIdPNotConfigured) {
		WriteJSON(w, http.StatusOK, IdPView{Scopes: []string{}, RequiredACR: []string{}, RequiredAMR: []string{},
			GroupRoles: []GroupRoleView{}})
		return
	}
	if err != nil {
		WriteProblem(w, idpProblem(d, err))
		return
	}
	WriteJSON(w, http.StatusOK, idpView(st))
}

type idpRequest struct {
	Enabled      *bool           `json:"enabled"`
	DisplayName  string          `json:"display_name"`
	Issuer       string          `json:"issuer"`
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	ConsoleURL   string          `json:"console_url"`
	CAPEM        string          `json:"ca_pem"`
	Scopes       []string        `json:"scopes"`
	GroupsClaim  string          `json:"groups_claim"`
	RequiredACR  []string        `json:"required_acr"`
	RequiredAMR  []string        `json:"required_amr"`
	GroupRoles   []GroupRoleView `json:"group_roles"`
	reauthFields
}

func (d Deps) putIdP(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req idpRequest
	if p := DecodeJSON(w, r, &req, idpMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if req.Enabled == nil {
		WriteProblem(w, Invalid("Укажите, включён ли вход через IdP.", FieldError{"enabled", "Поле обязательно."}))
		return
	}
	in := auth.IdPInput{Enabled: *req.Enabled, DisplayName: req.DisplayName, Issuer: req.Issuer, ClientID: req.ClientID,
		ClientSecret: req.ClientSecret, ConsoleURL: req.ConsoleURL, CAPEM: req.CAPEM, Scopes: req.Scopes,
		GroupsClaim: req.GroupsClaim, RequiredACR: req.RequiredACR, RequiredAMR: req.RequiredAMR}
	for _, g := range req.GroupRoles {
		in.GroupRoles = append(in.GroupRoles, auth.GroupRole{Group: g.Group, Role: auth.Role(g.Role)})
	}
	st, err := d.Auth.SetIdP(r.Context(), c, in, req.Password, req.Code)
	if err != nil {
		WriteProblem(w, idpProblem(d, err))
		return
	}
	WriteJSON(w, http.StatusOK, idpView(st))
}

func (d Deps) deleteIdP(w http.ResponseWriter, r *http.Request) {
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
	if err := d.Auth.DeleteIdP(r.Context(), c, req.Password, req.Code); err != nil {
		WriteProblem(w, idpProblem(d, err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
