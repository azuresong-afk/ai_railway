package api

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// authMaxBody — предел тела запросов входа и смены пароля.
const authMaxBody = 8 << 10

// authRoutes — первичная настройка, вход, выход, текущий пользователь, смена
// пароля, настройки входа (ИАФ.1–4, УПД.4, ЗИ.4; задача 2.7).
func authRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/auth/setup", Public: true, Handler: needAuth(d, d.setupStatus)},
		{Method: http.MethodPost, Path: "/api/v1/auth/setup", Public: true, MaxBody: authMaxBody, Handler: needAuth(d, d.setup)},
		{Method: http.MethodPost, Path: "/api/v1/auth/login", Public: true, MaxBody: authMaxBody, Handler: needAuth(d, d.login)},
		{Method: http.MethodPost, Path: "/api/v1/auth/logout", Permission: auth.PermSession, Handler: needAuth(d, d.logout)},
		{Method: http.MethodPost, Path: "/api/v1/auth/password", Permission: auth.PermSelf, MaxBody: authMaxBody, Handler: needAuth(d, d.changePassword)},
		{Method: http.MethodGet, Path: "/api/v1/me", Permission: auth.PermSession, Handler: needAuth(d, d.me)},
		{Method: http.MethodGet, Path: "/api/v1/auth/policy", Permission: auth.PermAuthPolicyRead, Handler: needAuth(d, d.getPolicy)},
		{Method: http.MethodPut, Path: "/api/v1/auth/policy", Permission: auth.PermAuthPolicyManage, MaxBody: authMaxBody, Handler: needAuth(d, d.putPolicy)},
	}
}

// needAuth — эндпоинт отвечает 503, если вход не подключён.
func needAuth(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Auth == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Вход в консоль не настроен на сервере."))
			return
		}
		h(w, r)
	}
}

// authProblem переводит ошибку internal/auth в ответ. Неизвестная ошибка —
// 500, причина — в техническом журнале.
func authProblem(logger *slog.Logger, err error) *Problem {
	var ie *auth.InputError
	var pe *auth.PasswordError
	switch {
	case errors.As(err, &ie):
		return Invalid("Проверьте введённые данные.", FieldError{ie.Field, ie.Reason})
	case errors.As(err, &pe):
		return Invalid("Пароль не соответствует парольной политике.", FieldError{"new_password", pe.Reason})
	case errors.Is(err, auth.ErrWrongPassword):
		return Invalid("Текущий пароль неверен.", FieldError{"current_password", "Текущий пароль неверен."})
	case errors.Is(err, auth.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Учётная запись не найдена.")
	case errors.Is(err, auth.ErrLoginTaken):
		return NewProblem(http.StatusConflict, CodeConflict, "Логин уже занят: выберите другой.")
	case errors.Is(err, auth.ErrLastAdmin):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Это последний активный администратор безопасности: сначала назначьте другого.")
	case errors.Is(err, auth.ErrUnauthenticated):
		// Сессию завершили, пока выполнялся запрос (выход, сброс, деактивация).
		return errUnauthorized()
	case errors.Is(err, auth.ErrLocked):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Учётная запись заблокирована после неудачных попыток: дождитесь окончания блокировки или обратитесь к администратору безопасности.")
	case errors.Is(err, auth.ErrInvalidCode):
		return Invalid("Код не принят: проверьте его и введите новый код из приложения.",
			FieldError{"code", "Код не принят."})
	case errors.Is(err, auth.ErrSessionState):
		return NewProblem(http.StatusConflict, CodeConflict, "Это действие недоступно на текущем шаге входа.")
	case errors.Is(err, auth.ErrMFAEnabled):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Второй фактор уже подключён. Чтобы подключить его заново, обратитесь к администратору безопасности.")
	case errors.Is(err, auth.ErrMFANotEnabled):
		return NewProblem(http.StatusConflict, CodeConflict, "Второй фактор не подключён.")
	case errors.Is(err, auth.ErrMFAUnavailable):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Второй фактор недоступен: на сервере не загружен ключ данных. Обратитесь к администратору системы.")
	case errors.Is(err, auth.ErrSelf):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Это действие нельзя выполнить над своей учётной записью.")
	case errors.Is(err, auth.ErrRoleChanged):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Роль пользователя изменилась во время запроса: обновите страницу и повторите.")
	case errors.Is(err, auth.ErrEscalation):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Недостаточно прав: у учётной записи или роли есть разрешения, которых нет у вас.")
	}
	if p := roleProblem(err); p != nil {
		return p
	}
	if p := apiTokenProblem(err); p != nil {
		return p
	}
	logger.Error("ошибка входа и учётных записей", "error", err)
	return errInternal()
}

type loginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// maxLoginInput — предел поля логина до нормализации (сама нормализация
// принимает до 64 символов): длинная строка — ошибка формата, а не попытка входа.
const maxLoginInput = 256

// MeResponse — текущий пользователь и состояние сессии.
type MeResponse struct {
	User         UserView `json:"user"`
	SessionState string   `json:"session_state"`
	// PasswordExpiresInDays — сколько дней осталось до обязательной смены
	// пароля, если пора предупреждать (ИАФ.2).
	PasswordExpiresInDays *int      `json:"password_expires_in_days,omitempty"`
	MFA                   MFAStatus `json:"mfa"`
	// Permissions — разрешения, действующие в сессии (консоль скрывает
	// недоступные действия; права всё равно проверяет сервер).
	Permissions []string `json:"permissions"`
}

// MFAStatus — второй фактор пользователя (ИАФ.5).
type MFAStatus struct {
	Enabled  bool `json:"enabled"`
	Required bool `json:"required"`
}

func (d Deps) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if p := DecodeJSON(w, r, &req, authMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	var bad []FieldError
	if req.Login == "" || len(req.Login) > maxLoginInput || !utf8.ValidString(req.Login) {
		bad = append(bad, FieldError{"login", "Введите логин."})
	}
	if n := len(req.Password); n < aisecCrypto.MinPasswordLen || n > aisecCrypto.MaxPasswordLen {
		bad = append(bad, FieldError{"password", "Введите пароль."})
	}
	if len(bad) > 0 {
		WriteProblem(w, Invalid("Введите логин и пароль.", bad...))
		return
	}
	res, err := d.Auth.Login(r.Context(), auth.LoginInput{
		Login: req.Login, Password: req.Password, SourceIP: clientAddr(r), UserAgent: r.UserAgent(),
	})
	if errors.Is(err, auth.ErrInvalidCredentials) {
		WriteProblem(w, NewProblem(http.StatusUnauthorized, CodeUnauthorized, "Неверный логин или пароль."))
		return
	}
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	setSessionCookies(w, res.Token, res.CSRF)
	d.writeMe(w, r, res.Caller)
}

func (d Deps) writeMe(w http.ResponseWriter, r *http.Request, c auth.Caller) {
	resp := MeResponse{User: userView(c.User, time.Now()), SessionState: string(c.Session.State)}
	g, err := d.Auth.CallerGrants(r.Context(), c)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	resp.Permissions = g.Names()
	left, warn, err := d.Auth.PasswordExpiresIn(r.Context(), c.User)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	if warn {
		days := int(left / (24 * time.Hour))
		resp.PasswordExpiresInDays = &days
	}
	mfa, err := d.Auth.MFAStatus(r.Context(), c.User)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	resp.MFA = MFAStatus{Enabled: mfa.Enabled, Required: mfa.Required}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) logout(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if err := d.Auth.Logout(r.Context(), c); err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) me(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	d.writeMe(w, r, c)
}

type passwordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (d Deps) changePassword(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req passwordRequest
	if p := DecodeJSON(w, r, &req, authMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		WriteProblem(w, Invalid("Введите текущий и новый пароль."))
		return
	}
	if err := d.Auth.ChangePassword(r.Context(), c, req.CurrentPassword, req.NewPassword); err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) getPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := d.Auth.Policy(r.Context())
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, p)
}

// policyRequest — все поля обязательны: пропущенное поле не должно молча
// стать нулём (например, отключить срок действия пароля).
type policyRequest struct {
	PasswordMinLength  *int  `json:"password_min_length"`
	PasswordMinClasses *int  `json:"password_min_classes"`
	PasswordHistory    *int  `json:"password_history"`
	PasswordMaxAgeDays *int  `json:"password_max_age_days"`
	PasswordWarnDays   *int  `json:"password_warn_days"`
	LockoutThreshold   *int  `json:"lockout_threshold"`
	LockoutMinutes     *int  `json:"lockout_minutes"`
	SessionIdleMinutes *int  `json:"session_idle_minutes"`
	SessionMaxPerUser  *int  `json:"session_max_per_user"`
	TempPasswordHours  *int  `json:"temp_password_hours"`
	MFARequiredAll     *bool `json:"mfa_required_all"`
}

func (d Deps) putPolicy(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req policyRequest
	if p := DecodeJSON(w, r, &req, authMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	var p auth.Policy
	var missing []FieldError
	set := func(name string, v *int, dst *int) {
		if v == nil {
			missing = append(missing, FieldError{name, "Поле обязательно."})
			return
		}
		*dst = *v
	}
	set("password_min_length", req.PasswordMinLength, &p.PasswordMinLength)
	set("password_min_classes", req.PasswordMinClasses, &p.PasswordMinClasses)
	set("password_history", req.PasswordHistory, &p.PasswordHistory)
	set("password_max_age_days", req.PasswordMaxAgeDays, &p.PasswordMaxAgeDays)
	set("password_warn_days", req.PasswordWarnDays, &p.PasswordWarnDays)
	set("lockout_threshold", req.LockoutThreshold, &p.LockoutThreshold)
	set("lockout_minutes", req.LockoutMinutes, &p.LockoutMinutes)
	set("session_idle_minutes", req.SessionIdleMinutes, &p.SessionIdleMinutes)
	set("session_max_per_user", req.SessionMaxPerUser, &p.SessionMaxPerUser)
	set("temp_password_hours", req.TempPasswordHours, &p.TempPasswordHours)
	if req.MFARequiredAll == nil {
		missing = append(missing, FieldError{"mfa_required_all", "Поле обязательно."})
	} else {
		p.MFARequiredAll = *req.MFARequiredAll
	}
	if len(missing) > 0 {
		WriteProblem(w, Invalid("Укажите все настройки входа.", missing...))
		return
	}
	if err := d.Auth.SetPolicy(r.Context(), c, p); err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, p)
}

// SetupStatus — нужна ли первичная настройка.
type SetupStatus struct {
	SetupRequired bool `json:"setup_required"`
}

func (d Deps) setupStatus(w http.ResponseWriter, r *http.Request) {
	need, err := d.Auth.SetupRequired(r.Context())
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, SetupStatus{SetupRequired: need})
}

type setupRequest struct {
	Token       string `json:"token"`
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// maxSetupToken — предел поля токена до разбора.
const maxSetupToken = 128

// setup создаёт первого администратора безопасности по токену из
// aisec-cli init (ЗИ.4). Сессию не открывает: дальше — обычный вход.
func (d Deps) setup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if p := DecodeJSON(w, r, &req, authMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	var bad []FieldError
	if req.Token == "" || len(req.Token) > maxSetupToken {
		bad = append(bad, FieldError{"token", "Введите токен первичной настройки из вывода aisec-cli init."})
	}
	if len(req.Login) > maxLoginInput || !utf8.ValidString(req.Login) {
		bad = append(bad, FieldError{"login", "Логин слишком длинный."})
	}
	if n := len(req.Password); n < aisecCrypto.MinPasswordLen || n > aisecCrypto.MaxPasswordLen {
		bad = append(bad, FieldError{"password", "Введите пароль."})
	}
	if len(bad) > 0 {
		WriteProblem(w, Invalid("Проверьте введённые данные.", bad...))
		return
	}
	u, err := d.Auth.Setup(r.Context(), auth.SetupInput{
		Token: req.Token, Login: req.Login, DisplayName: req.DisplayName, Password: req.Password, SourceIP: clientAddr(r),
	})
	var pe *auth.PasswordError
	switch {
	case errors.Is(err, auth.ErrSetupUnavailable):
		WriteProblem(w, NewProblem(http.StatusForbidden, CodeForbidden,
			"Первичная настройка недоступна: токен неверен, истёк или уже использован, либо настройка уже выполнена."))
	case errors.As(err, &pe):
		WriteProblem(w, Invalid("Пароль не соответствует парольной политике.", FieldError{"password", pe.Reason}))
	case err != nil:
		WriteProblem(w, authProblem(d.Logger, err))
	default:
		WriteJSON(w, http.StatusCreated, userView(u, time.Now()))
	}
}
