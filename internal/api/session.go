package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Cookie и заголовок сессии консоли (решение Р6, ТЗ 6.9). Префикс __Host-
// браузер принимает только с Secure, Path=/ и без Domain: cookie нельзя
// подложить с соседнего поддомена или по HTTP.
const (
	// SessionCookie — токен сессии: HttpOnly, недоступен скриптам.
	SessionCookie = "__Host-aisec_session"
	// CSRFCookie — CSRF-токен, привязанный к сессии: читается интерфейсом и
	// возвращается в заголовке CSRFHeader (двойная отправка).
	CSRFCookie = "__Host-aisec_csrf"
	CSRFHeader = "X-CSRF-Token"
)

// SessionAuthorizer проверяет права по сессии консоли: cookie → сессия
// (бездействие, срок) → CSRF для изменяющих запросов → права роли
// (предустановленной или своей, УПД.1).
type SessionAuthorizer struct {
	Auth   *auth.Service
	Logger *slog.Logger
}

// Authorize — Authorizer.
func (a SessionAuthorizer) Authorize(r *http.Request, permission string) (Principal, Decision) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return Principal{}, Unauthenticated
	}
	caller, err := a.Auth.Authenticate(r.Context(), c.Value, clientAddr(r))
	if err != nil {
		if !errors.Is(err, auth.ErrUnauthenticated) && a.Logger != nil {
			// Сбой хранилища: отказ, а причина — в техническом журнале (без токена).
			a.Logger.Error("проверка сессии не выполнена", "error", err)
		}
		return Principal{}, Unauthenticated
	}
	g, err := a.Auth.CallerGrants(r.Context(), caller)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Error("права роли не получены", "error", err)
		}
		// Сбой хранилища — не отказ по правам: 503 без записи access.denied.
		return Principal{}, Unavailable
	}
	p := Principal{ID: caller.User.ID, Caller: &caller, Grants: g}
	if unsafeMethod(r.Method) && !a.Auth.CheckCSRF(caller, r.Header.Get(CSRFHeader)) {
		return p, Forbidden
	}
	if !g.Allows(permission) {
		return p, Forbidden
	}
	return p, Allow
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// setSessionCookies выдаёт cookie сессии и CSRF. Без Max-Age: cookie
// живут до закрытия браузера, срок сессии контролирует сервер.
func setSessionCookies(w http.ResponseWriter, token, csrf string) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookie, Value: csrf, Path: "/",
		Secure: true, SameSite: http.SameSiteStrictMode})
}

// clearSessionCookies удаляет cookie сессии и CSRF у клиента.
func clearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, SameSite: http.SameSiteStrictMode})
}

// callerFrom — пользователь запроса (сессия консоли или токен API, у
// токена Caller.Token не nil); ok = false, если субъект не пользователь.
// Маршруты своих данных (self, session) токену недоступны: этих
// разрешений у него нет.
func callerFrom(r *http.Request) (auth.Caller, bool) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		return auth.Caller{}, false
	}
	return *p.Caller, true
}
