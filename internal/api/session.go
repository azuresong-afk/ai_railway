package api

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"

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
// (бездействие, срок) → CSRF для изменяющих запросов → право роли.
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
	p := Principal{ID: caller.User.ID, Caller: &caller}
	if unsafeMethod(r.Method) && !a.Auth.CheckCSRF(caller, r.Header.Get(CSRFHeader)) {
		return p, Forbidden
	}
	if !auth.Allowed(caller, permission) {
		return p, Forbidden
	}
	return p, Allow
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// clientAddr — адрес клиента по соединению; заголовкам прокси не доверяем
// (как и ограничитель частоты).
func clientAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.WithZone("").Unmap()
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

// callerFrom — сессия консоли из контекста запроса; ok = false, если
// субъект не сессия (такие маршруты для токенов API не предназначены).
func callerFrom(r *http.Request) (auth.Caller, bool) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		return auth.Caller{}, false
	}
	return *p.Caller, true
}
