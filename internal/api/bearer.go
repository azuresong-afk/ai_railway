package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// tokenAuditTimeout — предел записи api_token.used после ответа.
const tokenAuditTimeout = 5 * time.Second

// BearerAuthorizer проверяет запросы по токену API (ИАФ.9, задача 2.10).
// Есть заголовок Authorization — проверяется только он: в cookie не
// откатываемся, CSRF не нужен (заголовок браузер сам не подставляет).
// Заголовка нет — решает Next (сессия консоли). Права токена — пересечение
// его области с текущими правами роли владельца (auth.TokenGrants).
type BearerAuthorizer struct {
	Auth   *auth.Service
	Logger *slog.Logger
	// Next — проверка без заголовка Authorization; nil — DenyAll.
	Next Authorizer
}

// Authorize — Authorizer.
func (a BearerAuthorizer) Authorize(r *http.Request, permission string) (Principal, Decision) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		if a.Next == nil {
			return DenyAll{}.Authorize(r, permission)
		}
		return a.Next.Authorize(r, permission)
	}
	// Не Bearer или несколько заголовков — пустая строка: отказ с причиной
	// malformed в журнале аудита, без самого значения заголовка.
	raw, err := auth.BearerToken(values)
	if err != nil {
		raw = ""
	}
	c, err := a.Auth.AuthenticateAPIToken(r.Context(), raw, clientAddr(r))
	if err != nil {
		if !errors.Is(err, auth.ErrUnauthenticated) && a.Logger != nil {
			// Сбой хранилища или журнала: отказ, причина — в техническом журнале (без токена).
			a.Logger.Error("проверка токена API не выполнена", "error", err)
		}
		return Principal{}, Unauthenticated
	}
	g, err := a.Auth.CallerGrants(r.Context(), c)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Error("права владельца токена API не получены", "error", err)
		}
		return Principal{}, Unavailable
	}
	// Отдельная область ключей повторяемости: запрос по токену не
	// повторяет ответ, сохранённый для сессии того же пользователя.
	p := Principal{ID: "api_token:" + c.Token.ID, Caller: &c, Grants: g}
	if !g.Allows(permission) {
		return p, Forbidden
	}
	return p, Allow
}

// statusRecorder запоминает код ответа обработчика (аудит api_token.used).
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status, s.wrote = http.StatusOK, true
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap — для http.ResponseController.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// auditTokenUsed — запись каждого пропущенного запроса по токену в журнал
// аудита (РСБ.1): метод, шаблон пути, код ответа.
func auditTokenUsed(svc *auth.Service, logger *slog.Logger) func(*http.Request, Principal, string, string, int) {
	return func(r *http.Request, p Principal, method, path string, status int) {
		if p.Caller == nil || p.Caller.Token == nil {
			return
		}
		// Клиент мог уже отключиться: запись не должна пропасть вместе с его контекстом.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), tokenAuditTimeout)
		defer cancel()
		if err := svc.APITokenUsed(ctx, *p.Caller, method, path, status); err != nil {
			logger.Error("запрос по токену API не записан в журнал аудита", "error", err)
		}
	}
}
