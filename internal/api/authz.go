package api

import (
	"context"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Principal — аутентифицированный субъект запроса.
type Principal struct {
	ID string
	// Caller — сессия консоли и её пользователь; nil — субъект не сессия
	// (токен API, тесты).
	Caller *auth.Caller
}

type principalKey struct{}

// WithPrincipal кладёт субъекта в контекст запроса.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom возвращает субъекта, определённого проверкой прав.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// Decision — решение проверки прав.
type Decision int

// Решения. Нулевое значение — отказ без аутентификации: забытая проверка
// не открывает доступ.
const (
	Unauthenticated Decision = iota
	Forbidden
	Allow
)

// Authorizer решает, можно ли запросу выполнить действие с правом permission
// (УПД.3). Сессии консоли проверяет SessionAuthorizer (задача 2.7); токены
// API и свои роли — задача 2.9. Без подключённого входа действует DenyAll.
type Authorizer interface {
	Authorize(r *http.Request, permission string) (Principal, Decision)
}

// DenyAll отклоняет всё: у сервера без подключённой аутентификации нет
// доступных защищённых эндпоинтов.
type DenyAll struct{}

// Authorize всегда возвращает Unauthenticated.
func (DenyAll) Authorize(*http.Request, string) (Principal, Decision) {
	return Principal{}, Unauthenticated
}
