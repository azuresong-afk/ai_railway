package api

import (
	"context"
	"net/http"
)

// Principal — аутентифицированный субъект запроса.
type Principal struct {
	ID string
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
// (УПД.3). Сессии, токены и роли подключает задача 2.9; до неё действует DenyAll.
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
