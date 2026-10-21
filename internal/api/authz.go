package api

import (
	"context"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Principal — аутентифицированный субъект запроса.
type Principal struct {
	ID string
	// Caller — пользователь запроса: сессия консоли или токен API
	// (Caller.Token); nil — субъект не пользователь (шлюз, тесты).
	Caller *auth.Caller
	// Grants — права, действующие в запросе (УПД.1). Маршрут без признака
	// Scoped пропускает только разрешение на все объекты; со Scoped
	// обработчик сам отбирает объекты по Grants.Scope (УПД.8).
	Grants auth.Grants
}

// Denial — отказ в доступе к маршруту (УПД.6).
type Denial struct {
	Principal Principal // пустой при Unauthenticated
	Method    string
	// Path — шаблон маршрута (/api/v1/users/{id}), а не путь запроса.
	Path       string
	Permission string
	Decision   Decision
	// Reason — причина отказа Forbidden (DenyReason*).
	Reason string
}

// Причины отказа Forbidden для журнала аудита.
const (
	// DenyReasonPermission — у субъекта нет разрешения.
	DenyReasonPermission = "permission"
	// DenyReasonScope — разрешение только на свои объекты, а маршрут их не отбирает (УПД.8).
	DenyReasonScope = "scope"
	// DenyReasonCheck — разрешение есть, но не пройдена другая проверка
	// авторизатора (CSRF у сессии консоли).
	DenyReasonCheck = "check"
)

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
	// Unavailable — права не удалось проверить (сбой хранилища): 503 без
	// записи об отказе, причина — в техническом журнале.
	Unavailable
)

// Authorizer решает, можно ли запросу выполнить действие с правом permission
// (УПД.3), и возвращает субъекта с его правами. Решение Allow означает, что
// разрешение есть хотя бы со ScopeOwn; область проверяет маршрутизатор.
// Сессии консоли проверяет SessionAuthorizer по правам роли (задача 2.9),
// токены API — BearerAuthorizer (задача 2.10).
type Authorizer interface {
	Authorize(r *http.Request, permission string) (Principal, Decision)
}

// DenyAll отклоняет всё. Это умолчание сервера без подключённого входа:
// защищённые эндпоинты закрыты, пока не настроена аутентификация.
type DenyAll struct{}

// Authorize всегда возвращает Unauthenticated.
func (DenyAll) Authorize(*http.Request, string) (Principal, Decision) {
	return Principal{}, Unauthenticated
}
