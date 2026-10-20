package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Route — маршрут API. Каждый маршрут либо открытый (Public), либо требует
// права Permission: маршрут без того и другого не регистрируется (УПД.3).
type Route struct {
	Method string
	Path   string // шаблон net/http.ServeMux без метода, например /api/v1/users/{id}
	// Permission — имя разрешения; проверяется Authorizer до обработчика.
	Permission string
	// Public — маршрут без аутентификации (только статус и вход).
	Public bool
	// Idempotent включает поддержку заголовка Idempotency-Key (создающие запросы).
	Idempotent bool
	// MaxBody — предел тела; ноль — DefaultMaxBody.
	MaxBody int64
	Handler http.HandlerFunc
}

var routeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// Router — единственная точка регистрации маршрутов: проверяет права,
// размер тела и повторяемость единообразно для всех эндпоинтов.
type Router struct {
	mux      *http.ServeMux
	routes   []Route
	authz    Authorizer
	idem     IdempotencyStore
	hasher   aisecCrypto.Hasher
	logger   *slog.Logger
	fallback http.Handler
	// OnDenied вызывается при отказе в доступе (основа УПД.6 и аудита, задача 2.9).
	onDenied func(r *http.Request, permission string, d Decision)
}

// Routes возвращает копию списка маршрутов (контрактные тесты и документация).
func (rt *Router) Routes() []Route { return slices.Clone(rt.routes) }

// Add регистрирует маршруты. Ошибка означает ошибку программиста (неверное
// описание или дубликат): сервер при ней не запускается.
func (rt *Router) Add(routes ...Route) error {
	for _, r := range routes {
		if err := rt.add(r); err != nil {
			return fmt.Errorf("маршрут %s %s: %w", r.Method, r.Path, err)
		}
	}
	return nil
}

func (rt *Router) add(r Route) error {
	switch {
	case !slices.Contains(routeMethods, r.Method):
		return fmt.Errorf("метод %q не поддерживается", r.Method)
	case !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, " \t"):
		return fmt.Errorf("неверный путь")
	case r.Handler == nil:
		return fmt.Errorf("нет обработчика")
	case r.Public == (r.Permission != ""):
		return fmt.Errorf("нужно ровно одно из: Public или Permission")
	case r.Idempotent && r.Method != http.MethodPost && r.Method != http.MethodPatch:
		return fmt.Errorf("Idempotency-Key поддерживается для POST и PATCH")
	case r.MaxBody < 0:
		return fmt.Errorf("MaxBody меньше нуля")
	}
	if r.MaxBody == 0 {
		r.MaxBody = DefaultMaxBody
	}
	if rt.hasPattern(r) {
		return fmt.Errorf("маршрут уже зарегистрирован")
	}
	rt.routes = append(rt.routes, r)
	rt.mux.Handle(r.Method+" "+r.Path, rt.wrap(r))
	return nil
}

func (rt *Router) hasPattern(n Route) bool {
	return slices.ContainsFunc(rt.routes, func(r Route) bool { return r.Method == n.Method && r.Path == n.Path })
}

// wrap: права → предел тела → повторяемость → обработчик.
func (rt *Router) wrap(r Route) http.Handler {
	var h http.Handler = r.Handler
	if r.Idempotent {
		h = idempotent(rt.idem, rt.hasher, r.MaxBody, h)
	}
	inner := h
	h = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Body != nil {
			req.Body = http.MaxBytesReader(w, req.Body, r.MaxBody)
		}
		inner.ServeHTTP(w, req)
	})
	if r.Public {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p, d := rt.authz.Authorize(req, r.Permission)
		switch d {
		case Allow:
			h.ServeHTTP(w, req.WithContext(WithPrincipal(req.Context(), p)))
		case Forbidden:
			rt.denied(req, r.Permission, d)
			WriteProblem(w, errForbidden())
		default:
			rt.denied(req, r.Permission, Unauthenticated)
			WriteProblem(w, errUnauthorized())
		}
	})
}

func (rt *Router) denied(r *http.Request, permission string, d Decision) {
	if rt.onDenied != nil {
		rt.onDenied(r, permission, d)
	}
}

// canonicalPath: путь без «//», «.», «..» и завершающего «/»; перенаправлений
// сервер не выдаёт, такой путь — 404.
func canonicalPath(p string) bool {
	if p == "/" {
		return true
	}
	if strings.HasSuffix(p, "/") || strings.Contains(p, "//") {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// ServeHTTP направляет запрос; всё неизвестное — Problem Details, а не текст mux.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	api := strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/internal/")
	if api {
		w.Header().Set("Cache-Control", "no-store")
		if !canonicalPath(r.URL.Path) {
			WriteProblem(w, errNotFound())
			return
		}
	}
	rt.mux.ServeHTTP(w, r)
}

// notFound обслуживает всё, что не совпало с маршрутом: статика/SPA (если
// задан fallback) для путей вне API, иначе 404 или 405 с заголовком Allow.
func (rt *Router) notFound(w http.ResponseWriter, r *http.Request) {
	isAPI := strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/internal/")
	if !isAPI && rt.fallback != nil {
		rt.fallback.ServeHTTP(w, r)
		return
	}
	var allowed []string
	for _, m := range routeMethods {
		if m == r.Method {
			continue
		}
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, pattern := rt.mux.Handler(probe); pattern != "" && pattern != "/" {
			allowed = append(allowed, m)
		}
	}
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		WriteProblem(w, errMethodNotAllowed())
		return
	}
	WriteProblem(w, errNotFound())
}
