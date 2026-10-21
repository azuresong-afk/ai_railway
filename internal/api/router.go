package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

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
	// Scoped — обработчик проверяет права на уровне объектов (УПД.8) и
	// пускает субъекта с разрешением только на свои объекты (ScopeOwn).
	// Без признака нужно разрешение на все объекты.
	Scoped bool
	// Idempotent включает поддержку заголовка Idempotency-Key (создающие запросы).
	Idempotent bool
	// SecretOnce — ответ показывает секрет один раз (токен API, ключ
	// приложения, секрет TOTP, коды восстановления). Такой ответ нельзя
	// хранить для повтора по Idempotency-Key: признаки несовместимы.
	SecretOnce bool
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
	// onDenied вызывается при каждом отказе в доступе (УПД.6).
	onDenied func(r *http.Request, d Denial)
	// onTokenUsed вызывается после каждого пропущенного запроса по токену
	// API с шаблоном маршрута и кодом ответа (РСБ.1, задача 2.10).
	onTokenUsed func(r *http.Request, p Principal, method, path string, status int)
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
	case r.Public && r.Scoped:
		return fmt.Errorf("признак Scoped у открытого маршрута")
	case r.Idempotent && r.Method != http.MethodPost && r.Method != http.MethodPatch:
		return fmt.Errorf("Idempotency-Key поддерживается для POST и PATCH")
	case r.Idempotent && r.SecretOnce:
		return fmt.Errorf("ответ с одноразовым секретом не хранится для повтора: Idempotent несовместим с SecretOnce")
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
		reason := DenyReasonPermission
		if d == Forbidden && p.Grants.Allows(r.Permission) {
			reason = DenyReasonCheck
		}
		// Разрешение только на свои объекты пускает лишь к маршрутам,
		// которые сами отбирают объекты (УПД.8).
		if d == Allow && !r.Scoped && !p.Grants.Full(r.Permission) {
			d, reason = Forbidden, DenyReasonScope
		}
		switch d {
		case Allow:
			req = req.WithContext(WithPrincipal(req.Context(), p))
			if p.Caller != nil && p.Caller.Token != nil && rt.onTokenUsed != nil {
				rt.serveToken(w, req, h, p, r)
				return
			}
			h.ServeHTTP(w, req)
		case Forbidden:
			rt.denied(req, Denial{Principal: p, Method: r.Method, Path: r.Path, Permission: r.Permission, Decision: d, Reason: reason})
			WriteProblem(w, errForbidden())
		case Unavailable:
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
				"Не удалось проверить права доступа: повторите запрос позже."))
		case RateLimited:
			secs := max(int((p.RetryAfter+time.Second-1)/time.Second), 1)
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited,
				"Слишком много неудачных попыток входа по токену API с вашего адреса. Повторите через "+strconv.Itoa(secs)+" с."))
		default:
			rt.denied(req, Denial{Method: r.Method, Path: r.Path, Permission: r.Permission, Decision: Unauthenticated})
			WriteProblem(w, errUnauthorized())
		}
	})
}

// serveToken выполняет обработчик запроса по токену и пишет его итог;
// паника обработчика записывается как 500 и передаётся дальше (recoverer).
func (rt *Router) serveToken(w http.ResponseWriter, req *http.Request, h http.Handler, p Principal, r Route) {
	sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		v := recover()
		status := sw.status
		if v != nil {
			status = http.StatusInternalServerError
		}
		rt.onTokenUsed(req, p, r.Method, r.Path, status)
		if v != nil {
			panic(v)
		}
	}()
	h.ServeHTTP(sw, req)
}

func (rt *Router) denied(r *http.Request, d Denial) {
	if rt.onDenied != nil {
		rt.onDenied(r, d)
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
