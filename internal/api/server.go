package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Options — зависимости каркаса. Последующие задачи добавляют сюда свои
// зависимости (хранилище, аудит, сессии) и маршруты в routes.go.
type Options struct {
	Logger  *slog.Logger
	Version string
	// Hasher нужен для отпечатков Idempotency-Key.
	Hasher aisecCrypto.Hasher
	// Authorizer — проверка прав; по умолчанию DenyAll.
	Authorizer Authorizer
	// OnDenied — вызывается при каждом отказе в доступе (УПД.6).
	OnDenied func(r *http.Request, permission string, d Decision)
	// Ready проверяет готовность (например, связь с PostgreSQL); nil — всегда готов.
	Ready func(ctx context.Context) error
	// Idempotency — хранилище ключей; по умолчанию в памяти.
	Idempotency IdempotencyStore
	// RateLimit — настройки ЗИ.6; по умолчанию DefaultRateRules.
	RateLimit RateConfig
	// Fallback обслуживает пути вне /api и /internal (статика веб-консоли, задача 2.21).
	Fallback http.Handler
	// Extra — дополнительные маршруты (тесты); рабочие регистрируются в routes.go.
	Extra []Route
}

// Deps — зависимости обработчиков, которые видят файлы с маршрутами.
type Deps struct {
	Logger  *slog.Logger
	Version string
	Ready   func(ctx context.Context) error
}

// New собирает обработчик сервера: восстановление после паники, заголовки
// безопасности, ограничение частоты, маршрутизатор с проверкой прав.
func New(o Options) (http.Handler, *Router, error) {
	if o.Hasher == nil {
		return nil, nil, errors.New("api: не задан Hasher")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Authorizer == nil {
		o.Authorizer = DenyAll{}
	}
	if o.Idempotency == nil {
		o.Idempotency = NewMemoryIdempotency(0, 0, nil)
	}
	rt := &Router{
		mux: http.NewServeMux(), authz: o.Authorizer, idem: o.Idempotency, hasher: o.Hasher,
		logger: o.Logger, fallback: o.Fallback, onDenied: o.OnDenied,
	}
	rt.mux.HandleFunc("/", rt.notFound)
	deps := Deps{Logger: o.Logger, Version: o.Version, Ready: o.Ready}
	if err := rt.Add(append(Routes(deps), o.Extra...)...); err != nil {
		return nil, nil, err
	}
	limiter := NewRateLimiter(o.RateLimit)
	var h http.Handler = rt
	h = limiter.Middleware(h)
	h = SecurityHeaders(h)
	h = recoverer(o.Logger, h)
	return h, rt, nil
}

// recoverer превращает панику обработчика в 500 без подробностей для клиента.
// Трасса стека идёт в технический журнал; значение паники в журнал не
// попадает: в нём могут быть данные запроса.
func recoverer(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { //nolint:errorlint // sentinel-значение, не ошибка в цепочке
					panic(v)
				}
				logger.Error("паника в обработчике", "method", r.Method, "path", r.URL.Path,
					"stack", string(debug.Stack()))
				WriteProblem(w, errInternal())
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func contextTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}
