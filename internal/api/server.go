package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
	"github.com/azuresong-afk/ai_railway/internal/notify"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
	"github.com/azuresong-afk/ai_railway/internal/reports"
)

// Options — зависимости каркаса. Последующие задачи добавляют сюда свои
// зависимости (хранилище, аудит, сессии) и маршруты в routes.go.
type Options struct {
	Logger  *slog.Logger
	Version string
	// Hasher нужен для отпечатков Idempotency-Key.
	Hasher aisecCrypto.Hasher
	// Authorizer — проверка прав; по умолчанию, если задан Auth, —
	// BearerAuthorizer (токены API) поверх SessionAuthorizer, иначе DenyAll.
	Authorizer Authorizer
	// Auth — вход, сессии и учётные записи консоли (задача 2.7).
	Auth *auth.Service
	// Gateways — регистрация шлюзов по токену (задача 2.14); nil — 503.
	Gateways *gwregistry.Service
	// Integrity — контроль целостности (задача 2.17); nil — эндпоинты отвечают 503.
	Integrity IntegrityService
	// Status — «Состояние системы» (задача 2.20); nil — эндпоинт отвечает 503.
	Status StatusService
	// Events и Audit — события в консоли (задача 2.16); без любого из них
	// эндпоинты событий отвечают 503.
	Events EventsAPI
	Audit  AuditRecorder
	// Apps — приложения, ключи и провайдеры (задача 2.11); nil — их
	// эндпоинты отвечают 503.
	Apps *apps.Service
	// Policies — политики и их версии (задача 2.12); nil — их эндпоинты
	// отвечают 503.
	Policies *versions.Service
	// AuditLog и AuditVerifier — журнал аудита в консоли (задача 2.4a):
	// просмотр и проверка цепочки той же проверкой, что фоновая; nil — их
	// эндпоинты отвечают 503.
	AuditLog      AuditJournal
	AuditVerifier AuditChainVerifier
	// Alerts — оповещения и правила (задача 3.10 этапа 3); nil — их
	// эндпоинты отвечают 503.
	Alerts *alerting.Service
	// Notify — каналы уведомлений (задача 3.13 этапа 3); nil — их
	// эндпоинты отвечают 503.
	Notify *notify.Service
	// Incidents — инциденты (задача 3.16 этапа 3); nil — их эндпоинты
	// отвечают 503.
	Incidents *incidents.Service
	// Dashboards — агрегаты для дашбордов (задача 3.19 этапа 3); nil — их
	// эндпоинты отвечают 503.
	Dashboards DashboardReader
	// Reports — отчёты и расписания рассылки (задачи 3.24, 3.25 этапа 3);
	// nil — их эндпоинты отвечают 503.
	Reports *reports.Service
	// OnDenied — вызывается при каждом отказе в доступе (УПД.6). По
	// умолчанию, если задан Auth, отказ аутентифицированному субъекту
	// пишется в журнал аудита (access.denied).
	OnDenied func(r *http.Request, d Denial)
	// OnTokenUsed — вызывается после каждого пропущенного запроса по токену
	// API. По умолчанию, если задан Auth, — запись api_token.used в журнал аудита.
	OnTokenUsed func(r *http.Request, p Principal, method, path string, status int)
	// Ready проверяет готовность (например, связь с PostgreSQL); nil — всегда готов.
	Ready func(ctx context.Context) error
	// Idempotency — хранилище ключей; по умолчанию в памяти.
	Idempotency IdempotencyStore
	// RateLimit — настройки ЗИ.6; по умолчанию DefaultRateRules.
	RateLimit RateConfig
	// TrustedProxies — сети обратных прокси, от которых принимается
	// X-Forwarded-For (ТЗ 10.3); пусто — адрес клиента по соединению.
	TrustedProxies []netip.Prefix
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
	// Auth — nil, если вход не подключён: его эндпоинты отвечают 503.
	Auth *auth.Service
	// Gateways — nil, если внутренний УЦ не подключён: регистрация отвечает 503.
	Gateways *gwregistry.Service
	// Integrity — nil, если контроль целостности не подключён: его эндпоинты отвечают 503.
	Integrity IntegrityService
	// Status — nil, если сбор состояния не подключён: эндпоинт отвечает 503.
	Status StatusService
	// Events и Audit — nil, если события не подключены: их эндпоинты отвечают 503.
	Events EventsAPI
	Audit  AuditRecorder
	// Apps — nil, если приложения не подключены: их эндпоинты отвечают 503.
	Apps *apps.Service
	// Policies — nil, если политики не подключены: их эндпоинты отвечают 503.
	Policies *versions.Service
	// AuditLog и AuditVerifier — nil, если журнал аудита не подключён к
	// консоли: соответствующий эндпоинт отвечает 503.
	AuditLog      AuditJournal
	AuditVerifier AuditChainVerifier
	// Alerts — nil, если оповещения не подключены: их эндпоинты отвечают 503.
	Alerts *alerting.Service
	// Notify — nil, если каналы уведомлений не подключены: их эндпоинты отвечают 503.
	Notify *notify.Service
	// Incidents — nil, если инциденты не подключены: их эндпоинты отвечают 503.
	Incidents *incidents.Service
	// Dashboards — nil, если агрегаты дашбордов не подключены: их эндпоинты отвечают 503.
	Dashboards DashboardReader
	// Reports — nil, если отчёты не подключены: их эндпоинты отвечают 503.
	Reports *reports.Service
	// DashCache — общие снимки дашбордов на dashCacheTTL; DashStreams —
	// ограничение одновременных потоков SSE; Reauthorize — повторная
	// проверка прав запроса на каждом шаге потока.
	DashCache   *dashCache
	DashStreams *ExportGate
	Reauthorize func(r *http.Request, permission string) (Principal, Decision)
	// Exports — ограничение одновременных выгрузок событий (В11 ревью 2.r3a).
	Exports *ExportGate
	// AuditReads — ограничение одновременных выборок журнала аудита (В17
	// ревью 2.r3b).
	AuditReads *ExportGate
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
		if o.Auth != nil {
			o.Authorizer = BearerAuthorizer{Auth: o.Auth, Logger: o.Logger,
				Next:    SessionAuthorizer{Auth: o.Auth, Logger: o.Logger},
				Limiter: auth.NewFailureLimiter(auth.LimiterConfig{}), Malformed: new(atomic.Uint64)}
		}
	}
	if o.OnDenied == nil && o.Auth != nil {
		o.OnDenied = auditDenied(o.Auth, o.Logger)
	}
	if o.OnTokenUsed == nil && o.Auth != nil {
		o.OnTokenUsed = auditTokenUsed(o.Auth, o.Logger)
	}
	if o.Idempotency == nil {
		o.Idempotency = NewMemoryIdempotency(0, 0, nil)
	}
	rt := &Router{
		mux: http.NewServeMux(), authz: o.Authorizer, idem: o.Idempotency, hasher: o.Hasher,
		logger: o.Logger, fallback: o.Fallback, onDenied: o.OnDenied, onTokenUsed: o.OnTokenUsed,
	}
	rt.mux.HandleFunc("/", rt.notFound)
	deps := Deps{Logger: o.Logger, Version: o.Version, Ready: o.Ready, Auth: o.Auth, Gateways: o.Gateways, Integrity: o.Integrity,
		Status: o.Status, Events: o.Events, Audit: o.Audit, Apps: o.Apps, Policies: o.Policies,
		AuditLog: o.AuditLog, AuditVerifier: o.AuditVerifier, Alerts: o.Alerts, Notify: o.Notify, Incidents: o.Incidents,
		Dashboards: o.Dashboards, Reports: o.Reports, DashCache: newDashCache(), DashStreams: NewExportGate(dashStreamsPerSubject, dashStreamsTotal),
		Reauthorize: o.Authorizer.Authorize,
		Exports:     NewExportGate(MaxExportsPerSubject, MaxExportsTotal), AuditReads: NewExportGate(MaxAuditReadsPerSubject, MaxAuditReadsTotal)}
	if err := rt.Add(append(Routes(deps), o.Extra...)...); err != nil {
		return nil, nil, err
	}
	limiter := NewRateLimiter(o.RateLimit)
	var h http.Handler = rt
	h = limiter.Middleware(h)
	h = ClientAddrMiddleware(o.TrustedProxies, h)
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
				logger.Error("паника в обработчике", "class", "internal", "method", r.Method, "path", r.URL.Path,
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
