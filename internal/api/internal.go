package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// Внутренний API для шлюзов (ИАФ.10, решение Р8, задача 2.14): отдельный
// порт, TLS с обязательным клиентским сертификатом внутреннего УЦ
// (httpserver.Config.ClientCAPEM). Сертификат, кроме цепочки, сверяется с
// действующей строкой реестра шлюзов на каждом запросе. Контракт —
// api/internal-openapi.yaml.

// PermGatewayInternal — право зарегистрированного шлюза на внутренний API.
const PermGatewayInternal = "gateway.internal"

// heartbeatMaxBody — предел тела heartbeat.
const heartbeatMaxBody = 4 << 10

// InternalOptions — зависимости обработчика внутреннего порта.
type InternalOptions struct {
	Logger *slog.Logger
	// Hasher нужен маршрутизатору для отпечатков Idempotency-Key.
	Hasher   aisecCrypto.Hasher
	Gateways *gwregistry.Service
	// Authorizer — по умолчанию GatewayAuthorizer (тесты подменяют).
	Authorizer Authorizer
	// RateLimit — настройки ЗИ.6; по умолчанию DefaultRateRules.
	RateLimit RateConfig
	// Events — хранилище событий (задача 2.15); nil — приём событий выключен.
	Events events.Store
	// Now — часы для окна приёма событий; по умолчанию time.Now.
	Now func() time.Time
	// Extra — дополнительные маршруты (тесты и следующие задачи: пакеты 2.13).
	Extra []Route
}

// GatewayAuthorizer пускает только шлюз с проверенным клиентским
// сертификатом, который является текущим сертификатом действующего шлюза.
type GatewayAuthorizer struct {
	Gateways *gwregistry.Service
	Logger   *slog.Logger
}

// Authorize — см. Authorizer. Сертификат без проверенной цепочки, отозванный
// или неизвестный шлюз — Unauthenticated; другое право — Forbidden.
func (a GatewayAuthorizer) Authorize(r *http.Request, permission string) (Principal, Decision) {
	peer, ok := aisecCrypto.PeerFromTLS(r.TLS)
	if !ok || a.Gateways == nil {
		return Principal{}, Unauthenticated
	}
	gw, err := a.Gateways.Authenticate(r.Context(), peer, clientAddr(r))
	if err != nil {
		if !errors.Is(err, gwregistry.ErrUnknownCert) && !errors.Is(err, gwregistry.ErrRevoked) {
			a.Logger.Error("проверка сертификата шлюза", "error", err)
		}
		return Principal{}, Unauthenticated
	}
	if permission != PermGatewayInternal {
		return Principal{ID: gw.ID}, Forbidden
	}
	return Principal{ID: gw.ID, Grants: auth.Grants{PermGatewayInternal: auth.ScopeAll}}, Allow
}

// NewInternal собирает обработчик внутреннего порта: восстановление после
// паники, ограничение частоты, маршрутизатор с проверкой сертификата шлюза.
func NewInternal(o InternalOptions) (http.Handler, *Router, error) {
	if o.Hasher == nil || o.Gateways == nil {
		return nil, nil, errors.New("api: внутренний API без Hasher или реестра шлюзов")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Authorizer == nil {
		o.Authorizer = GatewayAuthorizer{Gateways: o.Gateways, Logger: o.Logger}
	}
	rt := &Router{
		mux: http.NewServeMux(), authz: o.Authorizer,
		idem: NewMemoryIdempotency(0, 0, nil), hasher: o.Hasher, logger: o.Logger,
	}
	rt.mux.HandleFunc("/", rt.notFound)
	if o.Now == nil {
		o.Now = time.Now
	}
	routes := internalRoutes(o.Gateways, o.Logger)
	if o.Events != nil {
		routes = append(routes, eventsRoutes(o.Events, o.Now, o.Logger)...)
	}
	if err := rt.Add(append(routes, o.Extra...)...); err != nil {
		return nil, nil, err
	}
	var h http.Handler = rt
	h = NewRateLimiter(o.RateLimit).Middleware(h)
	h = SecurityHeaders(h)
	h = recoverer(o.Logger, h)
	return h, rt, nil
}

func internalRoutes(g *gwregistry.Service, logger *slog.Logger) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/internal/v1/heartbeat", Permission: PermGatewayInternal, MaxBody: heartbeatMaxBody,
			Handler: heartbeat(g, logger)},
	}
}

// HeartbeatRequest — тело POST /internal/v1/heartbeat.
type HeartbeatRequest struct {
	Version    string `json:"version"`
	BundleETag string `json:"bundle_etag,omitempty"`
	// Selftest и Integrity — необязательные итоги проверок шлюза (задача 2.20).
	Selftest  *HeartbeatReport `json:"selftest,omitempty"`
	Integrity *HeartbeatReport `json:"integrity,omitempty"`
}

// HeartbeatReport — итог самотеста или контроля целостности шлюза: результат,
// время и число провалов, без путей и имён детекторов.
type HeartbeatReport struct {
	OK        bool      `json:"ok"`
	CheckedAt time.Time `json:"checked_at"`
	Reason    string    `json:"reason,omitempty"`
	Failed    int       `json:"failed"`
}

func (r *HeartbeatReport) report() *gwregistry.CheckReport {
	if r == nil {
		return nil
	}
	return &gwregistry.CheckReport{OK: r.OK, At: r.CheckedAt.UTC(), Reason: r.Reason, Failed: r.Failed}
}

// HeartbeatResponse — ответ на heartbeat: время сервера (шлюз сверяет часы,
// ВРМ.1) и рекомендуемый период.
type HeartbeatResponse struct {
	ServerTime      time.Time `json:"server_time"`
	IntervalSeconds int       `json:"interval_seconds"`
}

func heartbeat(g *gwregistry.Service, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		var req HeartbeatRequest
		if prob := DecodeJSON(w, r, &req, heartbeatMaxBody); prob != nil {
			WriteProblem(w, prob)
			return
		}
		in := gwregistry.HeartbeatInput{
			Version: req.Version, BundleETag: req.BundleETag, Selftest: req.Selftest.report(), Integrity: req.Integrity.report(),
		}
		if err := in.Validate(); err != nil {
			WriteProblem(w, Invalid("Неверные поля heartbeat: version — 1–64 символа латиницы, цифр и «.+_-», bundle_etag — до 128 печатных символов ASCII, selftest и integrity — результат, время проверки и число провалов 0–1000."))
			return
		}
		ctx, cancel := contextTimeout(r, 5*time.Second)
		defer cancel()
		now, err := g.Heartbeat(ctx, p.ID, in, clientAddr(r))
		switch {
		case errors.Is(err, gwregistry.ErrTooFrequent):
			w.Header().Set("Retry-After", retryAfterSeconds(g.HeartbeatMinInterval()))
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited, "Heartbeat отправляется слишком часто."))
			return
		case errors.Is(err, gwregistry.ErrInvalidRequest):
			WriteProblem(w, Invalid("Неверные поля heartbeat: время проверки не может быть в будущем."))
			return
		case errors.Is(err, gwregistry.ErrNotFound):
			// Шлюз отозван между проверкой сертификата и записью.
			WriteProblem(w, errUnauthorized())
			return
		case err != nil:
			logger.Error("heartbeat шлюза не записан", "gateway_id", p.ID, "error", err)
			WriteProblem(w, errInternal())
			return
		}
		WriteJSON(w, http.StatusOK, HeartbeatResponse{
			ServerTime: now.UTC(), IntervalSeconds: int(gwregistry.DefaultHeartbeatInterval / time.Second),
		})
	}
}

func retryAfterSeconds(d time.Duration) string {
	return strconv.Itoa(max(1, int((d+time.Second-1)/time.Second)))
}
