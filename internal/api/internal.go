package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/approvals"
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

// heartbeatMaxBody — предел тела heartbeat: с разделом budget — счётчики
// до 2 000 приложений за два месяца (задача 3.18).
const heartbeatMaxBody = 1 << 20

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
	// Approvals — очередь подтверждений (задача 4.10): по списку ожидающих
	// из heartbeat пропавшие запросы закрываются как interrupted; nil — нет.
	Approvals *approvals.Service
	// Quotas — признак автономной доли квот из heartbeat (задача 4.29,
	// ADR-0021, п. 5); nil — сервер его не принимает.
	Quotas QuotaObserver
	// Extra — дополнительные маршруты (тесты и следующие задачи: пакеты 2.13).
	Extra []Route
}

// QuotaObserver — состояние квот шлюза для «Состояния системы»
// (quotalease.Service).
type QuotaObserver interface {
	Observe(ctx context.Context, gatewayID string, autonomous bool) error
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
	routes := internalRoutes(o.Gateways, o.Approvals, o.Quotas, o.Logger)
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

func internalRoutes(g *gwregistry.Service, a *approvals.Service, q QuotaObserver, logger *slog.Logger) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/internal/v1/heartbeat", Permission: PermGatewayInternal, MaxBody: heartbeatMaxBody,
			Handler: heartbeat(g, a, q, logger)},
		{Method: http.MethodPost, Path: "/internal/v1/certificate", Permission: PermGatewayInternal, MaxBody: certificateMaxBody,
			Handler: reissueCertificate(g, logger)},
	}
}

// certificateMaxBody — предел тела перевыпуска (CSR в PEM, как при регистрации).
const certificateMaxBody = 16 << 10

// CertificateRequest — тело POST /internal/v1/certificate.
type CertificateRequest struct {
	CSR string `json:"csr"`
}

// CertificateResponse — перевыпущенный сертификат шлюза.
type CertificateResponse struct {
	Certificate string    `json:"certificate"`
	NotAfter    time.Time `json:"not_after"`
}

// reissueCertificate — перевыпуск сертификата шлюза по признаку из
// heartbeat (ADR-0018, п. 6.3): шлюз приходит с прежним сертификатом по
// mTLS, новый действует вместе с прежним до первого запроса с ним.
func reissueCertificate(g *gwregistry.Service, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		var req CertificateRequest
		if prob := DecodeJSON(w, r, &req, certificateMaxBody); prob != nil {
			WriteProblem(w, prob)
			return
		}
		ctx, cancel := contextTimeout(r, 10*time.Second)
		defer cancel()
		certPEM, info, err := g.Reissue(ctx, p.ID, []byte(req.CSR), clientAddr(r))
		switch {
		case errors.Is(err, gwregistry.ErrInvalidRequest):
			WriteProblem(w, Invalid("Неверный запрос на сертификат: нужен один CSR в PEM на ключ ECDSA P-256 с верной подписью.",
				FieldError{Field: "csr", Detail: "неверный CSR"}))
			return
		case errors.Is(err, gwregistry.ErrTooFrequent):
			w.Header().Set("Retry-After", "60")
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited, "Сертификат перевыпускается не чаще раза в минуту."))
			return
		case errors.Is(err, gwregistry.ErrReissueNotNeeded):
			WriteProblem(w, NewProblem(http.StatusConflict, CodeReissueNotNeeded,
				"Сертификат выпущен действующим корнем УЦ и не истекает в ближайшие 30 суток (или истекает вместе с корнем): перевыпуск не нужен."))
			return
		case errors.Is(err, gwregistry.ErrNoCA):
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Внутренний УЦ не подключён."))
			return
		case errors.Is(err, gwregistry.ErrNotFound):
			WriteProblem(w, errUnauthorized())
			return
		case err != nil:
			logger.Error("сертификат шлюза не перевыпущен", "gateway_id", p.ID, "error", err)
			WriteProblem(w, errInternal())
			return
		}
		WriteJSON(w, http.StatusOK, CertificateResponse{Certificate: string(certPEM), NotAfter: info.NotAfter.UTC()})
	}
}

// HeartbeatRequest — тело POST /internal/v1/heartbeat.
type HeartbeatRequest struct {
	Version    string `json:"version"`
	BundleETag string `json:"bundle_etag,omitempty"`
	// Selftest и Integrity — необязательные итоги проверок шлюза (задача 2.20).
	Selftest  *HeartbeatReport `json:"selftest,omitempty"`
	Integrity *HeartbeatReport `json:"integrity,omitempty"`
	// BundleKeys — KeyID ключей проверки пакетов шлюза (В19 ревью 2.r4).
	BundleKeys []string `json:"bundle_keys,omitempty"`
	// VerifyRequest — запрос проверки из консоли, на который выполнена
	// проверка с итогом Integrity (Н38 ревью 2.r4).
	VerifyRequest *time.Time `json:"verify_request,omitempty"`
	// StartedAt — время запуска процесса шлюза; Stopping — последний
	// heartbeat при корректной остановке (В27 ревью 2.r5, РСБ.2).
	StartedAt *time.Time `json:"started_at,omitempty"`
	Stopping  bool       `json:"stopping,omitempty"`
	// Budget — нарастающие счётчики расхода процесса шлюза (задача 3.18).
	Budget *HeartbeatBudget `json:"budget,omitempty"`
	// Time — часы шлюза при отправке; TLSFingerprint — отпечаток
	// действующего сертификата адреса приложений, пусто — сертификат шлюза
	// (3Н40, 3Н43 ревью 3.r3).
	Time           *time.Time `json:"time,omitempty"`
	TLSFingerprint *string    `json:"tls_fingerprint,omitempty"`
	// ApprovalsPending — ID запросов подтверждения, которые шлюз ждёт
	// (задача 4.10); шлюз присылает его только после ответа с approvals.
	// Пропавшие из списка запросы закрываются как interrupted.
	ApprovalsPending *[]string `json:"approvals_pending,omitempty"`
	// QuotaAutonomous — шлюз работает на автономной доле квот: аренду
	// получить не удаётся (задача 4.29, ADR-0021, п. 5); шлюз присылает поле
	// только после ответа с quota_leases.
	QuotaAutonomous *bool `json:"quota_autonomous,omitempty"`
}

// HeartbeatBudget — счётчики расхода процесса шлюза за текущий и, после
// смены месяца, прошлый месяц.
type HeartbeatBudget struct {
	Months []HeartbeatBudgetMonth `json:"months"`
}

// HeartbeatBudgetMonth — счётчики за месяц «ГГГГ-ММ» в часовом поясе установки.
type HeartbeatBudgetMonth struct {
	Month string                 `json:"month"`
	Apps  []HeartbeatBudgetUsage `json:"apps"`
}

// HeartbeatBudgetUsage — счётчики приложения: расход в 1e-7 ₽, токены и
// запросы с известной и неизвестной ценой модели.
type HeartbeatBudgetUsage struct {
	App              string `json:"app"`
	Cost             int64  `json:"cost"`
	PricedTokens     int64  `json:"priced_tokens"`
	UnpricedTokens   int64  `json:"unpriced_tokens"`
	Requests         int64  `json:"requests"`
	UnpricedRequests int64  `json:"unpriced_requests"`
}

func (b *HeartbeatBudget) report() *gwregistry.BudgetReport {
	if b == nil {
		return nil
	}
	out := &gwregistry.BudgetReport{Months: make([]gwregistry.BudgetMonth, 0, len(b.Months))}
	for _, m := range b.Months {
		bm := gwregistry.BudgetMonth{Month: m.Month, Apps: make([]gwregistry.BudgetUsage, 0, len(m.Apps))}
		for _, a := range m.Apps {
			bm.Apps = append(bm.Apps, gwregistry.BudgetUsage{App: a.App, Cost: a.Cost, PricedTokens: a.PricedTokens,
				UnpricedTokens: a.UnpricedTokens, Requests: a.Requests, UnpricedRequests: a.UnpricedRequests})
		}
		out.Months = append(out.Months, bm)
	}
	return out
}

// HeartbeatReport — итог самотеста или контроля целостности шлюза: результат,
// время и число провалов, без путей и имён детекторов.
type HeartbeatReport struct {
	OK        bool      `json:"ok"`
	CheckedAt time.Time `json:"checked_at"`
	Reason    string    `json:"reason,omitempty"`
	Failed    int       `json:"failed"`
	// Только у integrity (В20, Н34 ревью 2.r4): манифест и тестовый ключ.
	ManifestVersion string     `json:"manifest_version,omitempty"`
	ManifestCreated *time.Time `json:"manifest_created,omitempty"`
	TestSigned      bool       `json:"test_signed,omitempty"`
}

func (r *HeartbeatReport) report() *gwregistry.CheckReport {
	if r == nil {
		return nil
	}
	out := &gwregistry.CheckReport{OK: r.OK, At: r.CheckedAt.UTC(), Reason: r.Reason, Failed: r.Failed,
		ManifestVersion: r.ManifestVersion, TestSigned: r.TestSigned}
	if r.ManifestCreated != nil {
		out.ManifestCreated = r.ManifestCreated.UTC()
	}
	return out
}

// HeartbeatResponse — ответ на heartbeat: время сервера (шлюз сверяет часы,
// ВРМ.1), рекомендуемый период и запрос проверки целостности из консоли.
type HeartbeatResponse struct {
	ServerTime      time.Time `json:"server_time"`
	IntervalSeconds int       `json:"interval_seconds"`
	// VerifyRequestedAt — администратор запросил проверку целостности шлюза
	// (Н38 ревью 2.r4): шлюз проверяет себя и присылает итог с этим временем
	// в verify_request.
	VerifyRequestedAt *time.Time `json:"verify_requested_at,omitempty"`
	// Reissue — шлюзу нужен новый сертификат: прежний выпущен не действующим
	// корнем УЦ или скоро истекает (ADR-0018, п. 6.3).
	Reissue bool `json:"reissue,omitempty"`
	// Budget — расход остальных процессов и шлюзов за месяц по приложениям
	// с жёстким бюджетом (задача 3.18): шлюз складывает его со своим.
	Budget *HeartbeatBudgetState `json:"budget,omitempty"`
	// ClockTLS — сервер принимает поля time и tls_fingerprint (3Н40, 3Н43
	// ревью 3.r3): шлюз присылает их только после такого ответа, чтобы
	// новый шлюз работал с сервером прежней версии.
	ClockTLS bool `json:"clock_tls"`
	// Approvals — сервер ведёт очередь подтверждений и принимает поле
	// approvals_pending (задача 4.10).
	Approvals bool `json:"approvals,omitempty"`
	// QuotaLeases — сервер принимает поле quota_autonomous (задача 4.29).
	QuotaLeases bool `json:"quota_leases,omitempty"`
}

// HeartbeatBudgetState — расход остальных процессов: приложение → 1e-7 ₽.
type HeartbeatBudgetState struct {
	Month  string           `json:"month"`
	Others map[string]int64 `json:"others"`
}

func heartbeat(g *gwregistry.Service, a *approvals.Service, q QuotaObserver, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		var req HeartbeatRequest
		if prob := DecodeJSON(w, r, &req, heartbeatMaxBody); prob != nil {
			WriteProblem(w, prob)
			return
		}
		in := gwregistry.HeartbeatInput{
			Version: req.Version, BundleETag: req.BundleETag, Selftest: req.Selftest.report(), Integrity: req.Integrity.report(),
			BundleKeys: req.BundleKeys, Stopping: req.Stopping, Budget: req.Budget.report(), TLSFingerprint: req.TLSFingerprint,
		}
		if req.Time != nil {
			in.Time = *req.Time
		}
		if req.VerifyRequest != nil {
			in.VerifyRequest = *req.VerifyRequest
		}
		if req.StartedAt != nil {
			in.StartedAt = req.StartedAt.UTC()
		}
		if err := in.Validate(); err != nil || !validPending(req.ApprovalsPending) {
			WriteProblem(w, Invalid("Неверные поля heartbeat: version — 1–64 символа латиницы, цифр и «.+_-», bundle_etag — до 128 печатных символов ASCII, selftest и integrity — результат, время проверки и число провалов 0–1000, манифест — версия и время вместе, bundle_keys — до 2 идентификаторов ключей, stopping и budget — только вместе с started_at, budget — 1–2 месяца ГГГГ-ММ по возрастанию, до 2 000 приложений, счётчики 0–2^62, tls_fingerprint — пусто или 64 строчные шестнадцатеричные цифры, approvals_pending — до 256 разных UUID."))
			return
		}
		ctx, cancel := contextTimeout(r, 5*time.Second)
		defer cancel()
		res, err := g.Heartbeat(ctx, p.ID, in, clientAddr(r))
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
		resp := HeartbeatResponse{ServerTime: res.At.UTC(), ClockTLS: true, IntervalSeconds: int(gwregistry.DefaultHeartbeatInterval / time.Second),
			Reissue: res.Reissue, Approvals: a != nil, QuotaLeases: q != nil}
		if q != nil && req.QuotaAutonomous != nil {
			if err := q.Observe(ctx, p.ID, *req.QuotaAutonomous); err != nil {
				// heartbeat не отклоняется: условие обновится со следующим.
				logger.Error("квоты: признак автономной доли шлюза не записан", "class", "db", "gateway_id", p.ID, "error", err)
			}
		}
		if a != nil && (req.ApprovalsPending != nil || req.Stopping) {
			var pending []string
			if req.ApprovalsPending != nil {
				pending = *req.ApprovalsPending
			}
			if err := a.Sync(ctx, p.ID, pending, req.Stopping); err != nil {
				// heartbeat не отклоняется: запросы закроются по сроку.
				logger.Error("подтверждения: сверка ожидающих запросов шлюза", "gateway_id", p.ID, "error", err)
			}
		}
		if !res.VerifyRequestedAt.IsZero() {
			at := res.VerifyRequestedAt.UTC()
			resp.VerifyRequestedAt = &at
		}
		if b := res.Budget; b != nil {
			others := b.Others
			if others == nil {
				others = map[string]int64{}
			}
			resp.Budget = &HeartbeatBudgetState{Month: b.Month, Others: others}
		}
		WriteJSON(w, http.StatusOK, resp)
	}
}

// validPending — список ожидающих подтверждений: до MaxPending разных UUID.
func validPending(p *[]string) bool {
	if p == nil {
		return true
	}
	if len(*p) > approvals.MaxPending {
		return false
	}
	seen := make(map[string]bool, len(*p))
	for _, id := range *p {
		if !approvals.ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func retryAfterSeconds(d time.Duration) string {
	return strconv.Itoa(max(1, int((d+time.Second-1)/time.Second)))
}
