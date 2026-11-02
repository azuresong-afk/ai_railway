package sysstatus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/license"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Настройки по умолчанию (ТЗ 7.4 РСБ.5, 7.8 ВРМ.2).
const (
	// DefaultStorageLimit — предел размера журнала аудита, при котором
	// заполнение равно 100%.
	DefaultStorageLimit int64 = 20 << 30
	// DefaultWarnPercent — порог предупреждения о заполнении.
	DefaultWarnPercent = 80
	// DefaultEvalInterval — период проверки условий уведомлений.
	DefaultEvalInterval = time.Minute
	// offlineAfter — шлюз без контакта дольше этого срока считается «нет связи»
	// (три периода heartbeat).
	offlineAfter = 3 * gwregistry.DefaultHeartbeatInterval
	// dbTimeout — предел на один запрос к БД при сборе состояния.
	dbTimeout = 3 * time.Second
	// countWindow — окно счётчиков ИАФ.4 и УПД.6.
	countWindow = 24 * time.Hour
)

// GatewaySource — реестр шлюзов (gwregistry.Service).
type GatewaySource interface {
	List(ctx context.Context) ([]gwregistry.Gateway, error)
}

// IntegritySource — последние проверки целостности (integrity.PGStore).
type IntegritySource interface {
	Latest(ctx context.Context) ([]integrity.Result, error)
}

// AlertState — сохранённое состояние условия уведомления.
type AlertState struct {
	Active bool
	Since  time.Time
}

// Store — данные из PostgreSQL. Рабочая реализация — PGStore, для тестов
// без БД — Memory.
type Store interface {
	// AuditSize — размер таблицы журнала аудита вместе с индексами, байт.
	AuditSize(ctx context.Context) (int64, error)
	// EventStats — счётчики отправителей событий по ID шлюза.
	EventStats(ctx context.Context) (map[string]GatewayEvents, error)
	// AuditCounts — число блокировок учётных записей и отказов в доступе
	// в журнале аудита начиная с since.
	AuditCounts(ctx context.Context, since time.Time) (locked, denied int, err error)
	// AuditChain — итог последней проверки цепочки журнала аудита; nil —
	// проверок не было.
	AuditChain(ctx context.Context) (*AuditChainStatus, error)
	// AlertStates — сохранённые состояния условий по коду.
	AlertStates(ctx context.Context) (map[string]AlertState, error)
	// Transition записывает состояние условия. Если оно изменилось (или
	// условие впервые активно), в той же транзакции вызывается rec и его
	// запись попадает в журнал аудита; changed сообщает, что запись сделана.
	// Первое наблюдение неактивного условия записи не создаёт.
	Transition(ctx context.Context, condition string, active bool, now time.Time,
		rec func(active bool) audit.Entry) (changed bool, err error)
	// AlertJob — последний проход фоновой задачи правил оповещений
	// (alert_job_runs, 3В17 ревью 3.r2); now — часы сервиса.
	AlertJob(ctx context.Context, now time.Time) (AlertJobRun, error)
}

// SelftestSummary — итог самотеста сервера при запуске.
type SelftestSummary struct {
	OK     bool
	At     time.Time
	Failed int
}

// Options — зависимости и настройки сервиса.
type Options struct {
	Version   string
	StartedAt time.Time
	Selftest  *SelftestSummary
	Gateways  GatewaySource
	Integrity IntegritySource
	Store     Store
	// Clock — часы; по умолчанию time.Now.
	Clock func() time.Time
	// Sync — чтение состояния часов ОС; по умолчанию SystemClock.
	Sync ClockReader
	// Timezone — часовой пояс для показа из настроек установки (ВРМ.2,
	// H-Р10); nil — UTC.
	Timezone func(ctx context.Context) (string, error)
	// StorageLimit и WarnPercent — РСБ.5; ноль — значения по умолчанию.
	StorageLimit int64
	WarnPercent  int
	Logger       *slog.Logger
	// Bundle — итог сборки пакета конфигурации шлюзов (В16 ревью 2.r3b);
	// nil или ответ nil — сервер без внутреннего порта, раздела нет.
	Bundle func(ctx context.Context) (*BundleHealth, error)
	// CANotAfter — срок действующего корня внутреннего УЦ; нулевое время —
	// УЦ не подключён, условия ca_expiry нет (3В5 ревью 3.r1).
	CANotAfter time.Time
	// CustomerCert — сертификат заказчика для адреса шлюза (задача 3.27);
	// ok = false — сертификат не загружен. nil — условий customer_cert_expiry
	// и gateway_tls нет.
	CustomerCert func(ctx context.Context) (cert CustomerCert, ok bool, err error)
	// ShadowAISyslog — состояние приёма журналов по syslog (задача 4.23);
	// nil или Enabled = false — раздела нет.
	ShadowAISyslog func() ShadowAISyslogStats
	// License — состояние лицензии (задача 4.26); nil — условий license_* нет.
	License func(ctx context.Context) (license.State, error)
	// Quota — режим квот и шлюзы на автономной доле (задача 4.29); nil —
	// условий quota_approximate и quota_autonomous нет.
	Quota func(ctx context.Context) (QuotaHealth, error)
	// GatewayLimits — последние счётчики в памяти шлюзов из heartbeat
	// (gwregistry.Service.GatewayLimits, задача 5.9 этапа 5); nil — сервер
	// без внутреннего порта, данных и условия gateway_limits нет.
	GatewayLimits func() map[string]gwregistry.LimitsMark
	// ShadowAIStorage — число сводок теневого ИИ и предел (4Н25); nil —
	// модуль не подключён, условий shadow_ai_* нет.
	ShadowAIStorage func(ctx context.Context) (count, limit int64, err error)
	// ServiceDBs — состояние служебных баз (servicedb.Registry.States,
	// ADR-0028); nil — условий service_db_* нет.
	ServiceDBs func(ctx context.Context) ([]servicedb.State, error)
}

// CustomerCert — сведения о сертификате заказчика для адреса шлюза.
type CustomerCert struct {
	Host     string
	NotAfter time.Time
	// Fingerprint — SHA-256 листового сертификата, hex (gateway_tls.fingerprint).
	Fingerprint string
}

// Service собирает состояние системы и ведёт уведомления.
type Service struct {
	o Options
	// dropped — последний виденный счётчик отброшенных событий шлюза и
	// время его роста (DM-44). Хранится в памяти: после перезапуска сервера
	// первое наблюдение — точка отсчёта.
	mu      sync.Mutex
	dropped map[string]droppedMark
	// evicted — то же для вытеснений счётчиков в памяти шлюза (задача 5.9).
	evicted map[string]droppedMark
}

type droppedMark struct {
	startedAt time.Time
	n         uint64
	grewAt    time.Time
}

// observeDropped обновляет точки отсчёта и сообщает, вырос ли счётчик
// отброшенных событий шлюза за последние DroppedWindow.
func (s *Service) observeDropped(id string, ev GatewayEvents, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dropped == nil {
		s.dropped = map[string]droppedMark{}
	}
	return grew(s.dropped, id, ev.StartedAt, ev.Dropped, now)
}

// observeEvicted — то же для вытеснений счётчиков в памяти шлюза.
func (s *Service) observeEvicted(id string, startedAt time.Time, n uint64, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.evicted == nil {
		s.evicted = map[string]droppedMark{}
	}
	return grew(s.evicted, id, startedAt, n, now)
}

// grew обновляет точку отсчёта счётчика n процесса шлюза, запущенного в
// startedAt, и сообщает, рос ли он за последние DroppedWindow.
func grew(marks map[string]droppedMark, id string, startedAt time.Time, n uint64, now time.Time) bool {
	m, ok := marks[id]
	switch {
	case !ok:
		m = droppedMark{startedAt: startedAt, n: n}
	case !m.startedAt.Equal(startedAt):
		// Новый запуск шлюза: счётчик начат заново, любое ненулевое — рост.
		if n > 0 {
			m.grewAt = now
		}
		m.startedAt, m.n = startedAt, n
	case n > m.n:
		m.n, m.grewAt = n, now
	}
	marks[id] = m
	return !m.grewAt.IsZero() && now.Sub(m.grewAt) <= DroppedWindow
}

// New проверяет настройки.
func New(o Options) (*Service, error) {
	if o.StorageLimit < 0 {
		return nil, errors.New("состояние системы: предел хранилища не может быть отрицательным")
	}
	if o.WarnPercent < 0 || o.WarnPercent > 100 {
		return nil, errors.New("состояние системы: порог предупреждения — от 1 до 100 процентов")
	}
	if o.StorageLimit == 0 {
		o.StorageLimit = DefaultStorageLimit
	}
	if o.WarnPercent == 0 {
		o.WarnPercent = DefaultWarnPercent
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Sync == nil {
		o.Sync = SystemClock
	}
	if o.Timezone == nil {
		o.Timezone = func(context.Context) (string, error) { return "UTC", nil }
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Service{o: o}, nil
}

// collected — собранное состояние и вычисленные условия. Ключи conditions —
// коды условий, в том числе по компоненту (integrity:server и т. п.);
// details — подробности записи system.alert по коду.
type collected struct {
	st         Status
	conditions map[string]bool
	details    map[string]map[string]any
}

// bundleTimeout — предел сборки пакета при запросе состояния: сборка читает
// все приложения и политики.
const bundleTimeout = 10 * time.Second

func (s *Service) dbCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, dbTimeout)
}

// unavailable отмечает раздел как не собранный; причина — только в журнале.
func (s *Service) unavailable(c *collected, section string, err error) {
	c.st.Unavailable = append(c.st.Unavailable, section)
	s.o.Logger.Error("состояние системы: раздел не собран", "class", "status", "section", section, "error", err)
}

func reportOf(r *gwregistry.CheckReport) *Report {
	if r == nil {
		return nil
	}
	return &Report{OK: r.OK, CheckedAt: r.At.UTC(), Reason: r.Reason, Failed: r.Failed}
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func (s *Service) collect(ctx context.Context) collected {
	now := s.o.Clock().UTC()
	c := collected{conditions: map[string]bool{}, details: map[string]map[string]any{}}
	c.st = Status{
		GeneratedAt: now,
		Server:      ServerStatus{Version: s.o.Version, StartedAt: s.o.StartedAt.UTC(), Integrity: []IntegrityStatus{}},
		Gateways:    []GatewayStatus{}, Notifications: []Notification{}, Unavailable: []string{},
	}
	if sm := s.o.Selftest; sm != nil {
		c.st.Server.Selftest = &Report{OK: sm.OK, CheckedAt: sm.At.UTC(), Failed: sm.Failed}
	}

	// Целостность сервера: одно условие integrity:server на все его
	// компоненты, в подробностях — какие и почему (В18 ревью 2.r3b).
	serverFailed := c.st.Server.Selftest != nil && !c.st.Server.Selftest.OK
	var serverIssues []map[string]any
	if serverFailed {
		serverIssues = append(serverIssues, map[string]any{"component": "aisec-server", "source": "selftest",
			"failed": c.st.Server.Selftest.Failed})
	}
	if s.o.Integrity != nil {
		ictx, cancel := s.dbCtx(ctx)
		list, err := s.o.Integrity.Latest(ictx)
		cancel()
		if err != nil {
			s.unavailable(&c, "integrity", err)
		}
		for _, r := range list {
			c.st.Server.Integrity = append(c.st.Server.Integrity, IntegrityStatus{
				Component: r.Component, Trigger: string(r.Trigger), CheckedAt: r.At.UTC(), OK: r.OK(),
				Reason: string(r.Reason), ManifestVersion: r.ManifestVersion, TestSigned: r.TestSigned,
				Failed: len(r.Failures) + r.Omitted,
			})
			if !r.OK() {
				serverFailed = true
				serverIssues = append(serverIssues, map[string]any{"component": r.Component, "source": "integrity",
					"reason": string(r.Reason), "failed": len(r.Failures) + r.Omitted})
			}
		}
	}
	c.conditions[integrityServer] = serverFailed
	c.details[integrityServer] = map[string]any{"component": componentServer, "issues": serverIssues}
	// Сборки с тестовым ключом манифеста (Н34 ревью 2.r4): контроль
	// целостности такой сборки подписать может любой, у кого есть репозиторий.
	var testBuild []string
	for _, r := range c.st.Server.Integrity {
		if r.TestSigned && !slices.Contains(testBuild, componentServer) {
			testBuild = append(testBuild, componentServer)
		}
	}

	// Шлюзы и счётчики событий; active — действующие шлюзы на связи (для
	// условия gateway_tls).
	var stats map[string]GatewayEvents
	var active []gwregistry.Gateway
	var limits map[string]gwregistry.LimitsMark
	if s.o.GatewayLimits != nil {
		limits = s.o.GatewayLimits()
	}
	if s.o.Store != nil {
		sctx, cancel := s.dbCtx(ctx)
		var err error
		stats, err = s.o.Store.EventStats(sctx)
		cancel()
		if err != nil {
			s.unavailable(&c, "events", err)
		}
	}
	if s.o.Gateways != nil {
		gctx, cancel := s.dbCtx(ctx)
		list, err := s.o.Gateways.List(gctx)
		cancel()
		if err != nil {
			s.unavailable(&c, "gateways", err)
		}
		for _, g := range list {
			gs := GatewayStatus{
				ID: g.ID, Name: g.Name, State: gatewayState(g, now), LastSeenAt: timePtr(g.LastSeenAt), Version: g.Version,
				BundleETag: g.BundleETag, CertNotAfter: timePtr(g.CertNotAfter),
				Selftest: reportOf(g.Selftest), Integrity: reportOf(g.Integrity),
			}
			if ev, ok := stats[g.ID]; ok {
				e := ev
				gs.Events = &e
				c.st.Events.Dropped += ev.Dropped
				c.st.Events.Rejected += ev.Rejected
			}
			if m, ok := limits[g.ID]; ok {
				gs.Limits = gatewayLimits(m)
			}
			if g.Status == gwregistry.StatusActive {
				s.blinding(&c, g, &gs, stats, now)
				if m, ok := limits[g.ID]; ok && s.o.GatewayLimits != nil {
					s.gatewayLimits(&c, g, m, now)
				}
				if gs.State == GatewayOnline {
					active = append(active, g)
				}
				code := integrityGateway + g.ID
				var issues []map[string]any
				if gs.Selftest != nil && !gs.Selftest.OK {
					issues = append(issues, map[string]any{"source": "selftest", "failed": gs.Selftest.Failed})
				}
				if gs.Integrity != nil && !gs.Integrity.OK {
					issues = append(issues, map[string]any{"source": "integrity", "reason": gs.Integrity.Reason, "failed": gs.Integrity.Failed})
				}
				// Откат выпуска шлюза и чужой ключ проверки пакетов (В19, В20
				// ревью 2.r4).
				if g.Rollback() {
					issues = append(issues, map[string]any{"source": "integrity", "reason": "manifest_rollback",
						"manifest_version": g.Integrity.ManifestVersion, "previous_version": g.ManifestMaxVersion})
				}
				if g.BundleKeysOK != nil && !*g.BundleKeysOK {
					issues = append(issues, map[string]any{"source": "bundle_keys"})
				}
				if g.Integrity != nil && g.Integrity.TestSigned {
					testBuild = append(testBuild, componentGateway+g.ID)
				}
				c.conditions[code] = len(issues) > 0
				c.details[code] = map[string]any{"component": componentGateway + g.ID, "gateway_name": g.Name, "issues": issues}
			}
			c.st.Gateways = append(c.st.Gateways, gs)
		}
	}

	c.conditions[ConditionTestBuild] = len(testBuild) > 0
	c.details[ConditionTestBuild] = map[string]any{"components": testBuild}

	// Время (ВРМ.1–2).
	clk := s.o.Sync()
	c.st.Time = TimeStatus{ServerTime: now, Sync: clk.Sync, ErrorMicros: clk.ErrorMicros}
	tctx, cancel := s.dbCtx(ctx)
	tz, err := s.o.Timezone(tctx)
	cancel()
	if err != nil {
		s.unavailable(&c, "timezone", err)
	} else {
		c.st.Time.Timezone = tz
	}

	// Заполнение журнала аудита (РСБ.5).
	c.st.Storage = StorageStatus{LimitBytes: s.o.StorageLimit, WarnPercent: s.o.WarnPercent}
	if s.o.Store != nil {
		sctx, cancel := s.dbCtx(ctx)
		size, err := s.o.Store.AuditSize(sctx)
		cancel()
		if err != nil {
			s.unavailable(&c, "storage", err)
		} else {
			c.st.Storage.Available, c.st.Storage.AuditBytes = true, size
			c.st.Storage.UsedPercent = percent(size, s.o.StorageLimit)
			c.st.Storage.WarnExceeded = c.st.Storage.UsedPercent >= s.o.WarnPercent
		}
	}

	// Цепочка журнала аудита (РСБ.4): последняя проверка — фоновая или ручная.
	if s.o.Store != nil {
		actx, cancel := s.dbCtx(ctx)
		chain, err := s.o.Store.AuditChain(actx)
		cancel()
		if err != nil {
			s.unavailable(&c, "audit_chain", err)
		} else {
			c.st.AuditChain = chain
			c.conditions[ConditionAuditLog] = chain != nil && !chain.OK
		}
	}

	// Пакет конфигурации шлюзов (В16, Н28 ревью 2.r3b).
	var bundle *BundleHealth
	if s.o.Bundle != nil {
		bctx, cancel := context.WithTimeout(ctx, bundleTimeout)
		h, err := s.o.Bundle(bctx)
		cancel()
		switch {
		case err != nil:
			s.unavailable(&c, "bundle", err)
		case h != nil:
			bundle = h
			s.bundle(&c, h, now)
		}
	}

	s.shadowAISyslog(&c)
	c.conditions[ConditionTime] = clk.Sync == SyncUnsynchronized
	c.conditions[ConditionStorage] = c.st.Storage.WarnExceeded
	if ca := s.o.CANotAfter; !ca.IsZero() {
		left := ca.Sub(now)
		d := map[string]any{"root_not_after": ca.UTC().Format(time.RFC3339), "days_left": max(int(left/(24*time.Hour)), 0)}
		c.conditions[ConditionCAExpiry] = left <= CAExpiryWarn
		c.conditions[caExpiryCritical] = left <= CAExpiryCritical
		c.details[ConditionCAExpiry], c.details[caExpiryCritical] = d, d
	}
	if s.o.CustomerCert != nil {
		cctx, cancel := s.dbCtx(ctx)
		cert, ok, err := s.o.CustomerCert(cctx)
		cancel()
		switch {
		case err != nil:
			s.unavailable(&c, "customer_cert", err)
		case !ok:
			// Сертификат удалён — условия снимаются.
			c.conditions[ConditionCustomerCertExpiry], c.conditions[customerCertCritical] = false, false
		default:
			left := cert.NotAfter.Sub(now)
			d := map[string]any{"host": cert.Host, "cert_not_after": cert.NotAfter.UTC().Format(time.RFC3339),
				"days_left": max(int(left/(24*time.Hour)), 0)}
			c.conditions[ConditionCustomerCertExpiry] = left <= CustomerCertExpiryWarn
			c.conditions[customerCertCritical] = left <= CustomerCertExpiryCritical
			c.details[ConditionCustomerCertExpiry], c.details[customerCertCritical] = d, d
		}
		if err == nil {
			s.gatewayTLS(&c, active, cert, ok, bundle, now)
		}
	}
	if s.o.License != nil {
		lctx, cancel := s.dbCtx(ctx)
		st, err := s.o.License(lctx)
		cancel()
		if err != nil {
			s.unavailable(&c, "license", err)
		} else {
			licenseConditions(&c, st)
		}
	}
	if s.o.Quota != nil && s.o.Gateways != nil {
		s.quota(ctx, &c, active)
	}
	if s.o.Store != nil {
		s.alertJob(ctx, &c, now)
	}
	if s.o.ShadowAIStorage != nil {
		s.shadowAIStorage(ctx, &c)
	}
	if s.o.ServiceDBs != nil {
		s.serviceDBs(ctx, &c)
	}
	sort.Strings(c.st.Unavailable)
	return c
}

// gatewayLimits — счётчики в памяти шлюза для ответа.
func gatewayLimits(m gwregistry.LimitsMark) *GatewayLimits {
	out := &GatewayLimits{ReportedAt: m.At.UTC(), StartedAt: timePtr(m.StartedAt)}
	if t := m.ToolRate; t != nil {
		out.ToolRate = &GatewayToolRate{Keys: t.Keys, MaxKeys: t.MaxKeys, Evictions: t.Evictions}
	}
	if ss := m.Sessions; ss != nil {
		out.Sessions = &GatewaySessions{Sessions: ss.Sessions, MaxSessions: ss.MaxSessions, MaxAppSessions: ss.MaxAppSessions,
			Evictions: ss.Evictions, AppEvictions: ss.AppEvictions}
	}
	return out
}

// gatewayLimits — условие gateway_limits действующего шлюза (задача 5.9
// этапа 5): за DroppedWindow росли вытеснения счётчиков лимитов вызовов
// инструментов или сессий session.risk из-за общего предела. Вытеснения
// из-за доли приложения в условие не входят: приложение вытесняет свои же
// сессии, чужие оценки не страдают (4Н13); они видны в разделе шлюза.
func (s *Service) gatewayLimits(c *collected, g gwregistry.Gateway, m gwregistry.LimitsMark, now time.Time) {
	var tool, sess int64
	if m.ToolRate != nil {
		tool = m.ToolRate.Evictions
	}
	if m.Sessions != nil {
		sess = m.Sessions.Evictions
	}
	code := ConditionGatewayLimits + ":" + g.ID
	c.conditions[code] = s.observeEvicted(g.ID, m.StartedAt, uint64(tool)+uint64(sess), now) //nolint:gosec // G115: счётчики 0–2^62 (gwregistry.Limits.validate)
	c.details[code] = map[string]any{"component": componentGateway + g.ID, "gateway_name": g.Name,
		"tool_rate_evictions": tool, "session_evictions": sess}
}

// shadowAIStorage — заполнение хранилища сводок теневого ИИ и условия
// shadow_ai_storage (от ShadowAIWarnPercent) и shadow_ai_full (предел
// достигнут: импорт получает 507). Активно одно из двух.
func (s *Service) shadowAIStorage(ctx context.Context, c *collected) {
	sctx, cancel := s.dbCtx(ctx)
	n, limit, err := s.o.ShadowAIStorage(sctx)
	cancel()
	if err != nil {
		s.unavailable(c, "shadow_ai_storage", err)
		return
	}
	if limit <= 0 {
		return
	}
	st := &ShadowAIStorage{Aggregates: n, MaxAggregates: limit, UsedPercent: percent(n, limit), WarnPercent: ShadowAIWarnPercent}
	c.st.ShadowAIStorage = st
	full := n >= limit
	d := map[string]any{"aggregates": n, "max_aggregates": limit, "used_percent": st.UsedPercent}
	c.conditions[ConditionShadowAIFull] = full
	c.conditions[ConditionShadowAIStorage] = !full && st.UsedPercent >= ShadowAIWarnPercent
	c.details[ConditionShadowAIFull], c.details[ConditionShadowAIStorage] = d, d
}

// builtinFallbackKind — вид служебной базы, у которого без проверенной
// загруженной версии действует встроенная база выпуска: compliance.BaseKind
// (импорт compliance дал бы цикл; совпадение проверяет TestStatusServiceDBInvalid).
const builtinFallbackKind = "compliance_requirements"

// serviceDBs — условия служебных баз (ADR-0028): текущая сохранённая
// версия не прошла повторную проверку — работает предыдущая
// (service_db_previous) или база не используется (service_db_unused; у базы
// требований действует встроенная, подробность fallback: builtin).
// Непрошедшая предыдущая версия при действующей текущей — не условие:
// работе она не мешает, а возврат на неё отклоняется проверкой.
func (s *Service) serviceDBs(ctx context.Context, c *collected) {
	sctx, cancel := s.dbCtx(ctx)
	states, err := s.o.ServiceDBs(sctx)
	cancel()
	if err != nil {
		s.unavailable(c, "service_dbs", err)
		return
	}
	for _, st := range states {
		invalid := st.Current != nil && !st.Current.Valid
		prev, unused := ConditionServiceDBPrevious+":"+st.Kind, ConditionServiceDBUnused+":"+st.Kind
		c.conditions[prev] = invalid && st.Active == servicedb.ActivePrevious
		c.conditions[unused] = invalid && st.Active == servicedb.ActiveNone
		d := map[string]any{"component": componentServiceDB + st.Kind, "kind": st.Kind, "title": st.Title, "active": st.Active}
		if st.Kind == builtinFallbackKind && st.Active == servicedb.ActiveNone {
			// База требований без проверенной загруженной версии переходит на
			// встроенную базу выпуска (5Н9 ревью 5.r1 этапа 5).
			d["fallback"] = "builtin"
		}
		if invalid {
			d["version"], d["reason"] = st.Current.Version, st.Current.Reason
		}
		if st.Previous != nil && st.Active == servicedb.ActivePrevious {
			d["previous_version"] = st.Previous.Version
		}
		c.details[prev], c.details[unused] = d, d
	}
}

// licenseConditions — условия лицензии (ADR-0026, п. 8). Без лицензии
// («пилот по договору») все условия сняты, в том числе license_clock:
// сроков, которые можно продлить переводом часов, нет.
func licenseConditions(c *collected, st license.State) {
	// «state» занят состоянием условия (raised или cleared).
	d := map[string]any{"license_state": st.Phase}
	if st.Number > 0 {
		d["number"] = st.Number
	}
	if st.Signed != nil {
		d["valid_until"] = st.Signed.License.ValidUntil.UTC().Format(time.RFC3339)
		d["days_left"] = st.DaysLeft()
		d["grace_until"] = st.GraceUntil().UTC().Format(time.RFC3339)
	}
	expiring := st.Phase == license.PhaseExpiring
	c.conditions[ConditionLicenseExpiry] = expiring
	c.conditions[licenseExpiryCritical] = expiring && st.LeftUntil() <= license.ExpiryCritical
	c.conditions[ConditionLicenseGrace] = st.Phase == license.PhaseGrace
	c.conditions[ConditionLicenseRestricted] = st.Phase == license.PhaseRestricted
	c.conditions[ConditionLicenseInvalid] = st.Phase == license.PhaseInvalid
	c.conditions[ConditionLicenseClock] = st.Phase != license.PhaseNone && st.ClockBehind
	clock := map[string]any{"server_time": st.Now.UTC().Format(time.RFC3339), "license_time": st.At.UTC().Format(time.RFC3339)}
	for _, code := range []string{ConditionLicenseExpiry, licenseExpiryCritical, ConditionLicenseGrace, ConditionLicenseRestricted,
		ConditionLicenseInvalid} {
		c.details[code] = d
	}
	maps.Copy(clock, d)
	c.details[ConditionLicenseClock] = clock
}

// quota — условия квот (задача 4.29, ADR-0021, пп. 2 и 5): режим local при
// нескольких действующих шлюзах на связи и шлюзы на автономной доле.
func (s *Service) quota(ctx context.Context, c *collected, active []gwregistry.Gateway) {
	qctx, cancel := s.dbCtx(ctx)
	h, err := s.o.Quota(qctx)
	cancel()
	if err != nil {
		s.unavailable(c, "quota", err)
		return
	}
	c.conditions[ConditionQuotaApprox] = h.Mode == "local" && len(active) > 1
	c.details[ConditionQuotaApprox] = map[string]any{"gateways_online": len(active), "quota_mode": h.Mode}
	for _, g := range active {
		code := ConditionQuotaAutonomous + ":" + g.ID
		c.conditions[code] = h.Mode == "leased" && slices.Contains(h.Autonomous, g.ID)
		c.details[code] = map[string]any{"component": componentGateway + g.ID, "gateway_name": g.Name}
	}
}

// alertJob — условие alert_job_stale (DM-44, 3В17 ревью 3.r2): фоновая
// задача правил не отмечала проход дольше AlertJobStaleAfter, а сервер
// работает дольше этого срока. Условие поднимается вне транзакции прохода,
// поэтому видно и тогда, когда каждый проход откатывается.
func (s *Service) alertJob(ctx context.Context, c *collected, now time.Time) {
	jctx, cancel := s.dbCtx(ctx)
	job, err := s.o.Store.AlertJob(jctx, now)
	cancel()
	switch {
	case err != nil:
		s.unavailable(c, "alert_job", err)
		return
	case !job.Tracked:
		return
	}
	stale := now.Sub(s.o.StartedAt) > AlertJobStaleAfter && (job.LastRunAt.IsZero() || job.Age > AlertJobStaleAfter)
	d := map[string]any{"stale_after_minutes": int(AlertJobStaleAfter / time.Minute)}
	if !job.LastRunAt.IsZero() {
		d["last_run_at"] = job.LastRunAt.UTC().Format(time.RFC3339)
		d["age_seconds"] = int64(job.Age / time.Second)
	}
	// 3Н48 ревью 3.r4: проход идёт, но правило падает на каждом проходе.
	if job.FailingRules > 0 {
		d["failing_rules"] = job.FailingRules
		d["failing_since"] = job.FailingSince.UTC().Format(time.RFC3339)
	}
	c.conditions[ConditionAlertJob] = stale || job.FailingRules > 0
	c.details[ConditionAlertJob] = d
}

// blinding — условия DM-44 действующего шлюза: недоступен, отбрасывает
// события, скоро истекает сертификат, итог контроля целостности устарел
// или не приходит (Н29). Устаревший итог помечается Stale.
func (s *Service) blinding(c *collected, g gwregistry.Gateway, gs *GatewayStatus, stats map[string]GatewayEvents, now time.Time) {
	base := map[string]any{"component": componentGateway + g.ID, "gateway_name": g.Name}
	with := func(extra map[string]any) map[string]any {
		d := maps.Clone(base)
		maps.Copy(d, extra)
		return d
	}
	online := gs.State == GatewayOnline
	c.conditions[ConditionOffline+":"+g.ID] = !online
	c.details[ConditionOffline+":"+g.ID] = with(map[string]any{"last_seen_at": gs.LastSeenAt})
	if ev, ok := stats[g.ID]; ok {
		code := ConditionEventsDropped + ":" + g.ID
		c.conditions[code] = s.observeDropped(g.ID, ev, now)
		c.details[code] = with(map[string]any{"dropped": ev.Dropped, "started_at": ev.StartedAt})
	}
	if !g.CertNotAfter.IsZero() {
		code := ConditionCertExpiry + ":" + g.ID
		c.conditions[code] = g.CertNotAfter.Sub(now) < CertExpiryWarn
		c.details[code] = with(map[string]any{"cert_not_after": g.CertNotAfter.UTC()})
	}
	// Шлюз без связи не проверяется на устаревание: это условие offline.
	if online && g.ClockSkew != nil {
		code := ConditionGatewayClock + ":" + g.ID
		skew := *g.ClockSkew
		c.conditions[code] = skew > GatewayClockSkewWarn || skew < -GatewayClockSkewWarn
		c.details[code] = with(map[string]any{"skew_seconds": int64(skew / time.Second),
			"warn_seconds": int64(GatewayClockSkewWarn / time.Second)})
	}
	if online {
		code := ConditionReportsStale + ":" + g.ID
		stale := false
		switch {
		case gs.Integrity != nil:
			stale = now.Sub(gs.Integrity.CheckedAt) > StaleAfter
			gs.Integrity.Stale = stale
		case !g.StartedAt.IsZero():
			// Шлюз этой версии перестал присылать итог целостности.
			stale = now.Sub(g.StartedAt) > StaleAfter
		}
		c.conditions[code] = stale
		d := with(map[string]any{"stale_after_minutes": int(StaleAfter / time.Minute)})
		if gs.Integrity != nil {
			d["checked_at"] = gs.Integrity.CheckedAt
		}
		c.details[code] = d
	}
}

// gatewayTLS — условие ЗИ.4 по шлюзам на связи (3Н43 ревью 3.r3): шлюз
// применил текущий пакет, но дольше BundleLagAfter после его сборки
// отвечает приложениям не тем сертификатом, что загружен в консоли (без
// сертификата заказчика — своим). Пакет не собран или шлюз на другой
// версии — это условия config_bundle и config_bundle_lag, здесь не
// проверяются. Шлюз, который отпечаток не присылает, пропускается.
func (s *Service) gatewayTLS(c *collected, active []gwregistry.Gateway, cert CustomerCert, loaded bool, h *BundleHealth, now time.Time) {
	if h == nil || h.Failed || h.Version == 0 {
		return
	}
	want := ""
	if loaded {
		want = cert.Fingerprint
	}
	for _, g := range active {
		if g.TLSFingerprint == nil || g.BundleETag == "" || g.BundleETag != h.ETag {
			continue
		}
		code := ConditionGatewayTLS + ":" + g.ID
		c.conditions[code] = *g.TLSFingerprint != want && now.Sub(h.BuiltAt) > BundleLagAfter
		c.details[code] = map[string]any{"component": componentGateway + g.ID, "gateway_name": g.Name,
			"gateway_fingerprint": *g.TLSFingerprint, "expected_fingerprint": want, "host": cert.Host}
	}
}

// bundle заполняет раздел пакета и условия ОЦЛ.3: пакет собран не
// полностью; действующий шлюз на связи дольше BundleLagAfter работает на
// другой версии (защита от отката держится на файле шлюза — Н28).
func (s *Service) bundle(c *collected, h *BundleHealth, now time.Time) {
	bs := &BundleStatus{Version: h.Version, ETag: h.ETag, BuiltAt: timePtr(h.BuiltAt), Complete: !h.Failed && len(h.Excluded) == 0,
		Reason: h.Reason, Excluded: slices.Clone(h.Excluded), Lagging: []string{}}
	if bs.Excluded == nil {
		bs.Excluded = []ExcludedApp{}
	}
	c.conditions[ConditionBundle] = !bs.Complete
	excluded := make([]string, 0, len(h.Excluded))
	for _, x := range h.Excluded {
		excluded = append(excluded, x.Application)
	}
	c.details[ConditionBundle] = map[string]any{"version": h.Version, "failed": h.Failed, "reason": h.Reason,
		"excluded": excluded[:min(len(excluded), 50)], "excluded_count": len(excluded)}
	if !slices.Contains(c.st.Unavailable, "gateways") {
		for _, g := range c.st.Gateways {
			if g.State != GatewayOnline {
				continue
			}
			code := bundleLagGateway + g.ID
			// Шлюз без пакета (файл конфигурации этапа 1) ETag не присылает.
			lag := h.Version > 0 && g.BundleETag != "" && g.BundleETag != h.ETag && now.Sub(h.BuiltAt) > BundleLagAfter
			c.conditions[code] = lag
			c.details[code] = map[string]any{"component": componentGateway + g.ID, "gateway_name": g.Name,
				"gateway_etag": g.BundleETag, "current_etag": h.ETag}
			if lag {
				bs.Lagging = append(bs.Lagging, g.ID)
			}
		}
	}
	c.st.Bundle = bs
}

// percent — доля size от limit в процентах, не больше 100; limit > 0.
func percent(size, limit int64) int {
	if size <= 0 {
		return 0
	}
	if size >= limit {
		return 100
	}
	return int(size * 100 / limit)
}

func gatewayState(g gwregistry.Gateway, now time.Time) string {
	switch {
	case g.Status == gwregistry.StatusRevoked:
		return GatewayRevoked
	case g.Status == gwregistry.StatusPending:
		return GatewayPending
	case g.LastSeenAt.IsZero() || now.Sub(g.LastSeenAt) > offlineAfter:
		return GatewayOffline
	}
	return GatewayOnline
}

// titles и requirements — условия раздела 7.
var conditionInfo = []struct{ code, requirement, title string }{
	{ConditionAccount, "ИАФ.4", "Блокировки учётных записей после неудачных попыток входа"},
	{ConditionDenied, "УПД.6", "Отказы в доступе к функциям управления"},
	{ConditionAuditLog, "РСБ.4", "Нарушена цепочка журнала аудита"},
	{ConditionStorage, "РСБ.5", "Журнал аудита приближается к пределу хранилища"},
	{ConditionIntegrity, "ОЦЛ.5", "Нарушена целостность или не пройден самотест компонента"},
	{ConditionTime, "ВРМ.1", "Системное время не синхронизировано"},
	{ConditionBundle, "ОЦЛ.3", "Пакет конфигурации шлюзов собран не полностью"},
	{ConditionBundleLag, "ОЦЛ.3", "Шлюз работает на устаревшем пакете конфигурации"},
	{ConditionTestBuild, "ОЦЛ.1", "Сборка не для поставки (тестовый ключ манифеста)"},
	{ConditionOffline, "РСБ.7", "Шлюз не выходит на связь"},
	{ConditionEventsDropped, "РСБ.7", "Шлюз отбрасывает события"},
	{ConditionReportsStale, "ОЦЛ.5", "Нет свежего итога контроля целостности шлюза"},
	{ConditionCertExpiry, "ИАФ.10", "Скоро истекает сертификат шлюза"},
	{ConditionGatewayClock, "ВРМ.1", "Часы шлюза расходятся с часами сервера больше чем на минуту"},
	{ConditionGatewayTLS, "ЗИ.4", "Шлюз отвечает приложениям не тем сертификатом, что загружен в консоли"},
	{ConditionCAExpiry, "ИАФ.10", "Истекает корень внутреннего УЦ: нужна ротация (aisec-cli keys rotate-ca)"},
	{ConditionCustomerCertExpiry, "ЗИ.4", "Скоро истекает сертификат заказчика для адреса шлюза: загрузите новый"},
	{ConditionLicenseExpiry, "ЗИ.2", "Скоро истекает срок лицензии: запросите новую у производителя"},
	{ConditionLicenseGrace, "ЗИ.2", "Срок лицензии истёк, идёт льготный период: после него изменения конфигурации будут запрещены"},
	{ConditionLicenseRestricted, "ЗИ.2", "Льготный период лицензии закончился: изменения конфигурации запрещены, трафик и защита работают"},
	{ConditionLicenseInvalid, "ЗИ.2", "Загруженная лицензия не прошла проверку подписи: изменения конфигурации запрещены"},
	{ConditionLicenseClock, "ВРМ.1", "Часы сервера отстают от времени, которое уже видела лицензия: проверьте синхронизацию времени"},
	{ConditionAlertJob, "РСБ.7", "Фоновая задача правил оповещений не выполняется или правило падает на каждом проходе: правила частоты, аномалий и бюджетов молчат"},
	{ConditionQuotaApprox, "ЗИ.6", "Квоты соблюдаются приблизительно: шлюзов на связи больше одного, а режим квот — local: переключите на leased запросом PUT /api/v1/quota-settings (руководство администратора, раздел 7, «Квоты при нескольких экземплярах шлюза»)"},
	{ConditionQuotaAutonomous, "ЗИ.6", "Квоты в автономном режиме: шлюз не получает аренду квот у сервера и работает на равной доле"},
	{ConditionGatewayLimits, "РСБ.7", "Шлюз вытесняет счётчики лимитов вызовов инструментов или оценки сессий: для части ключей счёт начат заново"},
	{ConditionShadowAIStorage, "РСБ.7", "Хранилище сводок теневого ИИ заполнено на 90 % и больше: сократите срок хранения сводок"},
	{ConditionShadowAIFull, "РСБ.7", "Хранилище сводок теневого ИИ заполнено: импорт журналов и приём по syslog отклоняются"},
	{ConditionServiceDBPrevious, "ОЦЛ.5", "Сохранённая служебная база не прошла проверку подписи: работает предыдущая версия"},
	{ConditionServiceDBUnused, "ОЦЛ.5", "Сохранённая служебная база не прошла проверку подписи: загруженная база не используется (для базы требований действует встроенная база выпуска)"},
}

// family — условие раздела 7, к которому относится код (integrity:server —
// к integrity).
func family(code string) string {
	if i := strings.IndexByte(code, ':'); i > 0 {
		return code[:i]
	}
	return code
}

// component — компонент кода условия по компоненту: server или gateway:<ID>.
func component(code string) string {
	switch {
	case code == integrityServer:
		return componentServer
	case strings.HasPrefix(code, integrityGateway):
		return componentGateway + strings.TrimPrefix(code, integrityGateway)
	}
	for _, fam := range gatewayFamilies {
		if strings.HasPrefix(code, fam+":") {
			return componentGateway + strings.TrimPrefix(code, fam+":")
		}
	}
	for _, fam := range serviceDBFamilies {
		if strings.HasPrefix(code, fam+":") {
			return componentServiceDB + strings.TrimPrefix(code, fam+":")
		}
	}
	return ""
}

func requirementOf(fam string) string {
	for _, ci := range conditionInfo {
		if ci.code == fam {
			return ci.requirement
		}
	}
	return ""
}

// Status собирает текущее состояние системы. Сбой одного раздела не мешает
// остальным: раздел попадает в Unavailable.
func (s *Service) Status(ctx context.Context) Status {
	c := s.collect(ctx)
	var states map[string]AlertState
	var locked, denied *int
	if s.o.Store != nil {
		sctx, cancel := s.dbCtx(ctx)
		var err error
		states, err = s.o.Store.AlertStates(sctx)
		cancel()
		if err != nil {
			s.unavailable(&c, "notifications", err)
		}
		cctx, cancel2 := s.dbCtx(ctx)
		l, d, err := s.o.Store.AuditCounts(cctx, c.st.GeneratedAt.Add(-countWindow))
		cancel2()
		if err != nil {
			s.unavailable(&c, "notifications", err)
		} else {
			locked, denied = &l, &d
		}
	}
	for _, ci := range conditionInfo {
		n := Notification{Condition: ci.code, Requirement: ci.requirement, Title: ci.title}
		switch ci.code {
		case ConditionAccount:
			n.Count, n.Active = locked, locked != nil && *locked > 0
		case ConditionDenied:
			n.Count, n.Active = denied, denied != nil && *denied > 0
		case ConditionIntegrity, ConditionBundleLag, ConditionOffline, ConditionEventsDropped, ConditionReportsStale,
			ConditionCertExpiry, ConditionGatewayClock, ConditionGatewayTLS, ConditionQuotaAutonomous, ConditionGatewayLimits,
			ConditionServiceDBPrevious, ConditionServiceDBUnused:
			// Одна строка на все компоненты; «с» — самое раннее из активных.
			for _, code := range sortedCodes(c.conditions) {
				if family(code) != ci.code || !c.conditions[code] {
					continue
				}
				n.Active = true
				n.Components = append(n.Components, component(code))
				if st, ok := states[code]; ok && st.Active && (n.Since == nil || st.Since.Before(*n.Since)) {
					since := st.Since.UTC()
					n.Since = &since
				}
			}
		case ConditionTestBuild:
			n.Active = c.conditions[ci.code]
			if list, _ := c.details[ci.code]["components"].([]string); n.Active {
				n.Components = append(n.Components, list...)
			}
			if st, ok := states[ci.code]; ok && st.Active && n.Active {
				since := st.Since.UTC()
				n.Since = &since
			}
		default:
			n.Active = c.conditions[ci.code]
			if st, ok := states[ci.code]; ok && st.Active && n.Active {
				since := st.Since.UTC()
				n.Since = &since
			}
		}
		c.st.Notifications = append(c.st.Notifications, n)
	}
	sort.Strings(c.st.Unavailable)
	c.st.Unavailable = dedupe(c.st.Unavailable)
	return c.st
}

func sortedCodes(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// systemActor — «кто» для записей об уведомлениях.
var systemActor = audit.Actor{Type: audit.ActorSystem, ID: "system-status", Name: "Состояние системы"}

// Evaluate вычисляет условия ВРМ.1, РСБ.4, РСБ.5, ОЦЛ.3 и ОЦЛ.5 и при смене
// состояния пишет запись system.alert в журнал аудита. ОЦЛ.5 и отставание
// пакета ведутся по компоненту (В18 ревью 2.r3b): нарушение второго шлюза,
// пока первый ещё нарушен, тоже записывается. Повторный вызов без
// изменений ничего не пишет. ИАФ.4 и УПД.6 уже фиксируются записями
// auth.locked и access.denied, поэтому здесь не дублируются.
func (s *Service) Evaluate(ctx context.Context) error {
	if s.o.Store == nil {
		return nil
	}
	c := s.collect(ctx)
	now := c.st.GeneratedAt
	// Активные в хранилище условия компонентов, которых больше нет (шлюз
	// отозван или удалён), и прежнее общее условие integrity снимаются.
	// Шлюз, который есть в реестре, но не на связи, сохраняет прежнее
	// состояние: потеря связи не снимает отставание пакета (самопроверка H4, С2).
	sctx, cancel := s.dbCtx(ctx)
	states, err := s.o.Store.AlertStates(sctx)
	cancel()
	if err != nil {
		return fmt.Errorf("состояния уведомлений: %w", err)
	}
	known := map[string]bool{}
	for _, g := range c.st.Gateways {
		if g.State != GatewayRevoked {
			known[componentGateway+g.ID] = true
		}
	}
	for code, st := range states {
		comp := component(code)
		gone := strings.HasPrefix(comp, componentGateway) && !known[comp]
		if _, ok := c.conditions[code]; !ok && st.Active && (code == ConditionIntegrity || gone) {
			c.conditions[code] = false
		}
	}
	var errs []error
	for _, code := range sortedCodes(c.conditions) {
		active := c.conditions[code]
		if s.skip(c, family(code)) {
			continue
		}
		rec := func(active bool) audit.Entry { return s.alertEntry(code, active, c) }
		tctx, cancel := s.dbCtx(ctx)
		changed, err := s.o.Store.Transition(tctx, code, active, now, rec)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("условие %s: %w", code, err))
			continue
		}
		if changed {
			s.o.Logger.Warn("изменилось состояние уведомления", "class", "status", "condition", code, "active", active)
		}
	}
	return errors.Join(errs...)
}

// skip — раздел условия не собран: состояние не меняем, ложное «снято» хуже
// паузы.
func (s *Service) skip(c collected, fam string) bool {
	missing := func(sections ...string) bool {
		for _, sec := range sections {
			if slices.Contains(c.st.Unavailable, sec) {
				return true
			}
		}
		return false
	}
	switch fam {
	case ConditionStorage:
		return !c.st.Storage.Available
	case ConditionIntegrity, ConditionTestBuild:
		return missing("integrity", "gateways")
	case ConditionBundle:
		return missing("bundle") || c.st.Bundle == nil
	case ConditionBundleLag:
		return missing("bundle", "gateways") || c.st.Bundle == nil
	case ConditionOffline, ConditionCertExpiry, ConditionReportsStale, ConditionGatewayClock:
		return missing("gateways")
	case ConditionGatewayTLS:
		return missing("gateways", "bundle", "customer_cert")
	case ConditionEventsDropped:
		return missing("gateways", "events")
	case ConditionCustomerCertExpiry:
		return missing("customer_cert")
	case ConditionLicenseExpiry, ConditionLicenseGrace, ConditionLicenseRestricted, ConditionLicenseInvalid, ConditionLicenseClock:
		return missing("license")
	case ConditionQuotaApprox, ConditionQuotaAutonomous:
		return missing("gateways", "quota")
	case ConditionGatewayLimits:
		return missing("gateways")
	case ConditionShadowAIStorage, ConditionShadowAIFull:
		return missing("shadow_ai_storage")
	case ConditionServiceDBPrevious, ConditionServiceDBUnused:
		return missing("service_dbs")
	}
	return false
}

func (s *Service) alertEntry(code string, active bool, c collected) audit.Entry {
	st := c.st
	fam := family(code)
	state, result := "cleared", audit.ResultSuccess
	if active {
		state, result = "raised", audit.ResultFailure
	}
	d := map[string]any{"condition": code, "requirement": requirementOf(fam), "state": state}
	switch fam {
	case ConditionTime:
		d["sync"] = st.Time.Sync
	case ConditionStorage:
		d["used_percent"], d["warn_percent"] = st.Storage.UsedPercent, st.Storage.WarnPercent
	case ConditionAuditLog:
		if ch := st.AuditChain; ch != nil {
			d["reason"] = ch.Reason
			if ch.BrokenSeq != nil {
				d["broken_seq"] = *ch.BrokenSeq
			}
		}
	}
	if code == ConditionIntegrity {
		// Общее условие прежних версий: заменено условиями по компоненту.
		d["superseded"] = true
	}
	for k, v := range c.details[code] {
		if k == "issues" && !active {
			continue
		}
		d[k] = v
	}
	if active && fam == ConditionIntegrity {
		if issues, _ := c.details[code]["issues"].([]map[string]any); issues != nil {
			d["violations"] = len(issues)
		}
	}
	return audit.Entry{
		Actor: systemActor, Action: "system.alert", Object: audit.Object{Type: "system", ID: code},
		Result: result, Details: d,
	}
}

// Run вызывает Evaluate сразу и затем каждые interval, пока не отменён ctx.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultEvalInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.Evaluate(ctx); err != nil && ctx.Err() == nil {
			s.o.Logger.Error("уведомления состояния системы не обновлены", "class", "status", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// GatewayLister — GatewaySource поверх хранилища реестра шлюзов: сервер
// показывает шлюзы и без внутреннего УЦ (регистрацией занимается aisec-cli).
type GatewayLister struct {
	Store gwregistry.Store
	OrgID string
}

// List — см. GatewaySource.
func (l GatewayLister) List(ctx context.Context) ([]gwregistry.Gateway, error) {
	org := l.OrgID
	if org == "" {
		org = audit.DefaultOrgID
	}
	return l.Store.List(ctx, org)
}
