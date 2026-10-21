package sysstatus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
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
	// AlertStates — сохранённые состояния условий по коду.
	AlertStates(ctx context.Context) (map[string]AlertState, error)
	// Transition записывает состояние условия. Если оно изменилось (или
	// условие впервые активно), в той же транзакции вызывается rec и его
	// запись попадает в журнал аудита; changed сообщает, что запись сделана.
	// Первое наблюдение неактивного условия записи не создаёт.
	Transition(ctx context.Context, condition string, active bool, now time.Time,
		rec func(active bool) audit.Entry) (changed bool, err error)
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
	// Timezone — часовой пояс для показа (ВРМ.2); nil — UTC.
	Timezone *time.Location
	// StorageLimit и WarnPercent — РСБ.5; ноль — значения по умолчанию.
	StorageLimit int64
	WarnPercent  int
	Logger       *slog.Logger
}

// Service собирает состояние системы и ведёт уведомления.
type Service struct {
	o Options
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
		o.Timezone = time.UTC
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Service{o: o}, nil
}

// collected — собранное состояние и вычисленные условия.
type collected struct {
	st         Status
	conditions map[string]bool
}

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
	c := collected{conditions: map[string]bool{}}
	c.st = Status{
		GeneratedAt: now,
		Server:      ServerStatus{Version: s.o.Version, StartedAt: s.o.StartedAt.UTC(), Integrity: []IntegrityStatus{}},
		Gateways:    []GatewayStatus{}, Notifications: []Notification{}, Unavailable: []string{},
	}
	if sm := s.o.Selftest; sm != nil {
		c.st.Server.Selftest = &Report{OK: sm.OK, CheckedAt: sm.At.UTC(), Failed: sm.Failed}
	}

	// Целостность сервера.
	integrityFailed := c.st.Server.Selftest != nil && !c.st.Server.Selftest.OK
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
			integrityFailed = integrityFailed || !r.OK()
		}
	}

	// Шлюзы и счётчики событий.
	var stats map[string]GatewayEvents
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
			if g.Status == gwregistry.StatusActive {
				integrityFailed = integrityFailed || (gs.Selftest != nil && !gs.Selftest.OK) || (gs.Integrity != nil && !gs.Integrity.OK)
			}
			c.st.Gateways = append(c.st.Gateways, gs)
		}
	}

	// Время (ВРМ.1–2).
	clk := s.o.Sync()
	c.st.Time = TimeStatus{ServerTime: now, Timezone: s.o.Timezone.String(), Sync: clk.Sync, ErrorMicros: clk.ErrorMicros}

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

	c.conditions[ConditionTime] = clk.Sync == SyncUnsynchronized
	c.conditions[ConditionStorage] = c.st.Storage.WarnExceeded
	c.conditions[ConditionIntegrity] = integrityFailed
	sort.Strings(c.st.Unavailable)
	return c
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
	{ConditionStorage, "РСБ.5", "Журнал аудита приближается к пределу хранилища"},
	{ConditionIntegrity, "ОЦЛ.5", "Нарушена целостность или не пройден самотест компонента"},
	{ConditionTime, "ВРМ.1", "Системное время не синхронизировано"},
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

// Evaluate вычисляет условия ВРМ.1, РСБ.5 и ОЦЛ.5 и при смене состояния
// пишет запись system.alert в журнал аудита. Повторный вызов без изменений
// ничего не пишет. ИАФ.4 и УПД.6 уже фиксируются записями auth.locked и
// access.denied, поэтому здесь не дублируются.
func (s *Service) Evaluate(ctx context.Context) error {
	if s.o.Store == nil {
		return nil
	}
	c := s.collect(ctx)
	now := c.st.GeneratedAt
	var errs []error
	for _, ci := range conditionInfo {
		active, tracked := c.conditions[ci.code]
		if !tracked {
			continue
		}
		// Раздел не собран — состояние не меняем: ложное «снято» хуже паузы.
		if (ci.code == ConditionStorage && !c.st.Storage.Available) ||
			(ci.code == ConditionIntegrity && (slices.Contains(c.st.Unavailable, "integrity") || slices.Contains(c.st.Unavailable, "gateways"))) {
			continue
		}
		rec := func(active bool) audit.Entry { return s.alertEntry(ci.code, ci.requirement, active, c.st) }
		tctx, cancel := s.dbCtx(ctx)
		changed, err := s.o.Store.Transition(tctx, ci.code, active, now, rec)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("условие %s: %w", ci.code, err))
			continue
		}
		if changed {
			s.o.Logger.Warn("изменилось состояние уведомления", "class", "status", "condition", ci.code, "active", active)
		}
	}
	return errors.Join(errs...)
}

func (s *Service) alertEntry(code, requirement string, active bool, st Status) audit.Entry {
	state, result := "cleared", audit.ResultSuccess
	if active {
		state, result = "raised", audit.ResultFailure
	}
	d := map[string]any{"condition": code, "requirement": requirement, "state": state}
	switch code {
	case ConditionTime:
		d["sync"] = st.Time.Sync
	case ConditionStorage:
		d["used_percent"], d["warn_percent"] = st.Storage.UsedPercent, st.Storage.WarnPercent
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
