package quotalease

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Пределы и сроки сервиса.
const (
	// RatePerSecond — запросов аренды в секунду на шлюз (ADR-0021, п. 6);
	// ограничитель — по ID шлюза из сертификата mTLS, а не по адресу:
	// шлюзы за одним NAT не делят предел (ср. 4Н9).
	RatePerSecond = 10
	// OnlineAfter — шлюз без heartbeat дольше этого срока не считается «на
	// связи» (три периода heartbeat, как на «Состоянии системы»).
	OnlineAfter = 90 * time.Second
	// AutonomousFresh — сколько держится признак автономного режима из
	// последнего heartbeat шлюза.
	AutonomousFresh = 3 * time.Minute
	// CleanupInterval — период удаления старых выдач.
	CleanupInterval = time.Minute
)

var (
	// ErrModeLocal — установка в режиме local: аренда не выдаётся.
	ErrModeLocal = errors.New("аренда квот: установка в режиме local")
	// ErrRateLimited — шлюз запрашивает аренду чаще RatePerSecond.
	ErrRateLimited = errors.New("аренда квот: слишком частые запросы")
	// ErrNotSetUp — первичная настройка не выполнена.
	ErrNotSetUp = errors.New("аренда квот: первичная настройка не выполнена")
	// ErrConfirmRequired — переход на local при нескольких шлюзах на связи
	// без повторной проверки субъекта (ослабление, DM-40).
	ErrConfirmRequired = errors.New("переход на режим local при нескольких шлюзах требует повторной проверки")
	// ErrInvalidMode — неизвестный режим.
	ErrInvalidMode = errors.New("режим квот — local или leased")
)

// Violation — отчёт шлюза противоречит выдачам: аренда чужая, другого
// приложения или квоты, израсходовано больше выданного, отчёт о той же
// аренде с другим числом или ID запроса другой квоты. Запрос отклоняется целиком, в журнал аудита
// пишется quota.lease_violation (ADR-0021, п. 6).
type Violation struct {
	App, Quota, Lease, Reason string
}

func (v *Violation) Error() string {
	return "аренда квот: отчёт отклонён: " + v.Reason
}

// Причины Violation.
const (
	ReasonUnknownLease  = "unknown_lease"  // аренда чужая, другого приложения или квоты
	ReasonOverused      = "overused"       // израсходовано больше выданного
	ReasonRereported    = "rereported"     // повторный отчёт с другим числом
	ReasonReusedRequest = "reused_request" // ID запроса уже выдал аренду другой квоты
)

// Settings — режим квот установки.
type Settings struct {
	Mode string `json:"mode"`
	// ChangedAt — последняя смена режима; nil — не менялся.
	ChangedAt *time.Time `json:"changed_at"`
	// GatewaysOnline — действующих шлюзов на связи.
	GatewaysOnline int `json:"gateways_online"`
}

// Health — для «Состояния системы»: режим, шлюзы на связи и шлюзы,
// которые в последнем heartbeat сообщили об автономной доле.
type Health struct {
	Mode       string
	Online     int
	Autonomous []string
}

// By — субъект изменения режима. Confirm — повторная проверка паролем или
// кодом TOTP; nil — ослабление отклоняется с ErrConfirmRequired.
type By struct {
	Actor   audit.Actor
	IP      netip.Addr
	Confirm func(ctx context.Context) error
}

// Store — хранилище (PGStore).
type Store interface {
	Settings(ctx context.Context, orgID string, now time.Time) (Settings, error)
	// SetMode меняет режим под блокировкой строки настроек: fn получает
	// прежние настройки и возвращает запись аудита той же транзакции.
	SetMode(ctx context.Context, orgID, mode string, now time.Time, fn func(old Settings) (audit.Entry, error)) error
	Lease(ctx context.Context, in LeaseInput) (Response, error)
	Observe(ctx context.Context, orgID, gatewayID string, autonomous bool, now time.Time) error
	Health(ctx context.Context, orgID string, now time.Time) (Health, error)
	Purge(ctx context.Context, orgID string, now time.Time) (int64, error)
	Record(ctx context.Context, e audit.Entry) error
}

// LeaseInput — запрос аренды шлюза.
type LeaseInput struct {
	OrgID     string
	GatewayID string
	Request   Request
	Now       time.Time
	// NewID — UUID новой выдачи.
	NewID func() (string, error)
}

// Options — зависимости сервиса.
type Options struct {
	Store  Store
	IDs    *ids.Generator
	OrgID  string
	Clock  func() time.Time
	Logger *slog.Logger
}

// Service — аренда квот и режим установки.
type Service struct {
	o Options

	mu      sync.Mutex
	buckets map[string]*bucket
}

// bucket — ограничитель запросов шлюза: RatePerSecond в скользящую секунду.
type bucket struct {
	tokens float64
	at     time.Time
}

// New проверяет зависимости.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.IDs == nil || o.OrgID == "" {
		return nil, errors.New("аренда квот: нет хранилища, генератора ID или организации")
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Service{o: o, buckets: map[string]*bucket{}}, nil
}

func (s *Service) now() time.Time { return s.o.Clock().UTC().Truncate(time.Microsecond) }

// allow — ограничитель по ID шлюза.
func (s *Service) allow(gatewayID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buckets) > 10000 {
		for id, b := range s.buckets {
			if now.Sub(b.at) > time.Minute || now.Before(b.at) {
				delete(s.buckets, id)
			}
		}
	}
	b, ok := s.buckets[gatewayID]
	if !ok {
		b = &bucket{tokens: RatePerSecond, at: now}
		s.buckets[gatewayID] = b
	}
	if d := now.Sub(b.at); d > 0 {
		b.tokens = min(RatePerSecond, b.tokens+d.Seconds()*RatePerSecond)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Lease выдаёт аренды шлюзу gatewayID (CN сертификата mTLS) по разобранному
// запросу (Parse). Нарушение в отчётах — *Violation, запись в аудит.
func (s *Service) Lease(ctx context.Context, gatewayID string, ip netip.Addr, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, err
	}
	now := s.now()
	if !s.allow(gatewayID, now) {
		return Response{}, ErrRateLimited
	}
	resp, err := s.o.Store.Lease(ctx, LeaseInput{OrgID: s.o.OrgID, GatewayID: gatewayID, Request: req, Now: now,
		NewID: func() (string, error) {
			id, err := s.o.IDs.New()
			if err != nil {
				return "", err
			}
			return id.String(), nil
		}})
	var v *Violation
	if errors.As(err, &v) {
		e := audit.Entry{OrgID: s.o.OrgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: gatewayID}, SourceIP: ip,
			Action: "quota.lease_violation", Object: audit.Object{Type: "gateway", ID: gatewayID}, Result: audit.ResultFailure,
			Details: map[string]any{"app": v.App, "quota": v.Quota, "lease": v.Lease, "reason": v.Reason}}
		if rerr := s.o.Store.Record(ctx, e); rerr != nil {
			s.o.Logger.Error("аренда квот: нарушение не записано в аудит", "class", "audit", "gateway_id", gatewayID, "error", rerr)
		}
	}
	return resp, err
}

// Settings — режим и число шлюзов на связи.
func (s *Service) Settings(ctx context.Context) (Settings, error) {
	return s.o.Store.Settings(ctx, s.o.OrgID, s.now())
}

// Mode — режим установки для сборки пакета конфигурации шлюзов.
func (s *Service) Mode(ctx context.Context) (string, error) {
	st, err := s.Settings(ctx)
	return st.Mode, err
}

// SetMode меняет режим. Переход на local, когда на связи больше одного
// шлюза, — ослабление защиты (квоты и жёсткий бюджет соблюдаются
// приблизительно, DM-40): с повторной проверкой и weakening в аудите.
// Пишет install.quota_mode_changed.
func (s *Service) SetMode(ctx context.Context, by By, mode string) (Settings, error) {
	if !ValidMode(mode) {
		return Settings{}, ErrInvalidMode
	}
	now := s.now()
	err := s.o.Store.SetMode(ctx, s.o.OrgID, mode, now, func(old Settings) (audit.Entry, error) {
		weak := mode == ModeLocal && old.Mode == ModeLeased && old.GatewaysOnline > 1
		if weak {
			if by.Confirm == nil {
				return audit.Entry{}, ErrConfirmRequired
			}
			if err := by.Confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		reasons := []string{}
		if weak {
			reasons = append(reasons, "quota_local_multi_gateway")
		}
		return audit.Entry{Actor: by.Actor, SourceIP: by.IP, Action: "install.quota_mode_changed",
			Object: audit.Object{Type: "install_settings", ID: s.o.OrgID}, Result: audit.ResultSuccess,
			Details: map[string]any{"before": map[string]string{"quota_mode": old.Mode}, "after": map[string]string{"quota_mode": mode},
				"gateways_online": old.GatewaysOnline, "weakening": weak, "weakening_reasons": reasons}}, nil
	})
	if err != nil {
		return Settings{}, err
	}
	return s.o.Store.Settings(ctx, s.o.OrgID, now)
}

// Observe — признак автономной доли из heartbeat шлюза.
func (s *Service) Observe(ctx context.Context, gatewayID string, autonomous bool) error {
	return s.o.Store.Observe(ctx, s.o.OrgID, gatewayID, autonomous, s.now())
}

// Health — для «Состояния системы».
func (s *Service) Health(ctx context.Context) (Health, error) {
	return s.o.Store.Health(ctx, s.o.OrgID, s.now())
}

// RunCleanup удаляет выдачи старше двух окон (ADR-0021, п. 3) сразу и
// затем каждые interval, пока не отменён ctx.
func (s *Service) RunCleanup(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = CleanupInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.o.Store.Purge(ctx, s.o.OrgID, s.now()); err != nil && ctx.Err() == nil {
			s.o.Logger.Error("аренда квот: очистка старых выдач", "class", "db", "error", err)
		} else if n > 0 {
			s.o.Logger.Debug("аренда квот: удалены старые выдачи", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RetryAfter — подсказка для ответа 429 ограничителя.
func RetryAfter() time.Duration { return time.Second }

// String — для журнала.
func (v *Violation) String() string { return fmt.Sprintf("%s/%s: %s", v.App, v.Quota, v.Reason) }
