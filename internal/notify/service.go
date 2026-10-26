package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Ошибки сервиса.
var (
	ErrNotFound        = errors.New("уведомления: канал не найден")
	ErrVersionConflict = errors.New("уведомления: канал изменён другим пользователем")
	ErrNameTaken       = errors.New("уведомления: канал с таким названием уже есть")
	ErrTooMany         = errors.New("уведомления: достигнут предел числа каналов")
	ErrConfirmRequired = errors.New("уведомления: ослабление требует повторной проверки паролем или кодом")
	ErrRateLimited     = errors.New("уведомления: слишком частые тестовые отправки")
)

// Пределы тестовой отправки: не чаще TestBurst раз за TestWindow на канал.
const (
	TestBurst  = 5
	TestWindow = time.Minute
	// MaxDeliveriesPage — строк журнала доставки в ответе.
	MaxDeliveriesPage = 200
)

// Секреты канала шифруются с AAD места хранения (ADR-0007).
const (
	SecretTable  = "notify_channels"
	SecretColumn = "secret"
)

// Sealer — шифрование секретов ключом данных (keyring.Box).
type Sealer interface {
	SealKey(ctx context.Context, plaintext []byte, table, column, rowID string) (string, []byte, error)
	OpenContext(ctx context.Context, keyID string, sealed []byte, table, column, rowID string) ([]byte, error)
}

// Delivery — строка журнала доставки.
type Delivery struct {
	ID        string
	OrgID     string
	ChannelID string
	// AlertID — оповещение; пусто у тестовой отправки.
	AlertID   string
	Kind      string
	Status    string
	Attempts  int
	NextAt    time.Time
	Error     string
	CreatedAt time.Time
	UpdatedAt time.Time
	SentAt    time.Time
}

// Статусы доставки.
const (
	StatusPending = "pending"
	StatusSent    = "sent"
	StatusFailed  = "failed"
)

// Store — хранилище каналов и журнала доставки.
type Store interface {
	Channels(ctx context.Context) ([]Channel, error)
	Channel(ctx context.Context, id string) (Channel, error)
	// CreateChannel сохраняет канал и запись аудита одной транзакцией.
	CreateChannel(ctx context.Context, c Channel, rec audit.Entry) error
	// UpdateChannel меняет канал под блокировкой строки: fn получает
	// прежний канал и возвращает новый и запись аудита той же транзакции.
	UpdateChannel(ctx context.Context, id string, fn func(old Channel) (Channel, audit.Entry, error)) (Channel, error)
	// RecordTest пишет тестовую отправку в журнал доставки и аудит.
	RecordTest(ctx context.Context, d Delivery, rec audit.Entry) error
	// Deliveries — журнал доставки канала, новые сначала.
	Deliveries(ctx context.Context, channelID string, limit int) ([]Delivery, error)
	// ClaimDue выбирает до limit доставок, срок которых наступил, и
	// откладывает их на lease (повтор, если сервер остановится).
	ClaimDue(ctx context.Context, lease time.Duration, limit int) ([]Delivery, error)
	// FinishDelivery сохраняет итог попытки; rec — запись аудита той же
	// транзакции (окончательный отказ) или nil.
	FinishDelivery(ctx context.Context, d Delivery, rec *audit.Entry) error
	// AlertMessage — уведомление по оповещению (без содержимого запросов).
	AlertMessage(ctx context.Context, alertID string) (Message, error)

	// Передача журнала аудита в SIEM (задача 3.14). Курсор канала ставится
	// на конец журнала в транзакции, где канал подписывается (создание или
	// изменение с audit_stream: false → true).

	// StreamChannels — включённые каналы с подпиской на журнал.
	StreamChannels(ctx context.Context) ([]Channel, error)
	// ClaimStream берёт курсор канала, если срок next_at наступил, и
	// откладывает его на lease; false — не пора, занят или нет подписки.
	ClaimStream(ctx context.Context, channelID string, lease time.Duration) (StreamCursor, bool, error)
	// AuditAfter — до limit записей журнала с seq > after по порядку seq.
	AuditAfter(ctx context.Context, after int64, limit int) ([]audit.Record, error)
	// FinishStream сохраняет курсор c, если его last_seq всё ещё prevSeq,
	// и записи аудита recs той же транзакцией.
	FinishStream(ctx context.Context, prevSeq int64, c StreamCursor, recs []audit.Entry) error
	// StreamLag передаёт fn курсор и не переданную часть журнала под
	// блокировкой курсора; fn возвращает новое состояние отставания и
	// запись аудита о его смене.
	StreamLag(ctx context.Context, channelID string, fn func(StreamCursor, Backlog) (bool, *audit.Entry)) error
	// StreamState — курсор и не переданная часть журнала канала.
	StreamState(ctx context.Context, channelID string) (StreamCursor, Backlog, bool, error)
}

// Options — зависимости сервиса.
type Options struct {
	Store     Store
	Box       Sealer
	Provider  aisecCrypto.Provider
	Transport *Transport
	OrgID     string
	Now       func() time.Time
}

// Service — каналы уведомлений, тестовая отправка и доставка (Р4).
type Service struct {
	store     Store
	box       Sealer
	tls       aisecCrypto.TLSProvider
	transport *Transport
	ids       *ids.Generator
	orgID     string
	now       func() time.Time

	mu    sync.Mutex
	tests map[string][]time.Time
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Box == nil || o.Provider == nil || o.Transport == nil {
		return nil, errors.New("уведомления: нет хранилища, ключа данных, криптопрофиля или отправителя")
	}
	t, err := o.Provider.TLS()
	if err != nil {
		return nil, err
	}
	rnd, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	if o.OrgID == "" {
		o.OrgID = audit.DefaultOrgID
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{store: o.Store, box: o.Box, tls: t, transport: o.Transport, ids: ids.NewGenerator(rnd), orgID: o.OrgID,
		now: o.Now, tests: map[string][]time.Time{}}, nil
}

// By — субъект изменения.
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// Confirm — повторная проверка паролем или кодом TOTP перед ослаблением
	// (DM-40); nil — ослабление отклоняется с ErrConfirmRequired.
	Confirm func(ctx context.Context) error
}

func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func (b By) confirm(ctx context.Context) error {
	if b.Confirm == nil {
		return ErrConfirmRequired
	}
	return b.Confirm(ctx)
}

func (s *Service) entry(b By, action, id string, result audit.Result, details any) audit.Entry {
	return audit.Entry{OrgID: s.orgID, Actor: b.Actor, SourceIP: b.IP, Action: action,
		Object: audit.Object{Type: "notify_channel", ID: id}, Result: result, Details: details}
}

// Channels — все каналы организации.
func (s *Service) Channels(ctx context.Context) ([]Channel, error) { return s.store.Channels(ctx) }

// Channel — канал по ID.
func (s *Service) Channel(ctx context.Context, id string) (Channel, error) {
	return s.store.Channel(ctx, id)
}

// seal шифрует секреты канала; пустые — без шифротекста.
func (s *Service) seal(ctx context.Context, c *Channel, sec Secrets) error {
	c.SecretFields = sec.fields()
	c.Secret, c.SecretKeyID = nil, ""
	if len(c.SecretFields) == 0 {
		return nil
	}
	raw, err := json.Marshal(sec) //nolint:gosec // G117: секреты сериализуются только для шифрования ключом данных (SealKey)
	if err != nil {
		return err
	}
	keyID, sealed, err := s.box.SealKey(ctx, raw, SecretTable, SecretColumn, c.ID)
	if err != nil {
		return fmt.Errorf("уведомления: шифрование секретов канала: %w", err)
	}
	c.Secret, c.SecretKeyID = sealed, keyID
	return nil
}

// secrets расшифровывает секреты канала.
func (s *Service) secrets(ctx context.Context, c Channel) (Secrets, error) {
	var sec Secrets
	if len(c.Secret) == 0 {
		return sec, nil
	}
	raw, err := s.box.OpenContext(ctx, c.SecretKeyID, c.Secret, SecretTable, SecretColumn, c.ID)
	if err != nil {
		return sec, fmt.Errorf("уведомления: расшифровка секретов канала: %w", err)
	}
	if err := json.Unmarshal(raw, &sec); err != nil {
		return sec, errors.New("уведомления: секреты канала повреждены")
	}
	return sec, nil
}

// view — канал для аудита: без секретов и корневых сертификатов (размер).
func view(c Channel) map[string]any {
	st := c.Settings
	st.CAPEM = ""
	return map[string]any{"name": c.Name, "type": c.Type, "enabled": c.Enabled, "min_severity": c.MinSeverity,
		"settings": st, "ca_pem_bytes": len(c.Settings.CAPEM), "protected_fields": c.SecretFields, "audit_stream": c.AuditStream}
}

// CreateChannel создаёт канал (право notify_channels.manage). Создание
// ослаблением не считается.
func (s *Service) CreateChannel(ctx context.Context, by By, in ChannelInput) (Channel, error) {
	sec, err := normalize(&in, Secrets{}, s.tls)
	if err != nil {
		return Channel{}, err
	}
	id, err := s.ids.New()
	if err != nil {
		return Channel{}, err
	}
	now := s.now().UTC()
	c := Channel{ID: id.String(), OrgID: s.orgID, Name: in.Name, Type: in.Type, Enabled: *in.Enabled,
		MinSeverity: in.MinSeverity, Settings: in.Settings, AuditStream: *in.AuditStream, Version: 1, CreatedAt: now, CreatedBy: by.ref(),
		UpdatedAt: now, UpdatedBy: by.ref()}
	if err := s.seal(ctx, &c, sec); err != nil {
		return Channel{}, err
	}
	if err := s.store.CreateChannel(ctx, c, s.entry(by, "notify_channel.create", c.ID, audit.ResultSuccess, view(c))); err != nil {
		return Channel{}, err
	}
	return c, nil
}

// weakening — причины, по которым изменение ослабляет доставку
// уведомлений (DM-40, ADR-0020 п. 7): отключение, повышение порога
// серьёзности, смена адреса или корневых сертификатов получателя, удаление
// адресатов письма, снятие подписки на журнал аудита (РСБ.6).
func weakening(old, cur Channel, oldSec, sec Secrets) []string {
	var r []string
	if old.Enabled && !cur.Enabled {
		r = append(r, "disabled")
	}
	if SeverityRank(cur.MinSeverity) > SeverityRank(old.MinSeverity) {
		r = append(r, "min_severity_raised")
	}
	o, n := old.Settings, cur.Settings
	if o.Host != n.Host || o.Port != n.Port || oldSec.URL != sec.URL {
		r = append(r, "destination_changed")
	}
	if o.CAPEM != n.CAPEM {
		r = append(r, "trust_changed")
	}
	if old.AuditStream && !cur.AuditStream {
		r = append(r, "audit_stream_disabled")
	}
	for _, a := range o.To {
		if !slices.Contains(n.To, a) {
			r = append(r, "recipients_removed")
			break
		}
	}
	return r
}

// UpdateChannel заменяет настройки канала (право notify_channels.manage).
// Тип не меняется. Ослабление требует повторной проверки и пишется с
// weakening (DM-40); значения секретов в аудит не попадают — только
// какие из них изменены.
func (s *Service) UpdateChannel(ctx context.Context, by By, id string, in ChannelInput) (Channel, error) {
	return s.store.UpdateChannel(ctx, id, func(old Channel) (Channel, audit.Entry, error) {
		if in.Version != old.Version {
			return Channel{}, audit.Entry{}, ErrVersionConflict
		}
		if in.Type == "" {
			in.Type = old.Type
		}
		if in.Type != old.Type {
			return Channel{}, audit.Entry{}, invalidf("type — тип канала не меняется: создайте новый канал")
		}
		oldSec, err := s.secrets(ctx, old)
		if err != nil {
			return Channel{}, audit.Entry{}, err
		}
		if in.AuditStream == nil {
			in.AuditStream = &old.AuditStream
		}
		sec, err := normalize(&in, oldSec, s.tls)
		if err != nil {
			return Channel{}, audit.Entry{}, err
		}
		c := old
		c.Name, c.Enabled, c.MinSeverity, c.Settings, c.AuditStream = in.Name, *in.Enabled, in.MinSeverity, in.Settings, *in.AuditStream
		c.Version, c.UpdatedAt, c.UpdatedBy = old.Version+1, s.now().UTC(), by.ref()
		reasons := weakening(old, c, oldSec, sec)
		if len(reasons) > 0 {
			if err := by.confirm(ctx); err != nil {
				return Channel{}, audit.Entry{}, err
			}
		}
		var changed []string
		if oldSec.Password != sec.Password {
			changed = append(changed, SecretPassword)
		}
		if oldSec.SigningKey != sec.SigningKey {
			changed = append(changed, SecretSigningKey)
		}
		if oldSec.URL != sec.URL {
			changed = append(changed, SecretURL)
		}
		if changed != nil {
			if err := s.seal(ctx, &c, sec); err != nil {
				return Channel{}, audit.Entry{}, err
			}
		}
		if reasons == nil {
			reasons = []string{}
		}
		if changed == nil {
			changed = []string{}
		}
		return c, s.entry(by, "notify_channel.update", c.ID, audit.ResultSuccess, map[string]any{
			"before": view(old), "after": view(c), "protected_changed": changed,
			"weakening": len(reasons) > 0, "weakening_reasons": reasons}), nil
	})
}

// allowTest — не больше TestBurst тестовых отправок за TestWindow на канал.
func (s *Service) allowTest(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tests) > 10*MaxChannels {
		clear(s.tests)
	}
	recent := slices.DeleteFunc(s.tests[id], func(t time.Time) bool { return now.Sub(t) >= TestWindow })
	if len(recent) >= TestBurst {
		s.tests[id] = recent
		return false
	}
	s.tests[id] = append(recent, now)
	return true
}

// TestChannel — тестовая отправка одной попыткой (право
// notify_channels.manage): итог пишется в журнал доставки с признаком test
// и в аудит. Отключённый канал проверить можно — до включения.
func (s *Service) TestChannel(ctx context.Context, by By, id string) (Delivery, error) {
	c, err := s.store.Channel(ctx, id)
	if err != nil {
		return Delivery{}, err
	}
	now := s.now().UTC()
	if !s.allowTest(c.ID, now) {
		return Delivery{}, ErrRateLimited
	}
	did, err := s.ids.New()
	if err != nil {
		return Delivery{}, err
	}
	d := Delivery{ID: did.String(), OrgID: s.orgID, ChannelID: c.ID, Kind: KindTest, Attempts: 1, NextAt: now,
		CreatedAt: now}
	sec, err := s.secrets(ctx, c)
	if err == nil {
		err = s.transport.Send(ctx, c, sec, testMessage(d.ID, now))
	}
	result := audit.ResultSuccess
	d.UpdatedAt = s.now().UTC()
	if err != nil {
		// Код теста — обобщённый (3Н31 ревью 3.r2): точный код доставки
		// виден в журнале по оповещениям.
		d.Status, d.Error, result = StatusFailed, testCode(ErrorCode(err)), audit.ResultFailure
	} else {
		d.Status, d.SentAt = StatusSent, d.UpdatedAt
	}
	rec := s.entry(by, "notify_channel.test", c.ID, result, map[string]any{"delivery_id": d.ID, "type": c.Type,
		"error": d.Error})
	if err := s.store.RecordTest(ctx, d, rec); err != nil {
		return Delivery{}, err
	}
	return d, nil
}

// Deliveries — журнал доставки канала (право notify_channels.read).
func (s *Service) Deliveries(ctx context.Context, id string, limit int) ([]Delivery, error) {
	if _, err := s.store.Channel(ctx, id); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxDeliveriesPage {
		limit = MaxDeliveriesPage
	}
	return s.store.Deliveries(ctx, id, limit)
}
