// Пакет apps — приложения, ключи приложений и провайдеры в сервере
// управления (ТЗ 5.4, 7.2 ИАФ.8, 7.9 ЗИ.1; задача 2.11 этапа 2).
//
// Ключ приложения показывается один раз при выпуске, хранятся только
// префикс и хеш профиля. Учётные данные провайдера шифруются ключом данных
// с AAD места хранения (keyring.Box, ADR-0007) и не возвращаются в ответах.
// Каждое изменение пишется в журнал аудита той же транзакцией (РСБ.1).
// Доставка в шлюзы — задача 2.13.
package apps

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Пределы.
const (
	// DefaultKeyDays — срок ключа по умолчанию, MaxKeyDays — наибольший.
	DefaultKeyDays = 365
	MaxKeyDays     = 730
	// DefaultOverlap — перекрытие ключей при ротации по умолчанию,
	// MaxOverlap — наибольшее.
	DefaultOverlap = 24 * time.Hour
	MaxOverlap     = 30 * 24 * time.Hour
	// MaxActiveKeys — действующих ключей на приложение.
	MaxActiveKeys = 20
	// MaxKeysListed — предел выдачи ключей приложения (новые первыми).
	MaxKeysListed = 500
	// MaxCIDRs — подсетей привязки ключа.
	MaxCIDRs = 64
	// MaxCAPEM — размер корневых сертификатов провайдера.
	MaxCAPEM = 256 << 10
	// MaxCredential — размер учётных данных провайдера.
	MaxCredential = 16 << 10
	// MaxProviders — провайдеров в организации.
	MaxProviders = 1000
	// MaxTimeoutSeconds — таймаут провайдера, секунд.
	MaxTimeoutSeconds = 600
	maxName           = 200
	maxDescription    = 2000
	maxDepartment     = 200
	maxModels         = 100
	maxReason         = 500
	maxURL            = 2048
)

// Значения перечислимых полей.
const (
	ModeMonitor = string(policy.Monitor)
	ModeEnforce = string(policy.Enforce)
	// DefaultStorage — режим хранения содержимого по умолчанию (ТЗ 5.5).
	DefaultStorage  = "masked"
	DefaultFailMode = "fail_closed"
	DefaultUserFrom = "none"
	// defaultPolicy — политика нового приложения (решение Р7 этапа 1).
	defaultPolicy     = policy.DefaultTemplate
	monitorOnlyPolicy = policy.TemplateMonitorOnly
)

// Ошибки.
var (
	ErrNotFound         = errors.New("не найдено")
	ErrSlugTaken        = errors.New("ID уже занят")
	ErrProviderNotFound = errors.New("провайдер не найден")
	ErrProviderInUse    = errors.New("провайдер используется приложениями")
	ErrArchived         = errors.New("приложение в архиве")
	ErrKeyInactive      = errors.New("ключ отозван или истёк")
	ErrTooManyKeys      = errors.New("слишком много действующих ключей")
	ErrTooMany          = errors.New("достигнут предел числа объектов")
	ErrNoDataKey        = errors.New("ключ данных не подключён: учётные данные провайдеров недоступны")
	ErrNoCredential     = errors.New("учётные данные провайдера не заданы")
	// ErrPolicyRequired — изменение ослабляет защиту и требует права
	// applications.policy (В15 ревью 2.r3b).
	ErrPolicyRequired = errors.New("нужно право applications.policy")
	// ErrConfirmRequired — ослабление защиты без повторной проверки
	// субъекта (Н32 ревью 2.r3b): её нечем выполнить.
	ErrConfirmRequired = errors.New("ослабление защиты требует повторной проверки")
	// ErrBreaksBundle — изменение исключило бы приложение из пакета
	// конфигурации шлюзов (В16 ревью 2.r3b).
	ErrBreaksBundle = errors.New("изменение не войдёт в пакет конфигурации шлюзов")
	// errImmutable — попытка изменить неизменяемое (ошибка программиста;
	// в PostgreSQL то же запрещают триггеры).
	errImmutable = errors.New("приложения: изменение неизменяемого поля")
)

// InputError — неверные данные запроса; текст показывается пользователю.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

func invalid(errs ...error) error { return &InputError{Errs: errs} }

func invalidf(format string, a ...any) error { return invalid(fmt.Errorf(format, a...)) }

// Sealed — зашифрованные учётные данные провайдера.
type Sealed struct {
	Data  []byte
	KeyID string
	Alg   string
	SetAt time.Time
}

// Provider — провайдер модели (ТЗ 5.4).
type Provider struct {
	ID       string
	OrgID    string
	Slug     string
	Name     string
	Type     string
	BaseURL  string
	CAPEM    string
	AuthURL  string
	Scope    string
	FolderID string
	// Таймауты, секунды; 0 — по умолчанию шлюза.
	ConnectTimeout    int
	HeaderTimeout     int
	ResponseTimeout   int
	StreamIdleTimeout int
	External          bool
	// Credential — nil, если учётные данные не заданы.
	Credential *Sealed
	CreatedAt  time.Time
	CreatedBy  string
	UpdatedAt  time.Time
	UpdatedBy  string
}

// Quotas — лимиты приложения (ТЗ 5.2, quota); 0 — без лимита.
type Quotas struct {
	RequestsPerMinute        int `json:"requests_per_minute"`
	RequestsPerMinutePerUser int `json:"requests_per_minute_per_user"`
	RequestsPerMinutePerKey  int `json:"requests_per_minute_per_key"`
	TokensPerMinute          int `json:"tokens_per_minute"`
	TokensPerDay             int `json:"tokens_per_day"`
	MaxMessages              int `json:"max_messages"`
	MaxTokens                int `json:"max_tokens"`
	MaxInputBytes            int `json:"max_input_bytes"`
}

func (q Quotas) config() config.Quotas { return config.Quotas(q) }

// List — словарь или выражения заказчика для детектора lists (ТЗ 5.2).
type List struct {
	ID            string   `json:"id"`
	Category      string   `json:"category"`
	Threat        string   `json:"threat,omitempty"`
	Score         float64  `json:"score,omitempty"`
	Direction     string   `json:"direction,omitempty"`
	Words         []string `json:"words,omitempty"`
	Regex         []string `json:"regex,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
}

func listSpecs(ls []List) []lists.Spec {
	out := make([]lists.Spec, 0, len(ls))
	for _, l := range ls {
		out = append(out, lists.Spec(l))
	}
	return out
}

// Protection — поля защиты приложения: меняет только обладатель права
// applications.policy (УПД.2).
type Protection struct {
	Policy     string
	PolicyMode string
	Storage    string
}

// Application — приложение (ТЗ 5.4).
type Application struct {
	ID          string
	OrgID       string
	Slug        string
	Name        string
	Description string
	Department  string
	OwnerID     string
	Env         string
	ProviderID  string
	Models      []string
	Aliases     map[string]string
	Protection
	FailMode          string
	UserFrom          string
	Quotas            Quotas
	Lists             []List
	ExfilAllowDomains []string
	CreatedAt         time.Time
	CreatedBy         string
	UpdatedAt         time.Time
	UpdatedBy         string
	// ArchivedAt — нулевое, если приложение действует.
	ArchivedAt time.Time
}

// Archived — приложение в архиве.
func (a Application) Archived() bool { return !a.ArchivedAt.IsZero() }

// Key — ключ приложения без секрета (ИАФ.8).
type Key struct {
	ID           string
	OrgID        string
	AppID        string
	Name         string
	Prefix       string
	Hash         []byte
	HashAlg      string
	AllowedCIDRs []netip.Prefix
	ExpiresAt    time.Time
	CreatedAt    time.Time
	CreatedBy    string
	RotatedFrom  string
	RevokedAt    time.Time
	RevokedBy    string
}

// Состояния ключа.
const (
	KeyActive  = "active"
	KeyExpired = "expired"
	KeyRevoked = "revoked"
)

// Status — состояние ключа на момент now.
func (k Key) Status(now time.Time) string {
	switch {
	case !k.RevokedAt.IsZero():
		return KeyRevoked
	case !now.Before(k.ExpiresAt):
		return KeyExpired
	}
	return KeyActive
}

// Cursor — позиция в списке приложений.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}

// Policies — проверка политики приложения: шаблон или политика организации
// (задача 2.12). Возвращает режим политики; ok = false — политики нет.
type Policies interface {
	PolicyMode(ctx context.Context, orgID, id string) (mode string, ok bool, err error)
}

// Templates — политики только из шаблонов (ТЗ 5.3).
type Templates struct{}

// PolicyMode — см. Policies.
func (Templates) PolicyMode(_ context.Context, _, id string) (string, bool, error) {
	s, ok := policy.Template(id)
	if !ok {
		return "", false, nil
	}
	return string(s.Mode), true, nil
}

// Store — хранилище (миграция 0014_applications). Рабочая реализация —
// PGStore, для тестов без PostgreSQL — Memory. Функции fn выполняются
// внутри транзакции над заблокированной строкой и возвращают запись
// аудита, которая фиксируется вместе с изменением (РСБ.1).
type Store interface {
	CreateProvider(ctx context.Context, p Provider, rec audit.Entry) error
	UpdateProvider(ctx context.Context, orgID, id string, fn func(*Provider) (audit.Entry, error)) (Provider, error)
	// DeleteProvider удаляет провайдера без приложений (иначе ErrProviderInUse).
	DeleteProvider(ctx context.Context, orgID, id string, fn func(Provider) (audit.Entry, error)) (Provider, error)
	Provider(ctx context.Context, orgID, id string) (Provider, error)
	Providers(ctx context.Context, orgID string) ([]Provider, error)
	CountProviders(ctx context.Context, orgID string) (int, error)

	// CreateApplication — ErrSlugTaken, ErrProviderNotFound.
	CreateApplication(ctx context.Context, a Application, rec audit.Entry) error
	// UpdateApplication — изменение действующего приложения (fn может
	// сменить провайдера: ErrProviderNotFound).
	UpdateApplication(ctx context.Context, orgID, id string, fn func(*Application) (audit.Entry, error)) (Application, error)
	// ArchiveApplication отмечает архив и отзывает все неотозванные ключи
	// (revoked_at = a.ArchivedAt, revoked_by = a.UpdatedBy); fn получает их число.
	ArchiveApplication(ctx context.Context, orgID, id string, fn func(a *Application, openKeys int) (audit.Entry, error)) (Application, error)
	Application(ctx context.Context, orgID, id string) (Application, error)
	// Applications — по времени создания; ownerID не пуст — только его.
	Applications(ctx context.Context, orgID, ownerID string, after *Cursor, limit int) ([]Application, error)

	// CreateKey блокирует приложение, считает его действующие ключи и
	// сохраняет ключ, который вернула fn.
	CreateKey(ctx context.Context, orgID, appID string, now time.Time, fn func(a Application, active int) (Key, audit.Entry, error)) (Key, error)
	// UpdateKey блокирует приложение и ключ, считает действующие на now
	// ключи приложения: fn меняет срок или отметку отзыва и может вернуть
	// новый ключ (ротация), который сохраняется той же транзакцией.
	UpdateKey(ctx context.Context, orgID, id string, now time.Time, fn func(k *Key, a Application, active int) (*Key, audit.Entry, error)) (Key, error)
	Key(ctx context.Context, orgID, id string) (Key, error)
	// Keys — ключи приложения, новые первыми, не больше MaxKeysListed.
	Keys(ctx context.Context, orgID, appID string) ([]Key, error)
	// ActiveKeys — все неотозванные ключи организации со сроком позже now
	// (пакет конфигурации, Н25 ревью 2.r3b), по приложению и префиксу.
	ActiveKeys(ctx context.Context, orgID string, now time.Time) ([]Key, error)

	// Цены моделей и бюджеты (задача 3.18, миграция 0031_budgets).
	// CreatePrice — ErrPriceExists, ErrProviderNotFound.
	CreatePrice(ctx context.Context, p Price, rec audit.Entry) error
	UpdatePrice(ctx context.Context, orgID, id string, fn func(*Price) (audit.Entry, error)) (Price, error)
	DeletePrice(ctx context.Context, orgID, id string, fn func(Price) (audit.Entry, error)) (Price, error)
	// Prices — по ID провайдера и модели.
	Prices(ctx context.Context, orgID string) ([]Price, error)
	// SetBudget блокирует приложение и сохраняет бюджет, который вернула
	// fn (prev — прежний, nil — не было).
	SetBudget(ctx context.Context, orgID, appID string, fn func(a Application, prev *Budget) (Budget, audit.Entry, error)) (Budget, error)
	// DeleteBudget — ErrNoBudget, если бюджета нет.
	DeleteBudget(ctx context.Context, orgID, appID string, fn func(a Application, b Budget) (audit.Entry, error)) (Budget, error)
	// Budget — ErrNoBudget, если бюджета нет.
	Budget(ctx context.Context, orgID, appID string) (Budget, error)
	Budgets(ctx context.Context, orgID string) ([]Budget, error)
	// SaveUsage сохраняет счётчики процесса шлюза: по каждой строке —
	// наибольшее из прежнего и нового (повтор heartbeat ничего не удваивает).
	// Счётчики неизвестных приложений пропускаются.
	SaveUsage(ctx context.Context, orgID, gatewayID string, startedAt time.Time, months []gwregistry.BudgetMonth, now time.Time) error
	// HardUsageOthers — расход за month по slug приложений с жёстким
	// бюджетом без процесса (gatewayID, startedAt).
	HardUsageOthers(ctx context.Context, orgID, month, gatewayID string, startedAt time.Time) (map[string]int64, error)
	// Usage — суммарный расход за month по slug приложений.
	Usage(ctx context.Context, orgID, month string) (map[string]Usage, error)

	// Сертификат заказчика для адреса шлюза (задача 3.27, миграция
	// 0039_gateway_tls): один на организацию. SetGatewayTLS блокирует
	// запись и сохраняет ту, что вернула fn (prev — прежняя, nil — не было).
	SetGatewayTLS(ctx context.Context, orgID string, fn func(prev *GatewayTLS) (GatewayTLS, audit.Entry, error)) (GatewayTLS, error)
	// GatewayTLS — ErrNoGatewayTLS, если сертификата нет.
	GatewayTLS(ctx context.Context, orgID string) (GatewayTLS, error)
	// DeleteGatewayTLS — ErrNoGatewayTLS, если сертификата нет.
	DeleteGatewayTLS(ctx context.Context, orgID string, fn func(GatewayTLS) (audit.Entry, error)) (GatewayTLS, error)
}

// Options — зависимости Service.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	// Box — ключ данных для учётных данных провайдеров; nil — их нельзя
	// задать (ErrNoDataKey).
	Box   *keyring.Box
	OrgID string // пусто — организация по умолчанию
	Clock func() time.Time
	// Policies — проверка политики приложения; nil — только шаблоны.
	Policies Policies
	// OwnerCheck проверяет владельца приложения: действующая учётная
	// запись организации; ошибка — владелец не подходит.
	OwnerCheck func(ctx context.Context, userID string) error
}

// Service — приложения, ключи и провайдеры.
type Service struct {
	store    Store
	tls      aisecCrypto.TLSProvider
	hasher   aisecCrypto.Hasher
	random   aisecCrypto.Random
	ids      *ids.Generator
	box      *keyring.Box
	orgID    string
	clock    func() time.Time
	policies Policies
	owner    func(ctx context.Context, userID string) error
	// bundleCheck — проверка приложения сборкой пакета (В16 ревью 2.r3b);
	// nil — без проверки.
	bundleCheck func(ctx context.Context, before *Application, after Application) error
	// policyWeaker — переход с политики from на to ослабляет защиту (В23
	// ревью 2.r5); nil — ослаблением считается только переход на шаблон
	// «Только мониторинг».
	policyWeaker func(ctx context.Context, from, to string) (bool, error)
	// defaultStorage — режим хранения новых приложений из настроек
	// установки (Н42 ревью 2.r4, В26 ревью 2.r5); nil — DefaultStorage.
	defaultStorage func(ctx context.Context) (string, error)
	// timezone — часовой пояс установки для месяца расхода (задача 3.18);
	// nil — UTC.
	timezone func(ctx context.Context) (string, error)
}

// SetBundleCheck задаёт проверку приложения сборкой пакета (ошибка — с
// ErrBreaksBundle). Вызывается до начала обслуживания запросов: сборка
// создаётся после сервиса приложений.
func (s *Service) SetBundleCheck(fn func(ctx context.Context, before *Application, after Application) error) {
	s.bundleCheck = fn
}

// SetPolicyWeaker задаёт сравнение политик для смены политики приложения
// (versions.Service.Weaker). Вызывается до начала обслуживания запросов.
func (s *Service) SetPolicyWeaker(fn func(ctx context.Context, from, to string) (bool, error)) {
	s.policyWeaker = fn
}

// SetDefaultStorage задаёт чтение режима хранения по умолчанию из настроек
// установки. Вызывается до начала обслуживания запросов.
func (s *Service) SetDefaultStorage(fn func(ctx context.Context) (string, error)) {
	s.defaultStorage = fn
}

// storageDefault — режим хранения нового приложения без явного выбора.
func (s *Service) storageDefault(ctx context.Context) (string, error) {
	if s.defaultStorage == nil {
		return DefaultStorage, nil
	}
	return s.defaultStorage(ctx)
}

// weakerPolicy — смена политики from на to ослабляет защиту.
func (s *Service) weakerPolicy(ctx context.Context, from, to string) (bool, error) {
	if from == to || s.policyWeaker == nil {
		return false, nil
	}
	return s.policyWeaker(ctx, from, to)
}

func (s *Service) checkBundle(ctx context.Context, before *Application, after Application) error {
	if s.bundleCheck == nil {
		return nil
	}
	return s.bundleCheck(ctx, before, after)
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil || o.OwnerCheck == nil {
		return nil, errors.New("приложения: не заданы хранилище, криптопрофиль или проверка владельца")
	}
	h, err := o.Provider.Hasher()
	if err != nil {
		return nil, err
	}
	r, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	t, err := o.Provider.TLS()
	if err != nil {
		return nil, err
	}
	s := &Service{store: o.Store, tls: t, hasher: h, random: r, ids: ids.NewGenerator(r), box: o.Box,
		orgID: o.OrgID, clock: o.Clock, policies: o.Policies, owner: o.OwnerCheck}
	if s.orgID == "" {
		s.orgID = audit.DefaultOrgID
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.policies == nil {
		s.policies = Templates{}
	}
	return s, nil
}

// By — кто и откуда выполняет действие (РСБ.1).
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// Policy — у субъекта есть право applications.policy (УПД.2).
	Policy bool
	// Confirm — повторная проверка субъекта (пароль или код TOTP) перед
	// ослаблением защиты (Н32 ревью 2.r3b); nil — ослабление отклоняется
	// с ErrConfirmRequired.
	Confirm func(ctx context.Context) error
}

func (b By) entry(action, objType, objID string, details any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: audit.Object{Type: objType, ID: objID},
		Result: audit.ResultSuccess, Details: details}
}

// actorRef — ссылка на субъекта в полях created_by и подобных.
func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

func (s *Service) newID() (string, error) {
	id, err := s.ids.New()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func textLen(field, v string, lo, hi int) error {
	n := len([]rune(v))
	if n < lo || n > hi {
		if lo > 0 {
			return fmt.Errorf("%s — от %d до %d символов", field, lo, hi)
		}
		return fmt.Errorf("%s — не больше %d символов", field, hi)
	}
	return nil
}
