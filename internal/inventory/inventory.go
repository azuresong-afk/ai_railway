// Пакет inventory — реестр ИИ в сервере управления (ТЗ 5.11; задача 5.17
// этапа 5, ADR-0029).
//
// Приложения, ключи приложений и провайдеры реестр не копирует: их ведёт
// internal/apps, реестр показывает их сводку (без секретов и хешей ключей).
// Свои данные реестра — модели (провайдера и заказчика), файлы моделей
// заказчика с хешами (эталон для сверки сканером, DM-29) и использование
// «приложение — провайдер — модель» по трафику. Использование и модели
// провайдеров пополняет задача сервера по почасовым агрегатам дашбордов —
// без содержимого запросов и без новых полей в пакете событий шлюза.
// Каждое изменение пишется в журнал аудита той же транзакцией (РСБ.1).
package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Пределы (ADR-0029, пп. 2 и 8).
const (
	// MaxModels — моделей в организации.
	MaxModels = 5000
	// MaxUsage — записей использования в организации.
	MaxUsage = 20000
	// MaxFiles — файлов у модели.
	MaxFiles = 256
	// MaxBody — тело запроса ручной записи.
	MaxBody = 256 << 10
	// MaxFileSize — наибольший размер файла модели, 2^50 байт.
	MaxFileSize int64 = 1 << 50
	// MaxPathBytes — длина пути файла, байты.
	MaxPathBytes = 512
	// MaxDiscoveredNames — пар «провайдер/модель» в записи аудита
	// inventory.discovered.
	MaxDiscoveredNames = 20
	// DefaultLimit и MaxLimit — строк на странице списка.
	DefaultLimit = 50
	MaxLimit     = 200

	maxName        = 256
	maxVersion     = 128
	maxTitle       = 200
	maxOwner       = 200
	maxDescription = 2000
)

// SyncInterval — период задачи пополнения по трафику.
const SyncInterval = 10 * time.Minute

// SyncOverlap — сколько перечитывается до отметки: сервер принимает события
// до MaxEventAge назад, строки прошлых часов появляются, пока шлюз досылает
// накопленное (ADR-0029, п. 2).
const SyncOverlap = events.MaxEventAge + time.Hour

// Виды моделей.
const (
	KindProvider = "provider" // модель провайдера продукта
	KindCustomer = "customer" // модель заказчика (веса у заказчика)
)

// Происхождение записи модели.
const (
	OriginTraffic = "traffic"
	OriginManual  = "manual"
)

// Состояние модели; запрет использования (blocked) — задача 5.22.
const StatusActive = "active"

// Роли файлов модели.
const (
	RoleWeights   = "weights"
	RoleAdapter   = "adapter"
	RoleTokenizer = "tokenizer"
	RoleConfig    = "config"
	RoleOther     = "other"
)

// HashAlg — алгоритм хеша файлов модели в обоих профилях (ADR-0029, п. 1).
const HashAlg = "SHA-256"

// Состояния ключа приложения в сводке.
const (
	KeyActive  = "active"
	KeyExpired = "expired"
	KeyRevoked = "revoked"
)

// Ошибки.
var (
	ErrNotFound = errors.New("модель не найдена")
	// ErrExists — модель с этой парой «провайдер, имя» уже есть.
	ErrExists  = errors.New("модель уже есть в реестре")
	ErrTooMany = errors.New("достигнут предел числа моделей")
	// ErrNoProvider — провайдера с этим ID нет в организации.
	ErrNoProvider = errors.New("провайдер не найден")
	// errUnchanged — изменение ничего не меняет: без записи аудита.
	errUnchanged = errors.New("без изменений")
)

// InputError — неверные данные запроса; текст показывается пользователю.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

func invalid(errs ...error) error { return &InputError{Errs: errs} }

// File — файл модели: путь относительно каталога модели и хеш.
type File struct {
	Path    string
	Size    int64
	Role    string
	HashAlg string
	Hash    []byte
}

// Model — модель в реестре.
type Model struct {
	ID          string
	OrgID       string
	Kind        string
	Provider    string
	Name        string
	Version     string
	Title       string
	Description string
	Owner       string
	Origin      string
	Status      string
	// FirstSeen и LastSeen — первый и последний час в трафике; nil — не
	// встречалась.
	FirstSeen *time.Time
	LastSeen  *time.Time
	// Files — файлы (в списке моделей не заполняются, есть FileCount).
	Files     []File
	FileCount int
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
}

// Usage — тройка «приложение, провайдер, модель» из трафика.
type Usage struct {
	ID        int64
	App       string
	Provider  string
	Model     string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Key — ключ приложения в сводке: без хеша и секрета.
type Key struct {
	ID        string
	Name      string
	Prefix    string
	State     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// App — приложение в сводке.
type App struct {
	ID         string
	Slug       string
	Name       string
	Env        string
	Department string
	Provider   string
	Models     []string
	Archived   bool
	Keys       []Key
}

// Provider — провайдер в сводке: без адреса и учётных данных.
type Provider struct {
	ID              string
	Slug            string
	Name            string
	Type            string
	External        bool
	CredentialSet   bool
	CredentialSetAt *time.Time
	// Endpoint — адрес провайдера; заполняется только для выгрузки AI-BOM,
	// в документ попадают лишь схема, хост и порт.
	Endpoint string
}

// SyncState — состояние задачи пополнения.
type SyncState struct {
	SyncedUpto   *time.Time
	RunAt        *time.Time
	LimitReached bool
	Skipped      int64
}

// Overview — сводка реестра.
type Overview struct {
	Apps      []App
	Providers []Provider
	Models    int
	Usage     int
	Sync      SyncState
}

// Filter — отбор моделей. After — курсор: строки после (CreatedAt, ID).
type Filter struct {
	Kind     string
	Origin   string
	Provider string
	// Query — подстрока имени или названия без учёта регистра.
	Query string
	After *Cursor
	Limit int
}

// UsageFilter — отбор использования. After — строки с ID больше.
type UsageFilter struct {
	App      string
	Provider string
	Model    string
	After    int64
	Limit    int
}

// Cursor — позиция в списке моделей.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}

// Seen — тройка из агрегатов за окно: первый и последний час.
type Seen struct {
	App, Provider, Model string
	First, Last          time.Time
}

// DiscoverResult — итог запуска пополнения.
type DiscoverResult struct {
	// Models и Links — новые модели и новые записи использования.
	Models int
	Links  int
	// Skipped — тройки и модели, не добавленные из-за предела.
	Skipped int64
	// Names — до MaxDiscoveredNames новых пар «провайдер/модель».
	Names []string
	// SyncedUpto — новая отметка: последний прочитанный час.
	SyncedUpto *time.Time
}

// Store — хранилище (миграция 0069_inventory). Рабочая реализация —
// PGStore, для тестов без PostgreSQL — Memory. Функции fn выполняются
// внутри транзакции над заблокированной строкой и возвращают запись
// аудита, которая фиксируется вместе с изменением (РСБ.1).
type Store interface {
	// Overview — приложения с ключами, провайдеры, число моделей и
	// записей использования, состояние пополнения на момент now.
	Overview(ctx context.Context, orgID string, now time.Time) (Overview, error)
	// ProviderExists — есть ли провайдер с этим ID в организации.
	ProviderExists(ctx context.Context, orgID, slug string) (bool, error)
	Models(ctx context.Context, orgID string, f Filter) ([]Model, error)
	// Model — модель с файлами; ErrNotFound.
	Model(ctx context.Context, orgID, id string) (Model, error)
	// CreateModel — ErrExists, ErrTooMany.
	CreateModel(ctx context.Context, m Model, rec audit.Entry) error
	// UpdateModel передаёт fn заблокированную модель с файлами; файлы
	// заменяются целиком.
	UpdateModel(ctx context.Context, orgID, id string, fn func(*Model) (audit.Entry, error)) (Model, error)
	DeleteModel(ctx context.Context, orgID, id string, fn func(Model) (audit.Entry, error)) (Model, error)
	Usage(ctx context.Context, orgID string, f UsageFilter) ([]Usage, error)
	// Discover под блокировкой состояния читает тройки из агрегатов за окно
	// от отметки минус SyncOverlap (без отметки — все), добавляет
	// использование и модели провайдеров в пределах MaxUsage и MaxModels и
	// сохраняет состояние. rec получает итог и возвращает запись аудита
	// или nil (новых записей нет).
	Discover(ctx context.Context, orgID string, now time.Time, ids func() (string, error),
		rec func(DiscoverResult) *audit.Entry) (DiscoverResult, error)
	// Export читает реестр одним снимком и в той же транзакции записывает
	// запись аудита, которую вернёт fn; ошибка fn отменяет выгрузку.
	// ErrExportTooLarge — файлов моделей больше MaxAIBOMFiles.
	Export(ctx context.Context, orgID string, fn func(Snapshot) (audit.Entry, error)) error
}

// Options — зависимости Service.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	OrgID    string // пусто — организация по умолчанию
	Clock    func() time.Time
	Logger   *slog.Logger
}

// Service — реестр ИИ.
type Service struct {
	store  Store
	hasher aisecCrypto.Hasher
	ids    *ids.Generator
	orgID  string
	clock  func() time.Time
	logger *slog.Logger
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil {
		return nil, errors.New("реестр ИИ: не заданы хранилище или криптопрофиль")
	}
	r, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	h, err := o.Provider.Hasher()
	if err != nil {
		return nil, err
	}
	s := &Service{store: o.Store, hasher: h, ids: ids.NewGenerator(r), orgID: o.OrgID, clock: o.Clock, logger: o.Logger}
	if s.orgID == "" {
		s.orgID = audit.DefaultOrgID
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}
	return s, nil
}

// By — кто и откуда выполняет действие (РСБ.1).
type By struct {
	Actor audit.Actor
	IP    netip.Addr
}

func (b By) entry(action, id string, details map[string]any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: audit.Object{Type: "inventory_model", ID: id},
		Result: audit.ResultSuccess, Details: details}
}

// ref — ссылка на субъекта в полях created_by и подобных.
func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// systemActor — пополнение по трафику.
var systemActor = audit.Actor{Type: audit.ActorSystem, ID: "aisec-server", Name: "Сервер управления"}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

func (s *Service) newID() (string, error) {
	id, err := s.ids.New()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// Overview — сводка реестра.
func (s *Service) Overview(ctx context.Context) (Overview, error) {
	return s.store.Overview(ctx, s.orgID, s.now())
}

// Models — страница моделей.
func (s *Service) Models(ctx context.Context, f Filter) ([]Model, error) {
	var errs []error
	if f.Kind != "" && f.Kind != KindProvider && f.Kind != KindCustomer {
		errs = append(errs, errors.New("kind — provider или customer"))
	}
	if f.Origin != "" && f.Origin != OriginTraffic && f.Origin != OriginManual {
		errs = append(errs, errors.New("origin — traffic или manual"))
	}
	if f.Provider != "" && !slugRe.MatchString(f.Provider) {
		errs = append(errs, errors.New("provider — ID провайдера"))
	}
	if len([]rune(f.Query)) > maxName {
		errs = append(errs, fmt.Errorf("q — не больше %d символов", maxName))
	}
	if len(errs) > 0 {
		return nil, invalid(errs...)
	}
	f.Limit = clampLimit(f.Limit)
	return s.store.Models(ctx, s.orgID, f)
}

// Model — карточка модели: файлы и использование приложениями.
func (s *Service) Model(ctx context.Context, id string) (Model, []Usage, error) {
	m, err := s.store.Model(ctx, s.orgID, id)
	if err != nil {
		return Model{}, nil, err
	}
	var u []Usage
	if m.Provider != "" {
		if u, err = s.store.Usage(ctx, s.orgID, UsageFilter{Provider: m.Provider, Model: m.Name, Limit: MaxLimit}); err != nil {
			return Model{}, nil, err
		}
	}
	return m, u, nil
}

// Usage — страница использования.
func (s *Service) Usage(ctx context.Context, f UsageFilter) ([]Usage, error) {
	var errs []error
	for _, v := range []struct{ name, val string }{{"app", f.App}, {"provider", f.Provider}, {"model", f.Model}} {
		if len([]rune(v.val)) > maxName {
			errs = append(errs, fmt.Errorf("%s — не больше %d символов", v.name, maxName))
		}
	}
	if f.After < 0 {
		errs = append(errs, errors.New("after — неотрицательное число"))
	}
	if len(errs) > 0 {
		return nil, invalid(errs...)
	}
	f.Limit = clampLimit(f.Limit)
	return s.store.Usage(ctx, s.orgID, f)
}

// clampLimit — строк на странице; одна сверх MaxLimit — признак следующей
// страницы у вызывающего.
func clampLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultLimit
	case n > MaxLimit+1:
		return MaxLimit + 1
	}
	return n
}

// CreateModel добавляет модель вручную (inventory.model_created).
func (s *Service) CreateModel(ctx context.Context, by By, in ModelInput) (Model, error) {
	// Провайдер проверяется до транзакции и без внешнего ключа: запись
	// реестра — сведения, а не настройка маршрута, поэтому модель
	// удалённого позже провайдера остаётся в реестре как была (ADR-0029).
	if err := s.checkProvider(ctx, in.Provider); err != nil {
		return Model{}, err
	}
	id, err := s.newID()
	if err != nil {
		return Model{}, err
	}
	now := s.now()
	m := Model{ID: id, OrgID: s.orgID, Kind: in.Kind, Provider: in.Provider, Name: in.Name, Version: in.Version, Title: in.Title,
		Description: in.Description, Owner: in.Owner, Origin: OriginManual, Status: StatusActive, Files: in.files(),
		CreatedAt: now, CreatedBy: by.ref(), UpdatedAt: now, UpdatedBy: by.ref()}
	m.FileCount = len(m.Files)
	rec := by.entry("inventory.model_created", id, map[string]any{"kind": m.Kind, "provider": m.Provider, "name": m.Name,
		"version": m.Version, "files": len(m.Files)})
	if err := s.store.CreateModel(ctx, m, rec); err != nil {
		return Model{}, err
	}
	return m, nil
}

func (s *Service) checkProvider(ctx context.Context, slug string) error {
	if slug == "" {
		return nil
	}
	ok, err := s.store.ProviderExists(ctx, s.orgID, slug)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoProvider
	}
	return nil
}

// UpdateModel меняет описание, версию, вид и файлы модели
// (inventory.model_updated). Провайдер и имя не меняются: по ним модель
// связана с трафиком.
func (s *Service) UpdateModel(ctx context.Context, by By, id string, p ModelPatch) (Model, error) {
	m, err := s.store.UpdateModel(ctx, s.orgID, id, func(m *Model) (audit.Entry, error) {
		changed := []string{}
		set := func(field string, dst *string, v *string) {
			if v != nil && *v != *dst {
				*dst = *v
				changed = append(changed, field)
			}
		}
		set("version", &m.Version, p.Version)
		set("title", &m.Title, p.Title)
		set("description", &m.Description, p.Description)
		set("owner", &m.Owner, p.Owner)
		if p.Kind != nil && *p.Kind != m.Kind {
			if *p.Kind == KindProvider && m.Provider == "" {
				return audit.Entry{}, invalid(errors.New("kind — модель без провайдера может быть только моделью заказчика (customer)"))
			}
			m.Kind = *p.Kind
			changed = append(changed, "kind")
		}
		before := len(m.Files)
		if p.Files != nil {
			nf := p.files()
			if !sameFiles(m.Files, nf) {
				m.Files = nf
				changed = append(changed, "files")
			}
		}
		if len(changed) == 0 {
			return audit.Entry{}, errUnchanged
		}
		m.FileCount = len(m.Files)
		m.UpdatedAt, m.UpdatedBy = s.now(), by.ref()
		return by.entry("inventory.model_updated", m.ID, map[string]any{"provider": m.Provider, "name": m.Name, "changed": changed,
			"files_before": before, "files": len(m.Files)}), nil
	})
	if errors.Is(err, errUnchanged) {
		m, _, err = s.Model(ctx, id)
	}
	return m, err
}

func sameFiles(a, b []File) bool {
	if len(a) != len(b) {
		return false
	}
	idx := make(map[string]File, len(a))
	for _, f := range a {
		idx[f.Path] = f
	}
	for _, f := range b {
		o, ok := idx[f.Path]
		if !ok || o.Size != f.Size || o.Role != f.Role || o.HashAlg != f.HashAlg || string(o.Hash) != string(f.Hash) {
			return false
		}
	}
	return true
}

// DeleteModel удаляет модель с файлами (inventory.model_deleted). Модель из
// трафика появится снова, если её продолжают вызывать (ADR-0029, п. 2).
func (s *Service) DeleteModel(ctx context.Context, by By, id string) error {
	_, err := s.store.DeleteModel(ctx, s.orgID, id, func(m Model) (audit.Entry, error) {
		return by.entry("inventory.model_deleted", m.ID, map[string]any{"kind": m.Kind, "provider": m.Provider, "name": m.Name,
			"origin": m.Origin, "files": len(m.Files)}), nil
	})
	return err
}

// Discover — один запуск пополнения по трафику (inventory.discovered).
func (s *Service) Discover(ctx context.Context) (DiscoverResult, error) {
	res, err := s.store.Discover(ctx, s.orgID, s.now(), s.newID, func(r DiscoverResult) *audit.Entry {
		if r.Models == 0 && r.Links == 0 {
			return nil
		}
		return &audit.Entry{Actor: systemActor, Action: "inventory.discovered", Object: audit.Object{Type: "inventory", ID: s.orgID},
			Result: audit.ResultSuccess, Details: map[string]any{"models": r.Models, "links": r.Links, "skipped": r.Skipped, "names": r.Names}}
	})
	if err != nil {
		return DiscoverResult{}, err
	}
	if res.Skipped > 0 {
		s.logger.Warn("реестр ИИ: достигнут предел числа записей, новые модели и связи из трафика не добавлены",
			"class", "inventory", "skipped", res.Skipped, "max_models", MaxModels, "max_usage", MaxUsage)
	}
	return res, nil
}

// Run запускает пополнение сразу и затем раз в interval до отмены ctx.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = SyncInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := s.Discover(ctx); err != nil && ctx.Err() == nil {
			s.logger.Error("реестр ИИ: пополнение по трафику не выполнено", "class", "inventory", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
