package shadowai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Срок хранения агрегатов (ADR-0027, п. 6).
const (
	DefaultRetentionDays = 365
	MinRetentionDays     = 30
	MaxRetentionDays     = 1825
	// RetentionInterval — период фоновой очистки.
	RetentionInterval = time.Hour
	// ImportTimeout — предел обработки одного файла.
	ImportTimeout = 10 * time.Minute
)

// Пределы чтения.
const (
	MaxServicesList = 500
	MaxUsersList    = 1000
	MaxImportsList  = 100
	maxHourSpan     = 366 * 24 * time.Hour
	maxDaySpan      = 1830 * 24 * time.Hour
)

// Шаги динамики.
const (
	StepHour = "hour"
	StepDay  = "day"
)

// ImportRecord — запись журнала импорта.
type ImportRecord struct {
	ID             string    `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
	CatalogVersion uint64    `json:"catalog_version"`
	ImportResult
	// users — пользователи импорта, записанные хранилищем (4В27).
	users ImportUsers
}

// ImportUsers — пользователи импорта для аудита и обнаружения перебора
// псевдонимов (4В27): импорт журнала, где каждому подобранному логину отведён
// свой час, даёт таблицу «логин → псевдоним», годную и для событий шлюза.
type ImportUsers struct {
	// Users — разных псевдонимов в сводках импорта.
	Users int64
	// NewUsers — псевдонимов, которых не было в сводках организации.
	NewUsers int64
	// Baseline — до импорта в сводках не было ни одного пользователя:
	// исходный состав. Все его псевдонимы новые (4В28): пустые сводки —
	// свежая установка или очистка по сроку — не освобождают от правила.
	Baseline bool
	// NewUsersDay — новых псевдонимов организации за сутки вместе с этим
	// импортом. Сумма по организации, а не по субъекту (4Н28): у каждого
	// токена API свой субъект.
	NewUsersDay int64
}

// importUsersWindow — окно суммы новых псевдонимов организации.
const importUsersWindow = 24 * time.Hour

// aliasesOf — разные псевдонимы сводок по возрастанию.
func aliasesOf(aggs []Aggregate) []string {
	seen := map[string]struct{}{}
	for _, a := range aggs {
		if a.UserAlias != "" {
			seen[a.UserAlias] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// ServiceStat — сервис за период.
type ServiceStat struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Vendor    string    `json:"vendor"`
	Category  string    `json:"category"`
	Requests  int64     `json:"requests"`
	Bytes     int64     `json:"bytes"`
	Users     int64     `json:"users"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// UserStat — пользователь (псевдоним) за период.
type UserStat struct {
	Alias    string    `json:"alias"`
	Kind     string    `json:"kind"`
	Requests int64     `json:"requests"`
	Bytes    int64     `json:"bytes"`
	Services []string  `json:"services"`
	LastSeen time.Time `json:"last_seen"`
}

// Point — точка динамики.
type Point struct {
	Bucket   time.Time `json:"bucket"`
	Requests int64     `json:"requests"`
	Bytes    int64     `json:"bytes"`
	Users    int64     `json:"users"`
	Services int64     `json:"services"`
}

// Query — период чтения агрегатов.
type Query struct {
	From, To time.Time
	// Service — только этот сервис; пусто — все.
	Service string
	// Step — hour или day (только динамика).
	Step string
	// TZ — часовой пояс установки для суток.
	TZ    string
	Limit int
}

// Store — хранилище теневого ИИ (PGStore, Memory).
type Store interface {
	// SaveImport пишет запись импорта, агрегаты и запись аудита fn(число
	// пользователей, 4В27) одной транзакцией; повтор хеша — ErrDuplicate.
	// Сводки исключённых не пишутся; о новых сервисах — записи
	// shadow_ai.new_service той же транзакцией (DM-37).
	SaveImport(ctx context.Context, orgID string, imp ImportRecord, fn func(ImportUsers) audit.Entry) error
	// SaveSyslog пишет сводки приёма по syslog и записи о новых сервисах
	// одной транзакцией.
	SaveSyslog(ctx context.Context, orgID string, b SyslogBatch) error
	Exclusions(ctx context.Context, orgID string) ([]Exclusion, error)
	// AddExclusion добавляет исключение, удаляет сводки исключённого и пишет
	// запись аудита fn(удалено строк) одной транзакцией. Повтор —
	// ErrExclusionExists, сверх MaxExclusions — ErrTooManyExclusions.
	AddExclusion(ctx context.Context, orgID string, ex Exclusion, fn func(deleted int64) audit.Entry) error
	// RemoveExclusion снимает исключение и пишет rec; нет — ErrExclusionNotFound.
	RemoveExclusion(ctx context.Context, orgID, kind, value string, rec audit.Entry) error
	Imports(ctx context.Context, orgID string, limit int) ([]ImportRecord, error)
	Services(ctx context.Context, orgID string, q Query) ([]ServiceStat, error)
	Users(ctx context.Context, orgID string, q Query) ([]UserStat, error)
	Timeline(ctx context.Context, orgID string, q Query) ([]Point, error)
	RetentionDays(ctx context.Context, orgID string) (int, error)
	// SetRetentionDays меняет срок под блокировкой строки настроек: fn
	// получает прежний срок и возвращает запись аудита той же транзакции.
	SetRetentionDays(ctx context.Context, orgID string, days int, fn func(old int) (audit.Entry, error)) error
	// PurgeExpired удаляет агрегаты старше срока и пишет shadow_ai.retention,
	// если удалено что-то.
	PurgeExpired(ctx context.Context, orgID string) (int64, error)
}

// Options — зависимости сервиса.
type Options struct {
	Store Store
	// ServiceDBs — хранилище служебных баз (каталог — вид shadow_ai_catalog,
	// ADR-0028).
	ServiceDBs servicedb.Store
	Provider   aisecCrypto.Provider
	OrgID      string
	// UserMAC — ключ псевдонимов пользователей (тот же, что у шлюзов); nil —
	// пользователи из журналов не учитываются.
	UserMAC aisecCrypto.MAC
	// Location — часовой пояс установки (время без зоны в журнале, сутки).
	Location func(ctx context.Context) (*time.Location, error)
	IDs      *ids.Generator
	Clock    func() time.Time
	Limits   Limits
	Logger   *slog.Logger
	// vendor — ключ производителя для тестов; nil — встроенный.
	vendor aisecCrypto.Verifier
}

// By — субъект действия.
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// Confirm — повторная проверка паролем или кодом (сокращение срока).
	Confirm func(ctx context.Context) error
}

func (b By) entry(action string, obj audit.Object, details map[string]any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: obj, Result: audit.ResultSuccess, Details: details}
}

func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// Service — теневой ИИ: каталог, импорт, агрегаты.
type Service struct {
	o    Options
	busy chan struct{}

	// db — каталог: служебная база вида shadow_ai_catalog (ADR-0028).
	db *servicedb.Manager

	mu sync.Mutex
	// excl — кэш исключений; exclLoaded = false — перечитать из хранилища.
	excl       Exclusions
	exclLoaded bool
	// exclGen — поколение исключений: растёт при каждом изменении.
	exclGen uint64
	// syslog — слушатель приёма по syslog; nil — выключен.
	syslog *SyslogListener
}

// SyslogBatch — сводки приёма по syslog за период накопления.
type SyslogBatch struct {
	Aggregates   []Aggregate
	ServiceNames map[string]string
}

// New создаёт сервис. Каталог читается из хранилища при первом обращении
// (или Load) и проверяется заново.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.ServiceDBs == nil || o.Provider == nil {
		return nil, errors.New("теневой ИИ: нет хранилища или криптопрофиля")
	}
	if o.OrgID == "" {
		o.OrgID = audit.DefaultOrgID
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.IDs == nil {
		r, err := o.Provider.Random()
		if err != nil {
			return nil, err
		}
		o.IDs = ids.NewGenerator(r)
	}
	if o.Location == nil {
		o.Location = func(context.Context) (*time.Location, error) { return time.UTC, nil }
	}
	db, err := servicedb.NewManager(servicedb.Options{Store: o.ServiceDBs, Provider: o.Provider, Kind: DBKind(), OrgID: o.OrgID,
		Clock: o.Clock, Logger: o.Logger, Vendor: o.vendor})
	if err != nil {
		return nil, err
	}
	return &Service{o: o, db: db, busy: make(chan struct{}, 1)}, nil
}

// DB — каталог как служебная база (состояние для GET /api/v1/service-dbs).
func (s *Service) DB() *servicedb.Manager { return s.db }

// refreshSyslog — каталог или исключения изменились: слушатель syslog
// перечитывает их сразу, а не при следующей записи сводок.
func (s *Service) refreshSyslog(ctx context.Context) {
	s.mu.Lock()
	l := s.syslog
	s.mu.Unlock()
	if l != nil {
		l.Refresh(ctx)
	}
}

// UsersPseudonymized — задан ключ псевдонимов пользователей.
func (s *Service) UsersPseudonymized() bool { return s.o.UserMAC != nil }

// Load читает каталог из хранилища и проверяет подпись заново (ADR-0027,
// п. 3; ADR-0028, п. 5). Не прошедшая проверку текущая версия не
// используется: действует предыдущая, если она проверяется, иначе импорт
// отвечает ErrNoCatalog; запись аудита — service_db.stored_invalid.
func (s *Service) Load(ctx context.Context) error {
	return s.db.Load(ctx)
}

// current — действующий каталог; nil — нет.
func (s *Service) current(ctx context.Context) (*SignedCatalog, error) {
	v, err := s.db.Active(ctx)
	if err != nil || v == nil {
		return nil, err
	}
	sc := signedCatalog(*v)
	return &sc, nil
}

// CatalogView — каталог в ответах API: действующая версия, сервисы и обе
// сохранённые версии (ADR-0028, п. 7).
type CatalogView struct {
	// Loaded — сохранена хотя бы одна версия.
	Loaded bool `json:"loaded"`
	// Valid — есть действующий каталог (подпись проверена при запуске).
	Valid bool `json:"valid"`
	// Active — какая сохранённая версия действует: current, previous, none.
	Active       string           `json:"active"`
	Version      uint64           `json:"version,omitempty"`
	Date         string           `json:"date,omitempty"`
	SubkeySerial uint64           `json:"subkey_serial,omitempty"`
	SubkeyUntil  *time.Time       `json:"subkey_not_after,omitempty"`
	Fingerprint  string           `json:"fingerprint,omitempty"`
	UploadedAt   *time.Time       `json:"uploaded_at,omitempty"`
	Services     []CatalogService `json:"services"`
	// Current и Previous — сохранённые версии (откат — на Previous).
	Current  *servicedb.VersionState `json:"current,omitempty"`
	Previous *servicedb.VersionState `json:"previous,omitempty"`
}

// Catalog — сведения о каталоге и его сервисы.
func (s *Service) Catalog(ctx context.Context) (CatalogView, error) {
	// Состояние и действующий каталог — из одного снимка менеджера.
	st, active, err := s.db.Snapshot(ctx)
	if err != nil {
		return CatalogView{}, err
	}
	var sc *SignedCatalog
	if active != nil {
		c := signedCatalog(*active)
		sc = &c
	}
	v := CatalogView{Services: []CatalogService{}, Active: st.Active, Current: st.Current, Previous: st.Previous}
	v.Loaded = st.Current != nil || st.Previous != nil
	vs := st.Current
	if st.Active == servicedb.ActivePrevious {
		vs = st.Previous
	}
	if vs != nil {
		up := vs.UploadedAt
		v.Version, v.Date, v.SubkeySerial, v.Fingerprint, v.UploadedAt = vs.Version, vs.Date, vs.SubkeySerial, vs.Fingerprint, &up
	}
	if sc != nil {
		until := sc.Endorsement.NotAfter
		v.Valid, v.SubkeyUntil, v.Services = true, &until, sc.Catalog.Services
	}
	return v, nil
}

func (b By) db() servicedb.By { return servicedb.By{Actor: b.Actor, IP: b.IP} }

// UploadCatalog проверяет подписанный файл (срок заверения — на текущее
// время) и сохраняет его, если версия больше текущей сохранённой; прежняя
// становится предыдущей. Отказ — *servicedb.RejectError; и успех, и отказ
// пишутся в аудит без содержимого (service_db.loaded, service_db.rejected).
func (s *Service) UploadCatalog(ctx context.Context, by By, data []byte) (CatalogView, error) {
	if _, err := s.db.Upload(ctx, by.db(), data); err != nil {
		return CatalogView{}, err
	}
	s.refreshSyslog(ctx)
	return s.Catalog(ctx)
}

// RollbackCatalog возвращает предыдущую версию каталога после её повторной
// проверки (ADR-0028, п. 4). Отказ — *servicedb.RejectError.
func (s *Service) RollbackCatalog(ctx context.Context, by By) (CatalogView, error) {
	if _, err := s.db.Rollback(ctx, by.db()); err != nil {
		return CatalogView{}, err
	}
	s.refreshSyslog(ctx)
	return s.Catalog(ctx)
}

// Import разбирает журнал и сохраняет агрегаты (ADR-0027, п. 5). Одновременно
// идёт один импорт на сервер.
func (s *Service) Import(ctx context.Context, by By, format string, r io.Reader) (ImportRecord, error) {
	select {
	case s.busy <- struct{}{}:
		defer func() { <-s.busy }()
	default:
		return ImportRecord{}, ErrBusy
	}
	if _, err := newParser(format, timeBounds{}); err != nil {
		return ImportRecord{}, ErrBadFormat
	}
	sc, err := s.current(ctx)
	if err != nil {
		return ImportRecord{}, err
	}
	if sc == nil {
		return ImportRecord{}, ErrNoCatalog
	}
	loc, err := s.o.Location(ctx)
	if err != nil {
		return ImportRecord{}, err
	}
	days, err := s.o.Store.RetentionDays(ctx, s.o.OrgID)
	if err != nil {
		return ImportRecord{}, err
	}
	h, err := s.o.Provider.Hasher()
	if err != nil {
		return ImportRecord{}, err
	}
	ex, err := s.exclusions(ctx)
	if err != nil {
		return ImportRecord{}, err
	}
	now := s.o.Clock().UTC()
	ctx, cancel := context.WithTimeout(ctx, ImportTimeout)
	defer cancel()
	res, err := aggregate(ctx, r, importInput{format: format, catalog: sc.Catalog, mac: s.o.UserMAC, hasher: h, loc: loc, now: now,
		cutoff: now.Truncate(time.Hour).AddDate(0, 0, -days), exclude: ex, limits: s.o.Limits})
	if err != nil {
		return ImportRecord{}, err
	}
	uid, err := s.o.IDs.New()
	if err != nil {
		return ImportRecord{}, err
	}
	id := uid.String()
	imp := ImportRecord{ID: id, CreatedAt: now, CreatedBy: by.ref(), CatalogVersion: sc.Catalog.Version, ImportResult: res}
	details := map[string]any{"format": format, "lines": res.Lines, "matched": res.Matched, "unmatched": res.Unmatched,
		"errors": res.Errors, "outdated": res.Outdated, "excluded": res.Excluded, "services": res.Services, "aggregates": len(res.Aggregates),
		"sha256": res.SHA256, "catalog_version": sc.Catalog.Version, "users_pseudonymized": res.UsersPseudonymized}
	if res.From != nil {
		details["period_from"], details["period_to"] = res.From.Format(time.RFC3339), res.To.Format(time.RFC3339)
	}
	// Число пользователей и новых для организации — в аудите (4В27): по
	// нему правило security.shadow_ai_alias_probe видит перебор логинов.
	err = s.o.Store.SaveImport(ctx, s.o.OrgID, imp, func(u ImportUsers) audit.Entry {
		details["users"], details["new_users"], details["new_users_day"] = u.Users, u.NewUsers, u.NewUsersDay
		if u.Baseline {
			details["baseline"] = true
		}
		return by.entry("shadow_ai.import", audit.Object{Type: "shadow_ai_import", ID: id}, details)
	})
	if err != nil {
		return ImportRecord{}, err
	}
	return imp, nil
}

// Imports — последние импорты.
func (s *Service) Imports(ctx context.Context) ([]ImportRecord, error) {
	return s.o.Store.Imports(ctx, s.o.OrgID, MaxImportsList)
}

// QueryError — неверный период или параметр чтения.
type QueryError struct{ Msg string }

func (e *QueryError) Error() string { return e.Msg }

func (s *Service) checkQuery(ctx context.Context, q *Query, span time.Duration) error {
	if q.From.IsZero() || q.To.IsZero() || !q.To.After(q.From) {
		return &QueryError{"from и to — время RFC 3339, to позже from"}
	}
	if q.To.Sub(q.From) > span {
		return &QueryError{fmt.Sprintf("период не длиннее %d суток", int(span/(24*time.Hour)))}
	}
	if q.Service != "" && !validServiceID(q.Service) {
		return &QueryError{"service — ID сервиса каталога"}
	}
	loc, err := s.o.Location(ctx)
	if err != nil {
		return err
	}
	q.TZ = loc.String()
	q.From, q.To = q.From.UTC(), q.To.UTC()
	return nil
}

// Services — сервисы за период по убыванию обращений.
func (s *Service) Services(ctx context.Context, q Query) ([]ServiceStat, error) {
	if err := s.checkQuery(ctx, &q, maxDaySpan); err != nil {
		return nil, err
	}
	q.Limit = MaxServicesList
	out, err := s.o.Store.Services(ctx, s.o.OrgID, q)
	if err != nil {
		return nil, err
	}
	sc, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Name = out[i].ID
		if sc == nil {
			continue
		}
		if svc, ok := sc.Catalog.ByID(out[i].ID); ok {
			out[i].Name, out[i].Vendor, out[i].Category = svc.Name, svc.Vendor, svc.Category
		}
	}
	return out, nil
}

// Users — пользователи (псевдонимы) за период по убыванию обращений.
func (s *Service) Users(ctx context.Context, q Query) ([]UserStat, error) {
	if err := s.checkQuery(ctx, &q, maxDaySpan); err != nil {
		return nil, err
	}
	if q.Limit <= 0 || q.Limit > MaxUsersList {
		q.Limit = MaxUsersList
	}
	return s.o.Store.Users(ctx, s.o.OrgID, q)
}

// Timeline — динамика по часам или суткам (в часовом поясе установки).
func (s *Service) Timeline(ctx context.Context, q Query) ([]Point, error) {
	span := maxHourSpan
	switch q.Step {
	case StepHour:
	case StepDay:
		span = maxDaySpan
	default:
		return nil, &QueryError{"step — hour или day"}
	}
	if err := s.checkQuery(ctx, &q, span); err != nil {
		return nil, err
	}
	return s.o.Store.Timeline(ctx, s.o.OrgID, q)
}

// Settings — настройки теневого ИИ.
type Settings struct {
	RetentionDays int `json:"retention_days"`
	// UsersPseudonymized — серверу задан ключ псевдонимов пользователей.
	UsersPseudonymized bool `json:"users_pseudonymized"`
}

// Settings — текущие настройки.
func (s *Service) Settings(ctx context.Context) (Settings, error) {
	d, err := s.o.Store.RetentionDays(ctx, s.o.OrgID)
	return Settings{RetentionDays: d, UsersPseudonymized: s.UsersPseudonymized()}, err
}

// SetRetention меняет срок хранения агрегатов. Сокращение необратимо
// удаляет данные: повторная проверка и weakening в аудите (DM-40).
func (s *Service) SetRetention(ctx context.Context, by By, days int) (Settings, error) {
	if days < MinRetentionDays || days > MaxRetentionDays {
		return Settings{}, &QueryError{fmt.Sprintf("retention_days — от %d до %d суток", MinRetentionDays, MaxRetentionDays)}
	}
	err := s.o.Store.SetRetentionDays(ctx, s.o.OrgID, days, func(old int) (audit.Entry, error) {
		reduced := days < old
		if reduced {
			if by.Confirm == nil {
				return audit.Entry{}, ErrConfirmNeeded
			}
			if err := by.Confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		reasons := []string{}
		if reduced {
			reasons = append(reasons, "retention_reduced")
		}
		return by.entry("shadow_ai.settings_changed", audit.Object{Type: "shadow_ai_settings"}, map[string]any{
			"before": map[string]int{"retention_days": old}, "after": map[string]int{"retention_days": days},
			"weakening": reduced, "weakening_reasons": reasons}), nil
	})
	if err != nil {
		return Settings{}, err
	}
	return Settings{RetentionDays: days, UsersPseudonymized: s.UsersPseudonymized()}, nil
}

// RunRetention удаляет агрегаты старше срока сразу и затем каждые interval.
func (s *Service) RunRetention(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = RetentionInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := s.o.Store.PurgeExpired(ctx, s.o.OrgID); err != nil && ctx.Err() == nil {
			s.o.Logger.Error("теневой ИИ: очистка по сроку хранения не выполнена", "class", "shadow_ai", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
