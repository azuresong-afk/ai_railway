// Пакет versions — политики организации в сервере управления (ТЗ 5.3;
// задача 2.12 этапа 2): неизменяемые версии, откат новой версией,
// сравнение версий, импорт и экспорт YAML по схеме этапа 1.
//
// Версия хранится каноничным YAML (policy.Marshal) и хешем профиля: из них
// собирается пакет для шлюзов (задача 2.13). Каждое сохранение — новая
// версия с записью в журнал аудита той же транзакцией (РСБ.1); ослабление
// защиты помечается в записи признаком weakening (основа правила DM-40).
// Шаблоны (ТЗ 5.3) живут в коде (internal/policy) и здесь только читаются.
//
// Отдельный пакет, а не internal/policy, — чтобы драйвер PostgreSQL не
// попал в бинарник шлюза.
package versions

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Пределы.
const (
	// MaxPolicies — политик в организации.
	MaxPolicies = 1000
	// MaxVersionsListed — версий в одной странице списка.
	MaxVersionsListed = 100
	// MaxComment — символов в комментарии к версии.
	MaxComment = 500
)

// Источники версии (столбец source).
const (
	SourceAPI      = "api"
	SourceImport   = "import"
	SourceRollback = "rollback"
	SourceTemplate = "template"
)

// Ошибки.
var (
	ErrNotFound = errors.New("политика не найдена")
	ErrExists   = errors.New("политика с таким ID уже есть")
	// ErrConflict — base_version не совпадает с текущей версией: кто-то
	// сохранил свою версию раньше.
	ErrConflict = errors.New("политика изменена с тех пор, как её открыли")
	// ErrTemplate — шаблон не меняется, его ID не занять.
	ErrTemplate = errors.New("шаблон политики не меняется")
	ErrTooMany  = errors.New("достигнут предел числа политик")
	// ErrBreaksBundle — новая версия исключила бы приложения из пакета
	// конфигурации шлюзов (В16 ревью 2.r3b).
	ErrBreaksBundle = errors.New("версия не войдёт в пакет конфигурации шлюзов")
	// errSequence — версия не следующая по номеру (ошибка программиста; в
	// PostgreSQL то же запрещает триггер).
	errSequence = errors.New("политики: номер версии не по порядку")
)

// InputError — неверная политика или запрос; текст показывается пользователю.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

func invalid(err error) error {
	var ie *InputError
	if errors.As(err, &ie) {
		return err
	}
	// Ошибки проверки политики собраны errors.Join — по одной на поле.
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return &InputError{Errs: j.Unwrap()}
	}
	return &InputError{Errs: []error{err}}
}

func invalidf(format string, a ...any) error {
	return &InputError{Errs: []error{fmt.Errorf(format, a...)}}
}

// Policy — политика организации; Name и Mode — из текущей версии.
type Policy struct {
	ID        string
	OrgID     string
	Slug      string
	Name      string
	Mode      string
	Current   int
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
}

// Version — неизменяемая версия политики. В списке версий YAML пуст.
type Version struct {
	PolicyID string
	Version  int
	YAML     []byte
	Hash     []byte
	HashAlg  string
	Source   string
	Comment  string
	// RolledBackFrom — номер версии, содержимое которой вернул откат.
	RolledBackFrom int
	CreatedAt      time.Time
	CreatedBy      string
}

// Spec — разобранная спецификация версии.
func (v Version) Spec() (*policy.Spec, error) {
	return policy.Parse(bytes.NewReader(v.YAML))
}

// Store — хранилище (миграция 0017_policies). Рабочая реализация — PGStore,
// для тестов без PostgreSQL — Memory. Запись аудита фиксируется той же
// транзакцией, что и изменение.
type Store interface {
	// CreatePolicy сохраняет политику и её первую версию; занятый slug — ErrExists.
	CreatePolicy(ctx context.Context, p Policy, v Version, rec audit.Entry) error
	// AddVersion блокирует политику; base не равна текущей версии —
	// ErrConflict. fn получает политику и текущую версию (с YAML) и
	// возвращает следующую версию и запись аудита.
	AddVersion(ctx context.Context, orgID, slug string, base int,
		fn func(p Policy, cur Version) (Version, audit.Entry, error)) (Policy, Version, error)
	Policy(ctx context.Context, orgID, slug string) (Policy, error)
	// Policies — по slug, не больше MaxPolicies.
	Policies(ctx context.Context, orgID string) ([]Policy, error)
	CountPolicies(ctx context.Context, orgID string) (int, error)
	// Version — версия n; n = 0 — текущая.
	Version(ctx context.Context, orgID, slug string, n int) (Version, error)
	// Versions — версии без YAML, новые первыми; before > 0 — только с
	// номером меньше before.
	Versions(ctx context.Context, orgID, slug string, before, limit int) ([]Version, error)
}

// Options — зависимости Service.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	// Catalog — реестр детекторов: политика заказчика компилируется строго
	// (неизвестный детектор или направление — ошибка).
	Catalog policy.Catalog
	OrgID   string // пусто — организация по умолчанию
	Clock   func() time.Time
}

// Service — политики организации.
type Service struct {
	store   Store
	hasher  aisecCrypto.Hasher
	ids     *ids.Generator
	catalog policy.Catalog
	orgID   string
	clock   func() time.Time
	// bundleCheck — проверка новой версии с приложениями, которые на неё
	// ссылаются (В16 ревью 2.r3b); nil — без проверки.
	bundleCheck func(ctx context.Context, spec *policy.Spec) error
}

// SetBundleCheck задаёт проверку новой версии сборкой пакета (ошибка —
// с ErrBreaksBundle). Вызывается до начала обслуживания запросов: сборка
// создаётся после сервиса политик.
func (s *Service) SetBundleCheck(fn func(ctx context.Context, spec *policy.Spec) error) {
	s.bundleCheck = fn
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil || o.Catalog == nil {
		return nil, errors.New("политики: не заданы хранилище, криптопрофиль или реестр детекторов")
	}
	h, err := o.Provider.Hasher()
	if err != nil {
		return nil, err
	}
	r, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	s := &Service{store: o.Store, hasher: h, ids: ids.NewGenerator(r), catalog: o.Catalog, orgID: o.OrgID, clock: o.Clock}
	if s.orgID == "" {
		s.orgID = audit.DefaultOrgID
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	return s, nil
}

// By — кто и откуда выполняет действие (РСБ.1).
type By struct {
	Actor audit.Actor
	IP    netip.Addr
}

func (b By) entry(action, objID string, details any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: audit.Object{Type: "policy", ID: objID},
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

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

// Summary — строка списка политик: шаблон или политика организации.
type Summary struct {
	Slug     string
	Name     string
	Mode     string
	Template bool
	// Current и UpdatedAt — только у политик организации.
	Current   int
	UpdatedAt time.Time
}

// List — шаблоны (в порядке показа), затем политики организации по slug.
func (s *Service) List(ctx context.Context) ([]Summary, error) {
	var out []Summary
	for _, id := range policy.TemplateIDs() {
		t, _ := policy.Template(id)
		out = append(out, Summary{Slug: id, Name: t.Name, Mode: string(t.Mode), Template: true})
	}
	ps, err := s.store.Policies(ctx, s.orgID)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		out = append(out, Summary{Slug: p.Slug, Name: p.Name, Mode: p.Mode, Current: p.Current, UpdatedAt: p.UpdatedAt})
	}
	return out, nil
}

// Doc — версия политики с разобранной спецификацией. У шаблона Template =
// true, Version — 0 (версий у шаблонов нет).
type Doc struct {
	Policy   Policy
	Version  Version
	Spec     *policy.Spec
	Template bool
}

// Get — версия n политики slug (0 — текущая) или шаблон.
func (s *Service) Get(ctx context.Context, slug string, n int) (Doc, error) {
	if policy.IsTemplate(slug) {
		if n != 0 {
			return Doc{}, ErrNotFound
		}
		t, _ := policy.TemplateFor(slug, s.catalog)
		return Doc{Policy: Policy{Slug: slug, Name: t.Name, Mode: string(t.Mode)}, Spec: t, Template: true}, nil
	}
	if n < 0 {
		return Doc{}, ErrNotFound
	}
	p, err := s.store.Policy(ctx, s.orgID, slug)
	if err != nil {
		return Doc{}, err
	}
	v, err := s.store.Version(ctx, s.orgID, slug, n)
	if err != nil {
		return Doc{}, err
	}
	spec, err := v.Spec()
	if err != nil {
		return Doc{}, fmt.Errorf("политики: сохранённая версия %s/%d не разбирается: %w", slug, v.Version, err)
	}
	return Doc{Policy: p, Version: v, Spec: spec}, nil
}

// Versions — версии политики без содержимого, новые первыми.
func (s *Service) Versions(ctx context.Context, slug string, before, limit int) ([]Version, error) {
	if policy.IsTemplate(slug) {
		return nil, nil
	}
	if limit <= 0 || limit > MaxVersionsListed {
		limit = MaxVersionsListed
	}
	if _, err := s.store.Policy(ctx, s.orgID, slug); err != nil {
		return nil, err
	}
	return s.store.Versions(ctx, s.orgID, slug, before, limit)
}

// Defaults — значения, которые сервер подставляет вместо пустых полей,
// чтобы версия была однозначной и в пакете для шлюзов (2.13), и после
// смены умолчаний.
type Defaults struct {
	// NonText — значение пустого non_text. В консоли — allow_inline
	// (решение 1.19); при импорте YAML — allow_unchecked, как в этапе 1:
	// файл значит то же, что значил в шлюзе.
	NonText policy.NonText
}

// ConsoleDefaults — умолчания для политик из консоли и API (решение 1.19).
var ConsoleDefaults = Defaults{NonText: policy.NonTextAllowInline}

// ImportDefaults — умолчания для импорта YAML: смысл этапа 1.
var ImportDefaults = Defaults{NonText: policy.NonTextAllowUnchecked}

// prepare приводит спецификацию к сохраняемому виду и проверяет её строго
// по реестру детекторов. Возвращает каноничный YAML.
func (s *Service) prepare(spec *policy.Spec, slug string, n int, d Defaults) ([]byte, error) {
	sp := *spec
	sp.Rules = slices.Clone(spec.Rules)
	sp.ID, sp.Version = slug, n
	if sp.NonText == "" {
		sp.NonText = d.NonText
	}
	if sp.ResponseCheck == "" {
		sp.ResponseCheck = policy.ResponseIncremental
	}
	if _, err := policy.Compile(&sp, specCatalog(s.catalog, &sp)); err != nil {
		return nil, invalid(err)
	}
	y, err := policy.Marshal(&sp)
	if err != nil {
		return nil, invalid(err)
	}
	if len(y) > policy.MaxSpecSize {
		return nil, invalidf("политика больше %d байт", policy.MaxSpecSize)
	}
	*spec = sp
	return y, nil
}

func checkComment(c string) error {
	if !utf8.ValidString(c) || utf8.RuneCountInString(c) > MaxComment ||
		strings.ContainsFunc(c, func(r rune) bool { return r < 0x20 && r != '\n' || r == 0x7f }) {
		return invalidf("comment — до %d символов без управляющих символов", MaxComment)
	}
	return nil
}

func checkSlug(slug string) error {
	if policy.IsTemplate(slug) {
		return ErrTemplate
	}
	probe := policy.Spec{ID: slug, Name: "x", Version: 1, Mode: policy.Monitor}
	if probe.Validate() != nil {
		return invalidf("id — строчные латинские буквы, цифры и дефис, до 63 символов")
	}
	return nil
}

func (s *Service) newVersion(policyID string, n int, y []byte, source, comment string, by By, now time.Time) Version {
	return Version{PolicyID: policyID, Version: n, YAML: y, Hash: s.hasher.Sum(y), HashAlg: s.hasher.Name(),
		Source: source, Comment: comment, CreatedAt: now, CreatedBy: by.ref()}
}

// Create — новая политика (версия 1). spec.ID — ID политики.
func (s *Service) Create(ctx context.Context, by By, spec *policy.Spec, source, comment string, d Defaults) (Doc, error) {
	if err := checkSlug(spec.ID); err != nil {
		return Doc{}, err
	}
	if err := checkComment(comment); err != nil {
		return Doc{}, err
	}
	y, err := s.prepare(spec, spec.ID, 1, d)
	if err != nil {
		return Doc{}, err
	}
	n, err := s.store.CountPolicies(ctx, s.orgID)
	if err != nil {
		return Doc{}, err
	}
	if n >= MaxPolicies {
		return Doc{}, ErrTooMany
	}
	id, err := s.ids.New()
	if err != nil {
		return Doc{}, err
	}
	now := s.now()
	p := Policy{ID: id.String(), OrgID: s.orgID, Slug: spec.ID, Name: spec.Name, Mode: string(spec.Mode), Current: 1,
		CreatedAt: now, CreatedBy: by.ref(), UpdatedAt: now, UpdatedBy: by.ref()}
	v := s.newVersion(p.ID, 1, y, source, comment, by, now)
	action := "policy.create"
	if source == SourceImport {
		action = "policy.import"
	}
	details := map[string]any{"slug": p.Slug, "version": 1, "source": source, "mode": p.Mode,
		"non_text": string(spec.NonText), "rules": len(spec.Rules), "spec_hash": hex.EncodeToString(v.Hash)}
	if err := s.store.CreatePolicy(ctx, p, v, by.entry(action, p.ID, details)); err != nil {
		return Doc{}, err
	}
	return Doc{Policy: p, Version: v, Spec: spec}, nil
}

// Update — новая версия политики slug поверх версии base.
func (s *Service) Update(ctx context.Context, by By, slug string, base int, spec *policy.Spec, source, comment string, d Defaults) (Doc, error) {
	if policy.IsTemplate(slug) {
		return Doc{}, ErrTemplate
	}
	if spec.ID != "" && spec.ID != slug {
		return Doc{}, invalidf("id — ID политики не меняется: %s", slug)
	}
	return s.addVersion(ctx, by, slug, base, spec, source, comment, 0, d)
}

// Rollback — новая версия политики slug с содержимым версии to.
func (s *Service) Rollback(ctx context.Context, by By, slug string, to, base int, comment string) (Doc, error) {
	if policy.IsTemplate(slug) {
		return Doc{}, ErrTemplate
	}
	if to < 1 {
		return Doc{}, invalidf("version — номер версии от 1")
	}
	old, err := s.Get(ctx, slug, to)
	if err != nil {
		return Doc{}, err
	}
	if to >= base {
		return Doc{}, invalidf("version — откатить можно только к версии раньше текущей")
	}
	return s.addVersion(ctx, by, slug, base, old.Spec, SourceRollback, comment, to, Defaults{NonText: old.Spec.NonText})
}

func (s *Service) addVersion(ctx context.Context, by By, slug string, base int, spec *policy.Spec,
	source, comment string, rolledBackFrom int, d Defaults) (Doc, error) {
	if base < 1 {
		return Doc{}, invalidf("base_version — номер версии, поверх которой сохраняется изменение")
	}
	if err := checkComment(comment); err != nil {
		return Doc{}, err
	}
	// Проверка до блокировки: номер версии подставляется в YAML ниже.
	if _, err := s.prepare(spec, slug, base+1, d); err != nil {
		return Doc{}, err
	}
	if s.bundleCheck != nil {
		if err := s.bundleCheck(ctx, spec); err != nil {
			return Doc{}, err
		}
	}
	var out Doc
	p, v, err := s.store.AddVersion(ctx, s.orgID, slug, base, func(p Policy, cur Version) (Version, audit.Entry, error) {
		prev, err := cur.Spec()
		if err != nil {
			return Version{}, audit.Entry{}, fmt.Errorf("политики: текущая версия %s/%d не разбирается: %w", slug, cur.Version, err)
		}
		n := cur.Version + 1
		y, err := s.prepare(spec, slug, n, d)
		if err != nil {
			return Version{}, audit.Entry{}, err
		}
		now := s.now()
		v := s.newVersion(p.ID, n, y, source, comment, by, now)
		v.RolledBackFrom = rolledBackFrom
		diff := Compare(prev, spec)
		action := "policy.update"
		switch source {
		case SourceRollback:
			action = "policy.rollback"
		case SourceImport:
			action = "policy.import"
		}
		details := diff.details()
		details["slug"], details["from_version"], details["to_version"] = slug, cur.Version, n
		details["source"], details["spec_hash"] = source, hex.EncodeToString(v.Hash)
		if rolledBackFrom > 0 {
			details["rolled_back_from"] = rolledBackFrom
		}
		out.Spec = spec
		return v, by.entry(action, p.ID, details), nil
	})
	if err != nil {
		return Doc{}, err
	}
	out.Policy, out.Version = p, v
	return out, nil
}

// Import разбирает YAML (строгая схема этапа 1) и создаёт политику или,
// если она есть, новую версию поверх base.
func (s *Service) Import(ctx context.Context, by By, r io.Reader, base int, comment string) (Doc, bool, error) {
	spec, err := policy.Parse(r)
	if err != nil {
		return Doc{}, false, invalid(err)
	}
	if err := checkSlug(spec.ID); err != nil {
		return Doc{}, false, err
	}
	_, err = s.store.Policy(ctx, s.orgID, spec.ID)
	switch {
	case errors.Is(err, ErrNotFound):
		d, err := s.Create(ctx, by, spec, SourceImport, comment, ImportDefaults)
		return d, true, err
	case err != nil:
		return Doc{}, false, err
	}
	if base < 1 {
		return Doc{}, false, fmt.Errorf("%w: политика %s уже есть — укажите base_version", ErrConflict, spec.ID)
	}
	d, err := s.addVersion(ctx, by, spec.ID, base, spec, SourceImport, comment, 0, ImportDefaults)
	return d, false, err
}

// Export — YAML версии n (0 — текущая) политики или шаблона.
func (s *Service) Export(ctx context.Context, slug string, n int) ([]byte, Doc, error) {
	d, err := s.Get(ctx, slug, n)
	if err != nil {
		return nil, Doc{}, err
	}
	if d.Template {
		y, err := policy.Marshal(d.Spec)
		return y, d, err
	}
	return d.Version.YAML, d, nil
}

// Diff — сравнение версий from и to политики slug.
func (s *Service) Diff(ctx context.Context, slug string, from, to int) (Diff, error) {
	if from < 1 || to < 1 {
		return Diff{}, invalidf("from и to — номера версий от 1")
	}
	a, err := s.Get(ctx, slug, from)
	if err != nil {
		return Diff{}, err
	}
	b, err := s.Get(ctx, slug, to)
	if err != nil {
		return Diff{}, err
	}
	d := Compare(a.Spec, b.Spec)
	d.From, d.To = from, to
	return d, nil
}

// FromTemplate — копия шаблона для новой политики slug.
func (s *Service) FromTemplate(id, slug, name string) (*policy.Spec, error) {
	t, ok := policy.TemplateFor(id, s.catalog)
	if !ok {
		return nil, invalidf("from_template — один из шаблонов: %s", strings.Join(policy.TemplateIDs(), ", "))
	}
	t.ID = slug
	if name != "" {
		t.Name = name
	}
	return t, nil
}

// PolicyMode — режим текущей версии политики или шаблона (apps.Policies,
// задача 2.11): ok = false — такой политики нет.
func (s *Service) PolicyMode(ctx context.Context, orgID, id string) (string, bool, error) {
	if t, ok := policy.Template(id); ok {
		return string(t.Mode), true, nil
	}
	if orgID == "" {
		orgID = s.orgID
	}
	p, err := s.store.Policy(ctx, orgID, id)
	switch {
	case errors.Is(err, ErrNotFound):
		return "", false, nil
	case err != nil:
		return "", false, err
	}
	return p.Mode, true, nil
}
