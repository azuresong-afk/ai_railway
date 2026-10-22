package apps

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// AppInput — создание и изменение приложения. Поля защиты — отдельно
// (ProtectionInput): их меняет только обладатель права applications.policy.
type AppInput struct {
	Slug        string // только при создании
	Name        string
	Description string
	Department  string
	// OwnerID — пусто при создании — тот, кто создаёт.
	OwnerID    string
	Env        string
	ProviderID string
	Models     []string
	Aliases    map[string]string
	// UserFrom — пусто — значение по умолчанию.
	UserFrom string
	Quotas   Quotas
}

// ProtectionInput — поля защиты; пустое поле (nil у списков) — значение по
// умолчанию при создании и прежнее значение при изменении. Режим при сбое
// детекторов, словари и исключения DM-11 — тоже поля защиты: fail_open,
// удалённое слово или новый домен ослабляют её (В15 ревью 2.r3b).
type ProtectionInput struct {
	Policy            string
	PolicyMode        string
	Storage           string
	FailMode          string
	Lists             *[]List
	ExfilAllowDomains *[]string
}

// apply переносит заданные поля защиты, кроме политики, режима и режима
// хранения (их проверяет protection), в приложение.
func (in ProtectionInput) apply(a *Application) {
	if in.FailMode != "" {
		a.FailMode = in.FailMode
	}
	if in.Lists != nil {
		a.Lists = slices.Clone(*in.Lists)
	}
	if in.ExfilAllowDomains != nil {
		a.ExfilAllowDomains = slices.Clone(*in.ExfilAllowDomains)
	}
	if a.Lists == nil {
		a.Lists = []List{}
	}
	if a.ExfilAllowDomains == nil {
		a.ExfilAllowDomains = []string{}
	}
}

func (in *AppInput) defaults() {
	if in.UserFrom == "" {
		in.UserFrom = DefaultUserFrom
	}
	if in.Aliases == nil {
		in.Aliases = map[string]string{}
	}
}

// checkApp проверяет приложение целиком: поля AppInput и поля защиты,
// которые уже перенесены в a.
func (s *Service) checkApp(ctx context.Context, in Application) error {
	var errs []error
	if err := textLen("name", in.Name, 1, maxName); err != nil {
		errs = append(errs, err)
	}
	if err := noControl("name", in.Name); err != nil {
		errs = append(errs, err)
	}
	if err := textLen("description", in.Description, 0, maxDescription); err != nil {
		errs = append(errs, err)
	}
	if err := textLen("department", in.Department, 0, maxDepartment); err != nil {
		errs = append(errs, err)
	}
	if err := noControl("department", in.Department); err != nil {
		errs = append(errs, err)
	}
	if len(in.Models) > maxModels {
		errs = append(errs, errors.New("models — не больше 100 моделей"))
	}
	if len(in.Aliases) > maxModels {
		errs = append(errs, errors.New("aliases — не больше 100 псевдонимов"))
	}
	if _, err := store.ParseUUID(in.ProviderID); err != nil {
		errs = append(errs, errors.New("provider_id — ID провайдера"))
	}
	p := config.AppParams{Env: in.Env, FailMode: in.FailMode, Storage: in.Storage, UserFrom: in.UserFrom,
		Models: in.Models, Aliases: in.Aliases, Quotas: in.Quotas.config(), Lists: listSpecs(in.Lists),
		ExfilAllowDomains: in.ExfilAllowDomains}
	errs = append(errs, p.Check()...)
	if _, err := store.ParseUUID(in.OwnerID); err != nil {
		errs = append(errs, errors.New("owner_id — ID учётной записи владельца"))
	} else if err := s.owner(ctx, in.OwnerID); err != nil {
		errs = append(errs, errors.New("owner_id — действующая учётная запись консоли"))
	}
	if len(errs) > 0 {
		return invalid(errs...)
	}
	return nil
}

// protection проверяет поля защиты и заполняет умолчания из prev.
// Режим политики при создании — режим выбранной политики (решение по
// вопросу 1.19): выбор «ПДн — строго» не превращается молча в monitor.
func (s *Service) protection(ctx context.Context, in ProtectionInput, prev *Protection) (Protection, error) {
	out := Protection{Policy: in.Policy, PolicyMode: in.PolicyMode, Storage: in.Storage}
	if prev != nil {
		if out.Policy == "" {
			out.Policy = prev.Policy
		}
		if out.PolicyMode == "" && in.Policy == "" {
			out.PolicyMode = prev.PolicyMode
		}
		if out.Storage == "" {
			out.Storage = prev.Storage
		}
	}
	if out.Policy == "" {
		out.Policy = defaultPolicy
	}
	if out.Storage == "" {
		out.Storage = DefaultStorage
	}
	var errs []error
	mode, ok, err := s.policies.PolicyMode(ctx, s.orgID, out.Policy)
	if err != nil {
		return Protection{}, err
	}
	if !ok {
		errs = append(errs, errors.New("policy — шаблон или политика организации"))
	}
	if out.PolicyMode == "" {
		out.PolicyMode = mode
	}
	if out.PolicyMode != ModeMonitor && out.PolicyMode != ModeEnforce {
		errs = append(errs, errors.New("policy_mode — monitor или enforce"))
	}
	if out.Storage != "none" && out.Storage != "masked" && out.Storage != "full" {
		errs = append(errs, errors.New("storage — none, masked или full"))
	}
	if len(errs) > 0 {
		return Protection{}, invalid(errs...)
	}
	return out, nil
}

// guard — то, что определяет защиту приложения: поля защиты и признак
// «внешний» его провайдера (DM-40).
type guard struct {
	Protection
	FailMode         string
	Lists            []List
	Exfil            []string
	ExternalProvider bool
}

func guardOf(a Application, external bool) guard {
	return guard{Protection: a.Protection, FailMode: a.FailMode, Lists: a.Lists, Exfil: a.ExfilAllowDomains, ExternalProvider: external}
}

// weakening — изменение ослабляет защиту (DM-40, ТЗ 5.16): перевод в
// monitor, режим хранения none или full, «Только мониторинг», fail_open,
// новый домен-исключение DM-11, удалённый или изменённый словарь (кроме
// добавления слов и выражений), переход на невнешнего провайдера (в
// monitor данные к нему не маскируются).
func weakening(before, after guard) bool {
	return (before.PolicyMode == ModeEnforce && after.PolicyMode == ModeMonitor) ||
		(after.Storage != before.Storage && (after.Storage == "none" || after.Storage == "full")) ||
		(after.Policy != before.Policy && after.Policy == monitorOnlyPolicy) ||
		(before.FailMode != "fail_open" && after.FailMode == "fail_open") ||
		!subset(after.Exfil, before.Exfil, strings.ToLower) ||
		listsWeakened(before.Lists, after.Lists) ||
		(before.ExternalProvider && !after.ExternalProvider)
}

// subset — каждое значение a (после norm) есть в b.
func subset(a, b []string, norm func(string) string) bool {
	set := make(map[string]bool, len(b))
	for _, v := range b {
		set[norm(v)] = true
	}
	for _, v := range a {
		if !set[norm(v)] {
			return false
		}
	}
	return true
}

func same(s string) string { return s }

// listsWeakened — словарь удалён, или у него убрано слово или выражение,
// включён учёт регистра, изменены категория, угроза, балл или направление.
func listsWeakened(before, after []List) bool {
	byID := make(map[string]List, len(after))
	for _, l := range after {
		byID[l.ID] = l
	}
	for _, b := range before {
		a, ok := byID[b.ID]
		if !ok || a.Category != b.Category || a.Threat != b.Threat || a.Score != b.Score ||
			a.Direction != b.Direction || (a.CaseSensitive && !b.CaseSensitive) ||
			!subset(b.Words, a.Words, same) || !subset(b.Regex, a.Regex, same) {
			return true
		}
	}
	return false
}

func guardDetails(g guard) map[string]any {
	return map[string]any{"policy": g.Policy, "policy_mode": g.PolicyMode, "storage": g.Storage,
		"fail_mode": g.FailMode, "lists": len(g.Lists), "exfil_allow_domains": len(g.Exfil)}
}

// confirm — повторная проверка субъекта перед ослаблением защиты (Н32
// ревью 2.r3b): как выпуск токена (В8) и сокращение сроков (В13).
func (b By) confirm(ctx context.Context) error {
	if b.Confirm == nil {
		return ErrConfirmRequired
	}
	return b.Confirm(ctx)
}

// externalOf — признак «внешний» провайдеров по ID (чтение до транзакции:
// хранилище в памяти держит общую блокировку). Неизвестный — внешний.
func (s *Service) externalOf(ctx context.Context, ids ...string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, ok := out[id]; ok {
			continue
		}
		p, err := s.store.Provider(ctx, s.orgID, id)
		switch {
		case errors.Is(err, ErrNotFound):
			out[id] = true
		case err != nil:
			return nil, err
		default:
			out[id] = p.External
		}
	}
	return out, nil
}

func ext(m map[string]bool, id string) bool {
	v, ok := m[id]
	return v || !ok
}

// appDetails — сведения о приложении для аудита (без содержимого списков:
// только их число).
func appDetails(a Application) map[string]any {
	return map[string]any{
		"slug": a.Slug, "name": a.Name, "department": a.Department, "owner_id": a.OwnerID, "env": a.Env,
		"provider_id": a.ProviderID, "models": a.Models, "policy": a.Policy, "policy_mode": a.PolicyMode,
		"storage": a.Storage, "fail_mode": a.FailMode, "user_from": a.UserFrom, "quotas": a.Quotas,
		"lists": len(a.Lists), "exfil_allow_domains": len(a.ExfilAllowDomains),
	}
}

func (in AppInput) apply(a *Application) {
	a.Name, a.Description, a.Department, a.OwnerID = in.Name, in.Description, in.Department, in.OwnerID
	a.Env, a.ProviderID, a.UserFrom = in.Env, in.ProviderID, in.UserFrom
	a.Models, a.Aliases = slices.Clone(in.Models), maps.Clone(in.Aliases)
	a.Quotas = in.Quotas
}

// CreateApplication создаёт приложение. prot — nil, если у создающего нет
// права applications.policy: поля защиты получают умолчания. Ослабление
// относительно умолчаний (none или full, fail_open, домены-исключения) —
// с повторной проверкой (Н32).
func (s *Service) CreateApplication(ctx context.Context, by By, in AppInput, prot *ProtectionInput) (Application, error) {
	in.defaults()
	var errs []error
	if !config.ValidID(in.Slug) {
		errs = append(errs, errors.New("slug — строчные латинские буквы, цифры и дефис, до 63 символов"))
	}
	if prot == nil {
		prot = &ProtectionInput{}
	}
	pr, err := s.protection(ctx, *prot, nil)
	if err != nil {
		var ie *InputError
		if !errors.As(err, &ie) {
			return Application{}, err
		}
		errs = append(errs, ie.Errs...)
		pr.Storage = DefaultStorage
	}
	a := Application{OrgID: s.orgID, Slug: in.Slug, Protection: pr, FailMode: DefaultFailMode}
	in.apply(&a)
	prot.apply(&a)
	if err := s.checkApp(ctx, a); err != nil {
		var ie *InputError
		if !errors.As(err, &ie) {
			return Application{}, err
		}
		errs = append(errs, ie.Errs...)
	}
	if len(errs) > 0 {
		return Application{}, invalid(errs...)
	}
	if err := s.checkBundle(ctx, nil, a); err != nil {
		return Application{}, err
	}
	base := Application{Protection: Protection{PolicyMode: pr.PolicyMode, Storage: DefaultStorage, Policy: pr.Policy},
		FailMode: DefaultFailMode}
	weak := weakening(guardOf(base, true), guardOf(a, true))
	if weak {
		if err := by.confirm(ctx); err != nil {
			return Application{}, err
		}
	}
	if a.ID, err = s.newID(); err != nil {
		return Application{}, err
	}
	now := s.now()
	a.CreatedAt, a.CreatedBy, a.UpdatedAt, a.UpdatedBy = now, by.ref(), now, by.ref()
	d := appDetails(a)
	d["weakening"] = weak
	if err := s.store.CreateApplication(ctx, a, by.entry("application.create", "application", a.ID, d)); err != nil {
		return Application{}, err
	}
	return a, nil
}

// visible — приложение доступно субъекту: ownerID пуст (право на все
// объекты) или он владелец. Чужое — ErrNotFound, как отсутствующее (УПД.8).
func visible(a Application, ownerID string) error {
	if ownerID != "" && a.OwnerID != ownerID {
		return ErrNotFound
	}
	return nil
}

// Application — приложение по ID; ownerID не пуст — только своё.
func (s *Service) Application(ctx context.Context, id, ownerID string) (Application, error) {
	a, err := s.store.Application(ctx, s.orgID, id)
	if err != nil {
		return Application{}, err
	}
	if err := visible(a, ownerID); err != nil {
		return Application{}, err
	}
	return a, nil
}

// Applications — страница приложений; ownerID не пуст — только его.
func (s *Service) Applications(ctx context.Context, ownerID string, after *Cursor, limit int) ([]Application, error) {
	return s.store.Applications(ctx, s.orgID, ownerID, after, limit)
}

// UpdateApplication меняет приложение, кроме slug и полей защиты. Переход
// с внешнего провайдера на невнешнего ослабляет защиту: только с правом
// applications.policy (иначе ErrPolicyRequired) и с повторной проверкой.
func (s *Service) UpdateApplication(ctx context.Context, by By, id string, in AppInput) (Application, error) {
	in.defaults()
	cur, err := s.store.Application(ctx, s.orgID, id)
	if err != nil {
		return Application{}, err
	}
	next := cur
	in.apply(&next)
	if err := s.checkApp(ctx, next); err != nil {
		return Application{}, err
	}
	if err := s.checkBundle(ctx, &cur, next); err != nil {
		return Application{}, err
	}
	extOf, err := s.externalOf(ctx, cur.ProviderID, in.ProviderID)
	if err != nil {
		return Application{}, err
	}
	return s.store.UpdateApplication(ctx, s.orgID, id, func(a *Application) (audit.Entry, error) {
		before := appDetails(*a)
		weak := ext(extOf, a.ProviderID) && !ext(extOf, in.ProviderID)
		if weak && !by.Policy {
			return audit.Entry{}, ErrPolicyRequired
		}
		if weak {
			if err := by.confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		in.apply(a)
		a.UpdatedAt, a.UpdatedBy = s.now(), by.ref()
		return by.entry("application.update", "application", id, map[string]any{"before": before, "after": appDetails(*a),
			"weakening": weak}), nil
	})
}

// SetProtection меняет поля защиты (право applications.policy). Ослабление
// отмечается в аудите (DM-40) и требует повторной проверки (Н32).
func (s *Service) SetProtection(ctx context.Context, by By, id string, in ProtectionInput) (Application, error) {
	cur, err := s.store.Application(ctx, s.orgID, id)
	if err != nil {
		return Application{}, err
	}
	pr, err := s.protection(ctx, in, &cur.Protection)
	if err != nil {
		return Application{}, err
	}
	next := cur
	next.Protection = pr
	in.apply(&next)
	if err := s.checkApp(ctx, next); err != nil {
		return Application{}, err
	}
	if err := s.checkBundle(ctx, &cur, next); err != nil {
		return Application{}, err
	}
	// Сравнение политик — до транзакции (хранилище в памяти держит общую
	// блокировку); политику успели сменить — переход считается ослаблением.
	polWeak, err := s.weakerPolicy(ctx, cur.Policy, next.Policy)
	if err != nil {
		return Application{}, err
	}
	a, err := s.store.UpdateApplication(ctx, s.orgID, id, func(a *Application) (audit.Entry, error) {
		pr, err := s.protection(ctx, in, &a.Protection)
		if err != nil {
			return audit.Entry{}, err
		}
		before := guardOf(*a, true)
		a.Protection = pr
		in.apply(a)
		after := guardOf(*a, true)
		if guardEqual(before, after) {
			return audit.Entry{}, errUnchanged
		}
		if before.Policy != cur.Policy || after.Policy != next.Policy {
			polWeak = before.Policy != after.Policy
		}
		weak := weakening(before, after) || polWeak
		if weak {
			if err := by.confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		a.UpdatedAt, a.UpdatedBy = s.now(), by.ref()
		return by.entry("application.protection_changed", "application", id, map[string]any{
			"slug": a.Slug, "before": guardDetails(before), "after": guardDetails(after), "weakening": weak}), nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.Application(ctx, s.orgID, id)
	}
	return a, err
}

// guardEqual — поля защиты не изменились.
func guardEqual(a, b guard) bool {
	return a.Protection == b.Protection && a.FailMode == b.FailMode &&
		slices.Equal(a.Exfil, b.Exfil) && slices.EqualFunc(a.Lists, b.Lists, func(x, y List) bool {
		return x.ID == y.ID && x.Category == y.Category && x.Threat == y.Threat && x.Score == y.Score &&
			x.Direction == y.Direction && x.CaseSensitive == y.CaseSensitive &&
			slices.Equal(x.Words, y.Words) && slices.Equal(x.Regex, y.Regex)
	})
}

// ArchiveApplication переводит приложение в архив и отзывает его
// действующие ключи (ссылки из событий и аудита остаются).
func (s *Service) ArchiveApplication(ctx context.Context, by By, id string) (Application, error) {
	return s.store.ArchiveApplication(ctx, s.orgID, id, func(a *Application, active int) (audit.Entry, error) {
		now := s.now()
		a.ArchivedAt, a.UpdatedAt, a.UpdatedBy = now, now, by.ref()
		return by.entry("application.archive", "application", id, map[string]any{"slug": a.Slug, "revoked_keys": active}), nil
	})
}
