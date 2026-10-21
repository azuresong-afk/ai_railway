package apps

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// AppInput — создание и изменение приложения. Поля защиты — отдельно
// (Protection): их меняет только обладатель права applications.policy.
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
	// FailMode, UserFrom — пусто — значение по умолчанию.
	FailMode          string
	UserFrom          string
	Quotas            Quotas
	Lists             []List
	ExfilAllowDomains []string
}

// ProtectionInput — поля защиты; пустое поле — значение по умолчанию при
// создании и прежнее значение при изменении.
type ProtectionInput struct {
	Policy     string
	PolicyMode string
	Storage    string
}

func (in *AppInput) defaults() {
	if in.FailMode == "" {
		in.FailMode = DefaultFailMode
	}
	if in.UserFrom == "" {
		in.UserFrom = DefaultUserFrom
	}
	if in.Aliases == nil {
		in.Aliases = map[string]string{}
	}
}

func (s *Service) checkApp(ctx context.Context, in AppInput) error {
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
	p := config.AppParams{Env: in.Env, FailMode: in.FailMode, Storage: DefaultStorage, UserFrom: in.UserFrom,
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
	out := Protection(in)
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

// weakening — изменение полей защиты ослабляет её (DM-40): перевод в
// monitor, режим хранения none или full, «Только мониторинг».
func weakening(before, after Protection) bool {
	return (before.PolicyMode == ModeEnforce && after.PolicyMode == ModeMonitor) ||
		(after.Storage != before.Storage && (after.Storage == "none" || after.Storage == "full")) ||
		(after.Policy != before.Policy && after.Policy == monitorOnlyPolicy)
}

func protectionDetails(p Protection) map[string]any {
	return map[string]any{"policy": p.Policy, "policy_mode": p.PolicyMode, "storage": p.Storage}
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
	a.Env, a.ProviderID, a.FailMode, a.UserFrom = in.Env, in.ProviderID, in.FailMode, in.UserFrom
	a.Models, a.Aliases = slices.Clone(in.Models), maps.Clone(in.Aliases)
	a.Quotas, a.Lists, a.ExfilAllowDomains = in.Quotas, slices.Clone(in.Lists), slices.Clone(in.ExfilAllowDomains)
	if a.Lists == nil {
		a.Lists = []List{}
	}
	if a.ExfilAllowDomains == nil {
		a.ExfilAllowDomains = []string{}
	}
}

// CreateApplication создаёт приложение. prot — nil, если у создающего нет
// права applications.policy: поля защиты получают умолчания.
func (s *Service) CreateApplication(ctx context.Context, by By, in AppInput, prot *ProtectionInput) (Application, error) {
	in.defaults()
	var errs []error
	if !config.ValidID(in.Slug) {
		errs = append(errs, errors.New("slug — строчные латинские буквы, цифры и дефис, до 63 символов"))
	}
	if err := s.checkApp(ctx, in); err != nil {
		var ie *InputError
		if !errors.As(err, &ie) {
			return Application{}, err
		}
		errs = append(errs, ie.Errs...)
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
	}
	if len(errs) > 0 {
		return Application{}, invalid(errs...)
	}
	id, err := s.newID()
	if err != nil {
		return Application{}, err
	}
	now := s.now()
	a := Application{ID: id, OrgID: s.orgID, Slug: in.Slug, Protection: pr,
		CreatedAt: now, CreatedBy: by.ref(), UpdatedAt: now, UpdatedBy: by.ref()}
	in.apply(&a)
	d := appDetails(a)
	d["weakening"] = pr.Storage == "none" || pr.Storage == "full"
	if err := s.store.CreateApplication(ctx, a, by.entry("application.create", "application", id, d)); err != nil {
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

// UpdateApplication меняет приложение, кроме slug и полей защиты.
func (s *Service) UpdateApplication(ctx context.Context, by By, id string, in AppInput) (Application, error) {
	in.defaults()
	if err := s.checkApp(ctx, in); err != nil {
		return Application{}, err
	}
	return s.store.UpdateApplication(ctx, s.orgID, id, func(a *Application) (audit.Entry, error) {
		before := appDetails(*a)
		in.apply(a)
		a.UpdatedAt, a.UpdatedBy = s.now(), by.ref()
		return by.entry("application.update", "application", id, map[string]any{"before": before, "after": appDetails(*a)}), nil
	})
}

// SetProtection меняет политику, режим и режим хранения (право
// applications.policy). Ослабление защиты отмечается в аудите (DM-40).
func (s *Service) SetProtection(ctx context.Context, by By, id string, in ProtectionInput) (Application, error) {
	cur, err := s.store.Application(ctx, s.orgID, id)
	if err != nil {
		return Application{}, err
	}
	if _, err := s.protection(ctx, in, &cur.Protection); err != nil {
		return Application{}, err
	}
	a, err := s.store.UpdateApplication(ctx, s.orgID, id, func(a *Application) (audit.Entry, error) {
		pr, err := s.protection(ctx, in, &a.Protection)
		if err != nil {
			return audit.Entry{}, err
		}
		before := a.Protection
		if pr == before {
			return audit.Entry{}, errUnchanged
		}
		a.Protection = pr
		a.UpdatedAt, a.UpdatedBy = s.now(), by.ref()
		return by.entry("application.protection_changed", "application", id, map[string]any{
			"slug": a.Slug, "before": protectionDetails(before), "after": protectionDetails(pr), "weakening": weakening(before, pr)}), nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.Application(ctx, s.orgID, id)
	}
	return a, err
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
