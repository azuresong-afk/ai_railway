package apps

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Пользователь приложения по JWT корпоративного IdP и доступ к моделям по
// группам (ТЗ 4.3, 7.3 УПД.9, 5.16 DM-33; ADR-0025, раздел 4; задача 4.21
// этапа 4, миграция 0057_app_user_access). Одна запись на приложение; нет
// записи — прежнее поведение (режим off).
//
// Изменение — действие администратора с правом applications.policy и
// записью аудита той же транзакцией. Смягчение режима (required →
// optional → off), смена издателя, аудитории или утверждения с группами,
// рост допуска часов и расширение доступа к моделям — ослабление защиты:
// повторная проверка субъекта и признак weakening в аудите (DM-40).

// Режимы пользователя приложения.
const (
	// UserTokenOff — JWT не проверяется: пользователь по user_from
	// (X-AISec-User или поле user), как до задачи 4.21.
	UserTokenOff = "off"
	// UserTokenOptional — JWT, если он есть; иначе пользователь по user_from.
	UserTokenOptional = bundle.UserTokenOptional
	// UserTokenRequired — без действительного JWT запрос отклоняется 401.
	UserTokenRequired = bundle.UserTokenRequired
)

// Значения по умолчанию и пределы.
const (
	DefaultGroupsClaim = "groups"
	DefaultLeeway      = 60
	// MaxModelGroupEntries — пар «модель — группа» в настройке приложения.
	MaxModelGroupEntries = 500
)

// UserAccess — настройка пользователя приложения.
type UserAccess struct {
	AppID       string
	OrgID       string
	Mode        string
	Issuer      string
	Audience    string
	GroupsClaim string
	// Leeway — допуск часов для exp, nbf и iat, секунд.
	Leeway int
	// ModelGroups — модель или псевдоним → группы, которым она доступна.
	ModelGroups map[string][]string
	// Configured — запись есть (иначе значения по умолчанию).
	Configured bool
	UpdatedAt  time.Time
	UpdatedBy  string
}

// DefaultUserAccess — настройка приложения без записи.
func DefaultUserAccess(appID, orgID string) UserAccess {
	return UserAccess{AppID: appID, OrgID: orgID, Mode: UserTokenOff, GroupsClaim: DefaultGroupsClaim, Leeway: DefaultLeeway,
		ModelGroups: map[string][]string{}}
}

// UserAccessInput — новая настройка целиком.
type UserAccessInput struct {
	Mode        string
	Issuer      string
	Audience    string
	GroupsClaim string
	Leeway      *int
	ModelGroups map[string][]string
}

// userModeRank — сила режима: понижение — ослабление.
func userModeRank(mode string) int {
	switch mode {
	case UserTokenOptional:
		return 1
	case UserTokenRequired:
		return 2
	}
	return 0
}

// clean проверяет ввод и приводит его к записи: группы без повторов и по
// возрастанию, модели — из моделей и псевдонимов приложения a.
func (in UserAccessInput) clean(a Application) (UserAccess, error) {
	out := UserAccess{Mode: in.Mode, Issuer: strings.TrimSpace(in.Issuer), Audience: strings.TrimSpace(in.Audience),
		GroupsClaim: strings.TrimSpace(in.GroupsClaim), Leeway: DefaultLeeway, ModelGroups: map[string][]string{}}
	if out.GroupsClaim == "" {
		out.GroupsClaim = DefaultGroupsClaim
	}
	if in.Leeway != nil {
		out.Leeway = *in.Leeway
	}
	var errs []error
	if out.Mode != UserTokenOff && out.Mode != UserTokenOptional && out.Mode != UserTokenRequired {
		errs = append(errs, errors.New("mode — off (только X-AISec-User), optional (JWT или X-AISec-User) или required (JWT обязателен)"))
	}
	jwt := out.Mode == UserTokenOptional || out.Mode == UserTokenRequired
	switch {
	case jwt && out.Issuer == "":
		errs = append(errs, errors.New("issuer — адрес издателя JWT обязателен"))
	case out.Issuer != "":
		if err := bundle.CheckIssuer(out.Issuer); err != nil {
			errs = append(errs, fmt.Errorf("issuer — %w", err))
		}
	}
	switch {
	case jwt && out.Audience == "":
		errs = append(errs, errors.New("audience — аудитория JWT обязательна"))
	case len(out.Audience) > bundle.MaxAudienceLen || strings.ContainsFunc(out.Audience, func(r rune) bool { return r <= ' ' || r > '~' }):
		errs = append(errs, fmt.Errorf("audience — до %d печатных символов ASCII без пробелов", bundle.MaxAudienceLen))
	}
	if !bundle.ClaimName(out.GroupsClaim) {
		errs = append(errs, fmt.Errorf("groups_claim — до %d символов A–Z, a–z, 0–9 и _-.:/", bundle.MaxClaimNameLen))
	}
	if out.Leeway < 0 || out.Leeway > bundle.MaxUserTokenLeeway {
		errs = append(errs, fmt.Errorf("leeway — от 0 до %d секунд", bundle.MaxUserTokenLeeway))
	}
	if len(in.ModelGroups) > 0 && !jwt {
		errs = append(errs, errors.New("model_groups — доступ по группам работает только с JWT: выберите режим optional или required"))
	}
	entries := 0
	for m, groups := range in.ModelGroups {
		_, alias := a.Aliases[m]
		if !alias && !slices.Contains(a.Models, m) {
			errs = append(errs, fmt.Errorf("model_groups — %q не модель и не псевдоним приложения", clipName(m)))
			continue
		}
		set := map[string]bool{}
		for _, g := range groups {
			g = strings.TrimSpace(g)
			if !bundle.ValidGroup(g) {
				errs = append(errs, fmt.Errorf("model_groups[%s] — группа от 1 до %d байт без управляющих символов", clipName(m), bundle.MaxGroupLen))
				break
			}
			set[g] = true
		}
		if len(set) == 0 || len(set) > bundle.MaxGroupsPerModel {
			errs = append(errs, fmt.Errorf("model_groups[%s] — от 1 до %d групп", clipName(m), bundle.MaxGroupsPerModel))
			continue
		}
		entries += len(set)
		out.ModelGroups[m] = slices.Sorted(maps.Keys(set))
	}
	if entries > MaxModelGroupEntries {
		errs = append(errs, fmt.Errorf("model_groups — не больше %d пар «модель — группа»", MaxModelGroupEntries))
	}
	if len(errs) > 0 {
		return UserAccess{}, invalid(errs...)
	}
	return out, nil
}

func clipName(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// SetUserAccess задаёт режим пользователя и доступ к моделям по группам
// (право applications.policy). Ослабление требует повторной проверки.
func (s *Service) SetUserAccess(ctx context.Context, by By, appID string, in UserAccessInput) (UserAccess, error) {
	return s.store.SetUserAccess(ctx, s.orgID, appID, func(a Application, prev UserAccess) (UserAccess, audit.Entry, error) {
		if a.Archived() {
			return UserAccess{}, audit.Entry{}, ErrArchived
		}
		next, err := in.clean(a)
		if err != nil {
			return UserAccess{}, audit.Entry{}, err
		}
		next.AppID, next.OrgID, next.Configured = a.ID, s.orgID, true
		next.UpdatedAt, next.UpdatedBy = s.now(), by.ref()
		if prev.Configured && sameUserAccess(prev, next) {
			return UserAccess{}, audit.Entry{}, errUnchanged
		}
		reasons := userAccessWeakened(a, prev, next)
		if len(reasons) > 0 {
			if err := by.confirm(ctx); err != nil {
				return UserAccess{}, audit.Entry{}, err
			}
		}
		d := map[string]any{"slug": a.Slug, "before": userAccessDetails(prev), "after": userAccessDetails(next),
			"weakening": len(reasons) > 0}
		if len(reasons) > 0 {
			d["weakening_reasons"] = reasons
		}
		return next, by.entry("application.user_access_set", "application", a.ID, d), nil
	})
}

// UserAccess — настройка приложения (нет записи — DefaultUserAccess).
func (s *Service) UserAccess(ctx context.Context, appID string) (UserAccess, error) {
	return s.store.UserAccess(ctx, s.orgID, appID)
}

// UserAccessList — записи организации для пакета конфигурации.
func (s *Service) UserAccessList(ctx context.Context) ([]UserAccess, error) {
	return s.store.UserAccessList(ctx, s.orgID)
}

func sameUserAccess(a, b UserAccess) bool {
	return a.Mode == b.Mode && a.Issuer == b.Issuer && a.Audience == b.Audience && a.GroupsClaim == b.GroupsClaim &&
		a.Leeway == b.Leeway && maps.EqualFunc(a.ModelGroups, b.ModelGroups, slices.Equal)
}

// userAccessWeakened — причины ослабления (DM-40). Пока JWT не
// проверялся (off), смена издателя и прочего ослаблением не считается.
// Группы моделей, которых у приложения a уже нет, не учитываются: они не
// действуют, и их пропажа доступ не расширяет.
func userAccessWeakened(a Application, prev, next UserAccess) []any {
	var out []any
	if userModeRank(next.Mode) < userModeRank(prev.Mode) {
		out = append(out, "user_token_mode")
	}
	if prev.Mode == UserTokenOff || next.Mode == UserTokenOff {
		return out
	}
	if prev.Issuer != next.Issuer || prev.Audience != next.Audience {
		out = append(out, "user_token_trust")
	}
	if prev.GroupsClaim != next.GroupsClaim {
		out = append(out, "user_token_groups_claim")
	}
	if next.Leeway > prev.Leeway {
		out = append(out, "user_token_leeway")
	}
	// Модель без ограничения или с новой группой — доступ шире.
	for m, before := range prev.ModelGroups {
		if _, alias := a.Aliases[m]; !alias && !slices.Contains(a.Models, m) {
			continue
		}
		after, ok := next.ModelGroups[m]
		if !ok || slices.ContainsFunc(after, func(g string) bool { return !slices.Contains(before, g) }) {
			out = append(out, "model_groups")
			break
		}
	}
	return out
}

// userAccessDetails — подробности записи аудита.
func userAccessDetails(u UserAccess) map[string]any {
	if !u.Configured {
		return map[string]any{"mode": UserTokenOff}
	}
	return map[string]any{"mode": u.Mode, "issuer": u.Issuer, "audience": u.Audience, "groups_claim": u.GroupsClaim,
		"leeway": u.Leeway, "model_groups": u.ModelGroups}
}

func cloneUserAccess(u UserAccess) UserAccess {
	mg := make(map[string][]string, len(u.ModelGroups))
	for k, v := range u.ModelGroups {
		mg[k] = slices.Clone(v)
	}
	u.ModelGroups = mg
	return u
}

// SetUserAccess — см. Store.
func (m *Memory) SetUserAccess(_ context.Context, orgID, appID string,
	fn func(a Application, prev UserAccess) (UserAccess, audit.Entry, error)) (UserAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.apps[appID]
	if !ok || a.OrgID != orgID {
		return UserAccess{}, ErrNotFound
	}
	prev, ok := m.userAccess[appID]
	if !ok {
		prev = DefaultUserAccess(appID, orgID)
	}
	next, rec, err := fn(cloneApp(a), cloneUserAccess(prev))
	if errors.Is(err, errUnchanged) {
		return cloneUserAccess(prev), nil
	}
	if err != nil {
		return UserAccess{}, err
	}
	m.userAccess[appID] = cloneUserAccess(next)
	m.records = append(m.records, rec)
	return next, nil
}

// UserAccess — см. Store.
func (m *Memory) UserAccess(_ context.Context, orgID, appID string) (UserAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.apps[appID]; !ok || a.OrgID != orgID {
		return UserAccess{}, ErrNotFound
	}
	if u, ok := m.userAccess[appID]; ok {
		return cloneUserAccess(u), nil
	}
	return DefaultUserAccess(appID, orgID), nil
}

// UserAccessList — см. Store.
func (m *Memory) UserAccessList(_ context.Context, orgID string) ([]UserAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []UserAccess
	for _, u := range m.userAccess {
		if u.OrgID == orgID {
			out = append(out, cloneUserAccess(u))
		}
	}
	slices.SortFunc(out, func(a, b UserAccess) int { return strings.Compare(a.AppID, b.AppID) })
	return out, nil
}
