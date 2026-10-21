package auth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Ролевая модель (УПД.1–3, 8; задача 2.9). Предустановленные роли и их
// права заданы кодом (permissions.go), свои роли — в БД (RoleStore). У
// пользователя одна роль; права роли проверяются на каждом запросе, кэша
// нет: изменение своей роли действует сразу.

// Ошибки ролей.
var (
	ErrRoleNotFound = errors.New("роль не найдена")
	ErrRoleTaken    = errors.New("ID роли уже занят")
	// ErrRoleInUse — у роли есть пользователи (в том числе деактивированные).
	ErrRoleInUse = errors.New("роль назначена пользователям")
	// ErrRoleBuiltin — предустановленную роль нельзя изменить или удалить.
	ErrRoleBuiltin = errors.New("предустановленная роль не изменяется")
	// ErrOwnRole — свою роль нельзя изменить, удалить или сменить (УПД.2).
	ErrOwnRole = errors.New("действие над своей ролью запрещено")
	// ErrEscalation — действие дало бы права, которых нет у самого
	// пользователя, или затрагивает учётную запись с большими правами (УПД.2).
	ErrEscalation = errors.New("действие повысило бы права")
	// ErrTooManyRoles — достигнут предел числа своих ролей.
	ErrTooManyRoles = errors.New("слишком много своих ролей")
	// ErrRoleChanged — роль пользователя сменилась после проверки прав.
	ErrRoleChanged = errors.New("роль пользователя изменилась")
)

// Пределы ролей; те же — в CHECK миграции.
const (
	MaxRoleIDLen          = 48
	MaxRoleDescriptionLen = 500
	// MaxCustomRoles — предел своих ролей в организации.
	MaxCustomRoles = 100
)

// RoleDef — роль с правами.
type RoleDef struct {
	ID          Role
	DisplayName string
	Description string
	Builtin     bool
	// MFARequired — пользователю с этой ролью обязателен второй фактор
	// (ИАФ.5, задача 2.8). Своя роль с правом на изменение получает его
	// принудительно.
	MFARequired bool
	Grants      Grants
	CreatedAt   time.Time
	CreatedBy   string
	UpdatedAt   time.Time
}

func (r RoleDef) clone() RoleDef {
	r.Grants = r.Grants.Clone()
	if r.Grants == nil {
		r.Grants = Grants{}
	}
	return r
}

// LookupBuiltinRole — предустановленная роль по ID.
func LookupBuiltinRole(id Role) (RoleDef, bool) {
	r, ok := builtinIndex[id]
	if !ok {
		return RoleDef{}, false
	}
	return r.clone(), true
}

// RoleStore — хранилище своих ролей и назначений. Рабочая реализация —
// PGRoles; для тестов без PostgreSQL — authtest.Memory. Предустановленные
// роли в хранилище есть только строками для ссылок из users.role: их права
// хранилище берёт из LookupBuiltinRole.
//
// Изменяющие методы получают ID действующего пользователя и в той же
// транзакции перечитывают его роль и статус (Actor): проверка разделения
// обязанностей идёт по правам на момент записи, а не на начало запроса.
type RoleStore interface {
	// CustomRole — своя роль с правами; нет — ErrRoleNotFound.
	CustomRole(ctx context.Context, orgID string, id Role) (RoleDef, error)
	// ListCustomRoles — свои роли организации по ID.
	ListCustomRoles(ctx context.Context, orgID string) ([]RoleDef, error)
	// RoleUsers — число учётных записей (включая деактивированные) по ролям.
	RoleUsers(ctx context.Context, orgID string) (map[Role]int, error)
	// CreateRole передаёт в fn действующего и сохраняет свою роль с записью
	// аудита от fn. Занятый ID — ErrRoleTaken, предел MaxCustomRoles —
	// ErrTooManyRoles.
	CreateRole(ctx context.Context, orgID, actorID string, r RoleDef, fn func(actor Actor) (audit.Entry, error)) error
	// UpdateRole блокирует свою роль и передаёт её в fn вместе с
	// действующим; fn возвращает новое определение и запись аудита или
	// ошибку отказа. Предустановленная роль — ErrRoleBuiltin, нет роли —
	// ErrRoleNotFound.
	UpdateRole(ctx context.Context, orgID, actorID string, id Role,
		fn func(actor Actor, cur RoleDef) (RoleDef, audit.Entry, error)) error
	// DeleteRole блокирует свою роль, передаёт её в fn и удаляет вместе с
	// записью аудита от fn. Роль с пользователями — ErrRoleInUse.
	DeleteRole(ctx context.Context, orgID, actorID string, id Role, fn func(actor Actor, cur RoleDef) (audit.Entry, error)) error
	// AssignRole назначает роль пользователю. В одной транзакции блокирует
	// строки активных администраторов безопасности, затем действующего и
	// пользователя (по ID), затем роли; передаёт в fn действующего,
	// пользователя, его текущую и новую роль (fn проверяет права и
	// возвращает запись аудита), меняет роль и завершает все сессии
	// пользователя (RevokeAdmin). Снятие роли администратора безопасности с
	// последнего активного — ErrLastAdmin; нет пользователя — ErrNotFound,
	// нет роли — ErrRoleNotFound.
	AssignRole(ctx context.Context, orgID, actorID, userID string, role Role, now time.Time,
		fn func(actor Actor, u User, cur, next RoleDef) (audit.Entry, error)) (revoked int, err error)
}

// Actor — действующий пользователь, перечитанный в транзакции изменения.
type Actor struct {
	// Role — его роль сейчас; неизвестная роль — без прав.
	Role RoleDef
	// Active — учётная запись есть и активна.
	Active bool
}

// WithRoleStore подключает свои роли. Без него действуют только
// предустановленные роли, а у пользователя со своей ролью нет прав.
func WithRoleStore(rs RoleStore) Option { return func(s *Service) { s.roles = rs } }

// RoleDef — роль организации: предустановленная или своя.
func (s *Service) RoleDef(ctx context.Context, id Role) (RoleDef, error) {
	if r, ok := LookupBuiltinRole(id); ok {
		return r, nil
	}
	if s.roles == nil || !id.Valid() {
		return RoleDef{}, ErrRoleNotFound
	}
	return s.roles.CustomRole(ctx, s.orgID, id)
}

// Grants — права роли; неизвестная роль — пустой набор.
func (s *Service) Grants(ctx context.Context, id Role) (Grants, error) {
	r, err := s.RoleDef(ctx, id)
	if errors.Is(err, ErrRoleNotFound) {
		return Grants{}, nil
	}
	if err != nil {
		return nil, err
	}
	return r.Grants, nil
}

// CallerGrants — права, действующие в сессии c (SessionGrants).
func (s *Service) CallerGrants(ctx context.Context, c Caller) (Grants, error) {
	g, err := s.Grants(ctx, c.User.Role)
	if err != nil {
		return nil, err
	}
	return SessionGrants(c, g), nil
}

// RoleRequiresMFA — обязателен ли второй фактор для роли (ИАФ.5).
// Неизвестная роль — обязателен: при сомнении требование строже.
func (s *Service) RoleRequiresMFA(ctx context.Context, id Role) (bool, error) {
	r, err := s.RoleDef(ctx, id)
	if errors.Is(err, ErrRoleNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return r.MFARequired, nil
}

// RoleSummary — роль в списке с числом пользователей.
type RoleSummary struct {
	RoleDef
	Users int
}

// Roles — предустановленные и свои роли с числом пользователей.
func (s *Service) Roles(ctx context.Context) ([]RoleSummary, error) {
	defs := BuiltinRoles()
	counts := map[Role]int{}
	if s.roles != nil {
		custom, err := s.roles.ListCustomRoles(ctx, s.orgID)
		if err != nil {
			return nil, err
		}
		defs = append(defs, custom...)
		if counts, err = s.roles.RoleUsers(ctx, s.orgID); err != nil {
			return nil, err
		}
	}
	out := make([]RoleSummary, len(defs))
	for i, d := range defs {
		out[i] = RoleSummary{RoleDef: d, Users: counts[d.ID]}
	}
	return out, nil
}

// GrantInput — разрешение в запросе на создание или изменение роли.
type GrantInput struct {
	Permission string
	Scope      string // all или own; пусто — all
}

// RoleInput — данные своей роли.
type RoleInput struct {
	ID          string // только при создании
	DisplayName string
	Description string
	MFARequired bool
	Permissions []GrantInput
}

const (
	roleIDRule      = "ID роли: от 3 до 48 символов — латинские буквы в нижнем регистре, цифры и «_»; начинается с буквы."
	roleNameRule    = "Название: от 1 до 200 символов без управляющих символов."
	roleDescRule    = "Описание: до 500 символов без управляющих символов."
	rolePermsPrefix = "Разрешения: "
)

// parseRole проверяет данные своей роли и собирает определение. Право на
// изменение (не «.read») включает обязательный второй фактор.
func parseRole(in RoleInput) (RoleDef, error) {
	name, ok := CleanDisplayName(in.DisplayName)
	if !ok {
		return RoleDef{}, &InputError{"display_name", roleNameRule}
	}
	desc, ok := cleanDescription(in.Description)
	if !ok {
		return RoleDef{}, &InputError{"description", roleDescRule}
	}
	if len(in.Permissions) > len(permissionCatalog) {
		return RoleDef{}, &InputError{"permissions", rolePermsPrefix + "повторяются."}
	}
	g := make(Grants, len(in.Permissions))
	mfa := in.MFARequired
	for _, gi := range in.Permissions {
		p, ok := LookupPermission(gi.Permission)
		if !ok {
			return RoleDef{}, &InputError{"permissions", rolePermsPrefix + "неизвестное разрешение."}
		}
		scope := ScopeAll
		if gi.Scope != "" {
			if scope, ok = ParseScope(gi.Scope); !ok {
				return RoleDef{}, &InputError{"permissions", rolePermsPrefix + "область — all или own."}
			}
		}
		if scope == ScopeOwn && !p.Ownable {
			return RoleDef{}, &InputError{"permissions", rolePermsPrefix + "«" + p.Name + "» выдаётся только на все объекты."}
		}
		if _, dup := g[p.Name]; dup {
			return RoleDef{}, &InputError{"permissions", rolePermsPrefix + "повторяются."}
		}
		g[p.Name] = scope
		// Второй фактор — у ролей, которые что-то меняют или читают данные
		// безопасности (содержимое событий, УПД.7).
		mfa = mfa || !p.ReadOnly() || p.Security
	}
	return RoleDef{DisplayName: name, Description: desc, MFARequired: mfa, Grants: g}, nil
}

// cleanDescription — как CleanDisplayName, но допускает пустую строку и до 500 символов.
func cleanDescription(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxRoleDescriptionLen {
		return "", false
	}
	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return "", false
		}
	}
	return s, true
}

func roleObject(id Role) audit.Object { return audit.Object{Type: "role", ID: string(id)} }

// roleDetails — роль для подробностей аудита (значения до и после, РСБ.1).
func roleDetails(r RoleDef) map[string]any {
	perms := make([]string, 0, len(r.Grants))
	for _, p := range r.Grants.Names() {
		perms = append(perms, p+":"+r.Grants.Scope(p).String())
	}
	return map[string]any{"display_name": r.DisplayName, "description": r.Description,
		"mfa_required": r.MFARequired, "permissions": perms}
}

// denied пишет в аудит отказ по разделению обязанностей и возвращает err.
func (s *Service) denied(ctx context.Context, by Caller, action string, obj audit.Object, err error) error {
	reason := "escalation"
	switch {
	case errors.Is(err, ErrOwnRole):
		reason = "own_role"
	case errors.Is(err, ErrSelf):
		reason = "self"
	}
	if aerr := s.audit.Record(ctx, s.entry(by.actor(), by.SourceIP, action, obj, audit.ResultDenied,
		map[string]any{"reason": reason})); aerr != nil {
		return aerr
	}
	return err
}

// canManage — пользователь by может управлять учётной записью с ролью
// target: её права входят в его права (УПД.2). Иначе держатель
// users.manage сбросил бы пароль более сильной учётной записи и вошёл под
// ней. Отказ пишется в аудит действием action.
func (s *Service) canManage(ctx context.Context, by Caller, target Role, action string, obj audit.Object) error {
	mine, err := s.CallerGrants(ctx, by)
	if err != nil {
		return err
	}
	tg, err := s.Grants(ctx, target)
	if err != nil {
		return err
	}
	if !mine.Covers(tg) {
		return s.denied(ctx, by, action, obj, ErrEscalation)
	}
	return nil
}

// actorGrants — права действующего по данным транзакции (роль и статус на
// момент записи), ограниченные состоянием его сессии. ok — учётная запись
// активна и у неё всё ещё есть roles.manage, по которому пропущен запрос.
func actorGrants(by Caller, a Actor) (g Grants, ok bool) {
	if !a.Active {
		return Grants{}, false
	}
	g = SessionGrants(by, a.Role.Grants)
	return g, g.Full(PermRolesManage)
}

// CreateRole создаёт свою роль (УПД.1). Выдать можно только разрешения,
// которые есть у самого пользователя (УПД.2).
func (s *Service) CreateRole(ctx context.Context, by Caller, in RoleInput) (RoleDef, error) {
	id := Role(in.ID)
	if !id.Valid() {
		return RoleDef{}, &InputError{"id", roleIDRule}
	}
	if id.Builtin() {
		return RoleDef{}, ErrRoleTaken
	}
	r, err := parseRole(in)
	if err != nil {
		return RoleDef{}, err
	}
	if s.roles == nil {
		return RoleDef{}, errors.New("роли: хранилище не подключено")
	}
	now := s.clock()
	r.ID, r.CreatedAt, r.UpdatedAt, r.CreatedBy = id, now, now, by.User.ID
	var deny error
	err = s.roles.CreateRole(ctx, s.orgID, by.User.ID, r, func(a Actor) (audit.Entry, error) {
		if mine, ok := actorGrants(by, a); !ok || !mine.Covers(r.Grants) {
			deny = ErrEscalation
			return audit.Entry{}, deny
		}
		return s.entry(by.actor(), by.SourceIP, "role.create", roleObject(id), audit.ResultSuccess,
			map[string]any{"after": roleDetails(r)}), nil
	})
	if deny != nil {
		return RoleDef{}, s.denied(ctx, by, "role.create", roleObject(id), deny)
	}
	if err != nil {
		return RoleDef{}, err
	}
	return r, nil
}

// UpdateRole меняет название, описание и разрешения своей роли. Свою
// роль (которую носит сам) менять нельзя; новые и прежние разрешения роли
// должны входить в права пользователя: нельзя ни выдать недостающее, ни
// отнять права у роли сильнее своей (УПД.2).
func (s *Service) UpdateRole(ctx context.Context, by Caller, id Role, in RoleInput) (RoleDef, error) {
	if id.Builtin() {
		return RoleDef{}, ErrRoleBuiltin
	}
	if !id.Valid() || s.roles == nil {
		return RoleDef{}, ErrRoleNotFound
	}
	next, err := parseRole(in)
	if err != nil {
		return RoleDef{}, err
	}
	if by.User.Role == id {
		return RoleDef{}, s.denied(ctx, by, "role.update", roleObject(id), ErrOwnRole)
	}
	var (
		out  RoleDef
		deny error
	)
	err = s.roles.UpdateRole(ctx, s.orgID, by.User.ID, id, func(a Actor, cur RoleDef) (RoleDef, audit.Entry, error) {
		mine, ok := actorGrants(by, a)
		switch {
		case a.Role.ID == id:
			deny = ErrOwnRole
		case !ok || !mine.Covers(next.Grants) || !mine.Covers(cur.Grants):
			deny = ErrEscalation
		}
		if deny != nil {
			return RoleDef{}, audit.Entry{}, deny
		}
		out = next
		out.ID, out.CreatedAt, out.CreatedBy, out.UpdatedAt = cur.ID, cur.CreatedAt, cur.CreatedBy, s.clock()
		rec := s.entry(by.actor(), by.SourceIP, "role.update", roleObject(id), audit.ResultSuccess,
			map[string]any{"before": roleDetails(cur), "after": roleDetails(out)})
		return out, rec, nil
	})
	if deny != nil {
		return RoleDef{}, s.denied(ctx, by, "role.update", roleObject(id), deny)
	}
	if err != nil {
		return RoleDef{}, err
	}
	return out, nil
}

// DeleteRole удаляет свою роль без пользователей. Удалить роль сильнее
// своей или свою нельзя (УПД.2).
func (s *Service) DeleteRole(ctx context.Context, by Caller, id Role) error {
	if id.Builtin() {
		return ErrRoleBuiltin
	}
	if !id.Valid() || s.roles == nil {
		return ErrRoleNotFound
	}
	if by.User.Role == id {
		return s.denied(ctx, by, "role.delete", roleObject(id), ErrOwnRole)
	}
	var deny error
	err := s.roles.DeleteRole(ctx, s.orgID, by.User.ID, id, func(a Actor, cur RoleDef) (audit.Entry, error) {
		mine, ok := actorGrants(by, a)
		switch {
		case a.Role.ID == id:
			deny = ErrOwnRole
		case !ok || !mine.Covers(cur.Grants):
			deny = ErrEscalation
		}
		if deny != nil {
			return audit.Entry{}, deny
		}
		return s.entry(by.actor(), by.SourceIP, "role.delete", roleObject(id), audit.ResultSuccess,
			map[string]any{"before": roleDetails(cur)}), nil
	})
	if deny != nil {
		return s.denied(ctx, by, "role.delete", roleObject(id), deny)
	}
	return err
}

// AssignRole назначает роль пользователю и завершает все его сессии: новые
// права и требование второго фактора действуют со следующего входа. Свою
// роль сменить нельзя; права текущей и новой роли пользователя должны
// входить в права назначающего (УПД.2). Возвращает число завершённых сессий.
func (s *Service) AssignRole(ctx context.Context, by Caller, userID string, role Role) (int, error) {
	obj := userObject(userID)
	if by.User.ID == userID {
		return 0, s.denied(ctx, by, "user.role_changed", obj, ErrSelf)
	}
	if !role.Valid() {
		return 0, ErrRoleNotFound
	}
	if s.roles == nil {
		return 0, errors.New("роли: хранилище не подключено")
	}
	var deny error
	n, err := s.roles.AssignRole(ctx, s.orgID, by.User.ID, userID, role, s.clock(),
		func(a Actor, u User, cur, next RoleDef) (audit.Entry, error) {
			mine, ok := actorGrants(by, a)
			if !ok || !mine.Covers(cur.Grants) || !mine.Covers(next.Grants) {
				deny = ErrEscalation
				return audit.Entry{}, deny
			}
			return s.entry(by.actor(), by.SourceIP, "user.role_changed", obj, audit.ResultSuccess,
				map[string]any{"before": string(cur.ID), "after": string(next.ID)}), nil
		})
	if deny != nil {
		return 0, s.denied(ctx, by, "user.role_changed", obj, deny)
	}
	return n, err
}

// AccessDenied пишет в аудит отказ в доступе к эндпоинту (УПД.6, DM-39):
// кто, откуда, метод, шаблон пути, требуемое разрешение и причина.
func (s *Service) AccessDenied(ctx context.Context, by Caller, method, path, permission, reason string) error {
	return s.audit.Record(ctx, s.entry(by.actor(), by.SourceIP, "access.denied", audit.Object{}, audit.ResultDenied,
		map[string]any{"method": method, "path": path, "permission": permission, "reason": reason}))
}

// SortRoles упорядочивает роли: предустановленные в порядке каталога, затем свои по ID.
func SortRoles(rs []RoleSummary) {
	order := func(r RoleSummary) int {
		if i := slices.IndexFunc(builtinRoles, func(b RoleDef) bool { return b.ID == r.ID }); i >= 0 {
			return i
		}
		return len(builtinRoles)
	}
	slices.SortStableFunc(rs, func(a, b RoleSummary) int {
		if c := order(a) - order(b); c != 0 {
			return c
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
}
