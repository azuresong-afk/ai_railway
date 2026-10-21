package auth

import (
	"maps"
	"slices"
	"strings"
)

// Разрешения эндпоинтов консоли (УПД.1, 3). Новое разрешение добавляется
// константой, строкой в permissionCatalog и, если нужно, в права
// предустановленных ролей (builtinRoles); в api/openapi.yaml эндпоинт
// ссылается на него через x-permission.
const (
	// PermSession — любая сессия, в том числе до второго фактора: свои
	// данные, выход и второй фактор (ИАФ.5). Состояние сессии проверяет
	// обработчик. В роль не назначается: его даёт SessionGrants.
	PermSession = "session"
	// PermSelf — смена своего пароля: есть у любой роли, но не до второго
	// фактора. В роль не назначается: его даёт SessionGrants.
	PermSelf       = "self"
	PermSystemRead = "system.read"
	// PermIntegrityVerify — проверка целостности по команде (ОЦЛ.2, задача
	// 2.17): при -integrity-action stop нарушение останавливает сервер.
	PermIntegrityVerify  = "integrity.verify"
	PermUsersRead        = "users.read"
	PermUsersManage      = "users.manage"
	PermSessionsRead     = "sessions.read"
	PermSessionsManage   = "sessions.manage"
	PermAuthPolicyRead   = "auth_policy.read"
	PermAuthPolicyManage = "auth_policy.manage"
	PermRolesRead        = "roles.read"
	PermRolesManage      = "roles.manage"
	// PermAPITokensRead и PermAPITokensManage — токены API (ИАФ.9, задача
	// 2.10). Со ScopeOwn — только свои токены (УПД.8). Самому токену не
	// выдаются (TokenGrantable).
	PermAPITokensRead   = "api_tokens.read"
	PermAPITokensManage = "api_tokens.manage"
)

// Permission — разрешение из каталога.
type Permission struct {
	Name  string
	Title string // описание для консоли
	Group string // раздел консоли
	// Security — управление функциями безопасности (учётные записи, роли,
	// вход). Администратору системы такие разрешения не выдаются (УПД.2).
	Security bool
	// Ownable — разрешение может выдаваться только на свои объекты
	// (ScopeOwn, УПД.8). Эндпоинт с таким разрешением сам отбирает объекты.
	Ownable bool
}

// ReadOnly — разрешение только на чтение (имя оканчивается на «.read»).
func (p Permission) ReadOnly() bool { return strings.HasSuffix(p.Name, ".read") }

// TokenGrantable — разрешение можно выдать токену API (решение владельца
// по задаче 2.10): кроме функций безопасности и самих токенов. Управление
// доступом остаётся за человеком с паролем и вторым фактором; токен не
// выпускает и не продлевает токены.
func TokenGrantable(perm string) bool {
	p, ok := LookupPermission(perm)
	return ok && !p.Security && !strings.HasPrefix(p.Name, "api_tokens.")
}

var permissionCatalog = []Permission{
	{Name: PermSystemRead, Title: "Просмотр состояния и версии системы", Group: "Система"},
	{Name: PermIntegrityVerify, Title: "Запуск проверки целостности", Group: "Система", Security: true},
	{Name: PermUsersRead, Title: "Просмотр учётных записей", Group: "Пользователи"},
	{Name: PermUsersManage, Title: "Создание, деактивация и сброс пароля учётных записей", Group: "Пользователи", Security: true},
	{Name: PermSessionsRead, Title: "Просмотр сессий пользователей", Group: "Пользователи"},
	{Name: PermSessionsManage, Title: "Принудительное завершение сессий", Group: "Пользователи", Security: true},
	{Name: PermAuthPolicyRead, Title: "Просмотр парольной политики и настроек входа", Group: "Вход"},
	{Name: PermAuthPolicyManage, Title: "Изменение парольной политики и настроек входа", Group: "Вход", Security: true},
	{Name: PermRolesRead, Title: "Просмотр ролей и разрешений", Group: "Роли"},
	{Name: PermRolesManage, Title: "Создание, изменение и удаление ролей, назначение ролей", Group: "Роли", Security: true},
	{Name: PermAPITokensRead, Title: "Просмотр токенов API", Group: "Токены API", Ownable: true},
	{Name: PermAPITokensManage, Title: "Выпуск и отзыв токенов API", Group: "Токены API", Ownable: true},
}

var permissionIndex = func() map[string]Permission {
	m := make(map[string]Permission, len(permissionCatalog))
	for _, p := range permissionCatalog {
		if _, dup := m[p.Name]; dup || p.Name == PermSelf || p.Name == PermSession || !validPermissionName(p.Name) {
			panic("auth: неверное или повторное разрешение в каталоге: " + p.Name)
		}
		m[p.Name] = p
	}
	return m
}()

// Permissions — каталог разрешений в порядке объявления.
func Permissions() []Permission { return slices.Clone(permissionCatalog) }

// LookupPermission — разрешение каталога по имени.
func LookupPermission(name string) (Permission, bool) {
	p, ok := permissionIndex[name]
	return p, ok
}

// validPermissionName — «раздел.действие»: латиница в нижнем регистре, цифры, «_».
func validPermissionName(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	dot := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c == '_', c >= '0' && c <= '9' && i > 0:
		case c == '.' && i > 0 && i < len(s)-1 && !dot:
			dot = true
		default:
			return false
		}
	}
	return dot
}

// Scope — область действия разрешения (УПД.8).
type Scope uint8

// Области. Нулевое значение — разрешения нет.
const (
	ScopeNone Scope = iota
	// ScopeOwn — только свои объекты (например, приложения владельца).
	ScopeOwn
	// ScopeAll — все объекты организации.
	ScopeAll
)

// String — имя области в API и БД.
func (s Scope) String() string {
	switch s {
	case ScopeOwn:
		return "own"
	case ScopeAll:
		return "all"
	}
	return "none"
}

// ParseScope разбирает имя области; ok = false — неизвестное имя.
func ParseScope(s string) (Scope, bool) {
	switch s {
	case "own":
		return ScopeOwn, true
	case "all":
		return ScopeAll, true
	}
	return ScopeNone, false
}

// Grants — права: разрешение → область. В правах роли только разрешения
// каталога; PermSelf и PermSession добавляет SessionGrants по состоянию сессии.
type Grants map[string]Scope

// Scope — область разрешения perm; ScopeNone — разрешения нет.
func (g Grants) Scope(perm string) Scope { return g[perm] }

// Allows — есть ли разрешение perm с любой областью.
func (g Grants) Allows(perm string) bool { return g.Scope(perm) != ScopeNone }

// Full — есть ли разрешение perm на все объекты.
func (g Grants) Full(perm string) bool { return g.Scope(perm) == ScopeAll }

// Covers — каждое разрешение o есть в g с той же или более широкой
// областью: обладатель g не повышает свои права, выдавая o (УПД.2).
func (g Grants) Covers(o Grants) bool {
	for p, s := range o {
		if s != ScopeNone && g.Scope(p) < s {
			return false
		}
	}
	return true
}

// Names — имена разрешений по алфавиту.
func (g Grants) Names() []string {
	out := []string{}
	for p, s := range g {
		if s != ScopeNone {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// Clone — независимая копия.
func (g Grants) Clone() Grants { return maps.Clone(g) }

func grantAll(perms ...string) Grants {
	g := make(Grants, len(perms))
	for _, p := range perms {
		g[p] = ScopeAll
	}
	return g
}

// allPermissions — все разрешения каталога на все объекты.
func allPermissions() Grants {
	g := make(Grants, len(permissionCatalog))
	for _, p := range permissionCatalog {
		g[p.Name] = ScopeAll
	}
	return g
}

// readPermissions — все разрешения каталога только на чтение.
func readPermissions() Grants {
	g := Grants{}
	for _, p := range permissionCatalog {
		if p.ReadOnly() {
			g[p.Name] = ScopeAll
		}
	}
	return g
}

// builtinRoles — права предустановленных ролей задаются кодом и
// обновляются вместе с продуктом; изменить их из консоли нельзя (УПД.1).
// Администратор безопасности управляет пользователями, ролями и входом;
// администратор системы не меняет политики безопасности и выпускает
// только свои токены API; аудитор только читает (УПД.2). Разрешения следующих задач (приложения, политики,
// события) добавляются сюда вместе с эндпоинтами.
var builtinRoles = []RoleDef{
	{ID: RoleSecurityAdmin, DisplayName: "Администратор безопасности", Builtin: true, MFARequired: true,
		Description: "Политики, правила оповещений, доступ к содержимому событий, пользователи и роли",
		Grants:      allPermissions()},
	{ID: RoleSystemAdmin, DisplayName: "Администратор системы", Builtin: true, MFARequired: true,
		Description: "Приложения, провайдеры, интеграции, обновления, резервное копирование. Политики безопасности не меняет",
		Grants:      Grants{PermSystemRead: ScopeAll, PermAPITokensRead: ScopeOwn, PermAPITokensManage: ScopeOwn}},
	{ID: RoleAnalyst, DisplayName: "Аналитик", Builtin: true,
		Description: "Разбор оповещений и инцидентов, поиск по событиям",
		Grants:      grantAll(PermSystemRead)},
	{ID: RoleAuditor, DisplayName: "Аудитор", Builtin: true,
		Description: "Только просмотр: журнал аудита, отчёты, состояние соответствия. Ничего не меняет",
		Grants:      readPermissions()},
	{ID: RoleAppOwner, DisplayName: "Владелец приложения", Builtin: true,
		Description: "Статистика и события только своих приложений, без доступа к содержимому",
		Grants:      Grants{}},
}

var builtinIndex = func() map[Role]RoleDef {
	m := make(map[Role]RoleDef, len(builtinRoles))
	for _, r := range builtinRoles {
		m[r.ID] = r
	}
	return m
}()

// BuiltinRoles — предустановленные роли (копии).
func BuiltinRoles() []RoleDef {
	out := make([]RoleDef, len(builtinRoles))
	for i, r := range builtinRoles {
		out[i] = r.clone()
	}
	return out
}

// Builtin — роль из числа предустановленных.
func (r Role) Builtin() bool {
	_, ok := builtinIndex[r]
	return ok
}
