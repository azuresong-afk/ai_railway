package auth

// Разрешения эндпоинтов консоли. Полный набор и свои роли (УПД.1–3, 8) —
// задача 2.9; до неё права предустановленных ролей заданы таблицей ниже.
const (
	// PermSession — любая сессия, в том числе до второго фактора: свои
	// данные, выход и второй фактор (ИАФ.5). Состояние сессии проверяет обработчик.
	PermSession = "session"
	// PermSelf — смена своего пароля: есть у любой роли, но не до второго фактора.
	PermSelf             = "self"
	PermSystemRead       = "system.read"
	PermUsersRead        = "users.read"
	PermUsersManage      = "users.manage"
	PermSessionsRead     = "sessions.read"
	PermSessionsManage   = "sessions.manage"
	PermAuthPolicyRead   = "auth_policy.read"
	PermAuthPolicyManage = "auth_policy.manage"
)

// rolePermissions — права предустановленных ролей (ТЗ, 1.3). Управляет
// пользователями администратор безопасности; аудитор только читает
// (УПД.2); администратор системы политики безопасности не меняет.
var rolePermissions = map[Role]map[string]bool{
	RoleSecurityAdmin: set(PermSelf, PermSystemRead, PermUsersRead, PermUsersManage,
		PermSessionsRead, PermSessionsManage, PermAuthPolicyRead, PermAuthPolicyManage),
	RoleSystemAdmin: set(PermSelf, PermSystemRead),
	RoleAnalyst:     set(PermSelf, PermSystemRead),
	RoleAuditor:     set(PermSelf, PermSystemRead, PermUsersRead, PermSessionsRead, PermAuthPolicyRead),
	RoleAppOwner:    set(PermSelf),
}

func set(perms ...string) map[string]bool {
	m := make(map[string]bool, len(perms))
	for _, p := range perms {
		m[p] = true
	}
	return m
}

// Allowed — может ли сессия caller выполнить действие с правом perm.
// Сессия со временным или истёкшим паролем получает только PermSelf и
// PermSession, сессия до второго фактора — только PermSession.
func Allowed(c Caller, perm string) bool {
	if perm == PermSession {
		return true
	}
	switch c.Session.State {
	case SessionActive:
		return rolePermissions[c.User.Role][perm]
	case SessionPasswordChange:
		return perm == PermSelf
	default:
		return false
	}
}

// mfaRoles — роли, которым второй фактор обязателен всегда (ИАФ.5): они
// управляют учётными записями, политиками или системой. В задаче 2.9 признак
// переходит в модель ролей (RoleRequiresMFA).
var mfaRoles = map[Role]bool{RoleSecurityAdmin: true, RoleSystemAdmin: true}

// MFARequired — обязателен ли второй фактор пользователю при политике p.
func MFARequired(u User, p Policy) bool {
	return p.MFARequiredAll || mfaRoles[u.Role]
}
