package auth

// Разрешения эндпоинтов консоли. Полный набор и свои роли (УПД.1–3, 8) —
// задача 2.9; до неё права предустановленных ролей заданы таблицей ниже.
const (
	// PermSelf — свои данные, смена своего пароля и выход: есть у любой роли.
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
// Сессия со временным или истёкшим паролем получает только PermSelf.
func Allowed(c Caller, perm string) bool {
	if c.Session.State != SessionActive {
		return perm == PermSelf
	}
	return rolePermissions[c.User.Role][perm]
}
