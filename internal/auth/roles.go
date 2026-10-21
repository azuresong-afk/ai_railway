package auth

import "context"

// Allowed — может ли сессия caller с правами роли g выполнить действие с
// правом perm (любая область).
func Allowed(c Caller, g Grants, perm string) bool {
	return SessionGrants(c, g).Allows(perm)
}

// SessionGrants — права, действующие в сессии caller. PermSession есть у
// любой сессии, в том числе до второго фактора; PermSelf — у сессии с
// подтверждённым входом, включая временный или истёкший пароль; права
// роли g — только у SessionActive.
func SessionGrants(c Caller, g Grants) Grants {
	switch c.Session.State {
	case SessionActive:
		out := g.Clone()
		if out == nil {
			out = Grants{}
		}
		out[PermSelf], out[PermSession] = ScopeAll, ScopeAll
		return out
	case SessionPasswordChange:
		return Grants{PermSelf: ScopeAll, PermSession: ScopeAll}
	default:
		return Grants{PermSession: ScopeAll}
	}
}

// mfaRequired — обязателен ли второй фактор пользователю u при политике p
// (ИАФ.5): политика требует его от всех или роль требует его сама
// (RoleRequiresMFA; у security_admin и system_admin — всегда).
func (s *Service) mfaRequired(ctx context.Context, u User, p Policy) (bool, error) {
	if p.MFARequiredAll {
		return true, nil
	}
	return s.RoleRequiresMFA(ctx, u.Role)
}
