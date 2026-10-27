package authtest

import (
	"bytes"
	"context"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Настройки IdP и внешние учётные записи в памяти (ADR-0025). Семантика —
// как у auth.PGStore (idp_pg.go).

type oidcLogin struct {
	orgID   string
	hash    []byte
	expires time.Time
}

func cloneIdP(st auth.IdPSettings) auth.IdPSettings {
	st.Scopes = slices.Clone(st.Scopes)
	st.RequiredACR = slices.Clone(st.RequiredACR)
	st.RequiredAMR = slices.Clone(st.RequiredAMR)
	st.GroupRoles = slices.Clone(st.GroupRoles)
	st.Secret = bytes.Clone(st.Secret)
	return st
}

func (m *Memory) IdPSettings(_ context.Context, orgID string) (auth.IdPSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.IdPSettings{}, m.Fail
	}
	st, ok := m.idp[orgID]
	if !ok {
		return auth.IdPSettings{}, auth.ErrIdPNotConfigured
	}
	return cloneIdP(st), nil
}

func (m *Memory) SaveIdPSettings(_ context.Context, orgID string, st auth.IdPSettings, now time.Time, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, g := range st.GroupRoles {
		if _, ok := m.lookupRole(orgID, g.Role); !ok {
			return auth.ErrRoleNotFound
		}
	}
	st = cloneIdP(st)
	st.Version = m.idp[orgID].Version + 1
	st.UpdatedAt = now
	slices.SortFunc(st.GroupRoles, func(a, b auth.GroupRole) int { return compareStr(a.Group, b.Group) })
	m.idp[orgID] = st
	m.revokeExternal(orgID, now, &rec)
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) DeleteIdPSettings(_ context.Context, orgID string, now time.Time, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if _, ok := m.idp[orgID]; !ok {
		return auth.ErrIdPNotConfigured
	}
	delete(m.idp, orgID)
	m.revokeExternal(orgID, now, &rec)
	m.records = append(m.records, rec)
	return nil
}

// revokeExternal завершает сессии внешних пользователей организации.
func (m *Memory) revokeExternal(orgID string, now time.Time, rec *audit.Entry) {
	n := 0
	for _, s := range m.sessions {
		u, ok := m.users[s.UserID]
		if ok && u.OrgID == orgID && u.External() && s.RevokedAt.IsZero() {
			s.RevokedAt = now
			n++
		}
	}
	auth.AddDetail(rec, "revoked_sessions", int64(n))
}

func (m *Memory) StartOIDCLogin(_ context.Context, orgID string, idHash []byte, now, expires time.Time, maxPending int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.logins = slices.DeleteFunc(m.logins, func(l oidcLogin) bool { return l.orgID == orgID && !now.Before(l.expires) })
	n := 0
	for _, l := range m.logins {
		if l.orgID == orgID {
			n++
		}
	}
	if n >= maxPending {
		return auth.ErrTooManyLogins
	}
	m.logins = append(m.logins, oidcLogin{orgID: orgID, hash: bytes.Clone(idHash), expires: expires})
	return nil
}

func (m *Memory) TakeOIDCLogin(_ context.Context, orgID string, idHash []byte, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	i := slices.IndexFunc(m.logins, func(l oidcLogin) bool { return l.orgID == orgID && bytes.Equal(l.hash, idHash) })
	if i < 0 {
		return auth.ErrNotFound
	}
	l := m.logins[i]
	m.logins = slices.Delete(m.logins, i, i+1)
	if !now.Before(l.expires) {
		return auth.ErrNotFound
	}
	return nil
}

// PendingOIDCLogins — число незавершённых входов через IdP.
func (m *Memory) PendingOIDCLogins() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.logins)
}

func (m *Memory) byIdentity(orgID, issuer, subject string) *auth.User {
	for _, u := range m.users {
		if u.OrgID == orgID && u.External() && u.IdPIssuer == issuer && u.IdPSubject == subject {
			return u
		}
	}
	return nil
}

func (m *Memory) UserByIdentity(_ context.Context, orgID, issuer, subject string) (auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.User{}, m.Fail
	}
	u := m.byIdentity(orgID, issuer, subject)
	if u == nil {
		return auth.User{}, auth.ErrNotFound
	}
	return *u, nil
}

func (m *Memory) ExternalLogin(_ context.Context, in auth.ExternalLoginTx) (auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.User{}, m.Fail
	}
	if st, ok := m.idp[in.OrgID]; !ok || !st.Enabled || st.Version != in.SettingsVersion {
		return auth.User{}, auth.ErrIdPChanged
	}
	if _, ok := m.lookupRole(in.OrgID, in.Role); !ok {
		return auth.User{}, auth.ErrRoleNotFound
	}
	u := m.byIdentity(in.OrgID, in.Issuer, in.Subject)
	created := false
	prev := in.Role
	if u == nil {
		login := in.FallbackLogin
		if in.Login != "" && !m.loginTaken(in.OrgID, in.Login) {
			login = in.Login
		}
		if m.loginTaken(in.OrgID, login) {
			return auth.User{}, auth.ErrLoginTaken
		}
		u = &auth.User{ID: in.NewUserID, OrgID: in.OrgID, Login: login, DisplayName: in.DisplayName, Role: in.Role,
			Status: auth.StatusActive, PasswordHash: "!external", PasswordChangedAt: in.Now, CreatedAt: in.Now,
			CreatedBy: "oidc", Source: in.Source, IdPIssuer: in.Issuer, IdPSubject: in.Subject}
		m.users[u.ID] = u
		created = true
	} else {
		if u.Status != auth.StatusActive {
			return auth.User{}, auth.ErrDeactivated
		}
		prev = u.Role
		if u.Role != in.Role {
			if u.Role == auth.RoleSecurityAdmin && m.activeAdmins(in.OrgID) <= 1 {
				return auth.User{}, auth.ErrLastAdmin
			}
			u.Role = in.Role
			for _, s := range m.sessions {
				if s.UserID == u.ID && s.RevokedAt.IsZero() {
					s.RevokedAt = in.Now
				}
			}
		}
	}
	u.LastLoginAt = in.Now
	se := in.Session
	se.UserID = u.ID
	m.sessions[se.ID] = &se
	recs := in.Records(*u, created, prev)
	if len(recs) > 0 {
		m.evict(u.ID, se.State, se.CreatedAt, in.SessionLimit, &recs[len(recs)-1])
	}
	m.records = append(m.records, recs...)
	return *u, nil
}

func (m *Memory) loginTaken(orgID, login string) bool {
	for _, u := range m.users {
		if u.OrgID == orgID && u.Login == login {
			return true
		}
	}
	return false
}

func (m *Memory) activeAdmins(orgID string) int {
	n := 0
	for _, u := range m.users {
		if u.OrgID == orgID && u.Role == auth.RoleSecurityAdmin && u.Status == auth.StatusActive {
			n++
		}
	}
	return n
}

var _ auth.IdPStore = (*Memory)(nil)
