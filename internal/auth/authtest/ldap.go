package authtest

import (
	"bytes"
	"context"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Настройки каталога LDAP в памяти (ADR-0025, 2). Семантика — как у
// auth.PGStore (ldap_pg.go).

func cloneLDAP(st auth.LDAPSettings) auth.LDAPSettings {
	st.GroupRoles = slices.Clone(st.GroupRoles)
	st.Secret = bytes.Clone(st.Secret)
	return st
}

func (m *Memory) LDAPSettings(_ context.Context, orgID string) (auth.LDAPSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.LDAPSettings{}, m.Fail
	}
	st, ok := m.ldap[orgID]
	if !ok {
		return auth.LDAPSettings{}, auth.ErrLDAPNotConfigured
	}
	return cloneLDAP(st), nil
}

func (m *Memory) SaveLDAPSettings(_ context.Context, orgID string, st auth.LDAPSettings, now time.Time, rec audit.Entry) error {
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
	st = cloneLDAP(st)
	st.Version = m.ldap[orgID].Version + 1
	st.UpdatedAt = now
	slices.SortFunc(st.GroupRoles, func(a, b auth.GroupRole) int { return compareStr(a.Group, b.Group) })
	m.ldap[orgID] = st
	m.revokeExternal(orgID, auth.SourceLDAP, now, &rec)
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) DeleteLDAPSettings(_ context.Context, orgID string, now time.Time, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if _, ok := m.ldap[orgID]; !ok {
		return auth.ErrLDAPNotConfigured
	}
	delete(m.ldap, orgID)
	m.revokeExternal(orgID, auth.SourceLDAP, now, &rec)
	m.records = append(m.records, rec)
	return nil
}

var _ auth.LDAPStore = (*Memory)(nil)
