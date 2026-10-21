package authtest

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Memory — ещё и auth.RoleStore: семантика совпадает с auth.PGRoles.
var _ auth.RoleStore = (*Memory)(nil)

func (m *Memory) orgRoles(orgID string) map[auth.Role]auth.RoleDef {
	if m.roles == nil {
		m.roles = map[string]map[auth.Role]auth.RoleDef{}
	}
	if m.roles[orgID] == nil {
		m.roles[orgID] = map[auth.Role]auth.RoleDef{}
	}
	return m.roles[orgID]
}

func cloneRole(r auth.RoleDef) auth.RoleDef {
	r.Grants = r.Grants.Clone()
	if r.Grants == nil {
		r.Grants = auth.Grants{}
	}
	return r
}

// lookupRole — предустановленная или своя роль; вызывается под m.mu.
func (m *Memory) lookupRole(orgID string, id auth.Role) (auth.RoleDef, bool) {
	if r, ok := auth.LookupBuiltinRole(id); ok {
		return r, true
	}
	r, ok := m.orgRoles(orgID)[id]
	return cloneRole(r), ok
}

func (m *Memory) CustomRole(_ context.Context, orgID string, id auth.Role) (auth.RoleDef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.RoleDef{}, m.Fail
	}
	r, ok := m.orgRoles(orgID)[id]
	if !ok {
		return auth.RoleDef{}, auth.ErrRoleNotFound
	}
	return cloneRole(r), nil
}

func (m *Memory) ListCustomRoles(_ context.Context, orgID string) ([]auth.RoleDef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	out := make([]auth.RoleDef, 0, len(m.orgRoles(orgID)))
	for _, r := range m.orgRoles(orgID) {
		out = append(out, cloneRole(r))
	}
	slices.SortFunc(out, func(a, b auth.RoleDef) int { return strings.Compare(string(a.ID), string(b.ID)) })
	return out, nil
}

func (m *Memory) RoleUsers(_ context.Context, orgID string) (map[auth.Role]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	out := map[auth.Role]int{}
	for _, u := range m.users {
		if u.OrgID == orgID {
			out[u.Role]++
		}
	}
	return out, nil
}

// actor — действующий по текущим данным; вызывается под m.mu.
func (m *Memory) actor(orgID, actorID string) auth.Actor {
	u, ok := m.users[actorID]
	if !ok || u.OrgID != orgID {
		return auth.Actor{Role: auth.RoleDef{Grants: auth.Grants{}}}
	}
	r, ok := m.lookupRole(orgID, u.Role)
	if !ok {
		r = auth.RoleDef{ID: u.Role, Grants: auth.Grants{}}
	}
	return auth.Actor{Role: r, Active: u.Status == auth.StatusActive}
}

func (m *Memory) CreateRole(_ context.Context, orgID, actorID string, r auth.RoleDef, fn func(actor auth.Actor) (audit.Entry, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	rec, err := fn(m.actor(orgID, actorID))
	if err != nil {
		return err
	}
	roles := m.orgRoles(orgID)
	if len(roles) >= auth.MaxCustomRoles {
		return auth.ErrTooManyRoles
	}
	if _, ok := roles[r.ID]; ok || r.ID.Builtin() {
		return auth.ErrRoleTaken
	}
	roles[r.ID] = cloneRole(r)
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) customForChange(orgID string, id auth.Role) (auth.RoleDef, error) {
	if id.Builtin() {
		return auth.RoleDef{}, auth.ErrRoleBuiltin
	}
	r, ok := m.orgRoles(orgID)[id]
	if !ok {
		return auth.RoleDef{}, auth.ErrRoleNotFound
	}
	return cloneRole(r), nil
}

func (m *Memory) UpdateRole(_ context.Context, orgID, actorID string, id auth.Role,
	fn func(actor auth.Actor, cur auth.RoleDef) (auth.RoleDef, audit.Entry, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	actor := m.actor(orgID, actorID)
	if actor.Role.ID == id {
		_, _, err := fn(actor, auth.RoleDef{ID: id, Grants: auth.Grants{}})
		return err
	}
	cur, err := m.customForChange(orgID, id)
	if err != nil {
		return err
	}
	next, rec, err := fn(actor, cur)
	if err != nil {
		return err
	}
	next.ID, next.Builtin = id, false
	m.orgRoles(orgID)[id] = cloneRole(next)
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) DeleteRole(_ context.Context, orgID, actorID string, id auth.Role,
	fn func(actor auth.Actor, cur auth.RoleDef) (audit.Entry, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	actor := m.actor(orgID, actorID)
	if actor.Role.ID == id {
		_, err := fn(actor, auth.RoleDef{ID: id, Grants: auth.Grants{}})
		return err
	}
	cur, err := m.customForChange(orgID, id)
	if err != nil {
		return err
	}
	rec, err := fn(actor, cur)
	if err != nil {
		return err
	}
	for _, u := range m.users {
		if u.OrgID == orgID && u.Role == id {
			return auth.ErrRoleInUse
		}
	}
	delete(m.orgRoles(orgID), id)
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) AssignRole(_ context.Context, orgID, actorID, userID string, role auth.Role, now time.Time,
	fn func(actor auth.Actor, u auth.User, cur, next auth.RoleDef) (audit.Entry, error)) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return 0, m.Fail
	}
	u, ok := m.users[userID]
	if !ok || u.OrgID != orgID {
		return 0, auth.ErrNotFound
	}
	cur, ok := m.lookupRole(orgID, u.Role)
	if !ok {
		cur = auth.RoleDef{ID: u.Role, Grants: auth.Grants{}}
	}
	next, ok := m.lookupRole(orgID, role)
	if !ok {
		return 0, auth.ErrRoleNotFound
	}
	rec, err := fn(m.actor(orgID, actorID), *u, cur, next)
	if err != nil {
		return 0, err
	}
	if u.Role == auth.RoleSecurityAdmin && u.Status == auth.StatusActive && role != auth.RoleSecurityAdmin {
		n := 0
		for _, x := range m.users {
			if x.OrgID == orgID && x.Role == auth.RoleSecurityAdmin && x.Status == auth.StatusActive {
				n++
			}
		}
		if n <= 1 {
			return 0, auth.ErrLastAdmin
		}
	}
	if u.Role == role {
		return 0, nil
	}
	u.Role = role
	n := 0
	for _, s := range m.sessions {
		if s.UserID == userID && s.RevokedAt.IsZero() {
			s.RevokedAt = now
			n++
		}
	}
	auth.AddDetail(&rec, "revoked_sessions", n)
	m.records = append(m.records, rec)
	return n, nil
}
