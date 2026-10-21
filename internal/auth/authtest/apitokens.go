package authtest

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// errDuplicateToken — как нарушение UNIQUE (prefix) или PRIMARY KEY в БД.
var errDuplicateToken = errors.New("authtest: токен с таким ID или префиксом уже есть")

// Memory — ещё и auth.APITokenStore: семантика совпадает с auth.PGAPITokens.
var _ auth.APITokenStore = (*Memory)(nil)

func cloneToken(t auth.APIToken) auth.APIToken {
	t.Hash = slices.Clone(t.Hash)
	t.Grants = t.Grants.Clone()
	return t
}

func (m *Memory) CreateAPIToken(_ context.Context, t auth.APIToken, fn func(owner auth.Actor) (audit.Entry, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if _, ok := m.users[t.UserID]; !ok {
		return auth.ErrNotFound
	}
	rec, err := fn(m.actor(t.OrgID, t.UserID))
	if err != nil {
		return err
	}
	n := 0
	for _, x := range m.tokens {
		if x.UserID == t.UserID && x.Active(t.CreatedAt) {
			n++
		}
	}
	if n >= auth.MaxAPITokensPerUser {
		return auth.ErrTooManyAPITokens
	}
	if m.tokens == nil {
		m.tokens = map[string]*auth.APIToken{}
	}
	for _, x := range m.tokens {
		if x.Prefix == t.Prefix || x.ID == t.ID {
			return errDuplicateToken
		}
	}
	c := cloneToken(t)
	m.tokens[t.ID] = &c
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) APITokenByPrefix(_ context.Context, prefix string) (auth.APIToken, auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.APIToken{}, auth.User{}, m.Fail
	}
	for _, t := range m.tokens {
		if t.Prefix == prefix {
			u, ok := m.users[t.UserID]
			if !ok {
				return auth.APIToken{}, auth.User{}, auth.ErrNotFound
			}
			return cloneToken(*t), *u, nil
		}
	}
	return auth.APIToken{}, auth.User{}, auth.ErrNotFound
}

func (m *Memory) APITokenByID(_ context.Context, orgID, id string) (auth.APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.APIToken{}, m.Fail
	}
	t, ok := m.tokens[id]
	if !ok || t.OrgID != orgID {
		return auth.APIToken{}, auth.ErrAPITokenNotFound
	}
	return cloneToken(*t), nil
}

func (m *Memory) ListAPITokens(_ context.Context, orgID, userID string, after *auth.UserCursor, limit int) ([]auth.APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	var all []auth.APIToken
	for _, t := range m.tokens {
		if t.OrgID == orgID && (userID == "" || t.UserID == userID) {
			all = append(all, cloneToken(*t))
		}
	}
	slices.SortFunc(all, func(a, b auth.APIToken) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return compareStr(a.ID, b.ID)
	})
	var out []auth.APIToken
	for _, t := range all {
		if after != nil {
			if c := t.CreatedAt.Compare(after.CreatedAt); c < 0 || (c == 0 && t.ID <= after.ID) {
				continue
			}
		}
		if len(out) == limit {
			break
		}
		out = append(out, t)
	}
	return out, nil
}

func (m *Memory) TouchAPIToken(_ context.Context, id string, now time.Time, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if t, ok := m.tokens[id]; ok && !t.Revoked() {
		t.LastUsedAt, t.LastUsedIP = now, ip
	}
	return nil
}

func (m *Memory) RevokeAPIToken(_ context.Context, orgID, id, byID string, now time.Time,
	fn func(t auth.APIToken, owner auth.User) (string, audit.Entry, error)) (auth.APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.APIToken{}, m.Fail
	}
	t, ok := m.tokens[id]
	if !ok || t.OrgID != orgID {
		return auth.APIToken{}, auth.ErrAPITokenNotFound
	}
	owner, ok := m.users[t.UserID]
	if !ok {
		return auth.APIToken{}, auth.ErrNotFound
	}
	reason, rec, err := fn(cloneToken(*t), *owner)
	if err != nil {
		return auth.APIToken{}, err
	}
	t.RevokedAt, t.RevokedBy, t.RevokeReason = now, byID, reason
	m.records = append(m.records, rec)
	return cloneToken(*t), nil
}

// ExpireAPIToken переносит срок токена в прошлое (тесты срока).
func (m *Memory) ExpireAPIToken(id string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tokens[id]; ok {
		t.ExpiresAt = at
	}
}

// SetAPITokenHash подменяет сохранённый хеш (тест сравнения хеша).
func (m *Memory) SetAPITokenHash(id string, h []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tokens[id]; ok {
		t.Hash = slices.Clone(h)
	}
}
