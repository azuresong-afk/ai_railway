// Пакет authtest — хранилище учётных записей в памяти для тестов: логика
// входа и обработчики API проверяются без PostgreSQL (в том числе в CI).
// В рабочие бинарники не входит: его импортируют только тесты.
package authtest

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Memory — auth.Store и auth.Auditor в памяти. Семантика методов совпадает с
// auth.PGStore; записи аудита копятся в Records.
type Memory struct {
	mu       sync.Mutex
	policy   map[string]auth.Policy
	users    map[string]*auth.User
	history  map[string][]string // новые первыми
	sessions map[string]*auth.Session
	records  []audit.Entry
	setup    []*setupToken
	// Fail — если не nil, возвращается из каждого метода (сбой хранилища).
	Fail error
}

type setupToken struct {
	id, orgID, alg string
	hash           []byte
	expires        time.Time
	used           bool
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{
		policy: map[string]auth.Policy{}, users: map[string]*auth.User{},
		history: map[string][]string{}, sessions: map[string]*auth.Session{},
	}
}

var _ auth.Store = (*Memory)(nil)

// Records — копия записей аудита.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

// Actions — коды действий записей аудита по порядку.
func (m *Memory) Actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.records))
	for i, r := range m.records {
		out[i] = r.Action
	}
	return out
}

// Record — auth.Auditor.
func (m *Memory) Record(_ context.Context, e audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.records = append(m.records, e)
	return nil
}

func (m *Memory) Policy(_ context.Context, orgID string) (auth.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.Policy{}, m.Fail
	}
	if p, ok := m.policy[orgID]; ok {
		return p, nil
	}
	return auth.DefaultPolicy(), nil
}

func (m *Memory) SetPolicy(_ context.Context, orgID string, p auth.Policy, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.policy[orgID] = p
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) HasUsers(_ context.Context, orgID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.OrgID == orgID {
			return true, m.Fail
		}
	}
	return false, m.Fail
}

func (m *Memory) UserByLogin(_ context.Context, orgID, login string) (auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.User{}, m.Fail
	}
	for _, u := range m.users {
		if u.OrgID == orgID && u.Login == login {
			return *u, nil
		}
	}
	return auth.User{}, auth.ErrNotFound
}

func (m *Memory) UserByID(_ context.Context, orgID, id string) (auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.User{}, m.Fail
	}
	if u, ok := m.users[id]; ok && u.OrgID == orgID {
		return *u, nil
	}
	return auth.User{}, auth.ErrNotFound
}

func (m *Memory) ListUsers(_ context.Context, orgID string, after *auth.UserCursor, limit int) ([]auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	var all []auth.User
	for _, u := range m.users {
		if u.OrgID == orgID {
			all = append(all, *u)
		}
	}
	slices.SortFunc(all, func(a, b auth.User) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return compareStr(a.ID, b.ID)
	})
	var out []auth.User
	for _, u := range all {
		if after != nil {
			if c := u.CreatedAt.Compare(after.CreatedAt); c < 0 || (c == 0 && u.ID <= after.ID) {
				continue
			}
		}
		if len(out) == limit {
			break
		}
		out = append(out, u)
	}
	return out, nil
}

func compareStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (m *Memory) CreateUser(_ context.Context, u auth.User, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, x := range m.users {
		if x.OrgID == u.OrgID && x.Login == u.Login {
			return auth.ErrLoginTaken
		}
	}
	m.users[u.ID] = &u
	m.records = append(m.records, rec)
	return nil
}

// AddUser кладёт запись напрямую, без аудита (подготовка теста).
func (m *Memory) AddUser(u auth.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.ID] = &u
}

// AddSetupToken кладёт токен первичной настройки (как aisec-cli init).
func (m *Memory) AddSetupToken(orgID, hashAlg string, hash []byte, expires time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := "setup-" + strconv.Itoa(len(m.setup)+1)
	m.setup = append(m.setup, &setupToken{id: id, orgID: orgID, alg: hashAlg, hash: bytes.Clone(hash), expires: expires})
}

func (m *Memory) SetupFirstUser(_ context.Context, tokenHash []byte, hashAlg string, u auth.User, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, x := range m.users {
		if x.OrgID == u.OrgID {
			return auth.ErrSetupUnavailable
		}
	}
	for _, t := range m.setup {
		if t.orgID == u.OrgID && t.alg == hashAlg && bytes.Equal(t.hash, tokenHash) && !t.used && u.CreatedAt.Before(t.expires) {
			t.used = true
			auth.AddDetail(&rec, "setup_record_id", t.id)
			m.users[u.ID] = &u
			m.records = append(m.records, rec)
			return nil
		}
	}
	return auth.ErrSetupUnavailable
}

func (m *Memory) RecordFailure(_ context.Context, userID string, now time.Time, threshold int, lockUntil time.Time,
	recs func(attempts int, lockedNow bool) []audit.Entry) (int, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return 0, false, m.Fail
	}
	u, ok := m.users[userID]
	if !ok {
		return 0, false, auth.ErrNotFound
	}
	if !u.LockedAt.IsZero() && !u.LockedUntil.IsZero() && !now.Before(u.LockedUntil) {
		u.FailedAttempts, u.LockedAt, u.LockedUntil = 0, time.Time{}, time.Time{}
	}
	u.FailedAttempts++
	locked := false
	if u.LockedAt.IsZero() && u.FailedAttempts >= threshold {
		locked = true
		u.LockedAt, u.LockedUntil = now, lockUntil
	}
	if recs != nil {
		m.records = append(m.records, recs(u.FailedAttempts, locked)...)
	}
	return u.FailedAttempts, locked, nil
}

func (m *Memory) PasswordHistory(_ context.Context, userID string, n int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	h := m.history[userID]
	return slices.Clone(h[:min(n, len(h))]), nil
}

func (m *Memory) SetPassword(_ context.Context, ch auth.PasswordChange, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	u, ok := m.users[ch.UserID]
	if !ok {
		return auth.ErrNotFound
	}
	if ch.RequireActive && u.Status != auth.StatusActive {
		return auth.ErrDeactivated
	}
	if ch.ExpectHash != "" && ch.ExpectHash != u.PasswordHash {
		return auth.ErrWrongPassword
	}
	if ch.KeepSession != "" {
		if s, ok := m.sessions[ch.KeepSession]; !ok || s.UserID != ch.UserID || !s.RevokedAt.IsZero() {
			return auth.ErrUnauthenticated
		}
	}
	h := m.history[ch.UserID]
	if ch.Keep > 0 {
		h = append([]string{u.PasswordHash}, h...)
	}
	m.history[ch.UserID] = h[:min(ch.Keep, len(h))]
	u.PasswordHash, u.PasswordChangedAt, u.MustChangePassword = ch.NewHash, ch.Now, ch.Temporary
	u.TempPasswordExpires = time.Time{}
	if ch.Temporary {
		u.TempPasswordExpires = ch.TempExpires
	}
	if ch.Unlock {
		u.FailedAttempts, u.LockedAt, u.LockedUntil = 0, time.Time{}, time.Time{}
	}
	for _, s := range m.sessions {
		if s.UserID != ch.UserID || !s.RevokedAt.IsZero() {
			continue
		}
		if s.ID == ch.KeepSession {
			s.State = auth.SessionActive
			continue
		}
		s.RevokedAt = ch.Now
	}
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) SetStatus(_ context.Context, orgID, userID string, st auth.Status, now time.Time, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	u, ok := m.users[userID]
	if !ok || u.OrgID != orgID {
		return auth.ErrNotFound
	}
	auth.AddDetail(&rec, "previous_status", string(u.Status))
	if st == auth.StatusDeactivated {
		if u.Role == auth.RoleSecurityAdmin && u.Status == auth.StatusActive {
			n := 0
			for _, x := range m.users {
				if x.OrgID == orgID && x.Role == auth.RoleSecurityAdmin && x.Status == auth.StatusActive {
					n++
				}
			}
			if n <= 1 {
				return auth.ErrLastAdmin
			}
		}
		u.Status, u.DeactivatedAt = st, now
		for _, s := range m.sessions {
			if s.UserID == userID && s.RevokedAt.IsZero() {
				s.RevokedAt = now
			}
		}
	} else {
		u.Status, u.DeactivatedAt = st, time.Time{}
		u.FailedAttempts, u.LockedAt, u.LockedUntil = 0, time.Time{}, time.Time{}
	}
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) activeSessions(userID string) []*auth.Session {
	var out []*auth.Session
	for _, s := range m.sessions {
		if s.UserID == userID && s.RevokedAt.IsZero() {
			out = append(out, s)
		}
	}
	// Новые первыми.
	slices.SortFunc(out, func(a, b *auth.Session) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return compareStr(b.ID, a.ID)
	})
	return out
}

func (m *Memory) CreateSession(_ context.Context, s auth.Session, limit int, login *auth.LoginCheck, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	u, ok := m.users[s.UserID]
	if !ok {
		return auth.ErrNotFound
	}
	if login != nil {
		if !u.LockedAt.IsZero() && (u.LockedUntil.IsZero() || login.Now.Before(u.LockedUntil)) {
			return auth.ErrLocked
		}
		if u.Status != auth.StatusActive || u.PasswordHash != login.VerifiedHash {
			return auth.ErrInvalidCredentials
		}
		u.FailedAttempts, u.LockedAt, u.LockedUntil, u.LastLoginAt = 0, time.Time{}, time.Time{}, login.Now
		if login.Rehash != "" {
			u.PasswordHash = login.Rehash
		}
	}
	m.sessions[s.ID] = &s
	var evicted []string
	for i, x := range m.activeSessions(s.UserID) {
		if i >= limit {
			x.RevokedAt = s.CreatedAt
			evicted = append(evicted, x.ID)
		}
	}
	if len(evicted) > 0 {
		auth.AddDetail(&rec, "evicted_sessions", evicted)
	}
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) SessionByToken(_ context.Context, tokenHash []byte) (auth.Session, auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return auth.Session{}, auth.User{}, m.Fail
	}
	for _, s := range m.sessions {
		if bytes.Equal(s.TokenHash, tokenHash) && s.RevokedAt.IsZero() {
			return *s, *m.users[s.UserID], nil
		}
	}
	return auth.Session{}, auth.User{}, auth.ErrNotFound
}

func (m *Memory) TouchSession(_ context.Context, id string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok && s.RevokedAt.IsZero() && s.LastSeenAt.Before(now) {
		s.LastSeenAt = now
	}
	return m.Fail
}

func (m *Memory) SetSessionState(_ context.Context, id string, st auth.SessionState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok && s.RevokedAt.IsZero() {
		s.State = st
	}
	return m.Fail
}

func (m *Memory) RevokeSession(_ context.Context, id, _ string, now time.Time, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if s, ok := m.sessions[id]; ok && s.RevokedAt.IsZero() {
		s.RevokedAt = now
		m.records = append(m.records, rec)
	}
	return nil
}

func (m *Memory) RevokeUserSessions(_ context.Context, userID, _ string, now time.Time, rec audit.Entry) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return 0, m.Fail
	}
	n := 0
	for _, s := range m.activeSessions(userID) {
		s.RevokedAt = now
		n++
	}
	m.records = append(m.records, rec)
	return n, nil
}

func (m *Memory) ListSessions(_ context.Context, userID string) ([]auth.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	var out []auth.Session
	for _, s := range m.activeSessions(userID) {
		out = append(out, *s)
	}
	return out, nil
}
