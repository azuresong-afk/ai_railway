package versions

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов без PostgreSQL. Повторяет правила
// PGStore и триггеров миграции 0017: версии неизменяемы и идут подряд,
// политики не удаляются. Записи аудита копятся в Records.
type Memory struct {
	mu       sync.Mutex
	policies map[string]Policy    // по ID
	versions map[string][]Version // по ID политики, по возрастанию номера
	records  []audit.Entry
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{policies: map[string]Policy{}, versions: map[string][]Version{}}
}

// Records — копия записей аудита.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

func cloneVersion(v Version) Version {
	v.YAML, v.Hash = bytes.Clone(v.YAML), bytes.Clone(v.Hash)
	return v
}

func (m *Memory) find(orgID, slug string) (Policy, bool) {
	for _, p := range m.policies {
		if p.OrgID == orgID && p.Slug == slug {
			return p, true
		}
	}
	return Policy{}, false
}

// CreatePolicy — см. Store.
func (m *Memory) CreatePolicy(_ context.Context, p Policy, v Version, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.find(p.OrgID, p.Slug); ok {
		return ErrExists
	}
	if v.Version != 1 || p.Current != 1 || v.PolicyID != p.ID {
		return errSequence
	}
	m.policies[p.ID] = p
	m.versions[p.ID] = []Version{cloneVersion(v)}
	m.records = append(m.records, rec)
	return nil
}

// AddVersion — см. Store.
func (m *Memory) AddVersion(_ context.Context, orgID, slug string, base int,
	fn func(p Policy, cur Version) (Version, audit.Entry, error)) (Policy, Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.find(orgID, slug)
	if !ok {
		return Policy{}, Version{}, ErrNotFound
	}
	if p.Current != base {
		return Policy{}, Version{}, ErrConflict
	}
	vs := m.versions[p.ID]
	cur := vs[len(vs)-1]
	v, rec, err := fn(p, cloneVersion(cur))
	if err != nil {
		return Policy{}, Version{}, err
	}
	if v.Version != cur.Version+1 || v.PolicyID != p.ID {
		return Policy{}, Version{}, errSequence
	}
	spec, err := v.Spec()
	if err != nil {
		return Policy{}, Version{}, err
	}
	p.Current, p.Name, p.Mode = v.Version, spec.Name, string(spec.Mode)
	p.UpdatedAt, p.UpdatedBy = v.CreatedAt, v.CreatedBy
	m.policies[p.ID] = p
	m.versions[p.ID] = append(vs, cloneVersion(v))
	m.records = append(m.records, rec)
	return p, v, nil
}

// Policy — см. Store.
func (m *Memory) Policy(_ context.Context, orgID, slug string) (Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.find(orgID, slug)
	if !ok {
		return Policy{}, ErrNotFound
	}
	return p, nil
}

// Policies — см. Store.
func (m *Memory) Policies(_ context.Context, orgID string) ([]Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Policy
	for _, p := range m.policies {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b Policy) int { return strings.Compare(a.Slug, b.Slug) })
	if len(out) > MaxPolicies {
		out = out[:MaxPolicies]
	}
	return out, nil
}

// CountPolicies — см. Store.
func (m *Memory) CountPolicies(ctx context.Context, orgID string) (int, error) {
	ps, err := m.Policies(ctx, orgID)
	return len(ps), err
}

// Version — см. Store.
func (m *Memory) Version(_ context.Context, orgID, slug string, n int) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.find(orgID, slug)
	if !ok {
		return Version{}, ErrNotFound
	}
	if n == 0 {
		n = p.Current
	}
	vs := m.versions[p.ID]
	if n < 1 || n > len(vs) {
		return Version{}, ErrNotFound
	}
	return cloneVersion(vs[n-1]), nil
}

// Versions — см. Store.
func (m *Memory) Versions(_ context.Context, orgID, slug string, before, limit int) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.find(orgID, slug)
	if !ok {
		return nil, ErrNotFound
	}
	vs := m.versions[p.ID]
	out := []Version{}
	for i := len(vs) - 1; i >= 0 && len(out) < limit; i-- {
		if before > 0 && vs[i].Version >= before {
			continue
		}
		v := cloneVersion(vs[i])
		v.YAML = nil
		out = append(out, v)
	}
	return out, nil
}
