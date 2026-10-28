package compliance

import (
	"context"
	"slices"
	"sort"
	"sync"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов сервиса и API. Повторяет правила
// PGStore: версия базы растёт, запись аудита — вместе с данными.
type Memory struct {
	mu      sync.Mutex
	marks   map[string]Mark
	base    *StoredBase
	records []audit.Entry
}

// NewMemory — пустое хранилище.
func NewMemory() *Memory { return &Memory{marks: map[string]Mark{}} }

// Records — записи аудита.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

// Marks — см. Store.
func (m *Memory) Marks(_ context.Context, _ string) ([]Mark, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Mark, 0, len(m.marks))
	for _, v := range m.marks {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequirementID < out[j].RequirementID })
	return out, nil
}

// SetMark — см. Store.
func (m *Memory) SetMark(_ context.Context, orgID string, mk Mark, fn func(prev *Mark) audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var prev *Mark
	if p, ok := m.marks[mk.RequirementID]; ok {
		prev = &p
	}
	rec := fn(prev)
	rec.OrgID = orgID
	m.marks[mk.RequirementID] = mk
	m.records = append(m.records, rec)
	return nil
}

// ClearMark — см. Store.
func (m *Memory) ClearMark(_ context.Context, orgID, id string, fn func(prev Mark) audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.marks[id]
	if !ok {
		return ErrNoMark
	}
	rec := fn(p)
	rec.OrgID = orgID
	delete(m.marks, id)
	m.records = append(m.records, rec)
	return nil
}

// Base — см. Store.
func (m *Memory) Base(_ context.Context, _ string) (StoredBase, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.base == nil {
		return StoredBase{}, ErrNoBase
	}
	return *m.base, nil
}

// SaveBase — см. Store.
func (m *Memory) SaveBase(_ context.Context, orgID string, b StoredBase, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.base != nil && m.base.Version >= b.Version {
		return ErrStaleBase
	}
	rec.OrgID = orgID
	m.base = &b
	m.records = append(m.records, rec)
	return nil
}

// Record — см. Store.
func (m *Memory) Record(_ context.Context, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, rec)
	return nil
}
