package compliance

import (
	"context"
	"slices"
	"sort"
	"sync"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Memory — Store в памяти для тестов сервиса и API. Повторяет правила
// PGStore: запись аудита — вместе с данными.
type Memory struct {
	mu      sync.Mutex
	marks   map[string]Mark
	records []audit.Entry
	// dbs — служебные базы (загруженная база) для тестов: Options.ServiceDBs.
	dbs *servicedb.Memory
}

// NewMemory — пустое хранилище.
func NewMemory() *Memory { return &Memory{marks: map[string]Mark{}, dbs: servicedb.NewMemory()} }

// ServiceDBs — хранилище служебных баз в памяти, парное этому.
func (m *Memory) ServiceDBs() *servicedb.Memory { return m.dbs }

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
