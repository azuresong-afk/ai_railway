package license

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов и сервера без БД.
type Memory struct {
	mu      sync.Mutex
	list    map[string][]Stored
	clock   map[string]time.Time
	Records []audit.Entry
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{list: map[string][]Stored{}, clock: map[string]time.Time{}}
}

// Current — см. Store.
func (m *Memory) Current(_ context.Context, orgID string) (Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.list[orgID]
	if len(l) == 0 {
		return Stored{}, ErrNoLicense
	}
	s := l[len(l)-1]
	s.File = slices.Clone(s.File)
	return s, nil
}

// Save — см. Store.
func (m *Memory) Save(_ context.Context, orgID string, s Stored, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l := m.list[orgID]; len(l) > 0 && l[len(l)-1].Number >= s.Number {
		return ErrStale
	}
	s.File = slices.Clone(s.File)
	m.list[orgID] = append(m.list[orgID], s)
	rec.OrgID = orgID
	m.Records = append(m.Records, rec)
	return nil
}

// Record — см. Store.
func (m *Memory) Record(_ context.Context, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Records = append(m.Records, rec)
	return nil
}

// AdvanceClock — см. Store.
func (m *Memory) AdvanceClock(_ context.Context, orgID string, t time.Time) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.After(m.clock[orgID]) {
		m.clock[orgID] = t.UTC()
	}
	return m.clock[orgID], nil
}

// Replace подменяет файл загруженной лицензии (тесты: изменённая запись в БД).
func (m *Memory) Replace(orgID string, file []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l := m.list[orgID]; len(l) > 0 {
		l[len(l)-1].File = slices.Clone(file)
	}
}
