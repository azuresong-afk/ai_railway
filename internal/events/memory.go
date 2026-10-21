package events

import (
	"context"
	"sync"
	"time"
)

// Memory — Store в памяти для тестов без PostgreSQL: та же идемпотентность
// по ID, без шифрования (содержимое хранится как есть).
type Memory struct {
	mu     sync.Mutex
	events map[string]Stored
	stats  map[string]SenderStats
	// Err — ошибка, которую вернёт следующий Insert (проверка отказа БД).
	Err error
	// Чтение для API (задача 2.16): сроки хранения, сохранённые фильтры.
	retention Retention
	filters   map[string][]SavedFilter
	nextID    int
	auditFn   MemoryAudit
	// ReadErr — ошибка, которую вернут методы чтения (проверка отказа БД).
	ReadErr error
}

// Stored — событие в Memory и шлюз, от которого оно принято.
type Stored struct {
	GatewayID  string
	ReceivedAt time.Time
	Event      Event
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{
		events: map[string]Stored{}, stats: map[string]SenderStats{},
		retention: Retention{MetadataDays: 365, ContentDays: 90}, filters: map[string][]SavedFilter{},
	}
}

// Insert — см. Store.
func (m *Memory) Insert(_ context.Context, in Ingest) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return 0, 0, m.Err
	}
	accepted := 0
	for _, e := range in.Events {
		if _, ok := m.events[e.ID]; ok {
			continue
		}
		m.events[e.ID] = Stored{GatewayID: in.GatewayID, ReceivedAt: in.ReceivedAt, Event: e}
		accepted++
	}
	if in.Stats != nil {
		m.stats[in.GatewayID] = *in.Stats
	}
	return accepted, len(in.Events) - accepted, nil
}

// Get возвращает событие по ID.
func (m *Memory) Get(id string) (Stored, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.events[id]
	return s, ok
}

// Len — число событий.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// Stats — последние счётчики шлюза.
func (m *Memory) Stats(gatewayID string) (SenderStats, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.stats[gatewayID]
	return s, ok
}
