package sysstatus

import (
	"context"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов без PostgreSQL: те же правила смены
// состояния, записи аудита копятся в Records.
type Memory struct {
	mu     sync.Mutex
	size   int64
	events map[string]GatewayEvents
	locked int
	denied int
	states map[string]AlertState
	// Records — записи аудита об изменении состояния.
	Records []audit.Entry
	// Err — ошибка, которую вернут все методы (проверка отказа БД).
	Err error
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{events: map[string]GatewayEvents{}, states: map[string]AlertState{}}
}

// SetAuditSize задаёт размер журнала аудита.
func (m *Memory) SetAuditSize(n int64) { m.mu.Lock(); m.size = n; m.mu.Unlock() }

// SetEventStats задаёт счётчики шлюза.
func (m *Memory) SetEventStats(gatewayID string, ev GatewayEvents) {
	m.mu.Lock()
	m.events[gatewayID] = ev
	m.mu.Unlock()
}

// SetCounts задаёт счётчики ИАФ.4 и УПД.6.
func (m *Memory) SetCounts(locked, denied int) {
	m.mu.Lock()
	m.locked, m.denied = locked, denied
	m.mu.Unlock()
}

// AuditSize — см. Store.
func (m *Memory) AuditSize(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.size, m.Err
}

// EventStats — см. Store.
func (m *Memory) EventStats(context.Context) (map[string]GatewayEvents, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]GatewayEvents, len(m.events))
	for k, v := range m.events {
		out[k] = v
	}
	return out, m.Err
}

// AuditCounts — см. Store.
func (m *Memory) AuditCounts(context.Context, time.Time) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.locked, m.denied, m.Err
}

// AlertStates — см. Store.
func (m *Memory) AlertStates(context.Context) (map[string]AlertState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]AlertState, len(m.states))
	for k, v := range m.states {
		out[k] = v
	}
	return out, m.Err
}

// Transition — см. Store.
func (m *Memory) Transition(_ context.Context, condition string, active bool, now time.Time,
	rec func(active bool) audit.Entry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return false, m.Err
	}
	cur, exists := m.states[condition]
	changed := (exists && cur.Active != active) || (!exists && active)
	if exists && !changed {
		return false, nil
	}
	m.states[condition] = AlertState{Active: active, Since: now}
	if changed {
		m.Records = append(m.Records, rec(active))
	}
	return changed, nil
}
