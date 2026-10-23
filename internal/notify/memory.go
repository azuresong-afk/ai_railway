package notify

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов и разработки без PostgreSQL.
type Memory struct {
	mu         sync.Mutex
	channels   []Channel
	deliveries []Delivery
	messages   map[string]Message
	audited    []audit.Entry
	now        func() time.Time
	// Журнал аудита и курсоры передачи в SIEM (stream_memory.go).
	journal  []audit.Record
	archived int64
	cursors  map[string]*StreamCursor
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{messages: map[string]Message{}, now: time.Now}
}

// Audited — записи аудита, переданные хранилищу.
func (m *Memory) Audited() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.audited)
}

// Enqueue ставит оповещение msg в очередь доставки по каналам с порогом
// серьёзности не выше его (как PGStore.EnqueueAlertTx).
func (m *Memory) Enqueue(msg Message, newID func() string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages[msg.ID] = msg
	n := 0
	now := m.now().UTC()
	for _, c := range m.channels {
		if !c.Enabled || SeverityRank(msg.Severity) < SeverityRank(c.MinSeverity) {
			continue
		}
		m.deliveries = append(m.deliveries, Delivery{ID: newID(), OrgID: c.OrgID, ChannelID: c.ID, AlertID: msg.ID,
			Kind: KindAlert, Status: StatusPending, NextAt: now, CreatedAt: now, UpdatedAt: now})
		n++
	}
	return n
}

// SetNow подменяет часы очереди (тесты повторов).
func (m *Memory) SetNow(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

func (m *Memory) find(id string) int {
	return slices.IndexFunc(m.channels, func(c Channel) bool { return c.ID == id })
}

// Channels — см. Store.
func (m *Memory) Channels(context.Context) ([]Channel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.channels), nil
}

// Channel — см. Store.
func (m *Memory) Channel(_ context.Context, id string) (Channel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.find(id)
	if i < 0 {
		return Channel{}, ErrNotFound
	}
	return m.channels[i], nil
}

// CreateChannel — см. Store.
func (m *Memory) CreateChannel(_ context.Context, c Channel, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.channels) >= MaxChannels {
		return ErrTooMany
	}
	if slices.ContainsFunc(m.channels, func(x Channel) bool { return x.Name == c.Name }) {
		return ErrNameTaken
	}
	if c.AuditStream {
		m.resetCursor(c.ID)
	}
	m.channels = append(m.channels, c)
	m.audited = append(m.audited, rec)
	return nil
}

// UpdateChannel — см. Store.
func (m *Memory) UpdateChannel(_ context.Context, id string, fn func(old Channel) (Channel, audit.Entry, error)) (Channel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.find(id)
	if i < 0 {
		return Channel{}, ErrNotFound
	}
	c, rec, err := fn(m.channels[i])
	if err != nil {
		return Channel{}, err
	}
	if slices.ContainsFunc(m.channels, func(x Channel) bool { return x.ID != id && x.Name == c.Name }) {
		return Channel{}, ErrNameTaken
	}
	if r := lagReason(m.channels[i], c); r != "" {
		if cur, ok := m.cursors[c.ID]; ok && cur.LagRaised {
			cur.LagRaised = false
			m.audited = append(m.audited, lagCleared(c.OrgID, c, r))
		}
	}
	if c.AuditStream && !m.channels[i].AuditStream {
		m.resetCursor(c.ID)
	}
	m.channels[i] = c
	m.audited = append(m.audited, rec)
	return c, nil
}

// RecordTest — см. Store.
func (m *Memory) RecordTest(_ context.Context, d Delivery, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deliveries = append(m.deliveries, d)
	m.audited = append(m.audited, rec)
	return nil
}

// Deliveries — см. Store.
func (m *Memory) Deliveries(_ context.Context, channelID string, limit int) ([]Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Delivery
	for i := len(m.deliveries) - 1; i >= 0 && len(out) < limit; i-- {
		if m.deliveries[i].ChannelID == channelID {
			out = append(out, m.deliveries[i])
		}
	}
	return out, nil
}

// ClaimDue — см. Store.
func (m *Memory) ClaimDue(_ context.Context, lease time.Duration, limit int) ([]Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	var out []Delivery
	for i := range m.deliveries {
		d := &m.deliveries[i]
		if d.Status != StatusPending || d.NextAt.After(now) || len(out) == limit {
			continue
		}
		d.NextAt = now.Add(lease)
		out = append(out, *d)
	}
	return out, nil
}

// FinishDelivery — см. Store.
func (m *Memory) FinishDelivery(_ context.Context, d Delivery, rec *audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := slices.IndexFunc(m.deliveries, func(x Delivery) bool { return x.ID == d.ID })
	if i < 0 || m.deliveries[i].Status != StatusPending {
		return ErrNotFound
	}
	m.deliveries[i] = d
	if rec != nil {
		m.audited = append(m.audited, *rec)
	}
	return nil
}

// AlertMessage — см. Store.
func (m *Memory) AlertMessage(_ context.Context, alertID string) (Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	msg, ok := m.messages[alertID]
	if !ok {
		return Message{}, ErrNotFound
	}
	return msg, nil
}
