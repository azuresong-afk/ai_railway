package notify

import (
	"context"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Передача журнала в SIEM в Memory (тесты без PostgreSQL): журнал задаёт
// тест (AddAudit), записи передачи (разрыв, отставание) попадают в Audited.

// AddAudit добавляет записи журнала аудита; seq — по порядку, если не задан.
func (m *Memory) AddAudit(recs ...audit.Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range recs {
		if r.Seq == 0 {
			r.Seq = m.headSeq() + 1
		}
		m.journal = append(m.journal, r)
	}
}

// DropAudit удаляет записи журнала с seq не больше upto (архивация).
func (m *Memory) DropAudit(upto int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if upto > m.archived {
		m.archived = upto
	}
	m.journal = slices.DeleteFunc(m.journal, func(r audit.Record) bool { return r.Seq <= upto })
}

func (m *Memory) headSeq() int64 {
	if n := len(m.journal); n > 0 {
		return m.journal[n-1].Seq
	}
	return m.archived
}

// resetCursor ставит курсор канала на конец журнала.
func (m *Memory) resetCursor(id string) {
	if m.cursors == nil {
		m.cursors = map[string]*StreamCursor{}
	}
	now := m.now().UTC()
	m.cursors[id] = &StreamCursor{ChannelID: id, LastSeq: m.headSeq(), NextAt: now, UpdatedAt: now}
}

// StreamChannels — см. Store.
func (m *Memory) StreamChannels(context.Context) ([]Channel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Channel
	for _, c := range m.channels {
		if _, ok := m.cursors[c.ID]; c.AuditStream && !ok {
			m.resetCursor(c.ID)
			m.audited = append(m.audited, cursorLost(c.OrgID, c, m.headSeq()))
		}
		if c.Enabled && c.AuditStream {
			out = append(out, c)
		}
	}
	return out, nil
}

// ClaimStream — см. Store.
func (m *Memory) ClaimStream(_ context.Context, channelID string, lease time.Duration) (StreamCursor, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cursors[channelID]
	i := m.find(channelID)
	now := m.now().UTC()
	if !ok || i < 0 || !m.channels[i].Enabled || !m.channels[i].AuditStream || c.NextAt.After(now) {
		return StreamCursor{}, false, nil
	}
	c.NextAt = now.Add(lease)
	return *c, true, nil
}

// AuditAfter — см. Store.
func (m *Memory) AuditAfter(_ context.Context, after int64, limit int) ([]audit.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Record
	for _, r := range m.journal {
		if r.Seq > after && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

// FinishStream — см. Store.
func (m *Memory) FinishStream(_ context.Context, prevSeq int64, c StreamCursor, recs []audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.cursors[c.ChannelID]
	if !ok || cur.LastSeq != prevSeq {
		return nil
	}
	c.LagRaised = cur.LagRaised
	if c.SentAt.IsZero() {
		c.SentAt = cur.SentAt
	}
	*cur = c
	m.audited = append(m.audited, recs...)
	return nil
}

func (m *Memory) backlog(after int64) Backlog {
	b := Backlog{Head: m.headSeq()}
	if b.Head > after {
		b.Pending = b.Head - after
	}
	for _, r := range m.journal {
		if r.Seq > after {
			b.Oldest = r.TS.UTC()
			break
		}
	}
	return b
}

// StreamLag — см. Store.
func (m *Memory) StreamLag(_ context.Context, channelID string, fn func(StreamCursor, Backlog) (bool, *audit.Entry)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cursors[channelID]
	if !ok {
		return nil
	}
	lag, rec := fn(*c, m.backlog(c.LastSeq))
	if lag == c.LagRaised {
		return nil
	}
	c.LagRaised = lag
	if rec != nil {
		m.audited = append(m.audited, *rec)
	}
	return nil
}

// StreamState — см. Store.
func (m *Memory) StreamState(_ context.Context, channelID string) (StreamCursor, Backlog, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cursors[channelID]
	if !ok {
		return StreamCursor{}, Backlog{}, false, nil
	}
	return *c, m.backlog(c.LastSeq), true, nil
}
