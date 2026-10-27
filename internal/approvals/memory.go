package approvals

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов без PostgreSQL. Повторяет правила
// PGStore и миграции 0056: пределы ожидающих запросов, закрытие только
// ожидающих, записи аудита копятся в Records.
type Memory struct {
	mu      sync.Mutex
	reqs    map[string]Request
	records []audit.Entry
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory { return &Memory{reqs: map[string]Request{}} }

// Records — копия записей аудита.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

func clone(r Request) Request {
	if r.Args != nil {
		a := *r.Args
		a.Data = bytes.Clone(a.Data)
		r.Args = &a
	}
	return r
}

// Create — см. Store.
func (m *Memory) Create(_ context.Context, r Request, rec audit.Entry, maxGateway, maxAgent int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	gw, ag := 0, 0
	for _, x := range m.reqs {
		if x.State != Pending || x.GatewayID != r.GatewayID {
			continue
		}
		gw++
		if x.App == r.App && x.Agent == r.Agent {
			ag++
		}
	}
	switch {
	case gw >= maxGateway:
		return &QueueFullError{Scope: "gateway"}
	case ag >= maxAgent:
		return &QueueFullError{Scope: "agent"}
	}
	m.reqs[r.ID] = clone(r)
	m.records = append(m.records, rec)
	return nil
}

// Get — см. Store.
func (m *Memory) Get(_ context.Context, orgID, id string) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok || r.OrgID != orgID {
		return Request{}, ErrNotFound
	}
	return clone(r), nil
}

// Close — см. Store.
func (m *Memory) Close(_ context.Context, orgID, id string, fn func(*Request) (*audit.Entry, error)) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok || r.OrgID != orgID {
		return Request{}, ErrNotFound
	}
	r = clone(r)
	rec, err := fn(&r)
	if err != nil {
		return Request{}, err
	}
	m.reqs[id] = r
	if rec != nil {
		m.records = append(m.records, *rec)
	}
	return clone(r), nil
}

// List — см. Store.
func (m *Memory) List(_ context.Context, orgID string, f Filter) ([]Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Request
	for _, r := range m.reqs {
		if r.OrgID != orgID || f.State != "" && r.State != f.State || f.App != "" && r.App != f.App ||
			f.Agent != "" && r.Agent != f.Agent {
			continue
		}
		if !f.AfterTime.IsZero() && (r.CreatedAt.After(f.AfterTime) ||
			r.CreatedAt.Equal(f.AfterTime) && r.ID >= f.AfterID) {
			continue
		}
		out = append(out, clone(r))
	}
	slices.SortFunc(out, func(a, b Request) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

// close закрывает ожидающие запросы, подходящие под match, не больше limit.
func (m *Memory) close(orgID string, match func(Request) bool, state State, at func(Request) time.Time, limit int) []string {
	var ids []string
	for id, r := range m.reqs {
		if limit > 0 && len(ids) == limit {
			break
		}
		if r.OrgID != orgID || r.State != Pending || !match(r) {
			continue
		}
		r.State, r.ClosedAt = state, at(r)
		m.reqs[id] = r
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// Expire — см. Store.
func (m *Memory) Expire(_ context.Context, orgID string, now time.Time, limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.close(orgID, func(r Request) bool { return !now.Before(r.Deadline) }, Timeout,
		func(r Request) time.Time { return r.Deadline }, limit), nil
}

// Interrupt — см. Store.
func (m *Memory) Interrupt(_ context.Context, orgID, gatewayID string, keep []string, before, now time.Time) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.close(orgID, func(r Request) bool {
		return r.GatewayID == gatewayID && r.CreatedAt.Before(before) && !slices.Contains(keep, r.ID)
	}, Interrupted, func(Request) time.Time { return now }, 0), nil
}

// PurgeArgs — см. Store.
func (m *Memory) PurgeArgs(_ context.Context, orgID string, before time.Time, limit int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, r := range m.reqs {
		if n == limit {
			break
		}
		if r.OrgID == orgID && r.State != Pending && r.Args != nil && r.ClosedAt.Before(before) {
			r.Args = nil
			m.reqs[id] = r
			n++
		}
	}
	return n, nil
}

// Delete — см. Store.
func (m *Memory) Delete(_ context.Context, orgID string, before time.Time, limit int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, r := range m.reqs {
		if n == limit {
			break
		}
		if r.OrgID == orgID && r.State != Pending && r.ClosedAt.Before(before) {
			delete(m.reqs, id)
			n++
		}
	}
	return n, nil
}

// Record — см. Store.
func (m *Memory) Record(_ context.Context, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, rec)
	return nil
}
