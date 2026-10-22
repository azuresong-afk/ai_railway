package alerting

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Memory — Store и движок в памяти для тестов без PostgreSQL: те же
// правила дедупликации, подавления и группировки, время окон — по Clock.
// Отката нет: ошибка посреди Ingest оставляет уже учтённое.
type Memory struct {
	mu      sync.Mutex
	rules   map[string]*Rule
	alerts  map[string]*Alert
	refs    map[string][]EventRef
	history map[string][]History
	seen    map[string]map[string]time.Time
	records []audit.Entry
	nextID  int
	// Clock — часы «СУБД» для окон подавления и группировки.
	Clock func() time.Time
	// Err — ошибка, которую вернёт следующий вызов (проверка отказа БД).
	Err error
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{rules: map[string]*Rule{}, alerts: map[string]*Alert{}, refs: map[string][]EventRef{},
		history: map[string][]History{}, seen: map[string]map[string]time.Time{}, Clock: time.Now}
}

// Records — записи аудита, сделанные хранилищем.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

func (m *Memory) now() time.Time { return m.Clock().UTC().Truncate(time.Microsecond) }

// newID — синтетический UUIDv7-подобный ID по счётчику.
func (m *Memory) newID() string {
	m.nextID++
	return fmt.Sprintf("01900000-0000-7000-8000-%012x", m.nextID)
}

func (m *Memory) takeErr() error {
	err := m.Err
	m.Err = nil
	return err
}

// Ingest — приём пакета событий: движок «порога» и «нового».
func (m *Memory) Ingest(ctx context.Context, gatewayID string, evs []*events.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeErr(); err != nil {
		return err
	}
	return process(ctx, memOps{m}, gatewayID, evs, nil)
}

// memOps — txOps под блокировкой m.mu.
type memOps struct{ m *Memory }

func (o memOps) activeRules(_ context.Context, kinds ...string) ([]Rule, error) {
	var out []Rule
	for _, r := range o.m.sortedRules(audit.DefaultOrgID) {
		if r.Enabled && slices.Contains(kinds, r.Kind) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (o memOps) ruleByKey(_ context.Context, key string) (Rule, bool, error) {
	for _, r := range o.m.rules {
		if r.BuiltinKey == key {
			return r.clone(), true, nil
		}
	}
	return Rule{}, false, nil
}

func (o memOps) markSeen(_ context.Context, ruleID string, values []string) ([]string, error) {
	s := o.m.seen[ruleID]
	if s == nil {
		s = map[string]time.Time{}
		o.m.seen[ruleID] = s
	}
	var fresh []string
	for _, v := range values {
		if _, ok := s[v]; !ok {
			s[v] = o.m.now()
			fresh = append(fresh, v)
		}
	}
	return fresh, nil
}

func (o memOps) raise(_ context.Context, r *Rule, t *Trigger) error {
	m := o.m
	now := m.now()
	var open, closed *Alert
	for _, a := range m.alerts {
		if a.RuleID != r.ID || a.DedupKey != t.Key {
			continue
		}
		if a.Open {
			open = a
		}
		if a.Status == StatusClosed && (closed == nil || a.ClosedAt.After(closed.ClosedAt)) {
			closed = a
		}
	}
	// Окно группировки: оповещение старше окна новых срабатываний не берёт.
	if open != nil && r.GroupMinutes > 0 && open.CreatedAt.Before(now.Add(-time.Duration(r.GroupMinutes)*time.Minute)) {
		open.Open, open.UpdatedAt = false, now
		open = nil
	}
	if open != nil {
		prev := open.Count
		open.Count += t.Count
		open.LastTriggeredAt, open.UpdatedAt = now, now
		if !t.FirstEvent.IsZero() && (open.FirstEventAt.IsZero() || t.FirstEvent.Before(open.FirstEventAt)) {
			open.FirstEventAt = t.FirstEvent
		}
		if t.LastEvent.After(open.LastEventAt) {
			open.LastEventAt = t.LastEvent
		}
		open.Details = mergeDetails(open.Details, t.Details)
		m.addRefs(open.ID, prev, t.Events)
		return nil
	}
	if closed != nil && r.SuppressMinutes > 0 && closed.ClosedAt.After(now.Add(-time.Duration(r.SuppressMinutes)*time.Minute)) {
		closed.Suppressed += t.Count
		closed.UpdatedAt = now
		return nil
	}
	a := &Alert{ID: m.newID(), OrgID: r.OrgID, RuleID: r.ID, Kind: r.Kind, Severity: r.Severity, Title: title(r, t.Values),
		Status: StatusNew, DedupKey: t.Key, Open: true, Values: maps.Clone(t.Values), Count: t.Count,
		FirstEventAt: t.FirstEvent, LastEventAt: t.LastEvent, CreatedAt: now, LastTriggeredAt: now, UpdatedAt: now,
		Details: mergeDetails(nil, t.Details)}
	m.alerts[a.ID] = a
	m.addRefs(a.ID, 0, t.Events)
	return nil
}

// addRefs добавляет ссылки на события, пока их меньше MaxAlertEvents; prev
// — срабатываний в оповещении до этого.
func (m *Memory) addRefs(alertID string, prev int64, refs []EventRef) {
	room := MaxAlertEvents - int(min(prev, MaxAlertEvents))
	have := m.refs[alertID]
	for _, r := range refs {
		if room == 0 {
			break
		}
		if !slices.ContainsFunc(have, func(x EventRef) bool { return x.ID == r.ID }) {
			have = append(have, r)
			room--
		}
	}
	m.refs[alertID] = have
}

func (m *Memory) sortedRules(orgID string) []Rule {
	var out []Rule
	for _, r := range m.rules {
		if r.OrgID == orgID {
			out = append(out, r.clone())
		}
	}
	slices.SortFunc(out, func(a, b Rule) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	return out
}

// Rules — см. Store.
func (m *Memory) Rules(_ context.Context, orgID string) ([]Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeErr(); err != nil {
		return nil, err
	}
	return m.sortedRules(orgID), nil
}

// Rule — см. Store.
func (m *Memory) Rule(_ context.Context, orgID, id string) (Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rules[id]
	if !ok || r.OrgID != orgID {
		return Rule{}, ErrNotFound
	}
	return r.clone(), nil
}

// CountRules — см. Store.
func (m *Memory) CountRules(_ context.Context, orgID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.rules {
		if r.OrgID == orgID && !r.Builtin() {
			n++
		}
	}
	return n, nil
}

// CreateRule — см. Store.
func (m *Memory) CreateRule(_ context.Context, r Rule, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeErr(); err != nil {
		return err
	}
	for _, x := range m.rules {
		if r.Builtin() && x.OrgID == r.OrgID && x.BuiltinKey == r.BuiltinKey {
			return ErrExists
		}
	}
	c := r.clone()
	m.rules[r.ID] = &c
	m.records = append(m.records, rec)
	return nil
}

// UpdateRule — см. Store.
func (m *Memory) UpdateRule(ctx context.Context, orgID, id string, fn func(*Rule) (audit.Entry, []Raise, error)) (Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeErr(); err != nil {
		return Rule{}, err
	}
	cur, ok := m.rules[id]
	if !ok || cur.OrgID != orgID {
		return Rule{}, ErrNotFound
	}
	next := cur.clone()
	rec, raises, err := fn(&next)
	if err != nil {
		return Rule{}, err
	}
	if err := raiseBuiltin(ctx, memOps{m}, raises); err != nil {
		return Rule{}, err
	}
	*cur = next.clone()
	m.records = append(m.records, rec)
	return next, nil
}

// Alerts — см. Store.
func (m *Memory) Alerts(_ context.Context, orgID string, q AlertQuery) ([]Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeErr(); err != nil {
		return nil, err
	}
	var out []Alert
	for _, a := range m.alerts {
		if a.OrgID == orgID && q.match(a) {
			c := a.clone()
			c.RuleName = m.rules[a.RuleID].Name
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b Alert) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), cmp.Compare(b.ID, a.ID))
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// Alert — см. Store.
func (m *Memory) Alert(_ context.Context, orgID, id string) (Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.alerts[id]
	if !ok || a.OrgID != orgID {
		return Alert{}, ErrNotFound
	}
	c := a.clone()
	c.RuleName = m.rules[a.RuleID].Name
	return c, nil
}

// AlertEvents — см. Store.
func (m *Memory) AlertEvents(_ context.Context, orgID, id string) ([]EventRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.alerts[id]; !ok || a.OrgID != orgID {
		return nil, ErrNotFound
	}
	return slices.Clone(m.refs[id]), nil
}

// AlertHistory — см. Store.
func (m *Memory) AlertHistory(_ context.Context, orgID, id string) ([]History, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.alerts[id]; !ok || a.OrgID != orgID {
		return nil, ErrNotFound
	}
	return slices.Clone(m.history[id]), nil
}

// UpdateAlert — см. Store.
func (m *Memory) UpdateAlert(_ context.Context, orgID, id string, fn func(*Alert) (History, audit.Entry, error)) (Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeErr(); err != nil {
		return Alert{}, err
	}
	cur, ok := m.alerts[id]
	if !ok || cur.OrgID != orgID {
		return Alert{}, ErrNotFound
	}
	next := cur.clone()
	h, rec, err := fn(&next)
	if err != nil {
		return Alert{}, err
	}
	*cur = next.clone()
	m.history[id] = append(m.history[id], h)
	m.records = append(m.records, rec)
	next.RuleName = m.rules[next.RuleID].Name
	return next, nil
}
