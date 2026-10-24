package incidents

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Memory — Store в памяти для тестов без PostgreSQL: те же проверки, что
// у PGStore. Оповещения — в alerting.Memory; хранилища не блокируются
// одновременно, отката нет.
type Memory struct {
	mu           sync.Mutex
	alerts       *alerting.Memory
	ids          *ids.Generator
	incidents    map[string]*Incident
	timeline     map[string][]TimelineEntry
	comments     map[string][]Comment
	events       map[string][]EventRef
	instructions map[string][]Instruction
	records      []audit.Entry
	counter      int64
	// Clock — часы автоматических инцидентов.
	Clock func() time.Time
}

// NewMemory создаёт пустое хранилище поверх оповещений alerts.
func NewMemory(alerts *alerting.Memory, g *ids.Generator) *Memory {
	return &Memory{alerts: alerts, ids: g, incidents: map[string]*Incident{}, timeline: map[string][]TimelineEntry{},
		comments: map[string][]Comment{}, events: map[string][]EventRef{}, instructions: map[string][]Instruction{},
		Clock: time.Now}
}

// Records — записи аудита, сделанные хранилищем.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

func (m *Memory) counts(id string) Counts {
	return Counts{Timeline: len(m.timeline[id]), Comments: len(m.comments[id]), Events: len(m.events[id])}
}

// Incidents — см. Store.
func (m *Memory) Incidents(_ context.Context, orgID string, q Query) ([]Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Incident
	for _, i := range m.incidents {
		if i.OrgID == orgID && q.match(i) {
			out = append(out, i.clone())
		}
	}
	slices.SortFunc(out, func(a, b Incident) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), cmp.Compare(b.ID, a.ID))
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// Incident — см. Store.
func (m *Memory) Incident(_ context.Context, orgID, id string) (Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.incidents[id]
	if !ok || i.OrgID != orgID {
		return Incident{}, ErrNotFound
	}
	return i.clone(), nil
}

// Related — см. Store.
func (m *Memory) Related(ctx context.Context, orgID, id string) (Related, error) {
	m.mu.Lock()
	i, ok := m.incidents[id]
	if !ok || i.OrgID != orgID {
		m.mu.Unlock()
		return Related{}, ErrNotFound
	}
	r := Related{Incident: i.clone(), Timeline: slices.Clone(m.timeline[id]), Comments: slices.Clone(m.comments[id]), Events: slices.Clone(m.events[id])}
	m.mu.Unlock()
	a, err := m.alerts.IncidentAlerts(ctx, orgID, id)
	r.Alerts = a
	return r, err
}

// apply добавляет записи изменения (под m.mu).
func (m *Memory) apply(inc *Incident, ch *Change) {
	for _, e := range ch.Timeline {
		m.timeline[e.IncidentID] = append(m.timeline[e.IncidentID], e)
	}
	if ch.Comment != nil {
		m.comments[inc.ID] = append(m.comments[inc.ID], *ch.Comment)
	}
	have := m.events[inc.ID]
	for _, e := range ch.Events {
		if len(have) >= MaxEvents {
			break
		}
		if !slices.ContainsFunc(have, func(x EventRef) bool { return x.ID == e.ID }) {
			have = append(have, e)
		}
	}
	m.events[inc.ID] = have
	m.records = append(m.records, ch.Audit...)
}

// Create — см. Store.
func (m *Memory) Create(ctx context.Context, c Creation) (Incident, bool, error) {
	var src Source
	if c.AlertID != "" {
		a, refs, err := m.alerts.AlertForIncident(c.Incident.OrgID, c.AlertID)
		if err != nil {
			return Incident{}, false, ErrAlertNotFound
		}
		if a.IncidentID != "" {
			inc, err := m.Incident(ctx, c.Incident.OrgID, a.IncidentID)
			return inc, true, err
		}
		src.Alert, src.Refs = &a, refs
	}
	m.mu.Lock()
	if c.ReopenOf != "" {
		prev, ok := m.incidents[c.ReopenOf]
		if !ok || prev.OrgID != c.Incident.OrgID {
			m.mu.Unlock()
			return Incident{}, false, ErrNotFound
		}
		for _, i := range m.incidents {
			if i.ReopenedFrom == c.ReopenOf {
				out := i.clone()
				m.mu.Unlock()
				return out, true, nil
			}
		}
		p := prev.clone()
		src.Previous, src.Refs = &p, slices.Clone(m.events[c.ReopenOf])
	}
	inc := c.Incident.clone()
	inc.Number = m.counter + 1
	ch, err := c.Build(&inc, src)
	if err != nil {
		m.mu.Unlock()
		return Incident{}, false, err
	}
	m.counter++
	m.incidents[inc.ID] = &inc
	m.apply(&inc, &ch)
	out := inc.clone()
	m.mu.Unlock()
	if src.Alert != nil {
		if err := m.alerts.LinkIncident(inc.OrgID, src.Alert.ID, inc.ID); err != nil {
			return Incident{}, false, err
		}
	}
	return out, false, nil
}

// Update — см. Store.
func (m *Memory) Update(_ context.Context, orgID, id string, fn func(*Incident, Counts) (Change, error)) (Incident, error) {
	m.mu.Lock()
	cur, ok := m.incidents[id]
	if !ok || cur.OrgID != orgID {
		m.mu.Unlock()
		return Incident{}, ErrNotFound
	}
	next := cur.clone()
	ch, err := fn(&next, m.counts(id))
	if err == nil && ch.Comment != nil && ch.Comment.Replaces != "" {
		err = m.checkReplaces(id, ch.Comment)
	}
	if err != nil {
		m.mu.Unlock()
		return Incident{}, err
	}
	next.Version++
	*cur = next.clone()
	m.apply(&next, &ch)
	m.mu.Unlock()
	if ch.CloseAlerts != nil {
		if _, err := m.alerts.CloseForIncident(orgID, id, ch.CloseAlerts.By, ch.CloseAlerts.Comment); err != nil {
			return Incident{}, err
		}
	}
	return next, nil
}

// checkReplaces — правится существующий комментарий инцидента, своим
// автором и только последняя версия (под m.mu).
func (m *Memory) checkReplaces(id string, c *Comment) error {
	list := m.comments[id]
	i := slices.IndexFunc(list, func(x Comment) bool { return x.ID == c.Replaces })
	if i < 0 {
		return ErrCommentNotFound
	}
	if list[i].Author != c.Author {
		return ErrNotAuthor
	}
	if slices.ContainsFunc(list, func(x Comment) bool { return x.Replaces == c.Replaces }) {
		return ErrSuperseded
	}
	return nil
}

// LinkAlert — см. Store.
func (m *Memory) LinkAlert(ctx context.Context, orgID, id, alertID string,
	fn func(*Incident, alerting.Alert, []EventRef, Counts) (Change, error)) (Incident, bool, error) {
	a, refs, err := m.alerts.AlertForIncident(orgID, alertID)
	if err != nil {
		return Incident{}, false, ErrAlertNotFound
	}
	if a.IncidentID == id {
		inc, err := m.Incident(ctx, orgID, id)
		return inc, true, err
	}
	if a.IncidentID != "" {
		return Incident{}, false, ErrLinked
	}
	m.mu.Lock()
	cur, ok := m.incidents[id]
	if !ok || cur.OrgID != orgID {
		m.mu.Unlock()
		return Incident{}, false, ErrNotFound
	}
	next := cur.clone()
	c := m.counts(id)
	all, err := m.alerts.IncidentAlerts(ctx, orgID, id)
	if err != nil {
		m.mu.Unlock()
		return Incident{}, false, err
	}
	c.Alerts = len(all)
	ch, err := fn(&next, a, refs, c)
	if err != nil {
		m.mu.Unlock()
		return Incident{}, false, err
	}
	next.Version++
	*cur = next.clone()
	m.apply(&next, &ch)
	m.mu.Unlock()
	if err := m.alerts.LinkIncident(orgID, alertID, id); err != nil {
		return Incident{}, false, err
	}
	return next, false, nil
}

// Instructions — см. Store.
func (m *Memory) Instructions(_ context.Context, orgID string) (map[string]Instruction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]Instruction{}
	for k, vs := range m.instructions {
		if len(vs) > 0 && orgOf(k) == orgID {
			v := vs[len(vs)-1]
			out[v.Category] = v
		}
	}
	return out, nil
}

func instrKey(orgID, category string) string { return orgID + "/" + category }

func orgOf(key string) string {
	org, _, _ := strings.Cut(key, "/")
	return org
}

// SetInstructions — см. Store.
func (m *Memory) SetInstructions(_ context.Context, orgID, category string, fn func(cur Instruction) (Instruction, audit.Entry, error)) (Instruction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := instrKey(orgID, category)
	var cur Instruction
	if vs := m.instructions[k]; len(vs) > 0 {
		cur = vs[len(vs)-1]
	}
	next, rec, err := fn(cur)
	if err != nil {
		return Instruction{}, err
	}
	m.instructions[k] = append(m.instructions[k], next)
	m.records = append(m.records, rec)
	return next, nil
}

// Record — см. Store.
func (m *Memory) Record(_ context.Context, e audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, e)
	return nil
}

// OpenFromAlert — alerting.IncidentOpener (tx не используется).
func (m *Memory) OpenFromAlert(_ context.Context, _ pgx.Tx, a alerting.Alert, refs []EventRef, category string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inc, build, err := autoIncident(m.ids, a.OrgID, m.Clock().UTC().Truncate(time.Microsecond), &a, refs, category)
	if err != nil {
		return "", err
	}
	inc.Number = m.counter + 1
	ch, err := build(&inc)
	if err != nil {
		return "", err
	}
	m.counter++
	m.incidents[inc.ID] = &inc
	m.apply(&inc, &ch)
	return inc.ID, nil
}

// NoteAlert — alerting.IncidentOpener (tx не используется).
func (m *Memory) NoteAlert(_ context.Context, _ pgx.Tx, incidentID string, a alerting.Alert, refs []EventRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inc, ok := m.incidents[incidentID]
	if !ok {
		return ErrNotFound
	}
	ch := Change{Events: refs}
	if len(m.timeline[incidentID]) < MaxTimeline {
		e, err := triggeredEntry(m.ids, incidentID, m.Clock().UTC().Truncate(time.Microsecond), &a, len(refs))
		if err != nil {
			return err
		}
		ch.Timeline = []TimelineEntry{e}
	}
	m.apply(inc, &ch)
	return nil
}
