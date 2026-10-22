package events

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Чтение событий из Memory (тесты API без PostgreSQL): те же правила
// выборки, что у PGStore, — период по времени из ID, фильтр через
// Filter.Match, порядок от новых к старым.

// record — запись события с Details (нужен Match для поля detector).
func record(s *Stored) Record {
	e := &s.Event
	r := Record{
		ID: e.ID, Time: e.Time.UTC(), ReceivedAt: s.ReceivedAt.UTC(), GatewayID: s.GatewayID,
		Type: e.Type, App: e.App, Env: e.Env, User: e.User, Provider: e.Provider, Model: e.Model, Source: e.Source,
		PolicyMode: e.PolicyMode, Storage: storageOf(e), Threats: threatsOf(e), Stream: e.Stream,
		NonTextUnchecked: e.NonTextUnchecked, HasContent: e.Content != nil,
	}
	if d := e.Decision; d != nil {
		r.Action, r.Rule, r.Severity = d.Action, d.Rule, d.Severity
	}
	// В Memory только принятые события с проверенным UUIDv7.
	if ts, err := PartitionTime(e.ID); err == nil {
		r.TS = ts.UTC()
	}
	d := e.Details()
	r.Details = &d
	return r
}

// RecordOf — запись события для проверки фильтра (Filter.Match) без
// чтения из хранилища: правила оповещений в транзакции приёма (ADR-0020).
// ReceivedAt не заполняется.
func RecordOf(gatewayID string, e *Event) Record {
	return record(&Stored{GatewayID: gatewayID, Event: *e})
}

// selectLocked — записи выборки q по порядку (вызывать под m.mu).
// before — запись идёт в выдаче после позиции a (сортировка по убыванию ts, id).
func (r *Record) before(a *Position) bool {
	return r.TS.Before(a.TS) || r.TS.Equal(a.TS) && r.ID < a.ID
}

func (m *Memory) selectLocked(q *Query) []Record {
	var out []Record
	for _, s := range m.events {
		r := record(&s)
		if r.TS.Before(q.From) || !r.TS.Before(q.To) {
			continue
		}
		if !q.ReceivedBefore.IsZero() && r.ReceivedAt.After(q.ReceivedBefore) {
			continue
		}
		if a := q.After; a != nil && !r.before(a) {
			continue
		}
		if !q.Filter.Match(&r) {
			continue
		}
		if !q.WithDetails {
			r.Details = nil
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Record) int {
		if c := b.TS.Compare(a.TS); c != 0 {
			return c
		}
		return cmp.Compare(b.ID, a.ID)
	})
	return out
}

// List — см. Reader.
func (m *Memory) List(_ context.Context, q Query) ([]Record, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return nil, m.ReadErr
	}
	out := m.selectLocked(&q)
	limit := q.Limit
	if limit == 0 || limit > MaxListLimit+1 {
		limit = MaxListLimit + 1
	}
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []Record{}
	}
	return out, nil
}

// Each — см. Reader.
func (m *Memory) Each(_ context.Context, q Query, fn func(*Record) error) error {
	if err := q.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.ReadErr != nil {
		m.mu.Unlock()
		return m.ReadErr
	}
	out := m.selectLocked(&q)
	m.mu.Unlock()
	limit := q.Limit
	if limit == 0 || limit > MaxExportRows {
		limit = MaxExportRows
	}
	for i := range out {
		if i == limit {
			break
		}
		if err := fn(&out[i]); err != nil {
			return err
		}
	}
	return nil
}

// Count — см. Reader.
func (m *Memory) Count(_ context.Context, q Query, limit int) (int, error) {
	if err := q.Validate(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return 0, m.ReadErr
	}
	return min(len(m.selectLocked(&q)), limit+1), nil
}

// Export — см. Reader: выборка берётся одним снимком под блокировкой.
func (m *Memory) Export(_ context.Context, q Query, start func(n int) error, fn func(*Record) error) error {
	if err := q.Validate(); err != nil {
		return err
	}
	limit := q.Limit
	if limit <= 0 || limit > MaxExportRows {
		limit = MaxExportRows
	}
	m.mu.Lock()
	if m.ReadErr != nil {
		m.mu.Unlock()
		return m.ReadErr
	}
	out := m.selectLocked(&q)
	m.mu.Unlock()
	if len(out) > limit {
		return ErrTooManyRows
	}
	if err := start(len(out)); err != nil {
		return err
	}
	for i := range out {
		if err := fn(&out[i]); err != nil {
			return err
		}
	}
	return nil
}

// Card — см. Reader.
func (m *Memory) Card(_ context.Context, id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return Record{}, m.ReadErr
	}
	s, ok := m.events[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return record(&s), nil
}

// Content — см. Reader.
func (m *Memory) Content(_ context.Context, id string) (StoredContent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return StoredContent{}, m.ReadErr
	}
	s, ok := m.events[id]
	if !ok || s.Event.Content == nil {
		return StoredContent{}, ErrNotFound
	}
	return StoredContent{Storage: s.Event.Storage, Content: *s.Event.Content}, nil
}

// MemoryAudit — куда Memory пишет записи аудита об изменении сроков (тесты).
type MemoryAudit func(audit.Entry) error

// Retention — см. RetentionStore.
func (m *Memory) Retention(context.Context) (Retention, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return Retention{}, m.ReadErr
	}
	return m.retention, nil
}

// SetRetentionAudit задаёт приёмник записей аудита для SetRetention.
func (m *Memory) SetRetentionAudit(fn MemoryAudit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditFn = fn
}

// SetRetention — см. RetentionStore: без приёмника аудита изменение не
// выполняется, как и при его ошибке.
func (m *Memory) SetRetention(_ context.Context, r Retention, by audit.Actor, ip netip.Addr) (Retention, error) {
	if err := r.Validate(); err != nil {
		return Retention{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return Retention{}, m.ReadErr
	}
	if m.auditFn == nil {
		return Retention{}, fmt.Errorf("хранилище событий: нет журнала аудита")
	}
	old := m.retention
	if err := m.auditFn(RetentionAudit(audit.DefaultOrgID, old, r, by, ip)); err != nil {
		return Retention{}, err
	}
	r.UpdatedAt = time.Now().UTC()
	m.retention = r
	return old, nil
}

// Filters — см. FilterStore.
func (m *Memory) Filters(_ context.Context, userID string) ([]SavedFilter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return nil, m.ReadErr
	}
	out := slices.Clone(m.filters[userID])
	slices.SortFunc(out, func(a, b SavedFilter) int { return cmp.Compare(a.Name, b.Name) })
	if out == nil {
		out = []SavedFilter{}
	}
	return out, nil
}

// SaveFilter — см. FilterStore.
func (m *Memory) SaveFilter(_ context.Context, userID, name string, f Filter) (SavedFilter, error) {
	if !ValidFilterName(name) {
		return SavedFilter{}, ErrFilterName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return SavedFilter{}, m.ReadErr
	}
	list := m.filters[userID]
	if len(list) >= MaxSavedFilters {
		return SavedFilter{}, ErrTooManyFilters
	}
	if slices.ContainsFunc(list, func(s SavedFilter) bool { return s.Name == name }) {
		return SavedFilter{}, ErrFilterExists
	}
	m.nextID++
	sf := SavedFilter{
		ID: fmt.Sprintf("0192d000-0000-7000-8000-%012x", m.nextID), Name: name, Filter: f.String(),
		CreatedAt: time.Now().UTC(),
	}
	m.filters[userID] = append(list, sf)
	return sf, nil
}

// DeleteFilter — см. FilterStore.
func (m *Memory) DeleteFilter(_ context.Context, userID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return m.ReadErr
	}
	list := m.filters[userID]
	i := slices.IndexFunc(list, func(s SavedFilter) bool { return s.ID == id })
	if i < 0 {
		return ErrNotFound
	}
	m.filters[userID] = slices.Delete(list, i, i+1)
	return nil
}

// Aggregates — см. StatsReader: агрегаты считаются на лету по тем же правилам,
// что задание PGStore.Aggregate.
func (m *Memory) Aggregates(_ context.Context, q StatsQuery) ([]Aggregate, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReadErr != nil {
		return nil, m.ReadErr
	}
	unit := time.Minute
	if q.Interval == IntervalHour {
		unit = time.Hour
	}
	rows := map[string]*Aggregate{}
	for _, s := range m.events {
		r := record(&s)
		b := r.TS.Truncate(unit)
		if b.Before(q.From) || !b.Before(q.To) || (q.App != "" && r.App != q.App) {
			continue
		}
		k := statsKey(b, &r)
		a := rows[k]
		if a == nil {
			a = &Aggregate{Bucket: b, App: r.App, Type: r.Type, Action: r.Action, Severity: r.Severity, Threats: map[string]int64{}}
			rows[k] = a
		}
		a.Events++
		if len(r.Details.Findings) > 0 {
			a.WithFindings++
		}
		if r.NonTextUnchecked {
			a.NonTextUnchecked++
		}
		if t := r.Details.Tokens; t != nil {
			a.TokensPrompt += int64(t.Prompt)
			a.TokensCompletion += int64(t.Completion)
		}
		for _, t := range r.Threats {
			a.Threats[t]++
		}
	}
	out := make([]Aggregate, 0, len(rows))
	for _, a := range rows {
		out = append(out, *a)
	}
	slices.SortFunc(out, func(a, b Aggregate) int {
		return cmp.Or(a.Bucket.Compare(b.Bucket), cmp.Compare(a.App, b.App), cmp.Compare(a.Type, b.Type),
			cmp.Compare(a.Action, b.Action), cmp.Compare(a.Severity, b.Severity))
	})
	if len(out) > MaxStatsRows {
		return nil, ErrTooManyRows
	}
	return out, nil
}
