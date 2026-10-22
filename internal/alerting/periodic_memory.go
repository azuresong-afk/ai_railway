package alerting

import (
	"context"
	"slices"
	"strconv"
	"time"
)

// Фоновая задача в Memory (тесты без PostgreSQL): те же вычисления
// «частоты», «аномалии» и «бюджета», агрегаты событий задаёт тест
// (AddActivity), время — Clock.

// Activity — минутный агрегат событий для правил «аномалия» в Memory.
type Activity struct {
	Bucket time.Time
	App    string
	// Requests — запросов через шлюз и Check API; токены входа и выхода.
	Requests         float64
	PromptTokens     float64
	CompletionTokens float64
}

type countEntry struct {
	countRow
	pending int64
}

// AddActivity добавляет минутные агрегаты событий.
func (m *Memory) AddActivity(points ...Activity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range points {
		p.Bucket = p.Bucket.UTC().Truncate(time.Minute)
		m.activity = append(m.activity, p)
	}
}

// Enqueued — ID оповещений, поставленных в очередь доставки (каждое новое
// оповещение, задача 3.14), по порядку создания.
func (m *Memory) Enqueued() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.enqueued)
}

// Periodic — проход фоновой задачи на момент Clock в часовом поясе loc с
// расходом бюджетов usage.
func (m *Memory) Periodic(ctx context.Context, loc *time.Location, usage []BudgetUsage) (PeriodicResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeErr(); err != nil {
		return PeriodicResult{}, err
	}
	if loc == nil {
		loc = time.UTC
	}
	return runPeriodic(ctx, memOps{m}, m.now(), loc, usage, nil, nil)
}

// RuleState — см. Store.
func (m *Memory) RuleState(_ context.Context, orgID, ruleID string) (RuleState, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rules[ruleID]; !ok || r.OrgID != orgID {
		return RuleState{}, false, nil
	}
	st, ok := m.states[ruleID]
	return st, ok, nil
}

func (o memOps) addCounts(_ context.Context, ruleID string, rows []countRow) error {
	m := o.m
	if m.counts == nil {
		m.counts = map[string]map[string]*countEntry{}
	}
	byRule := m.counts[ruleID]
	if byRule == nil {
		byRule = map[string]*countEntry{}
		m.counts[ruleID] = byRule
	}
	for _, r := range rows {
		id := r.Key + keySep + strconv.FormatInt(r.Bucket.Unix(), 10)
		c, ok := byRule[id]
		if !ok {
			c = &countEntry{countRow: countRow{Key: r.Key, Values: r.Values, Bucket: r.Bucket}}
			byRule[id] = c
		}
		c.Count += r.Count
		c.pending += r.Count
		for _, ref := range r.Refs {
			if len(c.Refs) < maxCountRefs {
				c.Refs = append(c.Refs, ref)
			}
		}
	}
	return nil
}

func (o memOps) frequencyDue(_ context.Context, r *Rule, since time.Time) ([]freqDue, error) {
	by := map[string]*freqDue{}
	var entries []*countEntry
	for _, c := range o.m.counts[r.ID] {
		if c.Bucket.Before(since) {
			continue
		}
		entries = append(entries, c)
	}
	slices.SortFunc(entries, func(a, b *countEntry) int { return a.Bucket.Compare(b.Bucket) })
	for _, c := range entries {
		d, ok := by[c.Key]
		if !ok {
			d = &freqDue{Key: c.Key, Values: c.Values, First: c.Bucket}
			by[c.Key] = d
		}
		d.InWindow += c.Count
		d.Pending += c.pending
		d.Last = c.Bucket
		if c.pending > 0 {
			for _, ref := range c.Refs {
				if len(d.Refs) < MaxAlertEvents {
					d.Refs = append(d.Refs, ref)
				}
			}
		}
	}
	var out []freqDue
	for _, d := range by {
		if d.InWindow >= int64(r.Condition.Count) && d.Pending > 0 {
			out = append(out, *d)
		}
	}
	slices.SortFunc(out, func(a, b freqDue) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return 0
	})
	for _, d := range out {
		for _, c := range o.m.counts[r.ID] {
			if c.Key == d.Key && !c.Bucket.Before(since) {
				c.pending, c.Refs = 0, nil
			}
		}
	}
	return out, nil
}

func (o memOps) pruneCounts(_ context.Context, before time.Time) error {
	for _, byRule := range o.m.counts {
		for id, c := range byRule {
			if c.Bucket.Before(before) {
				delete(byRule, id)
			}
		}
	}
	return nil
}

func (o memOps) saveState(_ context.Context, ruleID string, st RuleState) error {
	if o.m.states == nil {
		o.m.states = map[string]RuleState{}
	}
	o.m.states[ruleID] = st
	return nil
}

// volume — значение метрики агрегата.
func (a *Activity) volume(metric string) float64 {
	switch metric {
	case MetricTokens:
		return a.PromptTokens + a.CompletionTokens
	case MetricCompletionTokens:
		return a.CompletionTokens
	}
	return a.Requests
}

func activityKey(a *Activity, byApp bool) string {
	if byApp {
		return a.App
	}
	return ""
}

func (o memOps) windowVolume(_ context.Context, metric string, byApp bool, from, to time.Time) (map[string]float64, error) {
	out := map[string]float64{}
	for i := range o.m.activity {
		a := &o.m.activity[i]
		if a.Bucket.Before(from) || !a.Bucket.Before(to) || byApp && a.App == "" {
			continue
		}
		if v := a.volume(metric); v > 0 {
			out[activityKey(a, byApp)] += v
		}
	}
	return out, nil
}

func (o memOps) hourVolumes(_ context.Context, metric string, byApp bool, hours []time.Time) (map[string]map[time.Time]float64, error) {
	out := map[string]map[time.Time]float64{}
	for i := range o.m.activity {
		a := &o.m.activity[i]
		h := a.Bucket.Truncate(time.Hour)
		if !slices.ContainsFunc(hours, h.Equal) || byApp && a.App == "" {
			continue
		}
		k := activityKey(a, byApp)
		if out[k] == nil {
			out[k] = map[time.Time]float64{}
		}
		out[k][h] += a.volume(metric)
	}
	return out, nil
}

func (o memOps) firstSeen(_ context.Context, metric string, byApp bool, since time.Time) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	for i := range o.m.activity {
		a := &o.m.activity[i]
		h := a.Bucket.Truncate(time.Hour)
		if h.Before(since) || a.volume(metric) <= 0 || byApp && a.App == "" {
			continue
		}
		k := activityKey(a, byApp)
		if f, ok := out[k]; !ok || h.Before(f) {
			out[k] = h
		}
	}
	return out, nil
}
