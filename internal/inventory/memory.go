package inventory

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов без PostgreSQL. Приложения, провайдеры
// и тройки из агрегатов задаются полями; записи аудита копятся в Records.
type Memory struct {
	mu sync.Mutex
	// Apps и Providers — сводка, которую вернёт Overview.
	Apps      []App
	Providers []Provider
	// Seen — тройки, которые Discover «прочитает» из агрегатов.
	Seen    []Seen
	Records []audit.Entry

	models map[string]Model
	usage  []Usage
	nextID int64
	sync   SyncState
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory { return &Memory{models: map[string]Model{}} }

// Overview — сводка реестра.
func (m *Memory) Overview(_ context.Context, _ string, _ time.Time) (Overview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Overview{Apps: slices.Clone(m.Apps), Providers: slices.Clone(m.Providers), Models: len(m.models), Usage: len(m.usage),
		Sync: m.sync}, nil
}

// ProviderExists — есть ли провайдер в Providers.
func (m *Memory) ProviderExists(_ context.Context, _, slug string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.ContainsFunc(m.Providers, func(p Provider) bool { return p.Slug == slug }), nil
}

func (m *Memory) sorted() []Model {
	out := make([]Model, 0, len(m.models))
	for _, v := range m.models {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b Model) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// Models — страница моделей.
func (m *Memory) Models(_ context.Context, _ string, f Filter) ([]Model, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Model{}
	q := strings.ToLower(f.Query)
	for _, v := range m.sorted() {
		if f.Kind != "" && v.Kind != f.Kind || f.Origin != "" && v.Origin != f.Origin || f.Provider != "" && v.Provider != f.Provider {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(v.Name), q) && !strings.Contains(strings.ToLower(v.Title), q) {
			continue
		}
		if a := f.After; a != nil {
			if c := v.CreatedAt.Compare(a.CreatedAt); c < 0 || c == 0 && v.ID <= a.ID {
				continue
			}
		}
		v.FileCount, v.Files = len(v.Files), nil
		out = append(out, v)
		if len(out) == f.Limit {
			break
		}
	}
	return out, nil
}

// Model — модель с файлами.
func (m *Memory) Model(_ context.Context, _, id string) (Model, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.models[id]
	if !ok {
		return Model{}, ErrNotFound
	}
	v.Files = slices.Clone(v.Files)
	return v, nil
}

// CreateModel — ErrExists, ErrTooMany.
func (m *Memory) CreateModel(_ context.Context, v Model, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.models) >= MaxModels {
		return ErrTooMany
	}
	for _, o := range m.models {
		if o.Provider == v.Provider && o.Name == v.Name {
			return ErrExists
		}
	}
	v.Files = slices.Clone(v.Files)
	m.models[v.ID] = v
	m.Records = append(m.Records, rec)
	return nil
}

// UpdateModel — изменение под блокировкой хранилища.
func (m *Memory) UpdateModel(_ context.Context, _, id string, fn func(*Model) (audit.Entry, error)) (Model, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.models[id]
	if !ok {
		return Model{}, ErrNotFound
	}
	v.Files = slices.Clone(v.Files)
	rec, err := fn(&v)
	if err != nil {
		return Model{}, err
	}
	m.models[id] = v
	m.Records = append(m.Records, rec)
	return v, nil
}

// DeleteModel удаляет модель.
func (m *Memory) DeleteModel(_ context.Context, _, id string, fn func(Model) (audit.Entry, error)) (Model, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.models[id]
	if !ok {
		return Model{}, ErrNotFound
	}
	rec, err := fn(v)
	if err != nil {
		return Model{}, err
	}
	delete(m.models, id)
	m.Records = append(m.Records, rec)
	return v, nil
}

// Usage — страница использования.
func (m *Memory) Usage(_ context.Context, _ string, f UsageFilter) ([]Usage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Usage{}
	for _, u := range m.usage {
		if f.App != "" && u.App != f.App || f.Provider != "" && u.Provider != f.Provider || f.Model != "" && u.Model != f.Model || u.ID <= f.After {
			continue
		}
		out = append(out, u)
		if len(out) == f.Limit {
			break
		}
	}
	return out, nil
}

// Discover — пополнение по Seen с теми же пределами, что у PGStore.
func (m *Memory) Discover(_ context.Context, _ string, now time.Time, newID func() (string, error),
	rec func(DiscoverResult) *audit.Entry) (DiscoverResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := DiscoverResult{Names: []string{}}
	for _, v := range m.Seen {
		i := slices.IndexFunc(m.usage, func(u Usage) bool { return u.App == v.App && u.Provider == v.Provider && u.Model == v.Model })
		switch {
		case i >= 0:
			u := &m.usage[i]
			u.FirstSeen, u.LastSeen = minTime(u.FirstSeen, v.First), maxTime(u.LastSeen, v.Last)
		case len(m.usage) >= MaxUsage:
			res.Skipped++
		default:
			m.nextID++
			m.usage = append(m.usage, Usage{ID: m.nextID, App: v.App, Provider: v.Provider, Model: v.Model, FirstSeen: v.First, LastSeen: v.Last})
			res.Links++
		}
		found := false
		for id, o := range m.models {
			if o.Provider == v.Provider && o.Name == v.Model {
				f, l := v.First, v.Last
				if o.FirstSeen != nil {
					f, l = minTime(*o.FirstSeen, f), maxTime(*o.LastSeen, l)
				}
				o.FirstSeen, o.LastSeen = &f, &l
				m.models[id] = o
				found = true
			}
		}
		if found {
			continue
		}
		if len(m.models) >= MaxModels {
			res.Skipped++
			continue
		}
		id, err := newID()
		if err != nil {
			return DiscoverResult{}, err
		}
		f, l := v.First, v.Last
		m.models[id] = Model{ID: id, Kind: KindProvider, Provider: v.Provider, Name: v.Model, Origin: OriginTraffic, Status: StatusActive,
			FirstSeen: &f, LastSeen: &l, CreatedAt: now, CreatedBy: systemRef, UpdatedAt: now, UpdatedBy: systemRef}
		res.Models++
		if len(res.Names) < MaxDiscoveredNames {
			res.Names = append(res.Names, v.Provider+"/"+v.Model)
		}
	}
	upto := now.Truncate(time.Hour)
	res.SyncedUpto = &upto
	run := now
	m.sync = SyncState{SyncedUpto: &upto, RunAt: &run, LimitReached: res.Skipped > 0, Skipped: res.Skipped}
	if e := rec(res); e != nil {
		m.Records = append(m.Records, *e)
	}
	return res, nil
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
