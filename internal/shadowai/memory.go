package shadowai

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"
	// Сутки в часовом поясе установки — по имени IANA и без базы зон ОС.
	_ "time/tzdata"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов API и сервиса. Повторяет правила
// PGStore: версия каталога растёт, хеш файла уникален, записи аудита — вместе
// с данными.
type Memory struct {
	mu        sync.Mutex
	catalog   *StoredCatalog
	imports   []ImportRecord
	aggs      map[aggKey]Aggregate
	retention int
	setUp     bool
	records   []audit.Entry
	now       func() time.Time
}

// NewMemory — пустое хранилище; первичная настройка считается выполненной.
func NewMemory() *Memory {
	return &Memory{aggs: map[aggKey]Aggregate{}, retention: DefaultRetentionDays, setUp: true, now: time.Now}
}

// SetNotSetUp — первичная настройка не выполнена (нет строки настроек).
func (m *Memory) SetNotSetUp() { m.mu.Lock(); m.setUp = false; m.mu.Unlock() }

// SetClock — часы очистки по сроку.
func (m *Memory) SetClock(now func() time.Time) { m.mu.Lock(); m.now = now; m.mu.Unlock() }

// Records — записи аудита.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

// Aggregates — все агрегаты по порядку.
func (m *Memory) Aggregates() []Aggregate {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Aggregate, 0, len(m.aggs))
	for _, a := range m.aggs {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Bucket.Equal(out[j].Bucket) {
			return out[i].Bucket.Before(out[j].Bucket)
		}
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].UserAlias < out[j].UserAlias
	})
	return out
}

// Catalog — см. Store.
func (m *Memory) Catalog(context.Context, string) (StoredCatalog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.catalog == nil {
		return StoredCatalog{}, ErrNoCatalog
	}
	c := *m.catalog
	c.File = slices.Clone(c.File)
	return c, nil
}

// SaveCatalog — см. Store.
func (m *Memory) SaveCatalog(_ context.Context, _ string, c StoredCatalog, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.catalog != nil && c.Version <= m.catalog.Version {
		return ErrStaleCatalog
	}
	c.File = slices.Clone(c.File)
	m.catalog = &c
	m.records = append(m.records, rec)
	return nil
}

// SaveImport — см. Store.
func (m *Memory) SaveImport(_ context.Context, _ string, imp ImportRecord, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, i := range m.imports {
		if i.SHA256 == imp.SHA256 {
			return ErrDuplicate
		}
	}
	for _, a := range imp.Aggregates {
		k := aggKey{bucket: a.Bucket.Unix(), service: a.Service, alias: a.UserAlias, kind: a.UserKind}
		cur, ok := m.aggs[k]
		if !ok {
			cur = a
		} else {
			cur.Requests = min(cur.Requests+a.Requests, maxCounter)
			cur.Bytes = min(cur.Bytes+a.Bytes, maxCounter)
		}
		m.aggs[k] = cur
	}
	imp.Aggregates = nil
	m.imports = append(m.imports, imp)
	m.records = append(m.records, rec)
	return nil
}

// Imports — см. Store.
func (m *Memory) Imports(_ context.Context, _ string, limit int) ([]ImportRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := slices.Clone(m.imports)
	slices.Reverse(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) inRange(q Query) []Aggregate {
	var out []Aggregate
	for _, a := range m.aggs {
		if a.Bucket.Before(q.From) || !a.Bucket.Before(q.To) || (q.Service != "" && a.Service != q.Service) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// Services — см. Store.
func (m *Memory) Services(_ context.Context, _ string, q Query) ([]ServiceStat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	by := map[string]*ServiceStat{}
	users := map[string]map[string]struct{}{}
	for _, a := range m.inRange(q) {
		s := by[a.Service]
		if s == nil {
			s = &ServiceStat{ID: a.Service, FirstSeen: a.Bucket, LastSeen: a.Bucket}
			by[a.Service], users[a.Service] = s, map[string]struct{}{}
		}
		s.Requests += a.Requests
		s.Bytes += a.Bytes
		if a.UserAlias != "" {
			users[a.Service][a.UserAlias] = struct{}{}
		}
		if a.Bucket.Before(s.FirstSeen) {
			s.FirstSeen = a.Bucket
		}
		if a.Bucket.After(s.LastSeen) {
			s.LastSeen = a.Bucket
		}
	}
	out := make([]ServiceStat, 0, len(by))
	for id, s := range by {
		s.Users = int64(len(users[id]))
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// Users — см. Store.
func (m *Memory) Users(_ context.Context, _ string, q Query) ([]UserStat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type key struct{ alias, kind string }
	by := map[key]*UserStat{}
	for _, a := range m.inRange(q) {
		if a.UserAlias == "" {
			continue
		}
		k := key{a.UserAlias, a.UserKind}
		u := by[k]
		if u == nil {
			u = &UserStat{Alias: a.UserAlias, Kind: a.UserKind, Services: []string{}}
			by[k] = u
		}
		u.Requests += a.Requests
		u.Bytes += a.Bytes
		if !slices.Contains(u.Services, a.Service) {
			u.Services = append(u.Services, a.Service)
		}
		if a.Bucket.After(u.LastSeen) {
			u.LastSeen = a.Bucket
		}
	}
	out := make([]UserStat, 0, len(by))
	for _, u := range by {
		slices.Sort(u.Services)
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Alias < out[j].Alias
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// Timeline — см. Store.
func (m *Memory) Timeline(_ context.Context, _ string, q Query) ([]Point, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	loc, err := time.LoadLocation(q.TZ)
	if err != nil {
		loc = time.UTC
	}
	by := map[int64]*Point{}
	users := map[int64]map[string]struct{}{}
	services := map[int64]map[string]struct{}{}
	for _, a := range m.inRange(q) {
		b := a.Bucket
		if q.Step == StepDay {
			l := b.In(loc)
			b = time.Date(l.Year(), l.Month(), l.Day(), 0, 0, 0, 0, loc).UTC()
		}
		p := by[b.Unix()]
		if p == nil {
			p = &Point{Bucket: b}
			by[b.Unix()], users[b.Unix()], services[b.Unix()] = p, map[string]struct{}{}, map[string]struct{}{}
		}
		p.Requests += a.Requests
		p.Bytes += a.Bytes
		if a.UserAlias != "" {
			users[b.Unix()][a.UserAlias] = struct{}{}
		}
		services[b.Unix()][a.Service] = struct{}{}
	}
	out := make([]Point, 0, len(by))
	for k, p := range by {
		p.Users, p.Services = int64(len(users[k])), int64(len(services[k]))
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bucket.Before(out[j].Bucket) })
	return out, nil
}

// RetentionDays — см. Store.
func (m *Memory) RetentionDays(context.Context, string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.retention, nil
}

// SetRetentionDays — см. Store.
func (m *Memory) SetRetentionDays(_ context.Context, _ string, days int, fn func(old int) (audit.Entry, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.setUp {
		return ErrNotSetUp
	}
	rec, err := fn(m.retention)
	if err != nil {
		return err
	}
	m.retention = days
	m.records = append(m.records, rec)
	return nil
}

// PurgeExpired — см. Store.
func (m *Memory) PurgeExpired(context.Context, string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := m.now().UTC().Truncate(time.Hour).AddDate(0, 0, -m.retention)
	var n int64
	for k, a := range m.aggs {
		if a.Bucket.Before(cutoff) {
			delete(m.aggs, k)
			n++
		}
	}
	if n > 0 {
		m.records = append(m.records, retentionEntry(n, m.retention))
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

func retentionEntry(rows int64, days int) audit.Entry {
	return audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, ID: "aisec-server", Name: "Сервер управления"},
		Action: "shadow_ai.retention", Object: audit.Object{Type: "shadow_ai_hour"}, Result: audit.ResultSuccess,
		Details: map[string]any{"rows": rows, "retention_days": days}}
}
