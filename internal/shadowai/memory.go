package shadowai

import (
	"context"
	"net/netip"
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
	// exclusions — исключения (задача 4.23).
	exclusions []Exclusion
	// failErr — ошибка следующей записи сводок; failAll — всех записей.
	failErr error
	failAll error
	// syslogSaves — сколько раз вызывалась запись партии syslog.
	syslogSaves int
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
	var prev uint64
	if m.catalog != nil {
		prev = m.catalog.Version
	}
	if c.Version <= prev {
		return ErrStaleCatalog
	}
	if d, ok := rec.Details.(map[string]any); ok {
		d["previous_version"] = prev
	}
	c.File = slices.Clone(c.File)
	m.catalog = &c
	m.records = append(m.records, rec)
	return nil
}

// writeLocked прибавляет сводки, кроме исключённых, и возвращает записанные
// сводки и новые сервисы среди них — по тем же правилам, что PGStore.
func (m *Memory) writeLocked(aggs []Aggregate) ([]Aggregate, []string) {
	ex := ExclusionsOf(m.exclusions)
	kept := make([]Aggregate, 0, len(aggs))
	for _, a := range aggs {
		if !ex.Excludes(a.Service, a.UserAlias) {
			kept = append(kept, a)
		}
	}
	ids, firsts := firstArrays(kept)
	var fresh []string
	for i, id := range ids {
		since := firsts[i].Add(-NewServiceWindow)
		seen := false
		for k := range m.aggs {
			if k.service == id && !time.Unix(k.bucket, 0).Before(since) {
				seen = true
				break
			}
		}
		if !seen {
			fresh = append(fresh, id)
		}
	}
	for _, a := range kept {
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
	return kept, fresh
}

// SaveImport — см. Store.
func (m *Memory) SaveImport(_ context.Context, _ string, imp ImportRecord, fn func(ImportUsers) audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeErr(); err != nil {
		return err
	}
	for _, i := range m.imports {
		if i.SHA256 == imp.SHA256 {
			return ErrDuplicate
		}
	}
	u := m.importUsersLocked(imp)
	imp.users = u
	rec := fn(u)
	kept, fresh := m.writeLocked(imp.Aggregates)
	m.records = append(m.records, rec)
	m.records = append(m.records, newServiceEntries(rec.Actor, rec.SourceIP, SourceImport, kept, imp.ServiceNames, fresh)...)
	imp.Aggregates, imp.ServiceNames = nil, nil
	m.imports = append(m.imports, imp)
	return nil
}

// importUsersLocked — пользователи импорта по сводкам до записи (4В27).
func (m *Memory) importUsersLocked(imp ImportRecord) ImportUsers {
	known := map[string]struct{}{}
	for k := range m.aggs {
		if k.alias != "" {
			known[k.alias] = struct{}{}
		}
	}
	aliases := aliasesOf(imp.Aggregates)
	u := ImportUsers{Users: int64(len(aliases)), Baseline: len(known) == 0 && len(aliases) > 0}
	for _, a := range aliases {
		if _, ok := known[a]; !ok {
			u.NewUsers++
		}
	}
	u.NewUsersDay = u.NewUsers
	since := imp.CreatedAt.Add(-importUsersWindow)
	for _, i := range m.imports {
		if i.CreatedAt.After(since) {
			u.NewUsersDay += i.users.NewUsers
		}
	}
	return u
}

// SaveSyslog — см. Store.
func (m *Memory) SaveSyslog(_ context.Context, _ string, b SyslogBatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syslogSaves++
	if err := m.takeErr(); err != nil {
		return err
	}
	kept, fresh := m.writeLocked(b.Aggregates)
	m.records = append(m.records, newServiceEntries(systemActor, netip.Addr{}, SourceSyslog, kept, b.ServiceNames, fresh)...)
	return nil
}

// FailNext — следующая запись сводок вернёт err (сбой БД в тестах).
func (m *Memory) FailNext(err error) { m.mu.Lock(); m.failErr = err; m.mu.Unlock() }

// FailAll — все записи сводок возвращают err, пока не вызван FailAll(nil).
func (m *Memory) FailAll(err error) { m.mu.Lock(); m.failAll = err; m.mu.Unlock() }

// SyslogSaves — число вызовов записи партии syslog.
func (m *Memory) SyslogSaves() int { m.mu.Lock(); defer m.mu.Unlock(); return m.syslogSaves }

func (m *Memory) takeErr() error {
	if m.failAll != nil {
		return m.failAll
	}
	err := m.failErr
	m.failErr = nil
	return err
}

// Exclusions — см. Store.
func (m *Memory) Exclusions(context.Context, string) ([]Exclusion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := slices.Clone(m.exclusions)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	if out == nil {
		out = []Exclusion{}
	}
	return out, nil
}

// AddExclusion — см. Store.
func (m *Memory) AddExclusion(_ context.Context, _ string, ex Exclusion, fn func(deleted int64) audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.exclusions {
		if e.Kind == ex.Kind && e.Value == ex.Value {
			return ErrExclusionExists
		}
	}
	if len(m.exclusions) >= MaxExclusions {
		return ErrTooManyExclusions
	}
	m.exclusions = append(m.exclusions, ex)
	var n int64
	for k := range m.aggs {
		if (ex.Kind == ExcludeService && k.service == ex.Value) || (ex.Kind == ExcludeUser && k.alias == ex.Value) {
			delete(m.aggs, k)
			n++
		}
	}
	m.records = append(m.records, fn(n))
	return nil
}

// RemoveExclusion — см. Store.
func (m *Memory) RemoveExclusion(_ context.Context, _ string, kind, value string, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := slices.IndexFunc(m.exclusions, func(e Exclusion) bool { return e.Kind == kind && e.Value == value })
	if i < 0 {
		return ErrExclusionNotFound
	}
	m.exclusions = slices.Delete(m.exclusions, i, i+1)
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
