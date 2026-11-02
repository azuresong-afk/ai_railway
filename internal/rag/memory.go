package rag

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов без PostgreSQL; записи аудита копятся
// в Records.
type Memory struct {
	mu      sync.Mutex
	Records []audit.Entry
	cols    map[string]*memCollection // по slug; одна организация
}

type memCollection struct {
	c    Collection
	docs []Document
	ex   []Exclusion
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory { return &Memory{cols: map[string]*memCollection{}} }

func (m *memCollection) view(withExclusions bool) Collection {
	c := m.c
	c.Diff.AddedIDs, c.Diff.ChangedIDs, c.Diff.RemovedIDs = slices.Clone(c.Diff.AddedIDs), slices.Clone(c.Diff.ChangedIDs),
		slices.Clone(c.Diff.RemovedIDs)
	c.ExclusionCount = len(m.ex)
	c.Exclusions = nil
	if withExclusions {
		c.Exclusions = slices.Clone(m.ex)
	}
	return c
}

func (m *memCollection) blocked() map[string]bool {
	b := make(map[string]bool, len(m.ex))
	for _, e := range m.ex {
		b[e.DocumentID] = true
	}
	return b
}

// Collections — коллекции по slug.
func (m *Memory) Collections(_ context.Context, _ string) ([]Collection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Collection, 0, len(m.cols))
	for _, c := range m.cols {
		out = append(out, c.view(false))
	}
	slices.SortFunc(out, func(a, b Collection) int { return strings.Compare(a.Slug, b.Slug) })
	return out, nil
}

// Collection — коллекция с исключениями.
func (m *Memory) Collection(_ context.Context, _, slug string) (Collection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cols[slug]
	if !ok {
		return Collection{}, ErrNotFound
	}
	return c.view(true), nil
}

// Documents — страница документов текущей версии.
func (m *Memory) Documents(_ context.Context, _, slug, after string, limit int) ([]Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cols[slug]
	if !ok {
		return nil, ErrNotFound
	}
	docs := slices.Clone(c.docs)
	slices.SortFunc(docs, func(a, b Document) int { return strings.Compare(a.ID, b.ID) })
	b := c.blocked()
	out := []Document{}
	for _, d := range docs {
		if d.ID <= after {
			continue
		}
		if len(out) >= limit {
			break
		}
		d.Blocked = b[d.ID]
		out = append(out, d)
	}
	return out, nil
}

// LoadManifest — новая версия манифеста.
func (m *Memory) LoadManifest(_ context.Context, _, slug string, docs []Document,
	fn func(cur *Collection, curDocs []Document) (Collection, []audit.Entry, error)) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.cols[slug]
	var cur *Collection
	var curDocs []Document
	if ok {
		v := mc.view(false)
		cur, curDocs = &v, slices.Clone(mc.docs)
	} else if len(m.cols) >= MaxCollections {
		return nil, ErrTooManyCollections
	}
	next, recs, err := fn(cur, curDocs)
	if err != nil {
		return nil, err
	}
	if !ok {
		mc = &memCollection{}
		m.cols[slug] = mc
	}
	mc.c, mc.docs = next, slices.Clone(docs)
	m.Records = append(m.Records, recs...)
	b := mc.blocked()
	blocked := []string{}
	for _, d := range docs {
		if b[d.ID] {
			blocked = append(blocked, d.ID)
		}
	}
	return blocked, nil
}

// AddExclusion — исключение документа.
func (m *Memory) AddExclusion(_ context.Context, _, slug string, ex Exclusion, rec func(Collection) audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cols[slug]
	switch {
	case !ok:
		return ErrNotFound
	case slices.ContainsFunc(c.ex, func(e Exclusion) bool { return e.DocumentID == ex.DocumentID }):
		return ErrExists
	case len(c.ex) >= MaxExclusions:
		return ErrTooManyExclusions
	}
	c.ex = append(c.ex, ex)
	m.Records = append(m.Records, rec(c.view(false)))
	return nil
}

// RemoveExclusion — снятие исключения.
func (m *Memory) RemoveExclusion(_ context.Context, _, slug, id string, rec func(Collection, Exclusion) audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cols[slug]
	if !ok {
		return ErrNotFound
	}
	i := slices.IndexFunc(c.ex, func(e Exclusion) bool { return e.ID == id })
	if i < 0 {
		return ErrExclusionNotFound
	}
	ex := c.ex[i]
	c.ex = slices.Delete(c.ex, i, i+1)
	m.Records = append(m.Records, rec(c.view(false), ex))
	return nil
}
