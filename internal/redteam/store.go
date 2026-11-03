package redteam

import (
	"context"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Store — хранилище целей, запусков и результатов. Изменение цели и
// начало и конец запуска пишутся вместе с записью аудита одной
// транзакцией (РСБ.1).
type Store interface {
	Targets(ctx context.Context, orgID string) ([]Target, error)
	Target(ctx context.Context, orgID, id string) (Target, error)
	// CreateTarget — ErrTooManyTargets сверх MaxTargets.
	CreateTarget(ctx context.Context, t Target, rec audit.Entry) error
	UpdateTarget(ctx context.Context, t Target, rec audit.Entry) error
	DeleteTarget(ctx context.Context, orgID, id string, rec audit.Entry) error
	CreateRun(ctx context.Context, r Run, rec audit.Entry) error
	// FinishRun — состояние, причина, итоги и время завершения.
	FinishRun(ctx context.Context, r Run, rec audit.Entry) error
	SaveResult(ctx context.Context, orgID string, res Result) error
	// Runs — запуски, новые первыми; targetID пусто — всех целей.
	Runs(ctx context.Context, orgID, targetID string, limit int) ([]Run, error)
	Run(ctx context.Context, orgID, id string) (Run, error)
	Results(ctx context.Context, orgID, runID string) ([]Result, error)
	// ActiveKeys — запуски с ключом (цель gateway) в состоянии queued или
	// running и со сроком позже now.
	ActiveKeys(ctx context.Context, orgID string, now time.Time) ([]Run, error)
	// Interrupt — незавершённые запуски получают failed с причиной
	// interrupted (запуск сервера) и запись аудита rec; возвращает их число.
	Interrupt(ctx context.Context, orgID string, now time.Time, rec func(Run) audit.Entry) (int, error)
	// Purge удаляет итоги старше results и завершённые запуски старше runs.
	Purge(ctx context.Context, orgID string, results, runs time.Time) error
}

// Memory — Store в памяти для тестов без PostgreSQL; записи аудита копятся
// в Records.
type Memory struct {
	mu      sync.Mutex
	Records []audit.Entry
	targets map[string]Target
	runs    map[string]Run
	results map[string][]Result
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{targets: map[string]Target{}, runs: map[string]Run{}, results: map[string][]Result{}}
}

// Audit — копия записей аудита.
func (m *Memory) Audit() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.Records)
}

func cloneTarget(t Target) Target {
	t.Headers = slices.Clone(t.Headers)
	if t.Headers == nil {
		t.Headers = []Header{}
	}
	return t
}

func cloneRun(r Run) Run {
	r.Counts = maps.Clone(r.Counts)
	r.KeyHash = slices.Clone(r.KeyHash)
	if r.FinishedAt != nil {
		f := *r.FinishedAt
		r.FinishedAt = &f
	}
	return r
}

// Targets — цели по имени.
func (m *Memory) Targets(_ context.Context, orgID string) ([]Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Target{}
	for _, t := range m.targets {
		if t.OrgID == orgID {
			out = append(out, cloneTarget(t))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name || out[i].Name == out[j].Name && out[i].ID < out[j].ID
	})
	return out, nil
}

// Target — цель по ID.
func (m *Memory) Target(_ context.Context, orgID, id string) (Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[id]
	if !ok || t.OrgID != orgID {
		return Target{}, ErrNotFound
	}
	return cloneTarget(t), nil
}

// CreateTarget добавляет цель.
func (m *Memory) CreateTarget(_ context.Context, t Target, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.targets {
		if x.OrgID == t.OrgID {
			n++
		}
	}
	if n >= MaxTargets {
		return ErrTooManyTargets
	}
	m.targets[t.ID] = cloneTarget(t)
	m.Records = append(m.Records, rec)
	return nil
}

// UpdateTarget меняет цель.
func (m *Memory) UpdateTarget(_ context.Context, t Target, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if x, ok := m.targets[t.ID]; !ok || x.OrgID != t.OrgID {
		return ErrNotFound
	}
	m.targets[t.ID] = cloneTarget(t)
	m.Records = append(m.Records, rec)
	return nil
}

// DeleteTarget удаляет цель; запуски остаются.
func (m *Memory) DeleteTarget(_ context.Context, orgID, id string, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if x, ok := m.targets[id]; !ok || x.OrgID != orgID {
		return ErrNotFound
	}
	delete(m.targets, id)
	for k, r := range m.runs {
		if r.TargetID == id {
			r.TargetID = ""
			m.runs[k] = r
		}
	}
	m.Records = append(m.Records, rec)
	return nil
}

// CreateRun добавляет запуск.
func (m *Memory) CreateRun(_ context.Context, r Run, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[r.ID] = cloneRun(r)
	m.Records = append(m.Records, rec)
	return nil
}

// FinishRun завершает запуск.
func (m *Memory) FinishRun(_ context.Context, r Run, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.runs[r.ID]
	if !ok || x.OrgID != r.OrgID {
		return ErrNotFound
	}
	if x.Status != RunQueued && x.Status != RunRunning {
		return ErrNotRunning
	}
	x.Status, x.Reason, x.Counts, x.FinishedAt = r.Status, r.Reason, maps.Clone(r.Counts), r.FinishedAt
	m.runs[r.ID] = x
	m.Records = append(m.Records, rec)
	return nil
}

// SaveResult сохраняет итог сценария.
func (m *Memory) SaveResult(_ context.Context, orgID string, res Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.runs[res.RunID]; !ok || r.OrgID != orgID {
		return ErrNotFound
	}
	m.results[res.RunID] = append(m.results[res.RunID], res)
	return nil
}

// Runs — запуски, новые первыми.
func (m *Memory) Runs(_ context.Context, orgID, targetID string, limit int) ([]Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Run{}
	for _, r := range m.runs {
		if r.OrgID == orgID && (targetID == "" || r.TargetID == targetID) {
			out = append(out, cloneRun(r))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt) || out[i].StartedAt.Equal(out[j].StartedAt) && out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Run — запуск по ID.
func (m *Memory) Run(_ context.Context, orgID, id string) (Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok || r.OrgID != orgID {
		return Run{}, ErrNotFound
	}
	return cloneRun(r), nil
}

// Results — итоги запуска по ID сценария.
func (m *Memory) Results(_ context.Context, orgID, runID string) ([]Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.runs[runID]; !ok || r.OrgID != orgID {
		return nil, ErrNotFound
	}
	out := slices.Clone(m.results[runID])
	sort.Slice(out, func(i, j int) bool { return out[i].ScenarioID < out[j].ScenarioID })
	return out, nil
}

// ActiveKeys — запуски с действующим ключом.
func (m *Memory) ActiveKeys(_ context.Context, orgID string, now time.Time) ([]Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Run
	for _, r := range m.runs {
		if r.OrgID == orgID && r.KeyPrefix != "" && (r.Status == RunQueued || r.Status == RunRunning) && r.Deadline.After(now) {
			out = append(out, cloneRun(r))
		}
	}
	return out, nil
}

// Interrupt завершает незавершённые запуски.
func (m *Memory) Interrupt(_ context.Context, orgID string, now time.Time, rec func(Run) audit.Entry) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, r := range m.runs {
		if r.OrgID == orgID && (r.Status == RunQueued || r.Status == RunRunning) {
			t := now
			r.Status, r.Reason, r.FinishedAt = RunFailed, ReasonInterrupted, &t
			m.runs[k] = r
			m.Records = append(m.Records, rec(cloneRun(r)))
			n++
		}
	}
	return n, nil
}

// Purge — очистка по срокам хранения.
func (m *Memory) Purge(_ context.Context, orgID string, results, runs time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.runs {
		if r.OrgID != orgID {
			continue
		}
		if r.FinishedAt != nil && r.FinishedAt.Before(runs) {
			delete(m.runs, id)
			delete(m.results, id)
			continue
		}
		if r.StartedAt.Before(results) {
			delete(m.results, id)
		}
	}
	return nil
}
