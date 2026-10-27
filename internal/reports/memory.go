package reports

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов.
type Memory struct {
	mu        sync.Mutex
	schedules []Schedule
	runs      []Run
	audited   []audit.Entry
	// RecordErr — ошибка записи аудита Record (тесты 3В32).
	RecordErr error
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory { return &Memory{} }

// Audited — записи аудита, сделанные хранилищем.
func (m *Memory) Audited() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.audited)
}

func (m *Memory) find(id string) int {
	return slices.IndexFunc(m.schedules, func(s Schedule) bool { return s.ID == id })
}

// Schedules — см. Store.
func (m *Memory) Schedules(context.Context) ([]Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.schedules), nil
}

// Schedule — см. Store.
func (m *Memory) Schedule(_ context.Context, id string) (Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i := m.find(id); i >= 0 {
		return m.schedules[i], nil
	}
	return Schedule{}, ErrNotFound
}

// CreateSchedule — см. Store.
func (m *Memory) CreateSchedule(_ context.Context, s Schedule, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.schedules) >= MaxSchedules {
		return ErrTooMany
	}
	for _, x := range m.schedules {
		if x.Name == s.Name {
			return &InputError{Fields: map[string]string{"name": "Расписание с таким названием уже есть."}}
		}
	}
	m.schedules = append(m.schedules, s)
	m.audited = append(m.audited, rec)
	return nil
}

// UpdateSchedule — см. Store.
func (m *Memory) UpdateSchedule(_ context.Context, id string, fn func(Schedule) (Schedule, audit.Entry, error)) (Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.find(id)
	if i < 0 {
		return Schedule{}, ErrNotFound
	}
	n, rec, err := fn(m.schedules[i])
	if err != nil {
		return Schedule{}, err
	}
	m.schedules[i] = n
	m.audited = append(m.audited, rec)
	return n, nil
}

// DeleteSchedule — см. Store.
func (m *Memory) DeleteSchedule(_ context.Context, id string, rec func(Schedule) audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.find(id)
	if i < 0 {
		return ErrNotFound
	}
	m.audited = append(m.audited, rec(m.schedules[i]))
	m.schedules = slices.Delete(m.schedules, i, i+1)
	m.runs = slices.DeleteFunc(m.runs, func(r Run) bool { return r.ScheduleID == id })
	return nil
}

// Runs — см. Store.
func (m *Memory) Runs(_ context.Context, id string, limit int) ([]Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Run
	for i := len(m.runs) - 1; i >= 0 && len(out) < limit; i-- {
		if m.runs[i].ScheduleID == id {
			out = append(out, m.runs[i])
		}
	}
	return out, nil
}

// EnqueueDue — см. Store.
func (m *Memory) EnqueueDue(_ context.Context, now time.Time, limit int, plan func(Schedule) (Run, time.Time, error)) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for i := range m.schedules {
		s := m.schedules[i]
		if n >= limit || !s.Enabled || s.NextRunAt.After(now) {
			continue
		}
		r, next, err := plan(s)
		if err != nil {
			return n, err
		}
		m.runs = append(m.runs, r)
		m.schedules[i].NextRunAt, m.schedules[i].LastRunAt = next, r.DueAt
		n++
	}
	return n, nil
}

// ClaimRun — см. Store.
func (m *Memory) ClaimRun(_ context.Context, now time.Time, lease time.Duration) (Run, Schedule, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.runs {
		r := &m.runs[i]
		if r.Status == RunPending && !r.NextAt.After(now) {
			r.NextAt = now.Add(lease)
			if r.Attempts >= MaxAttempts {
				r.Error = ErrCodeExhausted
			} else {
				r.Attempts++
			}
			out := *r
			return out, m.schedules[m.find(r.ScheduleID)], true, nil
		}
	}
	return Run{}, Schedule{}, false, nil
}

// Record — см. Store.
func (m *Memory) Record(_ context.Context, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.RecordErr != nil {
		return m.RecordErr
	}
	m.audited = append(m.audited, rec)
	return nil
}

// FinishRun — см. Store.
func (m *Memory) FinishRun(_ context.Context, r Run, rec *audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.runs {
		if m.runs[i].ID == r.ID {
			m.runs[i] = r
		}
	}
	if rec != nil {
		m.audited = append(m.audited, *rec)
	}
	return nil
}
