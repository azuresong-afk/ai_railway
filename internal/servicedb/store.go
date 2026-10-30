package servicedb

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Слоты хранения: текущая и предыдущая версия (ADR-0028, п. 2).
const (
	SlotCurrent  = "current"
	SlotPrevious = "previous"
)

// Stored — сохранённая база: подписанный файл целиком и сведения о нём.
type Stored struct {
	Version      uint64
	Date         time.Time
	Records      int
	SubkeySerial uint64
	Fingerprint  string
	File         []byte
	UploadedAt   time.Time
	// UploadedBy — «тип:ID» субъекта загрузки.
	UploadedBy string
}

func (s *Stored) clone() *Stored {
	if s == nil {
		return nil
	}
	c := *s
	c.File = slices.Clone(s.File)
	return &c
}

// Slots — сохранённые версии одного вида; nil — слот пуст.
type Slots struct {
	Current  *Stored
	Previous *Stored
}

// Store — хранилище служебных баз (PGStore, Memory). Операции одного вида
// идут по одной (блокировка вида), запись аудита — в той же транзакции.
type Store interface {
	// Slots — сохранённые версии вида.
	Slots(ctx context.Context, orgID, kind string) (Slots, error)
	// Save записывает b текущей версией, если её номер больше текущей
	// сохранённой (иначе ErrStale). Прежняя текущая становится предыдущей,
	// если keep(прежняя) == nil; иначе (не проходит проверку) она
	// удаляется, а предыдущая остаётся. fn(прежняя текущая или nil) — запись
	// аудита той же транзакции.
	Save(ctx context.Context, orgID, kind string, b Stored, keep func(Stored) error, fn func(prev *Stored) audit.Entry) error
	// Rollback делает предыдущую версию текущей, если check(предыдущая) ==
	// nil; слот предыдущей пустеет, прежняя текущая удаляется. Нет
	// предыдущей — ErrNoPrevious; check вернул ошибку — она же. fn(прежняя
	// текущая или nil, новая текущая) — запись аудита той же транзакции.
	Rollback(ctx context.Context, orgID, kind string, check func(Stored) error, fn func(from *Stored, to Stored) audit.Entry) (Stored, error)
	// Record пишет запись аудита вне транзакции данных (отказ, проверка при
	// запуске).
	Record(ctx context.Context, rec audit.Entry) error
}

// Memory — Store в памяти для тестов модулей и API; правила — как у PGStore.
type Memory struct {
	mu      sync.Mutex
	slots   map[string]*Slots
	records []audit.Entry
}

// NewMemory — пустое хранилище.
func NewMemory() *Memory { return &Memory{slots: map[string]*Slots{}} }

// Records — записи аудита.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

// Put кладёт файл в слот без проверок — для тестов (подмена в БД).
func (m *Memory) Put(kind, slot string, s *Stored) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sl := m.slotsLocked(kind)
	if slot == SlotPrevious {
		sl.Previous = s.clone()
	} else {
		sl.Current = s.clone()
	}
}

func (m *Memory) slotsLocked(kind string) *Slots {
	sl, ok := m.slots[kind]
	if !ok {
		sl = &Slots{}
		m.slots[kind] = sl
	}
	return sl
}

// Slots — см. Store.
func (m *Memory) Slots(_ context.Context, _, kind string) (Slots, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sl := m.slotsLocked(kind)
	return Slots{Current: sl.Current.clone(), Previous: sl.Previous.clone()}, nil
}

// Save — см. Store.
func (m *Memory) Save(_ context.Context, _, kind string, b Stored, keep func(Stored) error, fn func(prev *Stored) audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sl := m.slotsLocked(kind)
	if sl.Current != nil && b.Version <= sl.Current.Version {
		return ErrStale
	}
	prev := sl.Current.clone()
	rec := fn(prev)
	if prev != nil && keep(*prev) == nil {
		sl.Previous = prev
	}
	sl.Current = b.clone()
	m.records = append(m.records, rec)
	return nil
}

// Rollback — см. Store.
func (m *Memory) Rollback(_ context.Context, _, kind string, check func(Stored) error, fn func(from *Stored, to Stored) audit.Entry) (Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sl := m.slotsLocked(kind)
	if sl.Previous == nil {
		return Stored{}, ErrNoPrevious
	}
	if err := check(*sl.Previous.clone()); err != nil {
		return Stored{}, err
	}
	m.records = append(m.records, fn(sl.Current.clone(), *sl.Previous.clone()))
	sl.Current, sl.Previous = sl.Previous, nil
	return *sl.Current.clone(), nil
}

// Record — см. Store.
func (m *Memory) Record(_ context.Context, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, rec)
	return nil
}
