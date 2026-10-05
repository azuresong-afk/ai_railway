package events

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type memSink struct {
	mu     sync.Mutex
	n      uint64 // доставлено событий
	events []Event
	block  chan struct{}
	err    error
}

func (m *memSink) Send(_ context.Context, b []Event) error {
	if m.block != nil {
		<-m.block
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, b...)
	for range b {
		m.n++
	}
	return nil
}

func (m *memSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func ev(id string) Event {
	e := *request()
	e.ID = id
	return e
}

func TestQueueDeliversAndFlushesOnClose(t *testing.T) {
	sink := &memSink{}
	q := NewQueue(sink, QueueConfig{BatchSize: 10, FlushEach: time.Hour})
	for i := range 25 {
		if err := q.Enqueue(ev(string(rune('a' + i)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sink.count() != 25 || q.Dropped() != 0 {
		t.Fatalf("доставлено %d, отброшено %d", sink.count(), q.Dropped())
	}
	if err := q.Enqueue(ev("late")); err == nil || q.Dropped() != 1 {
		t.Fatal("после закрытия событие должно отбрасываться с учётом")
	}
}

func TestQueueDropsWhenFull(t *testing.T) {
	sink := &memSink{block: make(chan struct{})}
	q := NewQueue(sink, QueueConfig{Capacity: 5, BatchSize: 1, FlushEach: time.Hour})
	for i := range 50 {
		if err := q.Enqueue(ev(string(rune('a' + i)))); err != nil {
			t.Fatal(err)
		}
	}
	if q.Dropped() == 0 {
		t.Fatal("при переполнении события должны отбрасываться, а не блокировать запрос")
	}
	close(sink.block)
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	delivered := sink.n
	sink.mu.Unlock()
	if delivered+q.Dropped() != 50 {
		t.Fatalf("доставлено %d + отброшено %d ≠ 50", sink.count(), q.Dropped())
	}
}

func TestQueueRejectsInvalidAndCountsFailures(t *testing.T) {
	sink := &memSink{err: errors.New("получатель недоступен")}
	q := NewQueue(sink, QueueConfig{FlushEach: time.Hour})
	bad := ev("x")
	bad.Storage = StorageFull
	if err := q.Enqueue(bad); err == nil {
		t.Fatal("событие с режимом full должно отвергаться")
	}
	if err := q.Enqueue(ev("y")); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q.Failed() != 1 {
		t.Fatalf("неудачных отправок %d, ожидалась 1", q.Failed())
	}
}

func TestQueueCloseTimeout(t *testing.T) {
	sink := &memSink{block: make(chan struct{})}
	defer close(sink.block)
	q := NewQueue(sink, QueueConfig{BatchSize: 1, FlushEach: time.Hour})
	if err := q.Enqueue(ev("a")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := q.Close(ctx); err == nil {
		t.Fatal("ожидалась ошибка срока завершения")
	}
}

func TestFileSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), []Event{ev("a"), ev("b")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("права файла событий %o", info.Mode().Perm())
	}
	f, err := os.Open(path) //nolint:gosec // G304: путь во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("строк %d", n)
	}
	// Файл с широкими правами не используется.
	wide := filepath.Join(t.TempDir(), "wide.jsonl")
	if err := os.WriteFile(wide, nil, 0o644); err != nil { //nolint:gosec // G306: тест проверяет отказ от файла с широкими правами
		t.Fatal(err)
	}
	if _, err := NewFileSink(wide); err == nil {
		t.Fatal("файл с правами 0644 должен отвергаться")
	}
}
