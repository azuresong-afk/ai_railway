package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Sink — получатель пакетов событий. На этапе 1 — файл JSONL, с этапа 2 —
// сервер управления по mTLS (ТЗ, 4.1, 5.5). Шлюз зависит только от интерфейса.
type Sink interface {
	Send(ctx context.Context, batch []Event) error
}

// Queue — ограниченная очередь отправки событий (ТЗ, 4.4). Если очередь
// переполнена, событие отбрасывается и учитывается в счётчике: шлюз не
// должен блокировать запросы приложений из-за медленного получателя.
type Queue struct {
	ch        chan Event
	sink      Sink
	logger    *slog.Logger
	batchSize int
	flushEach time.Duration
	dropped   atomic.Uint64
	failed    atomic.Uint64
	wg        sync.WaitGroup
	closeOnce sync.Once
	closed    atomic.Bool
}

// QueueConfig — параметры очереди.
type QueueConfig struct {
	Capacity  int           // по умолчанию 10 000
	BatchSize int           // по умолчанию 100
	FlushEach time.Duration // по умолчанию 1 с
	Logger    *slog.Logger
}

// NewQueue запускает фоновую отправку.
func NewQueue(sink Sink, cfg QueueConfig) *Queue {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 10_000
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushEach <= 0 {
		cfg.FlushEach = time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	q := &Queue{ch: make(chan Event, cfg.Capacity), sink: sink, logger: cfg.Logger, batchSize: cfg.BatchSize, flushEach: cfg.FlushEach}
	q.wg.Add(1)
	go q.loop()
	return q
}

// Enqueue ставит событие в очередь без ожидания. Событие с ошибками схемы не
// принимается: это ошибка кода, а не данных.
func (q *Queue) Enqueue(e Event) error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("событие %s: %w", e.ID, err)
	}
	if q.closed.Load() {
		q.dropped.Add(1)
		return errors.New("очередь событий закрыта")
	}
	select {
	case q.ch <- e:
		return nil
	default:
		q.dropped.Add(1)
		return nil
	}
}

// Dropped — число отброшенных событий (метрика и системное оповещение, DM-44).
func (q *Queue) Dropped() uint64 { return q.dropped.Load() }

// Failed — число событий, которые получатель не принял.
func (q *Queue) Failed() uint64 { return q.failed.Load() }

func (q *Queue) loop() {
	defer q.wg.Done()
	t := time.NewTicker(q.flushEach)
	defer t.Stop()
	batch := make([]Event, 0, q.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := q.sink.Send(ctx, batch)
		cancel()
		if err != nil {
			q.failed.Add(uint64(len(batch)))
			q.logger.Error("события не отправлены", "count", len(batch), "error", err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-q.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= q.batchSize {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// Close перестаёт принимать события и отправляет оставшиеся (ТЗ, 4.4).
func (q *Queue) Close(ctx context.Context) error {
	q.closeOnce.Do(func() {
		q.closed.Store(true)
		close(q.ch)
	})
	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("очередь событий: не всё отправлено до завершения: %w", ctx.Err())
	}
}

// FileSink — приёмник-заглушка этапа 1: события пишутся строками JSON в файл
// с правами 0600. Для разработки и тестов; не способ хранения в поставке.
type FileSink struct {
	mu sync.Mutex
	f  *os.File
}

// NewFileSink открывает файл на дозапись. Файл создаётся с правами 0600;
// существующий файл с более широкими правами не используется.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // G304: путь задаёт администратор в конфигурации
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(fmt.Errorf("%s: файл событий доступен группе или остальным (права %o)", path, info.Mode().Perm()), f.Close())
	}
	return &FileSink{f: f}, nil
}

// Send дописывает пакет в файл.
func (s *FileSink) Send(_ context.Context, batch []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	enc := json.NewEncoder(s.f)
	for i := range batch {
		if err := enc.Encode(&batch[i]); err != nil {
			return err
		}
	}
	return s.f.Sync()
}

// Close закрывает файл.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
