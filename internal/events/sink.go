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

// Sink — получатель пакетов событий: сервер управления по mTLS (ТЗ, 4.1,
// 5.5, задача 2.15) или, без сервера, файл JSONL этапа 1. Шлюз зависит
// только от интерфейса. Send не сохраняет срез batch после возврата.
type Sink interface {
	Send(ctx context.Context, batch []Event) error
}

// ErrRetryLater — получатель временно недоступен (сеть, перегрузка, 5xx):
// пакет остаётся в очереди и отправляется повторно с растущей паузой. Любая
// другая ошибка значит, что пакет не будет принят никогда: он учитывается в
// Failed и отбрасывается.
var ErrRetryLater = errors.New("получатель событий временно недоступен")

// Queue — ограниченная очередь отправки событий (ТЗ, 4.4). Пока получатель
// недоступен, неотправленный пакет ждёт повтора, а новые события копятся в
// очереди; если очередь переполнена, событие отбрасывается и учитывается в
// счётчике: шлюз не блокирует запросы приложений из-за получателя.
type Queue struct {
	ch          chan Event
	done        chan struct{}
	sink        Sink
	logger      *slog.Logger
	batchSize   int
	flushEach   time.Duration
	sendTimeout time.Duration
	retryMin    time.Duration
	retryMax    time.Duration
	dropped     atomic.Uint64
	failed      atomic.Uint64
	wg          sync.WaitGroup
	closeOnce   sync.Once
	closed      atomic.Bool
	// closeCtx задаётся в Close до закрытия done и ограничивает досылку.
	closeCtx context.Context
}

// QueueConfig — параметры очереди.
type QueueConfig struct {
	Capacity  int           // по умолчанию 10 000
	BatchSize int           // по умолчанию 100
	FlushEach time.Duration // по умолчанию 1 с
	// SendTimeout — срок одной отправки пакета (с повторами внутри Sink);
	// по умолчанию 10 с.
	SendTimeout time.Duration
	// RetryMin и RetryMax — пауза перед повтором после ErrRetryLater:
	// растёт вдвое от RetryMin (1 с) до RetryMax (30 с).
	RetryMin time.Duration
	RetryMax time.Duration
	Logger   *slog.Logger
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
	if cfg.SendTimeout <= 0 {
		cfg.SendTimeout = 10 * time.Second
	}
	if cfg.RetryMin <= 0 {
		cfg.RetryMin = time.Second
	}
	if cfg.RetryMax < cfg.RetryMin {
		cfg.RetryMax = max(30*time.Second, cfg.RetryMin)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	q := &Queue{
		ch: make(chan Event, cfg.Capacity), done: make(chan struct{}), sink: sink, logger: cfg.Logger,
		batchSize: cfg.BatchSize, flushEach: cfg.FlushEach, sendTimeout: cfg.SendTimeout,
		retryMin: cfg.RetryMin, retryMax: cfg.RetryMax,
	}
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

// Dropped — число отброшенных событий: очередь переполнена или при остановке
// получатель недоступен (метрика и системное оповещение, DM-44).
func (q *Queue) Dropped() uint64 { return q.dropped.Load() }

// Failed — число событий, которые получатель отказался принять.
func (q *Queue) Failed() uint64 { return q.failed.Load() }

func (q *Queue) loop() {
	defer q.wg.Done()
	t := time.NewTicker(q.flushEach)
	defer t.Stop()
	batch := make([]Event, 0, q.batchSize)
	var backoff time.Duration
	for {
		if backoff > 0 {
			// Пакет ждёт повтора; новые события тем временем копятся в канале.
			wait := time.NewTimer(backoff)
			select {
			case <-wait.C:
				batch, backoff = q.flush(batch, backoff)
			case <-q.done:
				wait.Stop()
				q.shutdown(batch)
				return
			}
			continue
		}
		select {
		case e := <-q.ch:
			batch = append(batch, e)
			if len(batch) >= q.batchSize {
				batch, backoff = q.flush(batch, backoff)
			}
		case <-t.C:
			batch, backoff = q.flush(batch, backoff)
		case <-q.done:
			q.shutdown(batch)
			return
		}
	}
}

// flush отправляет пакет и возвращает остаток (пусто или тот же пакет для
// повтора) и паузу до повтора.
func (q *Queue) flush(batch []Event, backoff time.Duration) ([]Event, time.Duration) {
	if len(batch) == 0 {
		return batch, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), q.sendTimeout)
	err := q.sink.Send(ctx, batch)
	cancel()
	switch {
	case err == nil:
		return batch[:0], 0
	case errors.Is(err, ErrRetryLater):
		next := min(max(2*backoff, q.retryMin), q.retryMax)
		q.logger.Warn("события не отправлены, повтор позже", "count", len(batch), "retry_in", next.String(), "error", err)
		return batch, next
	default:
		q.failed.Add(uint64(len(batch)))
		q.logger.Error("получатель отказался принять события", "count", len(batch), "error", err)
		return batch[:0], 0
	}
}

// shutdown досылает ожидающий пакет и всё, что в очереди, в пределах срока
// Close. Что не удалось отправить, учитывается в Dropped или Failed.
func (q *Queue) shutdown(batch []Event) {
	ctx := q.closeCtx
	for {
		for len(batch) < q.batchSize {
			select {
			case e := <-q.ch:
				batch = append(batch, e)
				continue
			default:
			}
			break
		}
		if len(batch) == 0 {
			return
		}
		sctx, cancel := context.WithTimeout(ctx, q.sendTimeout)
		err := q.sink.Send(sctx, batch)
		cancel()
		switch {
		case err == nil:
		case errors.Is(err, ErrRetryLater) || ctx.Err() != nil:
			q.dropped.Add(uint64(len(batch)))
			q.logger.Warn("события не отправлены до остановки", "count", len(batch), "error", err)
		default:
			q.failed.Add(uint64(len(batch)))
			q.logger.Error("получатель отказался принять события", "count", len(batch), "error", err)
		}
		batch = batch[:0]
	}
}

// Close перестаёт принимать события и отправляет оставшиеся в пределах
// срока ctx (ТЗ, 4.4).
func (q *Queue) Close(ctx context.Context) error {
	q.closeOnce.Do(func() {
		q.closed.Store(true)
		q.closeCtx = ctx
		close(q.done)
	})
	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// События, поставленные одновременно с закрытием, уже не уйдут.
		for {
			select {
			case <-q.ch:
				q.dropped.Add(1)
				continue
			default:
			}
			return nil
		}
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
