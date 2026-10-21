package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Отправка событий на сервер управления (ТЗ 5.5, задача 2.15): POST
// /internal/v1/events:batch по mTLS тем же клиентом, что heartbeat. Шлюз
// работает автономно (ТЗ 4.2): недоступность сервера не блокирует запросы
// приложений — пакет ждёт повтора в events.Queue, новые события копятся в
// очереди, а при её переполнении отбрасываются со счётчиком (DM-44).

// Пределы отправителя.
const (
	// sinkAttempts — попыток отправить пакет за один вызов Send.
	sinkAttempts = 3
	// sinkPause — пауза между попытками (растёт вдвое).
	sinkPause = time.Second
	// sinkMaxRetryAfter — дольше Retry-After внутри Send не ждём: пакет
	// вернётся в очередь.
	sinkMaxRetryAfter = 5 * time.Second
	// SinkSendTimeout — срок Send со всеми попытками (для events.QueueConfig).
	SinkSendTimeout = sinkAttempts*controlTimeout + 2*sinkMaxRetryAfter
)

// ServerSinkConfig — параметры отправителя событий.
type ServerSinkConfig struct {
	// Client — HTTP-клиент с транспортом ControlTransport и сертификатом шлюза.
	Client *http.Client
	// Server — адрес внутреннего API (https://хост:8445).
	Server *url.URL
	Logger *slog.Logger
	Clock  func() time.Time
	// Sleep ждёт d или отмены ctx (тесты подменяют его).
	Sleep func(ctx context.Context, d time.Duration) bool
}

// ServerSink — events.Sink для сервера управления.
type ServerSink struct {
	client    *http.Client
	url       string
	logger    *slog.Logger
	sleep     func(ctx context.Context, d time.Duration) bool
	startedAt time.Time
	dropped   atomic.Pointer[func() uint64]
	rejected  atomic.Uint64
}

// NewServerSink создаёт отправителя.
func NewServerSink(c ServerSinkConfig) (*ServerSink, error) {
	if c.Client == nil || c.Server == nil {
		return nil, errors.New("отправитель событий: нет клиента или адреса сервера")
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = sleepCtx
	}
	return &ServerSink{
		client: c.Client, url: c.Server.JoinPath("/internal/v1/events:batch").String(), logger: c.Logger,
		sleep: c.Sleep, startedAt: c.Clock().UTC(),
	}, nil
}

// CountDropped подключает счётчик отброшенных событий очереди: он уходит
// на сервер в каждом пакете (stats.dropped).
func (s *ServerSink) CountDropped(f func() uint64) { s.dropped.Store(&f) }

// Rejected — события, которые сервер отверг (по одному или пакетом).
func (s *ServerSink) Rejected() uint64 { return s.rejected.Load() }

// Send отправляет пакет: до sinkAttempts попыток с паузой. Временная
// недоступность (сеть, 5xx, 429, 401) — events.ErrRetryLater: пакет
// останется в очереди. Отказ сервера в пакете (400, 413, 415, 422) — пакет
// не повторяется.
func (s *ServerSink) Send(ctx context.Context, batch []events.Event) error {
	if len(batch) == 0 {
		return nil
	}
	body, err := s.encode(batch)
	if err != nil {
		return err
	}
	if len(body) > events.MaxBatchBytes {
		if len(batch) == 1 {
			s.rejected.Add(1)
			return errors.New("событие больше предела пакета: не отправлено")
		}
		// Пакет делится пополам: события по отдельности укладываются в предел.
		half := len(batch) / 2
		return errors.Join(s.Send(ctx, batch[:half]), s.Send(ctx, batch[half:]))
	}
	pause := sinkPause
	var last error
	for attempt := 1; attempt <= sinkAttempts; attempt++ {
		var res events.BatchResult
		err := postControl(ctx, s.client, s.url, json.RawMessage(body), &res, http.StatusOK)
		if err == nil {
			s.accepted(batch, res)
			return nil
		}
		last = err
		var ce *controlError
		switch {
		case ctx.Err() != nil:
			return fmt.Errorf("%w: %w", events.ErrRetryLater, ctx.Err())
		case errors.As(err, &ce) && permanent(ce.Status):
			s.rejected.Add(uint64(len(batch)))
			return fmt.Errorf("сервер управления отверг пакет событий: %w", err)
		case errors.As(err, &ce) && ce.Status == http.StatusUnauthorized:
			s.logger.Error("сервер отклонил сертификат шлюза: события не принимаются; нужна повторная регистрация",
				"status", ce.Status)
			return fmt.Errorf("%w: %w", events.ErrRetryLater, err)
		case errors.As(err, &ce) && ce.RetryAfter > sinkMaxRetryAfter:
			return fmt.Errorf("%w: %w", events.ErrRetryLater, err)
		case errors.As(err, &ce) && ce.RetryAfter > 0:
			pause = max(pause, ce.RetryAfter)
		}
		if attempt < sinkAttempts && !s.sleep(ctx, pause) {
			break
		}
		pause *= 2
	}
	return fmt.Errorf("%w: %w", events.ErrRetryLater, last)
}

func (s *ServerSink) encode(batch []events.Event) ([]byte, error) {
	st := &events.SenderStats{StartedAt: s.startedAt, Rejected: s.rejected.Load()}
	if f := s.dropped.Load(); f != nil {
		st.Dropped = (*f)()
	}
	return json.Marshal(events.Batch{Events: batch, Stats: st})
}

// accepted учитывает ответ сервера: отклонённые события — в счётчик и
// журнал (только коды, без содержимого).
func (s *ServerSink) accepted(batch []events.Event, res events.BatchResult) {
	if len(res.Rejected) == 0 {
		return
	}
	s.rejected.Add(uint64(len(res.Rejected)))
	codes := map[string]int{}
	for _, r := range res.Rejected {
		if r.Index >= 0 && r.Index < len(batch) && len(r.Code) <= 32 {
			codes[r.Code]++
		}
	}
	s.logger.Warn("сервер управления отклонил события", "count", len(res.Rejected), "codes", codes)
}

// permanent — ответ, при котором повтор того же пакета бесполезен.
func permanent(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType,
		http.StatusUnprocessableEntity, http.StatusNotFound, http.StatusMethodNotAllowed:
		return true
	}
	return false
}
