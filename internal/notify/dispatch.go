package notify

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Повторы доставки (ADR-0020 п. 9): MaxAttempts попыток с задержкой
// 30 с · 4^(n−1), не больше 10 минут: 30 с, 2 мин, 8 мин, 10 мин.
const (
	MaxAttempts  = 5
	firstBackoff = 30 * time.Second
	maxBackoff   = 10 * time.Minute
	// DispatchInterval — период опроса очереди доставки.
	DispatchInterval = 5 * time.Second
	// dispatchBatch — доставок за один опрос.
	dispatchBatch = 20
	// dispatchLease — срок, на который доставка откладывается при выборке:
	// больше предела одной попытки (DefaultSendTimeout), повтор — только
	// если сервер остановился.
	dispatchLease = 2 * time.Minute
)

// Backoff — задержка перед следующей попыткой после attempts неудачных.
func Backoff(attempts int) time.Duration {
	d := firstBackoff
	for i := 1; i < attempts && d < maxBackoff; i++ {
		d *= 4
	}
	return min(d, maxBackoff)
}

// systemActor — субъект записей фоновой доставки.
var systemActor = audit.Actor{Type: audit.ActorSystem, ID: "aisec-server", Name: "aisec-server"}

// DispatchOnce выполняет одну попытку для доставок, срок которых наступил;
// возвращает число обработанных. Окончательный отказ пишет
// notify.delivery_failed: из него правило DM-44 поднимает оповещение.
func (s *Service) DispatchOnce(ctx context.Context) (int, error) {
	// Доставки выбираются по одной: отсрочка lease покрывает одну попытку,
	// а не всю пачку.
	n := 0
	for n < dispatchBatch {
		due, err := s.store.ClaimDue(ctx, dispatchLease, 1)
		if err != nil {
			return n, err
		}
		if len(due) == 0 {
			break
		}
		if err := s.deliver(ctx, due[0]); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *Service) deliver(ctx context.Context, d Delivery) error {
	c, err := s.store.Channel(ctx, d.ChannelID)
	if err != nil {
		return err
	}
	if !c.Enabled {
		// Канал отключён после постановки в очередь: отключение уже в
		// аудите с weakening, повторов и отдельного оповещения не нужно.
		d.Status, d.Error, d.UpdatedAt = StatusFailed, ErrCodeDisabled, s.now().UTC()
		return s.store.FinishDelivery(ctx, d, nil)
	}
	msg, sendErr := s.store.AlertMessage(ctx, d.AlertID)
	if errors.Is(sendErr, ErrNotFound) {
		d.Status, d.Error, d.UpdatedAt = StatusFailed, ErrCodeInternal, s.now().UTC()
		return s.store.FinishDelivery(ctx, d, nil)
	}
	if sendErr == nil {
		var sec Secrets
		if sec, sendErr = s.secrets(ctx, c); sendErr == nil {
			sendErr = s.transport.Send(ctx, c, sec, msg)
		} else {
			sendErr = failed(ErrCodeConfig)
		}
	}
	if ctx.Err() != nil {
		// Остановка сервера: попытка не засчитывается, повтор после lease.
		return ctx.Err()
	}
	now := s.now().UTC()
	d.Attempts++
	d.UpdatedAt = now
	if sendErr == nil {
		d.Status, d.Error, d.SentAt = StatusSent, "", now
		return s.store.FinishDelivery(ctx, d, nil)
	}
	d.Error = ErrorCode(sendErr)
	if d.Attempts < MaxAttempts {
		d.NextAt = now.Add(Backoff(d.Attempts))
		return s.store.FinishDelivery(ctx, d, nil)
	}
	d.Status = StatusFailed
	rec := audit.Entry{OrgID: s.orgID, Actor: systemActor, Action: "notify.delivery_failed",
		Object: audit.Object{Type: "notify_channel", ID: c.ID}, Result: audit.ResultFailure,
		Details: map[string]any{"channel_name": c.Name, "type": c.Type, "delivery_id": d.ID, "alert_id": d.AlertID,
			"attempts": d.Attempts, "error": d.Error}}
	return s.store.FinishDelivery(ctx, d, &rec)
}

// RunDispatcher доставляет уведомления из очереди каждые interval, пока не
// отменён ctx. Ошибки пишутся в технический журнал без адресов и секретов.
func (s *Service) RunDispatcher(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = DispatchInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for ctx.Err() == nil {
			n, err := s.DispatchOnce(ctx)
			if err != nil {
				if ctx.Err() == nil {
					logger.Error("уведомления: доставка не выполнена", "class", "notify", "error", err)
				}
				break
			}
			if n < dispatchBatch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
