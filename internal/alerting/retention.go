package alerting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Срок хранения закрытых оповещений (решение волны B этапа 3, ADR-0020):
// закрытые хранятся DefaultRetentionDays и затем удаляются фоновой задачей
// вместе со ссылками, историей и журналом доставки; открытые и «в работе» не
// удаляются никогда; связанные с инцидентом — по сроку инцидента (3.16).
const (
	DefaultRetentionDays = 365
	MinRetentionDays     = 90
	MaxRetentionDays     = 1825
	// RetentionInterval — период фоновой очистки.
	RetentionInterval = time.Hour
	// retentionBatch — оповещений в одной транзакции очистки.
	retentionBatch = 500
)

// ErrNotSetUp — первичная настройка не выполнена: строки настроек установки нет.
var ErrNotSetUp = errors.New("оповещения: первичная настройка не выполнена")

// RetentionStore — срок хранения и очистка (PGStore).
type RetentionStore interface {
	// RetentionDays — срок из настроек установки; нет строки — по умолчанию.
	RetentionDays(ctx context.Context) (int, error)
	// SetRetentionDays меняет срок под блокировкой строки настроек: fn
	// получает прежний срок и возвращает запись аудита той же транзакции.
	SetRetentionDays(ctx context.Context, days int, fn func(old int) (audit.Entry, error)) (int, error)
	// PurgeExpired удаляет одну пачку истёкших закрытых оповещений и
	// тестовых доставок; возвращает число удалённых оповещений.
	PurgeExpired(ctx context.Context) (int, error)
}

// RetentionDays — см. RetentionStore.
func (s *PGStore) RetentionDays(ctx context.Context) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var days int
	err := s.db.QueryRow(ctx, `SELECT alert_retention_days FROM install_settings WHERE org_id = $1`, s.orgID).Scan(&days)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultRetentionDays, nil
	}
	return days, err
}

// SetRetentionDays — см. RetentionStore.
func (s *PGStore) SetRetentionDays(ctx context.Context, days int, fn func(old int) (audit.Entry, error)) (int, error) {
	var old int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT alert_retention_days FROM install_settings WHERE org_id = $1 FOR UPDATE`, s.orgID).Scan(&old)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotSetUp
		}
		if err != nil {
			return err
		}
		rec, err := fn(old)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE install_settings SET alert_retention_days = $2 WHERE org_id = $1`, s.orgID, days); err != nil {
			return dbErr(err)
		}
		return s.audit.RecordTx(ctx, tx, rec)
	})
	return old, err
}

// PurgeExpired — см. RetentionStore. Триггеры миграции 0032 повторяют
// условие: роль сервера не удалит оповещение раньше срока даже прямым
// запросом.
func (s *PGStore) PurgeExpired(ctx context.Context) (int, error) {
	var n int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var days int
		if err := tx.QueryRow(ctx, `SELECT alert_retention_days($1)`, s.orgID).Scan(&days); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text FROM alerts WHERE org_id = $1 AND status = 'closed' AND incident_id IS NULL
			AND closed_at < now() - make_interval(days => $2) ORDER BY closed_at, id LIMIT $3 FOR UPDATE`, s.orgID, days, retentionBatch)
		if err != nil {
			return err
		}
		victims, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		// Тестовые отправки журнала доставки (задача 3.13) — по тому же сроку.
		tests, err := tx.Exec(ctx, `DELETE FROM alert_deliveries WHERE org_id = $1 AND alert_id IS NULL
			AND created_at < now() - make_interval(days => $2)`, s.orgID, days)
		if err != nil {
			return dbErr(err)
		}
		if len(victims) == 0 && tests.RowsAffected() == 0 {
			return nil
		}
		for _, q := range []string{
			`DELETE FROM alert_events WHERE alert_id = ANY($1::uuid[])`,
			`DELETE FROM alert_history WHERE alert_id = ANY($1::uuid[])`,
			`DELETE FROM alert_deliveries WHERE alert_id = ANY($1::uuid[])`,
			`DELETE FROM alerts WHERE id = ANY($1::uuid[])`,
		} {
			if _, err := tx.Exec(ctx, q, victims); err != nil {
				return dbErr(err)
			}
		}
		n = len(victims)
		return s.audit.RecordTx(ctx, tx, audit.Entry{
			OrgID: s.orgID, Actor: systemBy.Actor, Action: "alert.retention", Object: audit.Object{Type: "alerts"},
			Result: audit.ResultSuccess, Details: map[string]any{"alerts": n, "test_deliveries": tests.RowsAffected(),
				"retention_days": days},
		})
	})
	if err != nil {
		return 0, fmt.Errorf("оповещения: удаление по сроку хранения: %w", err)
	}
	return n, nil
}

// RetentionSettings — срок хранения закрытых оповещений.
type RetentionSettings struct {
	RetentionDays int `json:"retention_days"`
}

// Retention — текущий срок хранения.
func (s *Service) Retention(ctx context.Context) (RetentionSettings, error) {
	if s.retention == nil {
		return RetentionSettings{RetentionDays: DefaultRetentionDays}, nil
	}
	d, err := s.retention.RetentionDays(ctx)
	return RetentionSettings{RetentionDays: d}, err
}

// SetRetention меняет срок хранения (право alert_rules.manage). Сокращение
// необратимо удаляет оповещения, поэтому требует повторной проверки
// паролем или кодом TOTP (как В13 этапа 2) и пишется с weakening (DM-40).
func (s *Service) SetRetention(ctx context.Context, by By, days int) (RetentionSettings, error) {
	if days < MinRetentionDays || days > MaxRetentionDays {
		return RetentionSettings{}, &InputError{Errs: []error{fmt.Errorf("retention_days: от %d до %d суток", MinRetentionDays, MaxRetentionDays)}}
	}
	if s.retention == nil {
		return RetentionSettings{}, ErrNotSetUp
	}
	_, err := s.retention.SetRetentionDays(ctx, days, func(old int) (audit.Entry, error) {
		reduced := days < old
		if reduced {
			if err := by.confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		reasons := []string{}
		if reduced {
			reasons = append(reasons, "retention_reduced")
		}
		return by.entry("alert.settings_changed", "alert_settings", s.orgID, map[string]any{
			"before": map[string]int{"retention_days": old}, "after": map[string]int{"retention_days": days},
			"weakening": reduced, "weakening_reasons": reasons}), nil
	})
	if err != nil {
		return RetentionSettings{}, err
	}
	return RetentionSettings{RetentionDays: days}, nil
}

// RunRetention удаляет истёкшие оповещения сразу и затем каждые interval,
// пока не отменён ctx. Пачки идут подряд, пока очередь не опустеет.
func RunRetention(ctx context.Context, st RetentionStore, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = RetentionInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for ctx.Err() == nil {
			n, err := st.PurgeExpired(ctx)
			if err != nil {
				if ctx.Err() == nil {
					logger.Error("оповещения: очистка по сроку хранения не выполнена", "class", "alerts", "error", err)
				}
				break
			}
			if n < retentionBatch {
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
