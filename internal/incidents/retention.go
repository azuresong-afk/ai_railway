package incidents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Срок хранения закрытых инцидентов (3Н37 ревью 3.r2, ADR-0020, п. 5):
// закрытый инцидент хранится DefaultRetentionDays и затем удаляется
// фоновой задачей вместе с хронологией, комментариями, ссылками, этапами
// и связанными оповещениями; незакрытые не удаляются никогда.
const (
	DefaultRetentionDays = 1095
	MinRetentionDays     = 365
	MaxRetentionDays     = 1825
	// RetentionInterval — период фоновой очистки.
	RetentionInterval = time.Hour
	// retentionBatch — инцидентов в одной транзакции очистки.
	retentionBatch = 100
)

var (
	// ErrNotSetUp — первичная настройка не выполнена: строки настроек установки нет.
	ErrNotSetUp = errors.New("инциденты: первичная настройка не выполнена")
	// ErrConfirmRequired — сокращение срока без повторной проверки субъекта.
	ErrConfirmRequired = errors.New("сокращение срока хранения требует повторной проверки")
)

// RetentionStore — срок хранения и очистка (PGStore).
type RetentionStore interface {
	// RetentionDays — срок из настроек установки; нет строки — по умолчанию.
	RetentionDays(ctx context.Context, orgID string) (int, error)
	// SetRetentionDays меняет срок под блокировкой строки настроек: fn
	// получает прежний срок и возвращает запись аудита той же транзакции.
	SetRetentionDays(ctx context.Context, orgID string, days int, fn func(old int) (audit.Entry, error)) (int, error)
	// PurgeExpired удаляет одну пачку истёкших закрытых инцидентов;
	// возвращает число удалённых инцидентов.
	PurgeExpired(ctx context.Context, orgID string) (int, error)
}

// RetentionDays — см. RetentionStore.
func (s *PGStore) RetentionDays(ctx context.Context, orgID string) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var days int
	err := s.db.QueryRow(ctx, `SELECT incident_retention_days FROM install_settings WHERE org_id = $1`, orgID).Scan(&days)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultRetentionDays, nil
	}
	return days, err
}

// SetRetentionDays — см. RetentionStore.
func (s *PGStore) SetRetentionDays(ctx context.Context, orgID string, days int, fn func(old int) (audit.Entry, error)) (int, error) {
	var old int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT incident_retention_days FROM install_settings WHERE org_id = $1 FOR UPDATE`, orgID).Scan(&old)
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
		if _, err := tx.Exec(ctx, `UPDATE install_settings SET incident_retention_days = $2 WHERE org_id = $1`, orgID, days); err != nil {
			return err
		}
		rec.OrgID = orgID
		return s.audit.RecordTx(ctx, tx, rec)
	})
	return old, err
}

// PurgeExpired — см. RetentionStore. Триггеры миграции 0045 повторяют
// условие: роль сервера не удалит инцидент раньше срока даже прямым
// запросом. Инцидент, открытый заново, удаляется после следующего (его
// держит внешний ключ reopened_from), поэтому цепочка уходит за несколько
// пачек; инцидент с незакрытым оповещением (данные до миграции 0044)
// пропускается.
func (s *PGStore) PurgeExpired(ctx context.Context, orgID string) (int, error) {
	var n int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var days int
		if err := tx.QueryRow(ctx, `SELECT incident_retention_days($1)`, orgID).Scan(&days); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT i.id::text FROM incidents i WHERE i.org_id = $1 AND i.status = 'closed'
			AND i.closed_at < now() - make_interval(days => $2)
			AND NOT EXISTS (SELECT 1 FROM incidents r WHERE r.reopened_from = i.id)
			AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.incident_id = i.id AND a.status <> 'closed')
			ORDER BY i.closed_at, i.id LIMIT $3 FOR UPDATE OF i`, orgID, days, retentionBatch)
		if err != nil {
			return err
		}
		victims, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil || len(victims) == 0 {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT id::text FROM alerts WHERE incident_id = ANY($1::uuid[]) ORDER BY id FOR UPDATE`, victims)
		if err != nil {
			return err
		}
		alerts, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		// Сначала оповещения и их записи, затем записи инцидентов и сами
		// инциденты: внешние ключи проверяются к концу каждого запроса.
		var comments int64
		for _, d := range []struct {
			sql  string
			ids  []string
			rows *int64
		}{
			{`DELETE FROM alert_events WHERE alert_id = ANY($1::uuid[])`, alerts, nil},
			{`DELETE FROM alert_history WHERE alert_id = ANY($1::uuid[])`, alerts, nil},
			{`DELETE FROM alert_deliveries WHERE alert_id = ANY($1::uuid[])`, alerts, nil},
			{`DELETE FROM alerts WHERE id = ANY($1::uuid[])`, alerts, nil},
			{`DELETE FROM incident_timeline WHERE incident_id = ANY($1::uuid[])`, victims, nil},
			{`DELETE FROM incident_comments WHERE incident_id = ANY($1::uuid[])`, victims, &comments},
			{`DELETE FROM incident_events WHERE incident_id = ANY($1::uuid[])`, victims, nil},
			{`DELETE FROM incident_stages WHERE incident_id = ANY($1::uuid[])`, victims, nil},
			{`DELETE FROM incidents WHERE id = ANY($1::uuid[])`, victims, nil},
		} {
			tag, err := tx.Exec(ctx, d.sql, d.ids)
			if err != nil {
				return err
			}
			if d.rows != nil {
				*d.rows = tag.RowsAffected()
			}
		}
		n = len(victims)
		return s.audit.RecordTx(ctx, tx, audit.Entry{
			OrgID: orgID, Actor: systemBy.Actor, Action: "incident.retention", Object: audit.Object{Type: "incidents"},
			Result: audit.ResultSuccess, Details: map[string]any{"incidents": n, "alerts": len(alerts), "comments": comments,
				"retention_days": days},
		})
	})
	if err != nil {
		return 0, fmt.Errorf("инциденты: удаление по сроку хранения: %w", err)
	}
	return n, nil
}

// RetentionSettings — срок хранения закрытых инцидентов.
type RetentionSettings struct {
	RetentionDays int `json:"retention_days"`
}

// Retention — текущий срок хранения.
func (s *Service) Retention(ctx context.Context) (RetentionSettings, error) {
	if s.retention == nil {
		return RetentionSettings{RetentionDays: DefaultRetentionDays}, nil
	}
	d, err := s.retention.RetentionDays(ctx, s.orgID)
	return RetentionSettings{RetentionDays: d}, err
}

// SetRetention меняет срок хранения. Сокращение необратимо удаляет
// инциденты, поэтому требует повторной проверки паролем или кодом TOTP
// (как у оповещений) и пишется с weakening (DM-40).
func (s *Service) SetRetention(ctx context.Context, by By, days int) (RetentionSettings, error) {
	if days < MinRetentionDays || days > MaxRetentionDays {
		return RetentionSettings{}, &InputError{Errs: []error{fmt.Errorf("retention_days: от %d до %d суток", MinRetentionDays, MaxRetentionDays)}}
	}
	if s.retention == nil {
		return RetentionSettings{}, ErrNotSetUp
	}
	_, err := s.retention.SetRetentionDays(ctx, s.orgID, days, func(old int) (audit.Entry, error) {
		reduced := days < old
		if reduced {
			if by.Confirm == nil {
				return audit.Entry{}, ErrConfirmRequired
			}
			if err := by.Confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		reasons := []string{}
		if reduced {
			reasons = append(reasons, "retention_reduced")
		}
		e := by.entry("incident.settings_changed", s.orgID, map[string]any{
			"before": map[string]int{"retention_days": old}, "after": map[string]int{"retention_days": days},
			"weakening": reduced, "weakening_reasons": reasons})
		e.Object.Type = "incident_settings"
		return e, nil
	})
	if err != nil {
		return RetentionSettings{}, err
	}
	return RetentionSettings{RetentionDays: days}, nil
}

// RunRetention удаляет истёкшие инциденты сразу и затем каждые interval,
// пока не отменён ctx. Пачки идут подряд, пока очистка что-то удаляет:
// так цепочка повторных открытий уходит за один проход.
func RunRetention(ctx context.Context, st RetentionStore, orgID string, interval time.Duration, logger *slog.Logger) {
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
			n, err := st.PurgeExpired(ctx, orgID)
			if err != nil {
				if ctx.Err() == nil {
					logger.Error("инциденты: очистка по сроку хранения не выполнена", "class", "incidents", "error", err)
				}
				break
			}
			if n == 0 {
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
