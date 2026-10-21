package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Агрегаты событий по минутам и часам для дашбордов (ТЗ 5.5, 5.8; задача
// 2.16) считает фоновое задание, а не запрос дашборда. Задание находит
// минуты, в которые попали события, принятые после прошлого запуска, и
// пересчитывает эти минуты целиком из events, а их часы — из минутных
// агрегатов. Строка агрегата заменяется, а не увеличивается, поэтому
// повторный пересчёт даёт тот же результат, а позднее событие (шлюз
// досылал очередь) просто делает свою минуту «грязной» ещё раз.

// Параметры задания агрегатов.
const (
	// AggregateEvery — период задания.
	AggregateEvery = time.Minute
	// AggregateTimeout — предел одного запуска.
	AggregateTimeout = 30 * time.Second
	// aggregateLag — события, принятые позже now-aggregateLag, ждут
	// следующего запуска: их транзакции приёма могут быть ещё не
	// зафиксированы (предел приёма пакета — 15 с).
	aggregateLag = time.Minute
	// aggregateChunk — наибольшее окно времени приёма за один запуск:
	// после простоя задание догоняет частями.
	aggregateChunk = 6 * time.Hour
	// aggregateLookback — события старше не принимаются (MaxEventAge) и
	// пересчёта не требуют; ограничивает секции, которые читает задание.
	aggregateLookback = 8 * 24 * time.Hour
	// MinuteAggregateDays — срок хранения минутных агрегатов; часовые
	// хранятся столько же, сколько метаданные событий.
	MinuteAggregateDays = 31
	// aggregateLockID — ключ pg_try_advisory_xact_lock: два сервера не
	// пересчитывают одновременно.
	aggregateLockID int64 = 0x6169_7365_6361_6767 // «aisecagg»
)

// Интервалы агрегатов.
const (
	IntervalMinute = "minute"
	IntervalHour   = "hour"
)

// Пределы чтения агрегатов.
const (
	MaxMinuteRange = 24 * time.Hour
	MaxHourRange   = MaxQueryRange
	MaxStatsRows   = 10_000
)

// ErrTooManyRows — выборка больше допустимого: нужно сузить период или фильтр.
var ErrTooManyRows = errors.New("выборка больше допустимого числа строк")

// Aggregate — строка агрегата за интервал.
type Aggregate struct {
	Bucket           time.Time        `json:"bucket"`
	App              string           `json:"app"`
	Type             string           `json:"type"`
	Action           string           `json:"action"`
	Severity         string           `json:"severity"`
	Events           int64            `json:"events"`
	WithFindings     int64            `json:"with_findings"`
	NonTextUnchecked int64            `json:"non_text_unchecked"`
	TokensPrompt     int64            `json:"tokens_prompt"`
	TokensCompletion int64            `json:"tokens_completion"`
	Threats          map[string]int64 `json:"threats"`
}

// StatsQuery — чтение агрегатов за [From, To) по интервалу; App — только
// одно приложение (пусто — все).
type StatsQuery struct {
	Interval string
	From, To time.Time
	App      string
}

// Validate проверяет интервал и период.
func (q *StatsQuery) Validate() error {
	limit := MaxHourRange
	switch q.Interval {
	case IntervalMinute:
		limit = MaxMinuteRange
	case IntervalHour:
	default:
		return errors.New("интервал агрегатов: minute или hour")
	}
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) || q.To.Sub(q.From) > limit {
		return ErrBadRange
	}
	if len(q.App) > MaxFilterValue {
		return errors.New("имя приложения длиннее допустимого")
	}
	return nil
}

// StatsReader — чтение агрегатов.
type StatsReader interface {
	// Aggregates — строки агрегатов по возрастанию интервала; больше
	// MaxStatsRows — ErrTooManyRows.
	Aggregates(ctx context.Context, q StatsQuery) ([]Aggregate, error)
}

// aggregateTable — таблица интервала (константа кода, не ввод).
func aggregateTable(interval string) string {
	if interval == IntervalMinute {
		return "event_aggregates_minute"
	}
	return "event_aggregates_hour"
}

// Aggregates — см. StatsReader.
func (s *PGStore) Aggregates(ctx context.Context, q StatsQuery) ([]Aggregate, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	sql := "SELECT bucket, app, type, action, severity, events, with_findings, non_text_unchecked," +
		" tokens_prompt, tokens_completion, threats FROM " + aggregateTable(q.Interval) +
		" WHERE org_id = $1 AND bucket >= $2 AND bucket < $3 AND ($4 = '' OR app = $4)" +
		" ORDER BY bucket, app, type, action, severity LIMIT $5"
	rows, err := s.db.Query(ctx, sql, s.orgID, q.From.UTC(), q.To.UTC(), q.App, MaxStatsRows+1)
	if err != nil {
		return nil, dbError("агрегаты событий", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Aggregate, error) {
		var a Aggregate
		err := row.Scan(&a.Bucket, &a.App, &a.Type, &a.Action, &a.Severity, &a.Events, &a.WithFindings,
			&a.NonTextUnchecked, &a.TokensPrompt, &a.TokensCompletion, &a.Threats)
		a.Bucket = a.Bucket.UTC()
		return a, err
	})
	if err != nil {
		return nil, dbError("агрегаты событий", err)
	}
	if len(out) > MaxStatsRows {
		return nil, ErrTooManyRows
	}
	return out, nil
}

// Пересчёт минут: события «грязных» минут из events (диапазон по ts —
// отсечение секций и индекс events_org_ts), группировка по измерениям,
// угрозы — отдельной группировкой по unnest(threats). Строка заменяется.
const aggregateMinutes = `WITH d AS (SELECT DISTINCT unnest($2::timestamptz[]) AS b),
base AS (
	SELECT d.b, COALESCE(e.app, '') AS app, e.type, COALESCE(e.action, '') AS action,
		COALESCE(e.severity, '') AS severity, e.threats, e.non_text_unchecked,
		jsonb_array_length(COALESCE(e.details->'findings', '[]'::jsonb)) > 0 AS with_findings,
		COALESCE((e.details->'tokens'->>'prompt')::bigint, 0) AS tp,
		COALESCE((e.details->'tokens'->>'completion')::bigint, 0) AS tc
	FROM d JOIN events e ON e.org_id = $1 AND e.ts >= d.b AND e.ts < d.b + interval '1 minute'
),
main AS (
	SELECT b, app, type, action, severity, count(*) AS events,
		count(*) FILTER (WHERE with_findings) AS with_findings,
		count(*) FILTER (WHERE non_text_unchecked) AS non_text_unchecked,
		sum(tp) AS tokens_prompt, sum(tc) AS tokens_completion
	FROM base GROUP BY b, app, type, action, severity
),
thr AS (
	SELECT b, app, type, action, severity, jsonb_object_agg(t, n) AS threats
	FROM (SELECT b, app, type, action, severity, t, count(*) AS n
		FROM base CROSS JOIN LATERAL unnest(base.threats) AS t
		GROUP BY b, app, type, action, severity, t) AS x
	GROUP BY b, app, type, action, severity
)
INSERT INTO event_aggregates_minute (org_id, bucket, app, type, action, severity, events, with_findings,
	non_text_unchecked, tokens_prompt, tokens_completion, threats)
SELECT $1, m.b, m.app, m.type, m.action, m.severity, m.events, m.with_findings, m.non_text_unchecked,
	m.tokens_prompt, m.tokens_completion, COALESCE(t.threats, '{}'::jsonb)
FROM main m LEFT JOIN thr t USING (b, app, type, action, severity)
ON CONFLICT (org_id, bucket, app, type, action, severity) DO UPDATE SET
	events = EXCLUDED.events, with_findings = EXCLUDED.with_findings,
	non_text_unchecked = EXCLUDED.non_text_unchecked, tokens_prompt = EXCLUDED.tokens_prompt,
	tokens_completion = EXCLUDED.tokens_completion, threats = EXCLUDED.threats`

// Пересчёт часов из минутных агрегатов тех же «грязных» минут.
const aggregateHours = `WITH d AS (SELECT DISTINCT date_trunc('hour', b) AS h FROM unnest($2::timestamptz[]) AS b),
m AS (
	SELECT d.h, a.app, a.type, a.action, a.severity, a.events, a.with_findings, a.non_text_unchecked,
		a.tokens_prompt, a.tokens_completion, a.threats
	FROM d JOIN event_aggregates_minute a ON a.org_id = $1 AND a.bucket >= d.h AND a.bucket < d.h + interval '1 hour'
),
main AS (
	SELECT h, app, type, action, severity, sum(events) AS events, sum(with_findings) AS with_findings,
		sum(non_text_unchecked) AS non_text_unchecked, sum(tokens_prompt) AS tokens_prompt,
		sum(tokens_completion) AS tokens_completion
	FROM m GROUP BY h, app, type, action, severity
),
thr AS (
	SELECT h, app, type, action, severity, jsonb_object_agg(k, n) AS threats
	FROM (SELECT h, app, type, action, severity, j.key AS k, sum(j.value::bigint) AS n
		FROM m CROSS JOIN LATERAL jsonb_each_text(m.threats) AS j
		GROUP BY h, app, type, action, severity, j.key) AS x
	GROUP BY h, app, type, action, severity
)
INSERT INTO event_aggregates_hour (org_id, bucket, app, type, action, severity, events, with_findings,
	non_text_unchecked, tokens_prompt, tokens_completion, threats)
SELECT $1, m.h, m.app, m.type, m.action, m.severity, m.events, m.with_findings, m.non_text_unchecked,
	m.tokens_prompt, m.tokens_completion, COALESCE(t.threats, '{}'::jsonb)
FROM main m LEFT JOIN thr t USING (h, app, type, action, severity)
ON CONFLICT (org_id, bucket, app, type, action, severity) DO UPDATE SET
	events = EXCLUDED.events, with_findings = EXCLUDED.with_findings,
	non_text_unchecked = EXCLUDED.non_text_unchecked, tokens_prompt = EXCLUDED.tokens_prompt,
	tokens_completion = EXCLUDED.tokens_completion, threats = EXCLUDED.threats`

// AggregateResult — итог запуска задания агрегатов.
type AggregateResult struct {
	// Skipped — пересчёт уже идёт в другом процессе.
	Skipped bool
	// Minutes — число пересчитанных минут.
	Minutes int
	// Upto — новая отметка: учтены события, принятые не позже неё.
	Upto time.Time
}

// Aggregate выполняет один запуск задания: пересчитывает минуты и часы
// событий, принятых после прошлой отметки, сдвигает отметку и удаляет
// агрегаты старше сроков хранения. Всё — одной транзакцией.
func (s *PGStore) Aggregate(ctx context.Context) (AggregateResult, error) {
	ctx, cancel := context.WithTimeout(ctx, AggregateTimeout)
	defer cancel()
	var res AggregateResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		res = AggregateResult{}
		var locked bool
		if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", aggregateLockID).Scan(&locked); err != nil {
			return dbError("блокировка агрегатов", err)
		}
		if !locked {
			res.Skipped = true
			return nil
		}
		var from, now time.Time
		var metaDays int
		if err := tx.QueryRow(ctx, `SELECT a.received_upto, now(), s.metadata_days
			FROM event_aggregate_state a, event_settings s FOR UPDATE OF a`).Scan(&from, &now, &metaDays); err != nil {
			return dbError("отметка агрегатов", err)
		}
		upto := now.Add(-aggregateLag)
		if chunk := from.Add(aggregateChunk); chunk.Before(upto) {
			upto = chunk
		}
		res.Upto = from
		if !upto.After(from) {
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT date_trunc('minute', ts) FROM events
			WHERE org_id = $1 AND ts >= $2 AND received_at > $3 AND received_at <= $4`,
			s.orgID, now.Add(-aggregateLookback), from, upto)
		if err != nil {
			return dbError("поиск изменённых минут", err)
		}
		minutes, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
		if err != nil {
			return dbError("поиск изменённых минут", err)
		}
		if len(minutes) > 0 {
			if _, err := tx.Exec(ctx, aggregateMinutes, s.orgID, minutes); err != nil {
				return dbError("агрегаты по минутам", err)
			}
			if _, err := tx.Exec(ctx, aggregateHours, s.orgID, minutes); err != nil {
				return dbError("агрегаты по часам", err)
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE event_aggregate_state SET received_upto = $1", upto); err != nil {
			return dbError("отметка агрегатов", err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM event_aggregates_minute WHERE org_id = $1 AND bucket < $2",
			s.orgID, now.AddDate(0, 0, -MinuteAggregateDays)); err != nil {
			return dbError("срок минутных агрегатов", err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM event_aggregates_hour WHERE org_id = $1 AND bucket < $2",
			s.orgID, now.AddDate(0, 0, -metaDays)); err != nil {
			return dbError("срок часовых агрегатов", err)
		}
		res.Minutes, res.Upto = len(minutes), upto
		return nil
	})
	if err != nil {
		return AggregateResult{}, fmt.Errorf("агрегаты событий: %w", err)
	}
	return res, nil
}

// Aggregator — задание агрегатов (PGStore).
type Aggregator interface {
	Aggregate(ctx context.Context) (AggregateResult, error)
}

// RunAggregates запускает задание каждые every до отмены ctx. После простоя
// задание догоняет частями по aggregateChunk — запуски идут подряд, пока
// отметка не дойдёт до текущего времени. Сбой пишется в журнал; следующий
// запуск — по расписанию.
func RunAggregates(ctx context.Context, a Aggregator, every time.Duration, logger *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for range 64 { // не больше 64 частей подряд (16 суток), дальше — по таймеру
			res, err := a.Aggregate(ctx)
			if err != nil {
				if ctx.Err() == nil {
					logger.Error("агрегаты событий не пересчитаны", "error", err)
				}
				break
			}
			if res.Skipped || time.Since(res.Upto) < aggregateChunk {
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

// statsKey — ключ строки агрегата (хранилище Memory).
func statsKey(b time.Time, r *Record) string {
	return strings.Join([]string{b.Format(time.RFC3339), r.App, r.Type, r.Action, r.Severity}, "\x00")
}
