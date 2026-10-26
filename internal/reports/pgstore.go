package reports

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

const (
	pgTimeout         = 10 * time.Second
	pgRollbackTimeout = 5 * time.Second
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0041_report_schedules).
type PGStore struct {
	db    PGDB
	audit *audit.Log
	orgID string
}

// NewPGStore создаёт хранилище; журнал аудита работает через тот же пул.
func NewPGStore(db PGDB, a *audit.Log, orgID string) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("отчёты: нет БД или журнала аудита")
	}
	if orgID == "" {
		orgID = audit.DefaultOrgID
	}
	return &PGStore{db: db, audit: a, orgID: orgID}, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

func (s *PGStore) inTx(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("отчёты: начало транзакции: %w", err)
	}
	defer func() {
		rctx, c := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer c()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после фиксации безвреден, ошибку скрывает исходная
	}()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("отчёты: фиксация: %w", err)
	}
	return nil
}

// dbErr — ошибка БД без значений строк.
func dbErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		if pe.Code == "23505" && pe.ConstraintName == "report_schedules_org_id_name_key" {
			return &InputError{Fields: map[string]string{"name": "Расписание с таким названием уже есть."}}
		}
		return fmt.Errorf("отчёты: SQLSTATE %s %s", pe.Code, pe.ConstraintName)
	}
	return err
}

const scheduleCols = `id::text, org_id::text, name, report, frequency, COALESCE(weekday, 0)::int, COALESCE(day, 0)::int, at_time,
	format, channel_id::text, enabled, next_run_at, last_run_at, version, created_at, created_by, updated_at, updated_by,
	scope_incidents, scope_alerts, scope_budgets`

func scanSchedule(row pgx.Row) (Schedule, error) {
	var s Schedule
	var last *time.Time
	err := row.Scan(&s.ID, &s.OrgID, &s.Name, &s.Report, &s.Frequency, &s.Weekday, &s.Day, &s.At, &s.Format, &s.ChannelID,
		&s.Enabled, &s.NextRunAt, &last, &s.Version, &s.CreatedAt, &s.CreatedBy, &s.UpdatedAt, &s.UpdatedBy,
		&s.Scope.Incidents, &s.Scope.Alerts, &s.Scope.Budgets)
	if errors.Is(err, pgx.ErrNoRows) {
		return Schedule{}, ErrNotFound
	}
	if err != nil {
		return Schedule{}, dbErr(err)
	}
	s.NextRunAt, s.CreatedAt, s.UpdatedAt = s.NextRunAt.UTC(), s.CreatedAt.UTC(), s.UpdatedAt.UTC()
	if last != nil {
		s.LastRunAt = last.UTC()
	}
	return s, nil
}

func nullable(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

// Schedules — см. Store.
func (s *PGStore) Schedules(ctx context.Context) ([]Schedule, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+scheduleCols+` FROM report_schedules WHERE org_id = $1 ORDER BY created_at, id`, s.orgID)
	if err != nil {
		return nil, dbErr(err)
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, dbErr(rows.Err())
}

// Schedule — см. Store.
func (s *PGStore) Schedule(ctx context.Context, id string) (Schedule, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanSchedule(s.db.QueryRow(ctx, `SELECT `+scheduleCols+` FROM report_schedules WHERE org_id = $1 AND id = $2`, s.orgID, id))
}

// CreateSchedule — см. Store.
func (s *PGStore) CreateSchedule(ctx context.Context, sc Schedule, rec audit.Entry) error {
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('report_schedules:' || $1::text))`, s.orgID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM report_schedules WHERE org_id = $1`, s.orgID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxSchedules {
			return ErrTooMany
		}
		if _, err := tx.Exec(ctx, `INSERT INTO report_schedules (id, org_id, name, report, frequency, weekday, day, at_time, format,
			channel_id, enabled, next_run_at, version, created_at, created_by, updated_at, updated_by, scope_incidents, scope_alerts, scope_budgets)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
			sc.ID, s.orgID, sc.Name, sc.Report, sc.Frequency, nullable(sc.Weekday), nullable(sc.Day), sc.At, sc.Format, sc.ChannelID,
			sc.Enabled, sc.NextRunAt, sc.Version, sc.CreatedAt, sc.CreatedBy, sc.UpdatedAt, sc.UpdatedBy,
			sc.Scope.Incidents, sc.Scope.Alerts, sc.Scope.Budgets); err != nil {
			return dbErr(err)
		}
		return s.audit.RecordTx(ctx, tx, rec)
	})
}

// UpdateSchedule — см. Store.
func (s *PGStore) UpdateSchedule(ctx context.Context, id string, fn func(old Schedule) (Schedule, audit.Entry, error)) (Schedule, error) {
	var out Schedule
	err := s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		old, err := scanSchedule(tx.QueryRow(ctx, `SELECT `+scheduleCols+` FROM report_schedules WHERE org_id = $1 AND id = $2 FOR UPDATE`, s.orgID, id))
		if err != nil {
			return err
		}
		n, rec, err := fn(old)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE report_schedules SET name = $3, report = $4, frequency = $5, weekday = $6, day = $7, at_time = $8,
			format = $9, channel_id = $10, enabled = $11, next_run_at = $12, version = $13, updated_at = $14, updated_by = $15,
			scope_incidents = $16, scope_alerts = $17, scope_budgets = $18
			WHERE org_id = $1 AND id = $2`, s.orgID, id, n.Name, n.Report, n.Frequency, nullable(n.Weekday), nullable(n.Day), n.At, n.Format,
			n.ChannelID, n.Enabled, n.NextRunAt, n.Version, n.UpdatedAt, n.UpdatedBy, n.Scope.Incidents, n.Scope.Alerts, n.Scope.Budgets); err != nil {
			return dbErr(err)
		}
		out = n
		return s.audit.RecordTx(ctx, tx, rec)
	})
	return out, err
}

// DeleteSchedule — см. Store.
func (s *PGStore) DeleteSchedule(ctx context.Context, id string, rec func(old Schedule) audit.Entry) error {
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		old, err := scanSchedule(tx.QueryRow(ctx, `SELECT `+scheduleCols+` FROM report_schedules WHERE org_id = $1 AND id = $2 FOR UPDATE`, s.orgID, id))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM report_schedules WHERE org_id = $1 AND id = $2`, s.orgID, id); err != nil {
			return dbErr(err)
		}
		return s.audit.RecordTx(ctx, tx, rec(old))
	})
}

const runCols = `id::text, org_id::text, schedule_id::text, due_at, to_char(period_first, 'YYYY-MM-DD'), to_char(period_last, 'YYYY-MM-DD'),
	status, attempts, next_at, error, created_at, updated_at, sent_at`

func scanRun(row pgx.Row) (Run, error) {
	var r Run
	var sent *time.Time
	if err := row.Scan(&r.ID, &r.OrgID, &r.ScheduleID, &r.DueAt, &r.PeriodFirst, &r.PeriodLast, &r.Status, &r.Attempts, &r.NextAt,
		&r.Error, &r.CreatedAt, &r.UpdatedAt, &sent); err != nil {
		return Run{}, err
	}
	r.DueAt, r.NextAt, r.CreatedAt, r.UpdatedAt = r.DueAt.UTC(), r.NextAt.UTC(), r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	if sent != nil {
		r.SentAt = sent.UTC()
	}
	return r, nil
}

// Runs — см. Store.
func (s *PGStore) Runs(ctx context.Context, scheduleID string, limit int) ([]Run, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+runCols+` FROM report_runs WHERE org_id = $1 AND schedule_id = $2
		ORDER BY created_at DESC, id DESC LIMIT $3`, s.orgID, scheduleID, limit)
	if err != nil {
		return nil, dbErr(err)
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, dbErr(err)
		}
		out = append(out, r)
	}
	return out, dbErr(rows.Err())
}

// EnqueueDue — см. Store.
func (s *PGStore) EnqueueDue(ctx context.Context, now time.Time, limit int, plan func(Schedule) (Run, time.Time, error)) (int, error) {
	n := 0
	err := s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+scheduleCols+` FROM report_schedules WHERE org_id = $1 AND enabled AND next_run_at <= $2
			ORDER BY next_run_at, id LIMIT $3 FOR UPDATE SKIP LOCKED`, s.orgID, now, limit)
		if err != nil {
			return dbErr(err)
		}
		var due []Schedule
		for rows.Next() {
			sc, err := scanSchedule(rows)
			if err != nil {
				rows.Close()
				return err
			}
			due = append(due, sc)
		}
		if err := rows.Err(); err != nil {
			return dbErr(err)
		}
		for _, sc := range due {
			r, next, err := plan(sc)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO report_runs (id, org_id, schedule_id, due_at, period_first, period_last, status,
				attempts, next_at, error, created_at, updated_at) VALUES ($1, $2, $3, $4, $5::date, $6::date, 'pending', 0, $7, '', $8, $8)`,
				r.ID, s.orgID, sc.ID, r.DueAt, r.PeriodFirst, r.PeriodLast, r.NextAt, r.CreatedAt); err != nil {
				return dbErr(err)
			}
			if _, err := tx.Exec(ctx, `UPDATE report_schedules SET next_run_at = $3, last_run_at = $4 WHERE org_id = $1 AND id = $2`,
				s.orgID, sc.ID, next, r.DueAt); err != nil {
				return dbErr(err)
			}
			n++
		}
		return nil
	})
	return n, err
}

// ClaimRun — см. Store.
func (s *PGStore) ClaimRun(ctx context.Context, now time.Time, lease time.Duration) (Run, Schedule, bool, error) {
	var r Run
	var sc Schedule
	found := false
	err := s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		r, err = scanRun(tx.QueryRow(ctx, `UPDATE report_runs SET next_at = $3 WHERE id = (
			SELECT id FROM report_runs WHERE org_id = $1 AND status = 'pending' AND next_at <= $2
			ORDER BY next_at, id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+runCols, s.orgID, now, now.Add(lease)))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return dbErr(err)
		}
		sc, err = scanSchedule(tx.QueryRow(ctx, `SELECT `+scheduleCols+` FROM report_schedules WHERE org_id = $1 AND id = $2`, s.orgID, r.ScheduleID))
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return r, sc, found, err
}

// FinishRun — см. Store.
func (s *PGStore) FinishRun(ctx context.Context, r Run, rec *audit.Entry) error {
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var sent *time.Time
		if !r.SentAt.IsZero() {
			sent = &r.SentAt
		}
		if _, err := tx.Exec(ctx, `UPDATE report_runs SET status = $3, attempts = $4, next_at = $5, error = $6, updated_at = $7, sent_at = $8
			WHERE org_id = $1 AND id = $2`, s.orgID, r.ID, r.Status, r.Attempts, r.NextAt, r.Error, r.UpdatedAt, sent); err != nil {
			return dbErr(err)
		}
		if rec != nil {
			return s.audit.RecordTx(ctx, tx, *rec)
		}
		return nil
	})
}
