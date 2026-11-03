package redteam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

const (
	// pgTimeout — предел на одну операцию, если у контекста нет своего срока.
	pgTimeout = 10 * time.Second
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0075_redteam).
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("тестирование устойчивости: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

func dbErr(what string, err error) error {
	return fmt.Errorf("тестирование устойчивости: %s: %w", what, err)
}

// inTx — транзакция с записями аудита recs после fn.
func (s *PGStore) inTx(ctx context.Context, fn func(context.Context, pgx.Tx) error, recs ...audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return dbErr("начало транзакции", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после коммита безвреден, ошибку скрывает исходная
	}()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	for _, rec := range recs {
		if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
			return dbErr("аудит", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return dbErr("фиксация", err)
	}
	return nil
}

const targetCols = `id::text, org_id::text, name, kind, COALESCE(app_id::text, ''), model, url, request_template, response_path,
	headers, auth_header, ca_pem, authorization_note, storage, judge_provider, judge_model, limits,
	created_at, created_by, updated_at, updated_by`

func scanTarget(row pgx.Row) (Target, error) {
	var t Target
	var headers, limits []byte
	if err := row.Scan(&t.ID, &t.OrgID, &t.Name, &t.Kind, &t.AppID, &t.Model, &t.URL, &t.RequestTemplate, &t.ResponsePath,
		&headers, &t.AuthHeader, &t.CAPEM, &t.AuthorizationNote, &t.Storage, &t.JudgeProvider, &t.JudgeModel, &limits,
		&t.CreatedAt, &t.CreatedBy, &t.UpdatedAt, &t.UpdatedBy); err != nil {
		return Target{}, err
	}
	if err := json.Unmarshal(headers, &t.Headers); err != nil {
		return Target{}, fmt.Errorf("заголовки цели: %w", err)
	}
	if err := json.Unmarshal(limits, &t.Limits); err != nil {
		return Target{}, fmt.Errorf("пределы цели: %w", err)
	}
	if t.Headers == nil {
		t.Headers = []Header{}
	}
	t.CreatedAt, t.UpdatedAt = t.CreatedAt.UTC(), t.UpdatedAt.UTC()
	return t, nil
}

// Targets — цели по имени.
func (s *PGStore) Targets(ctx context.Context, orgID string) ([]Target, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+targetCols+` FROM redteam_targets WHERE org_id = $1 ORDER BY name, id`, orgID)
	if err != nil {
		return nil, dbErr("цели", err)
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, dbErr("цели", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("цели", err)
	}
	return out, nil
}

// Target — цель по ID.
func (s *PGStore) Target(ctx context.Context, orgID, id string) (Target, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	t, err := scanTarget(s.db.QueryRow(ctx, `SELECT `+targetCols+` FROM redteam_targets WHERE org_id = $1 AND id = $2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	if err != nil {
		return Target{}, dbErr("цель", err)
	}
	return t, nil
}

func targetArgs(t Target) ([]any, error) {
	// Без заголовков — пустой массив, не null (CHECK headers в 0075).
	hs := t.Headers
	if hs == nil {
		hs = []Header{}
	}
	headers, err := json.Marshal(hs)
	if err != nil {
		return nil, err
	}
	limits, err := json.Marshal(t.Limits)
	if err != nil {
		return nil, err
	}
	var app any
	if t.AppID != "" {
		app = t.AppID
	}
	return []any{t.ID, t.OrgID, t.Name, t.Kind, app, t.Model, t.URL, t.RequestTemplate, t.ResponsePath, headers, t.AuthHeader, t.CAPEM,
		t.AuthorizationNote, t.Storage, t.JudgeProvider, t.JudgeModel, limits, t.CreatedAt, t.CreatedBy, t.UpdatedAt, t.UpdatedBy}, nil
}

// lockOrg — блокировка целей организации на транзакцию (предел числа).
func lockOrg(ctx context.Context, tx pgx.Tx, orgID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('aisec.redteam:' || $1, 0))`, orgID)
	return err
}

// CreateTarget добавляет цель.
func (s *PGStore) CreateTarget(ctx context.Context, t Target, rec audit.Entry) error {
	args, err := targetArgs(t)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockOrg(ctx, tx, t.OrgID); err != nil {
			return dbErr("блокировка", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM redteam_targets WHERE org_id = $1`, t.OrgID).Scan(&n); err != nil {
			return dbErr("число целей", err)
		}
		if n >= MaxTargets {
			return ErrTooManyTargets
		}
		_, err := tx.Exec(ctx, `INSERT INTO redteam_targets (id, org_id, name, kind, app_id, model, url, request_template, response_path,
			headers, auth_header, ca_pem, authorization_note, storage, judge_provider, judge_model, limits, created_at, created_by,
			updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
			args...)
		if err != nil {
			return dbErr("цель", err)
		}
		return nil
	}, rec)
}

// UpdateTarget меняет цель.
func (s *PGStore) UpdateTarget(ctx context.Context, t Target, rec audit.Entry) error {
	args, err := targetArgs(t)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE redteam_targets SET name = $3, app_id = $5, model = $6, url = $7, request_template = $8,
			response_path = $9, headers = $10, auth_header = $11, ca_pem = $12, authorization_note = $13, storage = $14,
			judge_provider = $15, judge_model = $16, limits = $17, updated_at = $20, updated_by = $21
			WHERE id = $1 AND org_id = $2 AND kind = $4 AND created_at = $18 AND created_by = $19`, args...)
		if err != nil {
			return dbErr("цель", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	}, rec)
}

// DeleteTarget удаляет цель; запуски остаются.
func (s *PGStore) DeleteTarget(ctx context.Context, orgID, id string, rec audit.Entry) error {
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM redteam_targets WHERE org_id = $1 AND id = $2`, orgID, id)
		if err != nil {
			return dbErr("цель", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	}, rec)
}

const runCols = `id::text, org_id::text, COALESCE(target_id::text, ''), target_name, target_kind, COALESCE(app_id::text, ''), status,
	reason, scenarios, counts, db_version, started_at, started_by, finished_at, deadline, COALESCE(key_prefix, ''), key_hash`

func scanRun(row pgx.Row) (Run, error) {
	var r Run
	var counts []byte
	var dbv int64
	if err := row.Scan(&r.ID, &r.OrgID, &r.TargetID, &r.TargetName, &r.TargetKind, &r.AppID, &r.Status, &r.Reason, &r.Scenarios, &counts,
		&dbv, &r.StartedAt, &r.StartedBy, &r.FinishedAt, &r.Deadline, &r.KeyPrefix, &r.KeyHash); err != nil {
		return Run{}, err
	}
	if err := json.Unmarshal(counts, &r.Counts); err != nil {
		return Run{}, fmt.Errorf("итоги запуска: %w", err)
	}
	r.DBVersion = uint64(max(dbv, 0)) //nolint:gosec // G115: столбец с CHECK (db_version >= 0)
	r.StartedAt, r.Deadline = r.StartedAt.UTC(), r.Deadline.UTC()
	if r.FinishedAt != nil {
		f := r.FinishedAt.UTC()
		r.FinishedAt = &f
	}
	return r, nil
}

// CreateRun добавляет запуск.
func (s *PGStore) CreateRun(ctx context.Context, r Run, rec audit.Entry) error {
	counts, err := json.Marshal(r.Counts)
	if err != nil {
		return err
	}
	var app, prefix, hash any
	if r.AppID != "" {
		app = r.AppID
	}
	if r.KeyPrefix != "" {
		prefix, hash = r.KeyPrefix, r.KeyHash
	}
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO redteam_runs (id, org_id, target_id, target_name, target_kind, app_id, status, reason, scenarios,
			counts, db_version, started_at, started_by, deadline, key_prefix, key_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			r.ID, r.OrgID, r.TargetID, r.TargetName, r.TargetKind, app, r.Status, r.Reason, r.Scenarios, counts,
			int64(min(r.DBVersion, 1<<53)), r.StartedAt, r.StartedBy, r.Deadline, prefix, hash) //nolint:gosec // G115: версия базы до 2^53
		if err != nil {
			return dbErr("запуск", err)
		}
		return nil
	}, rec)
}

// FinishRun завершает запуск.
func (s *PGStore) FinishRun(ctx context.Context, r Run, rec audit.Entry) error {
	counts, err := json.Marshal(r.Counts)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE redteam_runs SET status = $3, reason = $4, counts = $5, finished_at = $6
			WHERE id = $1 AND org_id = $2 AND status IN ('queued', 'running')`, r.ID, r.OrgID, r.Status, r.Reason, counts, r.FinishedAt)
		if err != nil {
			return dbErr("запуск", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotRunning
		}
		return nil
	}, rec)
}

// SaveResult сохраняет итог сценария.
func (s *PGStore) SaveResult(ctx context.Context, orgID string, res Result) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	enc := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil || string(b) == "null" {
			return []byte("[]")
		}
		return b
	}
	var ok bool
	err := s.db.QueryRow(ctx, `INSERT INTO redteam_results (run_id, scenario_id, lang, threat, category, verdict, step, matched,
			findings, judge, event_ids, http_status, latency_ms, error_code, example, created_at)
		SELECT r.id, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, clock_timestamp()
		FROM redteam_runs r WHERE r.id = $1 AND r.org_id = $2
		RETURNING true`, res.RunID, orgID, res.ScenarioID, res.Lang, res.Threat, res.Category, res.Verdict, res.Step, enc(res.Matched),
		enc(res.Findings), res.Judge, enc(res.EventIDs), res.HTTPStatus, res.LatencyMS, res.ErrorCode, res.Example).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return dbErr("итог сценария", err)
	}
	return nil
}

// Runs — запуски, новые первыми.
func (s *PGStore) Runs(ctx context.Context, orgID, targetID string, limit int) ([]Run, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var target any
	if targetID != "" {
		target = targetID
	}
	rows, err := s.db.Query(ctx, `SELECT `+runCols+` FROM redteam_runs WHERE org_id = $1 AND ($2::uuid IS NULL OR target_id = $2)
		ORDER BY started_at DESC, id DESC LIMIT $3`, orgID, target, limit)
	if err != nil {
		return nil, dbErr("запуски", err)
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, dbErr("запуски", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("запуски", err)
	}
	return out, nil
}

// Run — запуск по ID.
func (s *PGStore) Run(ctx context.Context, orgID, id string) (Run, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	r, err := scanRun(s.db.QueryRow(ctx, `SELECT `+runCols+` FROM redteam_runs WHERE org_id = $1 AND id = $2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, dbErr("запуск", err)
	}
	return r, nil
}

// Results — итоги запуска по ID сценария.
func (s *PGStore) Results(ctx context.Context, orgID, runID string) ([]Result, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT s.run_id::text, s.scenario_id, s.lang, s.threat, s.category, s.verdict, s.step, s.matched,
			s.findings, s.judge, s.event_ids, s.http_status, s.latency_ms, s.error_code, s.example
		FROM redteam_results s JOIN redteam_runs r ON r.id = s.run_id
		WHERE r.org_id = $1 AND s.run_id = $2 ORDER BY s.scenario_id COLLATE "C"`, orgID, runID)
	if err != nil {
		return nil, dbErr("итоги", err)
	}
	defer rows.Close()
	out := []Result{}
	for rows.Next() {
		var res Result
		var matched, findings, eventIDs []byte
		if err := rows.Scan(&res.RunID, &res.ScenarioID, &res.Lang, &res.Threat, &res.Category, &res.Verdict, &res.Step, &matched,
			&findings, &res.Judge, &eventIDs, &res.HTTPStatus, &res.LatencyMS, &res.ErrorCode, &res.Example); err != nil {
			return nil, dbErr("итоги", err)
		}
		for _, p := range []struct {
			b   []byte
			dst any
		}{{matched, &res.Matched}, {findings, &res.Findings}, {eventIDs, &res.EventIDs}} {
			if err := json.Unmarshal(p.b, p.dst); err != nil {
				return nil, dbErr("итоги", err)
			}
		}
		out = append(out, res)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("итоги", err)
	}
	if len(out) == 0 {
		if _, err := s.Run(ctx, orgID, runID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ActiveKeys — запуски с действующим ключом.
func (s *PGStore) ActiveKeys(ctx context.Context, orgID string, now time.Time) ([]Run, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+runCols+` FROM redteam_runs WHERE org_id = $1 AND status IN ('queued', 'running')
		AND key_prefix IS NOT NULL AND deadline > $2 ORDER BY key_prefix`, orgID, now)
	if err != nil {
		return nil, dbErr("ключи запусков", err)
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, dbErr("ключи запусков", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("ключи запусков", err)
	}
	return out, nil
}

// Interrupt завершает незавершённые запуски с записью аудита.
func (s *PGStore) Interrupt(ctx context.Context, orgID string, now time.Time, rec func(Run) audit.Entry) (int, error) {
	n := 0
	err := s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE redteam_runs SET status = 'failed', reason = $2, finished_at = $3
			WHERE org_id = $1 AND status IN ('queued', 'running') RETURNING `+runCols, orgID, ReasonInterrupted, now)
		if err != nil {
			return dbErr("прерванные запуски", err)
		}
		var runs []Run
		for rows.Next() {
			r, err := scanRun(rows)
			if err != nil {
				rows.Close()
				return dbErr("прерванные запуски", err)
			}
			runs = append(runs, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return dbErr("прерванные запуски", err)
		}
		for _, r := range runs {
			if err := s.audit.RecordTx(ctx, tx, rec(r)); err != nil {
				return dbErr("аудит", err)
			}
		}
		n = len(runs)
		return nil
	})
	return n, err
}

// Purge удаляет итоги сценариев старше results и завершённые запуски
// старше runs (ADR-0031, раздел 7).
func (s *PGStore) Purge(ctx context.Context, orgID string, results, runs time.Time) error {
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM redteam_results s USING redteam_runs r WHERE r.id = s.run_id AND r.org_id = $1
			AND s.created_at < $2`, orgID, results); err != nil {
			return dbErr("очистка итогов", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM redteam_runs WHERE org_id = $1 AND finished_at < $2`, orgID, runs); err != nil {
			return dbErr("очистка запусков", err)
		}
		return nil
	})
}
