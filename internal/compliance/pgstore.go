package compliance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

const (
	// pgTimeout — предел на одну операцию, если у контекста нет своего срока.
	pgTimeout = 30 * time.Second
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0065_compliance). SQL только
// параметризованный.
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал аудита должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("соответствие: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
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
		return fmt.Errorf("соответствие: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после коммита безвреден, ошибку скрывает исходная
	}()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("соответствие: фиксация: %w", err)
	}
	return nil
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, orgID string, rec audit.Entry) error {
	rec.OrgID = orgID
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("соответствие: %w", err)
	}
	return nil
}

const markCols = `requirement_id, status, comment, document, COALESCE(to_char(review_by, 'YYYY-MM-DD'), ''), set_at, set_by`

func scanMark(row pgx.Row) (Mark, error) {
	var m Mark
	var st string
	if err := row.Scan(&m.RequirementID, &st, &m.Comment, &m.Document, &m.ReviewBy, &m.SetAt, &m.SetBy); err != nil {
		return Mark{}, err
	}
	m.Status, m.SetAt = Status(st), m.SetAt.UTC()
	return m, nil
}

// Marks — см. Store.
func (s *PGStore) Marks(ctx context.Context, orgID string) ([]Mark, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+markCols+` FROM compliance_marks WHERE org_id = $1 ORDER BY requirement_id`, orgID)
	if err != nil {
		return nil, fmt.Errorf("соответствие: чтение отметок: %w", err)
	}
	defer rows.Close()
	out := []Mark{}
	for rows.Next() {
		m, err := scanMark(rows)
		if err != nil {
			return nil, fmt.Errorf("соответствие: чтение отметок: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("соответствие: чтение отметок: %w", err)
	}
	return out, nil
}

// SetMark — см. Store. Прежняя отметка читается под блокировкой строки,
// запись аудита делается той же транзакцией.
func (s *PGStore) SetMark(ctx context.Context, orgID string, m Mark, fn func(prev *Mark) audit.Entry) error {
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var prev *Mark
		p, err := scanMark(tx.QueryRow(ctx, `SELECT `+markCols+` FROM compliance_marks WHERE org_id = $1 AND requirement_id = $2 FOR UPDATE`,
			orgID, m.RequirementID))
		switch {
		case err == nil:
			prev = &p
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("соответствие: чтение отметки: %w", err)
		}
		var review any
		if m.ReviewBy != "" {
			review = m.ReviewBy
		}
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_marks (org_id, requirement_id, status, comment, document, review_by, set_at, set_by)
			VALUES ($1, $2, $3, $4, $5, $6::date, $7, $8)
			ON CONFLICT (org_id, requirement_id) DO UPDATE SET status = EXCLUDED.status, comment = EXCLUDED.comment,
				document = EXCLUDED.document, review_by = EXCLUDED.review_by, set_at = EXCLUDED.set_at, set_by = EXCLUDED.set_by`,
			orgID, m.RequirementID, string(m.Status), m.Comment, m.Document, review, m.SetAt, m.SetBy); err != nil {
			return fmt.Errorf("соответствие: сохранение отметки: %w", err)
		}
		return s.record(ctx, tx, orgID, fn(prev))
	})
}

// ClearMark — см. Store.
func (s *PGStore) ClearMark(ctx context.Context, orgID, id string, fn func(prev Mark) audit.Entry) error {
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		p, err := scanMark(tx.QueryRow(ctx, `SELECT `+markCols+` FROM compliance_marks WHERE org_id = $1 AND requirement_id = $2 FOR UPDATE`, orgID, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoMark
		}
		if err != nil {
			return fmt.Errorf("соответствие: чтение отметки: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM compliance_marks WHERE org_id = $1 AND requirement_id = $2`, orgID, id); err != nil {
			return fmt.Errorf("соответствие: снятие отметки: %w", err)
		}
		return s.record(ctx, tx, orgID, fn(p))
	})
}
