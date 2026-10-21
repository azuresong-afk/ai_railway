package versions

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

// PGStore — Store на PostgreSQL (миграция 0017_policies).
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("политики: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

func (s *PGStore) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("политики: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после коммита безвреден, ошибку скрывает исходная
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return pgErr(fmt.Errorf("политики: фиксация: %w", err))
	}
	return nil
}

// pgErr: уникальность slug — ErrExists; повтор номера версии (гонка двух
// сохранений) — ErrConflict.
func pgErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		if pe.ConstraintName == "policy_versions_pkey" {
			return ErrConflict
		}
		return ErrExists
	}
	return err
}

const policyCols = `id, org_id, slug, name, mode, current_version, created_at, created_by, updated_at, updated_by`

func scanPolicy(r pgx.Row) (Policy, error) {
	var p Policy
	err := r.Scan(&p.ID, &p.OrgID, &p.Slug, &p.Name, &p.Mode, &p.Current, &p.CreatedAt, &p.CreatedBy, &p.UpdatedAt, &p.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	p.CreatedAt, p.UpdatedAt = p.CreatedAt.UTC(), p.UpdatedAt.UTC()
	return p, err
}

const versionCols = `v.policy_id, v.version, v.spec_yaml, v.spec_hash, v.hash_alg, v.source, v.comment,
	coalesce(v.rolled_back_from, 0), v.created_at, v.created_by`

func scanVersion(r pgx.Row) (Version, error) {
	var (
		v    Version
		yaml string
	)
	err := r.Scan(&v.PolicyID, &v.Version, &yaml, &v.Hash, &v.HashAlg, &v.Source, &v.Comment, &v.RolledBackFrom, &v.CreatedAt, &v.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	v.YAML, v.CreatedAt = []byte(yaml), v.CreatedAt.UTC()
	return v, err
}

func nullInt(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}

func insertVersion(ctx context.Context, tx pgx.Tx, v Version) error {
	_, err := tx.Exec(ctx, `INSERT INTO policy_versions (policy_id, version, spec_yaml, spec_hash, hash_alg, source, comment,
		rolled_back_from, created_at, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		v.PolicyID, v.Version, string(v.YAML), v.Hash, v.HashAlg, v.Source, v.Comment, nullInt(v.RolledBackFrom), v.CreatedAt, v.CreatedBy)
	return pgErr(err)
}

// CreatePolicy — см. Store.
func (s *PGStore) CreatePolicy(ctx context.Context, p Policy, v Version, rec audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO policies (`+policyCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			p.ID, p.OrgID, p.Slug, p.Name, p.Mode, p.Current, p.CreatedAt, p.CreatedBy, p.UpdatedAt, p.UpdatedBy); err != nil {
			return pgErr(err)
		}
		if err := insertVersion(ctx, tx, v); err != nil {
			return err
		}
		return s.record(ctx, tx, rec)
	})
}

// AddVersion — см. Store.
func (s *PGStore) AddVersion(ctx context.Context, orgID, slug string, base int,
	fn func(p Policy, cur Version) (Version, audit.Entry, error)) (Policy, Version, error) {
	var (
		p Policy
		v Version
	)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		p, err = scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+` FROM policies WHERE org_id = $1 AND slug = $2 FOR UPDATE`, orgID, slug))
		if err != nil {
			return err
		}
		if p.Current != base {
			return ErrConflict
		}
		cur, err := scanVersion(tx.QueryRow(ctx, `SELECT `+versionCols+` FROM policy_versions v WHERE v.policy_id = $1 AND v.version = $2`, p.ID, p.Current))
		if err != nil {
			return err
		}
		var rec audit.Entry
		if v, rec, err = fn(p, cur); err != nil {
			return err
		}
		if v.Version != cur.Version+1 || v.PolicyID != p.ID {
			return errSequence
		}
		spec, err := v.Spec()
		if err != nil {
			return err
		}
		if err := insertVersion(ctx, tx, v); err != nil {
			return err
		}
		p.Current, p.Name, p.Mode, p.UpdatedAt, p.UpdatedBy = v.Version, spec.Name, string(spec.Mode), v.CreatedAt, v.CreatedBy
		if _, err := tx.Exec(ctx, `UPDATE policies SET current_version = $2, name = $3, mode = $4, updated_at = $5, updated_by = $6
			WHERE id = $1`, p.ID, p.Current, p.Name, p.Mode, p.UpdatedAt, p.UpdatedBy); err != nil {
			return err
		}
		return s.record(ctx, tx, rec)
	})
	if err != nil {
		return Policy{}, Version{}, err
	}
	return p, v, nil
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, rec audit.Entry) error {
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("политики: %w", err)
	}
	return nil
}

// Policy — см. Store.
func (s *PGStore) Policy(ctx context.Context, orgID, slug string) (Policy, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanPolicy(s.db.QueryRow(ctx, `SELECT `+policyCols+` FROM policies WHERE org_id = $1 AND slug = $2`, orgID, slug))
}

// Policies — см. Store.
func (s *PGStore) Policies(ctx context.Context, orgID string) ([]Policy, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+policyCols+` FROM policies WHERE org_id = $1 ORDER BY slug LIMIT $2`, orgID, MaxPolicies)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountPolicies — см. Store.
func (s *PGStore) CountPolicies(ctx context.Context, orgID string) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id = $1`, orgID).Scan(&n)
	return n, err
}

// Version — см. Store.
func (s *PGStore) Version(ctx context.Context, orgID, slug string, n int) (Version, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanVersion(s.db.QueryRow(ctx, `SELECT `+versionCols+` FROM policy_versions v
		JOIN policies p ON p.id = v.policy_id
		WHERE p.org_id = $1 AND p.slug = $2 AND v.version = CASE WHEN $3::integer = 0 THEN p.current_version ELSE $3::integer END`,
		orgID, slug, n))
}

// Versions — см. Store.
func (s *PGStore) Versions(ctx context.Context, orgID, slug string, before, limit int) ([]Version, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT v.policy_id, v.version, '', v.spec_hash, v.hash_alg, v.source, v.comment,
		coalesce(v.rolled_back_from, 0), v.created_at, v.created_by FROM policy_versions v
		JOIN policies p ON p.id = v.policy_id
		WHERE p.org_id = $1 AND p.slug = $2 AND ($3::integer = 0 OR v.version < $3::integer)
		ORDER BY v.version DESC LIMIT $4`, orgID, slug, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		v.YAML = nil
		out = append(out, v)
	}
	return out, rows.Err()
}
