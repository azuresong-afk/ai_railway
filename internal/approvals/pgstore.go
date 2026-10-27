package approvals

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/policy"
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

// PGStore — Store на PostgreSQL (миграция 0056_approvals).
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("подтверждения: нет БД или журнала аудита")
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
		return fmt.Errorf("подтверждения: начало транзакции: %w", err)
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
		return fmt.Errorf("подтверждения: фиксация: %w", err)
	}
	return nil
}

const columns = `id::text, org_id::text, gateway_id::text, path, app, agent, user_alias, session, server, tool, approved_hash, risk,
	rule, message, severity, args_hash, args, args_key_id::text, args_alg, request_event_id::text, state, created_at, deadline,
	closed_at, decided_by::text, decided_by_name, comment`

func scan(row pgx.Row) (Request, error) {
	var (
		r                    Request
		risk, sev, state     string
		args                 []byte
		keyID, alg, evID, by *string
		closed               *time.Time
	)
	if err := row.Scan(&r.ID, &r.OrgID, &r.GatewayID, &r.Path, &r.App, &r.Agent, &r.User, &r.Session, &r.Server, &r.Tool,
		&r.ApprovedHash, &risk, &r.Rule, &r.Message, &sev, &r.ArgsHash, &args, &keyID, &alg, &evID, &state, &r.CreatedAt,
		&r.Deadline, &closed, &by, &r.DecidedByName, &r.Comment); err != nil {
		return Request{}, err
	}
	r.Risk, r.Severity, r.State = policy.ToolRisk(risk), policy.Severity(sev), State(state)
	if args != nil {
		r.Args = &Sealed{Data: args, KeyID: deref(keyID), Alg: deref(alg)}
	}
	r.RequestEventID, r.DecidedBy = deref(evID), deref(by)
	r.CreatedAt, r.Deadline = r.CreatedAt.UTC(), r.Deadline.UTC()
	if closed != nil {
		r.ClosedAt = closed.UTC()
	}
	return r, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// lockGateway — пределы очереди шлюза считаются без гонки.
func lockGateway(ctx context.Context, tx pgx.Tx, gatewayID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('aisec.approvals:' || $1, 0))`, gatewayID)
	return err
}

// Create — см. Store.
func (s *PGStore) Create(ctx context.Context, r Request, rec audit.Entry, maxGateway, maxAgent int) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockGateway(ctx, tx, r.GatewayID); err != nil {
			return err
		}
		var gw, ag int
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE app = $2 AND agent = $3)
			FROM approval_requests WHERE gateway_id = $1 AND state = 'pending'`, r.GatewayID, r.App, r.Agent).Scan(&gw, &ag); err != nil {
			return err
		}
		switch {
		case gw >= maxGateway:
			return &QueueFullError{Scope: "gateway"}
		case ag >= maxAgent:
			return &QueueFullError{Scope: "agent"}
		}
		var args []byte
		var keyID, alg *string
		if r.Args != nil {
			args, keyID, alg = r.Args.Data, &r.Args.KeyID, &r.Args.Alg
		}
		if _, err := tx.Exec(ctx, `INSERT INTO approval_requests (id, org_id, gateway_id, path, app, agent, user_alias, session,
			server, tool, approved_hash, risk, rule, message, severity, args_hash, args, args_key_id, args_alg, request_event_id,
			state, created_at, deadline)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, 'pending', $21, $22)`,
			r.ID, r.OrgID, r.GatewayID, r.Path, r.App, r.Agent, r.User, r.Session, r.Server, r.Tool, r.ApprovedHash, string(r.Risk),
			r.Rule, r.Message, string(r.Severity), r.ArgsHash, args, keyID, alg, nullStr(r.RequestEventID), r.CreatedAt,
			r.Deadline); err != nil {
			return fmt.Errorf("подтверждения: запись запроса: %w", err)
		}
		return s.audit.RecordTx(ctx, tx, rec)
	})
}

// Get — см. Store.
func (s *PGStore) Get(ctx context.Context, orgID, id string) (Request, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	r, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM approval_requests WHERE id = $1 AND org_id = $2`, id, orgID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	return r, err
}

// Close — см. Store.
func (s *PGStore) Close(ctx context.Context, orgID, id string, fn func(*Request) (*audit.Entry, error)) (Request, error) {
	var out Request
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM approval_requests WHERE id = $1 AND org_id = $2 FOR UPDATE`,
			id, orgID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		before := r.State
		rec, err := fn(&r)
		if err != nil {
			return err
		}
		out = r
		if before != Pending || r.State == Pending {
			return nil // закрытый не меняется
		}
		if _, err := tx.Exec(ctx, `UPDATE approval_requests SET state = $2, closed_at = $3, decided_by = $4, decided_by_name = $5,
			comment = $6 WHERE id = $1 AND state = 'pending'`,
			id, string(r.State), r.ClosedAt, nullStr(r.DecidedBy), r.DecidedByName, r.Comment); err != nil {
			return fmt.Errorf("подтверждения: закрытие запроса: %w", err)
		}
		if rec != nil {
			return s.audit.RecordTx(ctx, tx, *rec)
		}
		return nil
	})
	return out, err
}

// List — см. Store.
func (s *PGStore) List(ctx context.Context, orgID string, f Filter) ([]Request, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(ctx, `SELECT `+columns+` FROM approval_requests
		WHERE org_id = $1 AND ($2 = '' OR state = $2) AND ($3 = '' OR app = $3) AND ($4 = '' OR agent = $4)
			AND ($5::timestamptz IS NULL OR (created_at, id) < ($5, $6::uuid))
		ORDER BY created_at DESC, id DESC LIMIT $7`,
		orgID, string(f.State), f.App, f.Agent, nullTime(f.AfterTime), nullStr(f.AfterID), limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Request, error) { return scan(r) })
}

// collectIDs — ID из UPDATE … RETURNING.
func collectIDs(rows pgx.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Expire — см. Store.
func (s *PGStore) Expire(ctx context.Context, orgID string, now time.Time, limit int) ([]string, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return collectIDs(s.db.Query(ctx, `UPDATE approval_requests SET state = 'timeout', closed_at = deadline
		WHERE id IN (SELECT id FROM approval_requests WHERE org_id = $1 AND state = 'pending' AND deadline <= $2
			ORDER BY deadline LIMIT $3 FOR UPDATE SKIP LOCKED)
		RETURNING id::text`, orgID, now, limit))
}

// Interrupt — см. Store.
func (s *PGStore) Interrupt(ctx context.Context, orgID, gatewayID string, keep []string, before, now time.Time) ([]string, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	if keep == nil {
		keep = []string{}
	}
	return collectIDs(s.db.Query(ctx, `UPDATE approval_requests SET state = 'interrupted', closed_at = $5
		WHERE org_id = $1 AND gateway_id = $2 AND state = 'pending' AND created_at < $4 AND NOT (id::text = ANY ($3))
		RETURNING id::text`, orgID, gatewayID, keep, before, now))
}

// PurgeArgs — см. Store.
func (s *PGStore) PurgeArgs(ctx context.Context, orgID string, before time.Time, limit int) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	ids, err := collectIDs(s.db.Query(ctx, `UPDATE approval_requests SET args = NULL, args_key_id = NULL, args_alg = NULL
		WHERE id IN (SELECT id FROM approval_requests WHERE org_id = $1 AND closed_at < $2 AND args IS NOT NULL
			ORDER BY closed_at LIMIT $3 FOR UPDATE SKIP LOCKED)
		RETURNING id::text`, orgID, before, limit))
	return len(ids), err
}

// Delete — см. Store.
func (s *PGStore) Delete(ctx context.Context, orgID string, before time.Time, limit int) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	ids, err := collectIDs(s.db.Query(ctx, `DELETE FROM approval_requests
		WHERE id IN (SELECT id FROM approval_requests WHERE org_id = $1 AND closed_at < $2
			ORDER BY closed_at LIMIT $3 FOR UPDATE SKIP LOCKED)
		RETURNING id::text`, orgID, before, limit))
	return len(ids), err
}

// Record — см. Store.
func (s *PGStore) Record(ctx context.Context, rec audit.Entry) error {
	return s.audit.Record(ctx, rec)
}
