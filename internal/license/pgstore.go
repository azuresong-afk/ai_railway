package license

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
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0062_licenses). SQL только
// параметризованный.
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал аудита должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("лицензия: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

// Current — см. Store.
func (s *PGStore) Current(ctx context.Context, orgID string) (Stored, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var st Stored
	var number int64
	err := s.db.QueryRow(ctx, `SELECT number, file, loaded_at, loaded_by FROM licenses WHERE org_id = $1
		ORDER BY number DESC LIMIT 1`, orgID).Scan(&number, &st.File, &st.LoadedAt, &st.LoadedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Stored{}, ErrNoLicense
	}
	if err != nil {
		return Stored{}, fmt.Errorf("лицензия: чтение: %w", err)
	}
	st.Number = uint64(number) //nolint:gosec // G115: CHECK number >= 1 в схеме
	return st, nil
}

// Save — см. Store. Номер сравнивается в той же транзакции под
// транзакционной блокировкой организации: одновременные загрузки идут по
// очереди, и лицензия с меньшим номером после большей не сохранится.
func (s *PGStore) Save(ctx context.Context, orgID string, st Stored, rec audit.Entry) error {
	if st.Number == 0 || st.Number > maxNumber {
		return ErrStale
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("лицензия: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после коммита безвреден, ошибку скрывает исходная
	}()
	// Загрузки одной организации идут по очереди: без блокировки две
	// транзакции READ COMMITTED увидели бы один и тот же наибольший номер.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('aisec.licenses:' || $1::text, 0))", orgID); err != nil {
		return fmt.Errorf("лицензия: блокировка: %w", err)
	}
	var top int64
	if err := tx.QueryRow(ctx, "SELECT coalesce(max(number), 0) FROM licenses WHERE org_id = $1", orgID).Scan(&top); err != nil {
		return fmt.Errorf("лицензия: номер: %w", err)
	}
	if uint64(top) >= st.Number { //nolint:gosec // G115: номер неотрицателен (CHECK)
		return ErrStale
	}
	if _, err := tx.Exec(ctx, "INSERT INTO licenses (org_id, number, file, loaded_at, loaded_by) VALUES ($1, $2, $3, $4, $5)",
		orgID, int64(st.Number), st.File, st.LoadedAt, st.LoadedBy); err != nil { //nolint:gosec // G115: номер не больше 2^53 (проверено выше)
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return ErrStale
		}
		return fmt.Errorf("лицензия: сохранение: %w", err)
	}
	rec.OrgID = orgID
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("лицензия: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("лицензия: фиксация: %w", err)
	}
	return nil
}

// Record — см. Store.
func (s *PGStore) Record(ctx context.Context, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	if err := s.audit.Record(ctx, rec); err != nil {
		return fmt.Errorf("лицензия: %w", err)
	}
	return nil
}

// AdvanceClock — см. Store. Отметка поднимается одним запросом: greatest
// не даёт опустить её и при одновременных вызовах.
func (s *PGStore) AdvanceClock(ctx context.Context, orgID string, t time.Time) (time.Time, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var hw time.Time
	err := s.db.QueryRow(ctx, `INSERT INTO license_clock (org_id, high_water) VALUES ($1, $2)
		ON CONFLICT (org_id) DO UPDATE SET high_water = greatest(license_clock.high_water, EXCLUDED.high_water)
		RETURNING high_water`, orgID, t.UTC()).Scan(&hw)
	if err != nil {
		return time.Time{}, fmt.Errorf("лицензия: отметка часов: %w", err)
	}
	return hw.UTC(), nil
}

// Usage — число действующих шлюзов и приложений не в архиве (Options.Usage).
func (s *PGStore) Usage(ctx context.Context, orgID string) (Usage, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var u Usage
	err := s.db.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM gateways WHERE org_id = $1 AND status = 'active'),
		(SELECT count(*) FROM applications WHERE org_id = $1 AND archived_at IS NULL)`, orgID).Scan(&u.Gateways, &u.Applications)
	if err != nil {
		return Usage{}, fmt.Errorf("лицензия: число шлюзов и приложений: %w", err)
	}
	return u, nil
}
