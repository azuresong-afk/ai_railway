package servicedb

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
	// pgRollbackTimeout — предел на откат транзакции после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
	// maxStoredFile — файл базы целиком (aisecCrypto.MaxServiceDBSize).
	maxStoredFile = 4 << 20
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// PGStore — Store на PostgreSQL (миграция 0068_service_dbs). SQL только
// параметризованный.
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал аудита должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("служебные базы: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

// inTx выполняет fn в транзакции под блокировкой вида организации.
func (s *PGStore) inTx(ctx context.Context, orgID, kind string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("служебные базы: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после фиксации безвреден, ошибку скрывает исходная
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('aisec.service_db:' || $1 || ':' || $2, 0))`, orgID, kind); err != nil {
		return fmt.Errorf("служебные базы: блокировка вида: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("служебные базы: фиксация: %w", err)
	}
	return nil
}

const selectSlot = `SELECT version, db_date, records, subkey_serial, fingerprint, file, uploaded_at, uploaded_by
	FROM service_dbs WHERE org_id = $1 AND kind = $2 AND slot = $3`

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// readSlot — версия в слоте; пусто — nil.
func readSlot(ctx context.Context, q rowQuerier, sql, orgID, kind, slot string) (*Stored, error) {
	var b Stored
	var version, serial int64
	err := q.QueryRow(ctx, sql, orgID, kind, slot).
		Scan(&version, &b.Date, &b.Records, &serial, &b.Fingerprint, &b.File, &b.UploadedAt, &b.UploadedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("служебные базы: чтение %s: %w", slot, err)
	}
	b.Version, b.SubkeySerial = uint64(version), uint64(serial) //nolint:gosec // G115: CHECK > 0 в схеме
	return &b, nil
}

// Slots — см. Store.
func (s *PGStore) Slots(ctx context.Context, orgID, kind string) (Slots, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Slots{}, fmt.Errorf("служебные базы: начало транзакции: %w", err)
	}
	// Оба слота — из одного снимка: откат или загрузка между чтениями не
	// должны дать несогласованную пару.
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: транзакция только читает
	}()
	if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`); err != nil {
		return Slots{}, fmt.Errorf("служебные базы: %w", err)
	}
	var out Slots
	if out.Current, err = readSlot(ctx, tx, selectSlot, orgID, kind, SlotCurrent); err != nil {
		return Slots{}, err
	}
	if out.Previous, err = readSlot(ctx, tx, selectSlot, orgID, kind, SlotPrevious); err != nil {
		return Slots{}, err
	}
	return out, nil
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, orgID string, rec audit.Entry) error {
	rec.OrgID = orgID
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("служебные базы: %w", err)
	}
	return nil
}

// Save — см. Store.
func (s *PGStore) Save(ctx context.Context, orgID, kind string, b Stored, keep func(Stored) error, fn func(prev *Stored) audit.Entry) error {
	if b.Version == 0 || b.Version > MaxVersion || b.SubkeySerial == 0 || b.SubkeySerial > MaxVersion ||
		len(b.File) == 0 || len(b.File) > maxStoredFile {
		return ErrContent
	}
	return s.inTx(ctx, orgID, kind, func(ctx context.Context, tx pgx.Tx) error {
		cur, err := readSlot(ctx, tx, selectSlot+` FOR UPDATE`, orgID, kind, SlotCurrent)
		if err != nil {
			return err
		}
		if cur != nil && b.Version <= cur.Version {
			return ErrStale
		}
		rec := fn(cur.clone())
		if cur != nil {
			// Прежняя текущая уходит в предыдущую, только если проходит
			// проверку: откат должен вести на проверенную базу.
			if keep(*cur) == nil {
				if _, err := tx.Exec(ctx, `DELETE FROM service_dbs WHERE org_id = $1 AND kind = $2 AND slot = $3`, orgID, kind, SlotPrevious); err != nil {
					return fmt.Errorf("служебные базы: удаление предыдущей: %w", err)
				}
				if _, err := tx.Exec(ctx, `UPDATE service_dbs SET slot = $3 WHERE org_id = $1 AND kind = $2 AND slot = $4`,
					orgID, kind, SlotPrevious, SlotCurrent); err != nil {
					return fmt.Errorf("служебные базы: сдвиг текущей: %w", err)
				}
			} else if _, err := tx.Exec(ctx, `DELETE FROM service_dbs WHERE org_id = $1 AND kind = $2 AND slot = $3`, orgID, kind, SlotCurrent); err != nil {
				return fmt.Errorf("служебные базы: удаление текущей: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO service_dbs
			(org_id, kind, slot, version, db_date, records, subkey_serial, fingerprint, file, uploaded_at, uploaded_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			orgID, kind, SlotCurrent, int64(b.Version), b.Date, b.Records, int64(b.SubkeySerial), b.Fingerprint, b.File, b.UploadedAt, b.UploadedBy); err != nil { //nolint:gosec // G115: версия и номер не больше 2^53 (проверено выше)
			return fmt.Errorf("служебные базы: запись: %w", err)
		}
		return s.record(ctx, tx, orgID, rec)
	})
}

// Rollback — см. Store.
func (s *PGStore) Rollback(ctx context.Context, orgID, kind string, check func(Stored) error, fn func(from *Stored, to Stored) audit.Entry) (Stored, error) {
	var to Stored
	err := s.inTx(ctx, orgID, kind, func(ctx context.Context, tx pgx.Tx) error {
		prev, err := readSlot(ctx, tx, selectSlot+` FOR UPDATE`, orgID, kind, SlotPrevious)
		if err != nil {
			return err
		}
		if prev == nil {
			return ErrNoPrevious
		}
		if err := check(*prev.clone()); err != nil {
			return err
		}
		cur, err := readSlot(ctx, tx, selectSlot+` FOR UPDATE`, orgID, kind, SlotCurrent)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM service_dbs WHERE org_id = $1 AND kind = $2 AND slot = $3`, orgID, kind, SlotCurrent); err != nil {
			return fmt.Errorf("служебные базы: удаление текущей: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE service_dbs SET slot = $3 WHERE org_id = $1 AND kind = $2 AND slot = $4`,
			orgID, kind, SlotCurrent, SlotPrevious); err != nil {
			return fmt.Errorf("служебные базы: откат: %w", err)
		}
		to = *prev
		return s.record(ctx, tx, orgID, fn(cur, *prev.clone()))
	})
	if err != nil {
		return Stored{}, err
	}
	return to, nil
}

// Record — см. Store.
func (s *PGStore) Record(ctx context.Context, rec audit.Entry) error {
	return s.audit.Record(ctx, rec)
}
