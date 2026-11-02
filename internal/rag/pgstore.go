package rag

import (
	"context"
	"encoding/json"
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
	// pgLoadTimeout — предел на загрузку манифеста: чтение текущей версии и
	// запись до 100 000 строк.
	pgLoadTimeout = 2 * time.Minute
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0071_rag).
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("RAG: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
}

func pgCtx(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// inTx — транзакция со сроком d; fn делает все запросы с контекстом срока.
func (s *PGStore) inTx(ctx context.Context, d time.Duration, fn func(context.Context, pgx.Tx) error) error {
	ctx, cancel := pgCtx(ctx, d)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("RAG: начало транзакции: %w", err)
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
		return fmt.Errorf("RAG: фиксация: %w", err)
	}
	return nil
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, recs ...audit.Entry) error {
	for _, rec := range recs {
		if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
			return fmt.Errorf("RAG: %w", err)
		}
	}
	return nil
}

// lockOrg — блокировка коллекций организации на транзакцию: предел числа
// коллекций и версии манифеста без гонки.
func lockOrg(ctx context.Context, tx pgx.Tx, orgID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('aisec.rag:' || $1, 0))`, orgID)
	return err
}

func dbErr(what string, err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrExists
	}
	return fmt.Errorf("RAG: %s: %w", what, err)
}

const collectionCols = `c.id, c.org_id, c.slug, c.version, c.documents, c.size, c.excluded, c.loaded_at, c.loaded_by,
	c.prev_loaded_at, c.diff, c.created_at, (SELECT count(*) FROM rag_exclusions e WHERE e.collection_id = c.id)`

func scanCollection(row pgx.Row) (Collection, error) {
	var c Collection
	var diff []byte
	if err := row.Scan(&c.ID, &c.OrgID, &c.Slug, &c.Version, &c.Documents, &c.Size, &c.Excluded, &c.LoadedAt, &c.LoadedBy,
		&c.PrevLoadedAt, &diff, &c.CreatedAt, &c.ExclusionCount); err != nil {
		return Collection{}, err
	}
	if err := json.Unmarshal(diff, &c.Diff); err != nil {
		return Collection{}, fmt.Errorf("разница версий: %w", err)
	}
	for _, p := range []*[]string{&c.Diff.AddedIDs, &c.Diff.ChangedIDs, &c.Diff.RemovedIDs} {
		if *p == nil {
			*p = []string{}
		}
	}
	c.LoadedAt, c.CreatedAt = c.LoadedAt.UTC(), c.CreatedAt.UTC()
	if c.PrevLoadedAt != nil {
		t := c.PrevLoadedAt.UTC()
		c.PrevLoadedAt = &t
	}
	return c, nil
}

// Collections — коллекции организации по slug.
func (s *PGStore) Collections(ctx context.Context, orgID string) ([]Collection, error) {
	ctx, cancel := pgCtx(ctx, pgTimeout)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+collectionCols+` FROM rag_collections c WHERE c.org_id = $1 ORDER BY c.slug`, orgID)
	if err != nil {
		return nil, dbErr("коллекции", err)
	}
	defer rows.Close()
	out := []Collection{}
	for rows.Next() {
		c, err := scanCollection(rows)
		if err != nil {
			return nil, dbErr("коллекции", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("коллекции", err)
	}
	return out, nil
}

// Collection — коллекция с исключениями.
func (s *PGStore) Collection(ctx context.Context, orgID, slug string) (Collection, error) {
	ctx, cancel := pgCtx(ctx, pgTimeout)
	defer cancel()
	c, err := scanCollection(s.db.QueryRow(ctx, `SELECT `+collectionCols+` FROM rag_collections c WHERE c.org_id = $1 AND c.slug = $2`,
		orgID, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return Collection{}, ErrNotFound
	}
	if err != nil {
		return Collection{}, dbErr("коллекция", err)
	}
	rows, err := s.db.Query(ctx, `SELECT id, doc_id, reason, created_at, created_by FROM rag_exclusions WHERE collection_id = $1
		ORDER BY created_at, id`, c.ID)
	if err != nil {
		return Collection{}, dbErr("исключения", err)
	}
	defer rows.Close()
	c.Exclusions = []Exclusion{}
	for rows.Next() {
		var e Exclusion
		if err := rows.Scan(&e.ID, &e.DocumentID, &e.Reason, &e.CreatedAt, &e.CreatedBy); err != nil {
			return Collection{}, dbErr("исключения", err)
		}
		e.CreatedAt = e.CreatedAt.UTC()
		c.Exclusions = append(c.Exclusions, e)
	}
	if err := rows.Err(); err != nil {
		return Collection{}, dbErr("исключения", err)
	}
	return c, nil
}

// Documents — страница документов текущей версии по возрастанию ID
// (сравнение байтов, COLLATE "C" — тот же порядок, что у курсора).
func (s *PGStore) Documents(ctx context.Context, orgID, slug, after string, limit int) ([]Document, error) {
	ctx, cancel := pgCtx(ctx, pgTimeout)
	defer cancel()
	var id string
	var version int
	err := s.db.QueryRow(ctx, `SELECT id, version FROM rag_collections WHERE org_id = $1 AND slug = $2`, orgID, slug).Scan(&id, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, dbErr("коллекция", err)
	}
	rows, err := s.db.Query(ctx, `SELECT d.doc_id, d.sha256, d.size, d.excluded,
			EXISTS (SELECT 1 FROM rag_exclusions e WHERE e.collection_id = d.collection_id AND e.doc_id = d.doc_id)
		FROM rag_documents d WHERE d.collection_id = $1 AND d.version = $2 AND d.doc_id COLLATE "C" > $3
		ORDER BY d.doc_id COLLATE "C" LIMIT $4`, id, version, after, limit)
	if err != nil {
		return nil, dbErr("документы", err)
	}
	defer rows.Close()
	out := []Document{}
	for rows.Next() {
		var d Document
		if err := rows.Scan(&d.ID, &d.SHA256, &d.Size, &d.Excluded, &d.Blocked); err != nil {
			return nil, dbErr("документы", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("документы", err)
	}
	return out, nil
}

// LoadManifest — новая версия манифеста: документы пишутся COPY, версии
// старше предыдущей удаляются.
func (s *PGStore) LoadManifest(ctx context.Context, orgID, slug string, docs []Document,
	fn func(cur *Collection, curDocs []Document) (Collection, []audit.Entry, error)) ([]string, error) {
	var blocked []string
	err := s.inTx(ctx, pgLoadTimeout, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockOrg(ctx, tx, orgID); err != nil {
			return dbErr("блокировка", err)
		}
		var cur *Collection
		var curDocs []Document
		c, err := scanCollection(tx.QueryRow(ctx, `SELECT `+collectionCols+` FROM rag_collections c WHERE c.org_id = $1 AND c.slug = $2`,
			orgID, slug))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM rag_collections WHERE org_id = $1`, orgID).Scan(&n); err != nil {
				return dbErr("число коллекций", err)
			}
			if n >= MaxCollections {
				return ErrTooManyCollections
			}
		case err != nil:
			return dbErr("коллекция", err)
		default:
			cur = &c
			if curDocs, err = readVersion(ctx, tx, c.ID, c.Version); err != nil {
				return err
			}
		}
		next, recs, err := fn(cur, curDocs)
		if err != nil {
			return err
		}
		diff, err := json.Marshal(next.Diff)
		if err != nil {
			return fmt.Errorf("RAG: разница версий: %w", err)
		}
		if cur == nil {
			_, err = tx.Exec(ctx, `INSERT INTO rag_collections (id, org_id, slug, version, documents, size, excluded, loaded_at, loaded_by,
					prev_loaded_at, diff, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
				next.ID, orgID, slug, next.Version, next.Documents, next.Size, next.Excluded, next.LoadedAt, next.LoadedBy,
				next.PrevLoadedAt, diff, next.CreatedAt)
		} else {
			_, err = tx.Exec(ctx, `UPDATE rag_collections SET version = $2, documents = $3, size = $4, excluded = $5, loaded_at = $6,
					loaded_by = $7, prev_loaded_at = $8, diff = $9 WHERE id = $1`,
				next.ID, next.Version, next.Documents, next.Size, next.Excluded, next.LoadedAt, next.LoadedBy, next.PrevLoadedAt, diff)
		}
		if err != nil {
			return dbErr("коллекция", err)
		}
		// Хранятся текущая и предыдущая версии.
		if _, err := tx.Exec(ctx, `DELETE FROM rag_documents WHERE collection_id = $1 AND version < $2`, next.ID, next.Version-1); err != nil {
			return dbErr("прежние версии", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"rag_documents"}, []string{"collection_id", "version", "doc_id", "sha256", "size", "excluded"},
			pgx.CopyFromSlice(len(docs), func(i int) ([]any, error) {
				d := docs[i]
				return []any{next.ID, next.Version, d.ID, d.SHA256, d.Size, d.Excluded}, nil
			})); err != nil {
			return dbErr("документы", err)
		}
		rows, err := tx.Query(ctx, `SELECT e.doc_id FROM rag_exclusions e JOIN rag_documents d
				ON d.collection_id = e.collection_id AND d.doc_id = e.doc_id AND d.version = $2
			WHERE e.collection_id = $1`, next.ID, next.Version)
		if err != nil {
			return dbErr("исключения", err)
		}
		blocked, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return dbErr("исключения", err)
		}
		return s.record(ctx, tx, recs...)
	})
	if err != nil {
		return nil, err
	}
	return blocked, nil
}

// readVersion — документы версии манифеста.
func readVersion(ctx context.Context, tx pgx.Tx, id string, version int) ([]Document, error) {
	rows, err := tx.Query(ctx, `SELECT doc_id, sha256, size, excluded FROM rag_documents WHERE collection_id = $1 AND version = $2`, id, version)
	if err != nil {
		return nil, dbErr("текущая версия", err)
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var d Document
		if err := rows.Scan(&d.ID, &d.SHA256, &d.Size, &d.Excluded); err != nil {
			return nil, dbErr("текущая версия", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("текущая версия", err)
	}
	return out, nil
}

// lockCollection — коллекция под блокировкой строки; ErrNotFound.
func lockCollection(ctx context.Context, tx pgx.Tx, orgID, slug string) (Collection, error) {
	c, err := scanCollection(tx.QueryRow(ctx, `SELECT `+collectionCols+` FROM rag_collections c WHERE c.org_id = $1 AND c.slug = $2
		FOR UPDATE OF c`, orgID, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return Collection{}, ErrNotFound
	}
	if err != nil {
		return Collection{}, dbErr("коллекция", err)
	}
	return c, nil
}

// AddExclusion — исключение документа.
func (s *PGStore) AddExclusion(ctx context.Context, orgID, slug string, ex Exclusion, rec func(Collection) audit.Entry) error {
	return s.inTx(ctx, pgTimeout, func(ctx context.Context, tx pgx.Tx) error {
		c, err := lockCollection(ctx, tx, orgID, slug)
		if err != nil {
			return err
		}
		var dup bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rag_exclusions WHERE collection_id = $1 AND doc_id = $2)`,
			c.ID, ex.DocumentID).Scan(&dup); err != nil {
			return dbErr("исключения", err)
		}
		switch {
		case dup:
			return ErrExists
		case c.ExclusionCount >= MaxExclusions:
			return ErrTooManyExclusions
		}
		if _, err := tx.Exec(ctx, `INSERT INTO rag_exclusions (id, collection_id, doc_id, reason, created_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6)`, ex.ID, c.ID, ex.DocumentID, ex.Reason, ex.CreatedAt, ex.CreatedBy); err != nil {
			return dbErr("исключение", err)
		}
		c.ExclusionCount++
		return s.record(ctx, tx, rec(c))
	})
}

// RemoveExclusion — снятие исключения.
func (s *PGStore) RemoveExclusion(ctx context.Context, orgID, slug, id string, rec func(Collection, Exclusion) audit.Entry) error {
	return s.inTx(ctx, pgTimeout, func(ctx context.Context, tx pgx.Tx) error {
		c, err := lockCollection(ctx, tx, orgID, slug)
		if err != nil {
			return err
		}
		var ex Exclusion
		err = tx.QueryRow(ctx, `DELETE FROM rag_exclusions WHERE collection_id = $1 AND id = $2
			RETURNING id, doc_id, reason, created_at, created_by`, c.ID, id).Scan(&ex.ID, &ex.DocumentID, &ex.Reason, &ex.CreatedAt, &ex.CreatedBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrExclusionNotFound
		}
		if err != nil {
			return dbErr("исключение", err)
		}
		c.ExclusionCount--
		return s.record(ctx, tx, rec(c, ex))
	})
}
