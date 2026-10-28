package shadowai

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
	// upsertBatch — агрегатов в одном запросе вставки.
	upsertBatch = 5000
	// sumCap — предел сумм при чтении (bigint).
	sumCap = "4000000000000000000"
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0061_shadow_ai). SQL только
// параметризованный.
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал аудита должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("теневой ИИ: нет БД или журнала аудита")
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
		return fmt.Errorf("теневой ИИ: начало транзакции: %w", err)
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
		return fmt.Errorf("теневой ИИ: фиксация: %w", err)
	}
	return nil
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, orgID string, rec audit.Entry) error {
	rec.OrgID = orgID
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("теневой ИИ: %w", err)
	}
	return nil
}

// Catalog — см. Store.
func (s *PGStore) Catalog(ctx context.Context, orgID string) (StoredCatalog, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var c StoredCatalog
	var version, serial int64
	err := s.db.QueryRow(ctx, `SELECT version, catalog_date, subkey_serial, fingerprint, services, file, uploaded_at, uploaded_by
		FROM shadow_ai_catalog WHERE org_id = $1`, orgID).
		Scan(&version, &c.Date, &serial, &c.Fingerprint, &c.Services, &c.File, &c.UploadedAt, &c.UploadedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCatalog{}, ErrNoCatalog
	}
	if err != nil {
		return StoredCatalog{}, fmt.Errorf("теневой ИИ: каталог: %w", err)
	}
	c.Version, c.SubkeySerial = uint64(version), uint64(serial) //nolint:gosec // G115: CHECK > 0 в схеме
	return c, nil
}

// SaveCatalog — см. Store. Версия сравнивается в самом запросе: две
// загрузки одновременно не опустят версию.
func (s *PGStore) SaveCatalog(ctx context.Context, orgID string, c StoredCatalog, rec audit.Entry) error {
	if c.Version > maxCatalogVersion || c.SubkeySerial > maxCatalogVersion {
		return ErrStaleCatalog
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO shadow_ai_catalog
			(org_id, version, catalog_date, subkey_serial, fingerprint, services, file, uploaded_at, uploaded_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (org_id) DO UPDATE SET version = EXCLUDED.version, catalog_date = EXCLUDED.catalog_date,
				subkey_serial = EXCLUDED.subkey_serial, fingerprint = EXCLUDED.fingerprint, services = EXCLUDED.services,
				file = EXCLUDED.file, uploaded_at = EXCLUDED.uploaded_at, uploaded_by = EXCLUDED.uploaded_by
			WHERE shadow_ai_catalog.version < EXCLUDED.version`,
			orgID, int64(c.Version), c.Date, int64(c.SubkeySerial), c.Fingerprint, c.Services, c.File, c.UploadedAt, c.UploadedBy) //nolint:gosec // G115: версия и номер не больше 2^53 (проверено выше)
		if err != nil {
			return fmt.Errorf("теневой ИИ: сохранение каталога: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrStaleCatalog
		}
		return s.record(ctx, tx, orgID, rec)
	})
}

// SaveImport — см. Store.
func (s *PGStore) SaveImport(ctx context.Context, orgID string, imp ImportRecord, rec audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO shadow_ai_imports (id, org_id, created_at, created_by, format, sha256, catalog_version,
			lines, matched, unmatched, errors, outdated, error_lines, services, users_pseudonymized, period_from, period_to)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
			ON CONFLICT (org_id, sha256) DO NOTHING RETURNING id::text`,
			imp.ID, orgID, imp.CreatedAt, imp.CreatedBy, imp.Format, imp.SHA256, int64(imp.CatalogVersion), //nolint:gosec // G115: версия каталога не больше 2^53
			imp.Lines, imp.Matched, imp.Unmatched, imp.Errors, imp.Outdated, imp.ErrorLines, imp.Services, imp.UsersPseudonymized,
			imp.From, imp.To).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDuplicate
		}
		if err != nil {
			return fmt.Errorf("теневой ИИ: запись импорта: %w", err)
		}
		for start := 0; start < len(imp.Aggregates); start += upsertBatch {
			part := imp.Aggregates[start:min(start+upsertBatch, len(imp.Aggregates))]
			buckets := make([]time.Time, len(part))
			services := make([]string, len(part))
			aliases := make([]string, len(part))
			kinds := make([]string, len(part))
			reqs := make([]int64, len(part))
			bytes := make([]int64, len(part))
			for i, a := range part {
				buckets[i], services[i], aliases[i], kinds[i], reqs[i], bytes[i] = a.Bucket, a.Service, a.UserAlias, a.UserKind, a.Requests, a.Bytes
			}
			if _, err := tx.Exec(ctx, `INSERT INTO shadow_ai_hour (org_id, bucket, service, user_alias, user_kind, requests, bytes)
				SELECT $1, b, s, u, k, r, y FROM unnest($2::timestamptz[], $3::text[], $4::text[], $5::text[], $6::bigint[], $7::bigint[])
					AS t(b, s, u, k, r, y)
				ON CONFLICT (org_id, bucket, service, user_alias, user_kind) DO UPDATE SET
					requests = LEAST(shadow_ai_hour.requests + EXCLUDED.requests, 4611686018427387904),
					bytes = LEAST(shadow_ai_hour.bytes + EXCLUDED.bytes, 4611686018427387904)`,
				orgID, buckets, services, aliases, kinds, reqs, bytes); err != nil {
				return fmt.Errorf("теневой ИИ: запись агрегатов: %w", err)
			}
		}
		return s.record(ctx, tx, orgID, rec)
	})
}

// Imports — см. Store.
func (s *PGStore) Imports(ctx context.Context, orgID string, limit int) ([]ImportRecord, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT id::text, created_at, created_by, format, sha256, catalog_version, lines, matched, unmatched,
		errors, outdated, error_lines, services, users_pseudonymized, period_from, period_to
		FROM shadow_ai_imports WHERE org_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("теневой ИИ: журнал импорта: %w", err)
	}
	defer rows.Close()
	out := []ImportRecord{}
	for rows.Next() {
		var r ImportRecord
		var version int64
		if err := rows.Scan(&r.ID, &r.CreatedAt, &r.CreatedBy, &r.Format, &r.SHA256, &version, &r.Lines, &r.Matched, &r.Unmatched,
			&r.Errors, &r.Outdated, &r.ErrorLines, &r.Services, &r.UsersPseudonymized, &r.From, &r.To); err != nil {
			return nil, fmt.Errorf("теневой ИИ: журнал импорта: %w", err)
		}
		r.CatalogVersion = uint64(version) //nolint:gosec // G115: CHECK > 0 в схеме
		if r.ErrorLines == nil {
			r.ErrorLines = []int64{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Services — см. Store.
func (s *PGStore) Services(ctx context.Context, orgID string, q Query) ([]ServiceStat, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT service, LEAST(sum(requests), `+sumCap+`)::bigint AS req, LEAST(sum(bytes), `+sumCap+`)::bigint,
		count(DISTINCT user_alias) FILTER (WHERE user_alias <> ''), min(bucket), max(bucket)
		FROM shadow_ai_hour WHERE org_id = $1 AND bucket >= $2 AND bucket < $3 AND ($4 = '' OR service = $4)
		GROUP BY service ORDER BY req DESC, service LIMIT $5`, orgID, q.From, q.To, q.Service, q.Limit)
	if err != nil {
		return nil, fmt.Errorf("теневой ИИ: сервисы: %w", err)
	}
	defer rows.Close()
	out := []ServiceStat{}
	for rows.Next() {
		var st ServiceStat
		if err := rows.Scan(&st.ID, &st.Requests, &st.Bytes, &st.Users, &st.FirstSeen, &st.LastSeen); err != nil {
			return nil, fmt.Errorf("теневой ИИ: сервисы: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Users — см. Store.
func (s *PGStore) Users(ctx context.Context, orgID string, q Query) ([]UserStat, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT user_alias, user_kind, LEAST(sum(requests), `+sumCap+`)::bigint AS req,
		LEAST(sum(bytes), `+sumCap+`)::bigint, array_agg(DISTINCT service ORDER BY service), max(bucket)
		FROM shadow_ai_hour WHERE org_id = $1 AND bucket >= $2 AND bucket < $3 AND user_alias <> '' AND ($4 = '' OR service = $4)
		GROUP BY user_alias, user_kind ORDER BY req DESC, user_alias LIMIT $5`, orgID, q.From, q.To, q.Service, q.Limit)
	if err != nil {
		return nil, fmt.Errorf("теневой ИИ: пользователи: %w", err)
	}
	defer rows.Close()
	out := []UserStat{}
	for rows.Next() {
		var u UserStat
		if err := rows.Scan(&u.Alias, &u.Kind, &u.Requests, &u.Bytes, &u.Services, &u.LastSeen); err != nil {
			return nil, fmt.Errorf("теневой ИИ: пользователи: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Timeline — см. Store. Сутки — в часовом поясе установки.
func (s *PGStore) Timeline(ctx context.Context, orgID string, q Query) ([]Point, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT CASE WHEN $5 = 'day' THEN date_trunc('day', bucket AT TIME ZONE $6) AT TIME ZONE $6 ELSE bucket END AS b,
		LEAST(sum(requests), `+sumCap+`)::bigint, LEAST(sum(bytes), `+sumCap+`)::bigint,
		count(DISTINCT user_alias) FILTER (WHERE user_alias <> ''), count(DISTINCT service)
		FROM shadow_ai_hour WHERE org_id = $1 AND bucket >= $2 AND bucket < $3 AND ($4 = '' OR service = $4)
		GROUP BY b ORDER BY b`, orgID, q.From, q.To, q.Service, q.Step, q.TZ)
	if err != nil {
		return nil, fmt.Errorf("теневой ИИ: динамика: %w", err)
	}
	defer rows.Close()
	out := []Point{}
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.Bucket, &p.Requests, &p.Bytes, &p.Users, &p.Services); err != nil {
			return nil, fmt.Errorf("теневой ИИ: динамика: %w", err)
		}
		p.Bucket = p.Bucket.UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

// RetentionDays — см. Store.
func (s *PGStore) RetentionDays(ctx context.Context, orgID string) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var days int
	err := s.db.QueryRow(ctx, `SELECT shadow_ai_retention_days FROM install_settings WHERE org_id = $1`, orgID).Scan(&days)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultRetentionDays, nil
	}
	return days, err
}

// SetRetentionDays — см. Store.
func (s *PGStore) SetRetentionDays(ctx context.Context, orgID string, days int, fn func(old int) (audit.Entry, error)) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var old int
		err := tx.QueryRow(ctx, `SELECT shadow_ai_retention_days FROM install_settings WHERE org_id = $1 FOR UPDATE`, orgID).Scan(&old)
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
		if _, err := tx.Exec(ctx, `UPDATE install_settings SET shadow_ai_retention_days = $2 WHERE org_id = $1`, orgID, days); err != nil {
			return err
		}
		return s.record(ctx, tx, orgID, rec)
	})
}

// PurgeExpired — см. Store.
func (s *PGStore) PurgeExpired(ctx context.Context, orgID string) (int64, error) {
	var n int64
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var days int
		err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT shadow_ai_retention_days FROM install_settings WHERE org_id = $1), $2)`,
			orgID, DefaultRetentionDays).Scan(&days)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM shadow_ai_hour WHERE org_id = $1
			AND bucket < date_trunc('hour', now()) - make_interval(days => $2)`, orgID, days)
		if err != nil {
			return err
		}
		if n = tag.RowsAffected(); n == 0 {
			return nil
		}
		return s.record(ctx, tx, orgID, retentionEntry(n, days))
	})
	if err != nil {
		return 0, fmt.Errorf("теневой ИИ: удаление по сроку хранения: %w", err)
	}
	return n, nil
}

// Record — см. Store.
func (s *PGStore) Record(ctx context.Context, rec audit.Entry) error {
	return s.audit.Record(ctx, rec)
}
