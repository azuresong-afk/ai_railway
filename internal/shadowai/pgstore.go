package shadowai

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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

// PGStore — Store на PostgreSQL (миграции 0061_shadow_ai, 0063_shadow_ai_exclusions). SQL только
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

// lockWrites — блокировка записи сводок и исключений организации до конца
// транзакции: новый сервис определяется по сводкам, видимым под ней.
func lockWrites(ctx context.Context, tx pgx.Tx, orgID string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('aisec.shadow_ai:' || $1, 0))`, orgID); err != nil {
		return fmt.Errorf("теневой ИИ: блокировка записи: %w", err)
	}
	return nil
}

// writeAggregates прибавляет сводки, кроме исключённых (исключение могло
// появиться после разбора — блокировка lockWrites делает список точным), и
// возвращает записанные сводки и новые сервисы среди них (DM-37).
func writeAggregates(ctx context.Context, tx pgx.Tx, orgID string, aggs []Aggregate) ([]Aggregate, []string, error) {
	rows, err := tx.Query(ctx, `SELECT kind, value FROM shadow_ai_exclusions WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, nil, fmt.Errorf("теневой ИИ: исключения: %w", err)
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Exclusion, error) {
		var e Exclusion
		err := r.Scan(&e.Kind, &e.Value)
		return e, err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("теневой ИИ: исключения: %w", err)
	}
	ex := ExclusionsOf(list)
	kept := make([]Aggregate, 0, len(aggs))
	for _, a := range aggs {
		if !ex.Excludes(a.Service, a.UserAlias) {
			kept = append(kept, a)
		}
	}
	ids, firsts := firstArrays(kept)
	var fresh []string
	if len(ids) > 0 {
		rows, err := tx.Query(ctx, `SELECT t.s FROM unnest($2::text[], $3::timestamptz[]) AS t(s, f)
			WHERE NOT EXISTS (SELECT 1 FROM shadow_ai_hour h WHERE h.org_id = $1 AND h.service = t.s
				AND h.bucket >= t.f - make_interval(days => $4))
			ORDER BY t.s`, orgID, ids, firsts, int(NewServiceWindow/(24*time.Hour)))
		if err != nil {
			return nil, nil, fmt.Errorf("теневой ИИ: новые сервисы: %w", err)
		}
		fresh, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return nil, nil, fmt.Errorf("теневой ИИ: новые сервисы: %w", err)
		}
	}
	for start := 0; start < len(kept); start += upsertBatch {
		part := kept[start:min(start+upsertBatch, len(kept))]
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
			return nil, nil, fmt.Errorf("теневой ИИ: запись агрегатов: %w", err)
		}
	}
	return kept, fresh, nil
}

// SaveImport — см. Store.
func (s *PGStore) SaveImport(ctx context.Context, orgID string, imp ImportRecord, rec audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO shadow_ai_imports (id, org_id, created_at, created_by, format, sha256, catalog_version,
			lines, matched, unmatched, errors, outdated, error_lines, services, users_pseudonymized, period_from, period_to, excluded)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
			ON CONFLICT (org_id, sha256) DO NOTHING RETURNING id::text`,
			imp.ID, orgID, imp.CreatedAt, imp.CreatedBy, imp.Format, imp.SHA256, int64(imp.CatalogVersion), //nolint:gosec // G115: версия каталога не больше 2^53
			imp.Lines, imp.Matched, imp.Unmatched, imp.Errors, imp.Outdated, imp.ErrorLines, imp.Services, imp.UsersPseudonymized,
			imp.From, imp.To, imp.Excluded).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDuplicate
		}
		if err != nil {
			return fmt.Errorf("теневой ИИ: запись импорта: %w", err)
		}
		if err := lockWrites(ctx, tx, orgID); err != nil {
			return err
		}
		kept, fresh, err := writeAggregates(ctx, tx, orgID, imp.Aggregates)
		if err != nil {
			return err
		}
		if err := s.record(ctx, tx, orgID, rec); err != nil {
			return err
		}
		for _, e := range newServiceEntries(rec.Actor, rec.SourceIP, SourceImport, kept, imp.ServiceNames, fresh) {
			if err := s.record(ctx, tx, orgID, e); err != nil {
				return err
			}
		}
		return nil
	})
}

// SaveSyslog — см. Store.
func (s *PGStore) SaveSyslog(ctx context.Context, orgID string, b SyslogBatch) error {
	if len(b.Aggregates) == 0 {
		return nil
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockWrites(ctx, tx, orgID); err != nil {
			return err
		}
		kept, fresh, err := writeAggregates(ctx, tx, orgID, b.Aggregates)
		if err != nil {
			return err
		}
		for _, e := range newServiceEntries(systemActor, netip.Addr{}, SourceSyslog, kept, b.ServiceNames, fresh) {
			if err := s.record(ctx, tx, orgID, e); err != nil {
				return err
			}
		}
		return nil
	})
}

// Exclusions — см. Store.
func (s *PGStore) Exclusions(ctx context.Context, orgID string) ([]Exclusion, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT kind, value, comment, created_at, created_by FROM shadow_ai_exclusions
		WHERE org_id = $1 ORDER BY kind, value LIMIT $2`, orgID, MaxExclusions)
	if err != nil {
		return nil, fmt.Errorf("теневой ИИ: исключения: %w", err)
	}
	defer rows.Close()
	out := []Exclusion{}
	for rows.Next() {
		var e Exclusion
		if err := rows.Scan(&e.Kind, &e.Value, &e.Comment, &e.CreatedAt, &e.CreatedBy); err != nil {
			return nil, fmt.Errorf("теневой ИИ: исключения: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddExclusion — см. Store.
func (s *PGStore) AddExclusion(ctx context.Context, orgID string, ex Exclusion, fn func(deleted int64) audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockWrites(ctx, tx, orgID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM shadow_ai_exclusions WHERE org_id = $1`, orgID).Scan(&n); err != nil {
			return fmt.Errorf("теневой ИИ: исключения: %w", err)
		}
		if n >= MaxExclusions {
			return ErrTooManyExclusions
		}
		tag, err := tx.Exec(ctx, `INSERT INTO shadow_ai_exclusions (org_id, kind, value, comment, created_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (org_id, kind, value) DO NOTHING`,
			orgID, ex.Kind, ex.Value, ex.Comment, ex.CreatedAt, ex.CreatedBy)
		if err != nil {
			return fmt.Errorf("теневой ИИ: исключение: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrExclusionExists
		}
		q := `DELETE FROM shadow_ai_hour WHERE org_id = $1 AND service = $2`
		if ex.Kind == ExcludeUser {
			q = `DELETE FROM shadow_ai_hour WHERE org_id = $1 AND user_alias = $2`
		}
		tag, err = tx.Exec(ctx, q, orgID, ex.Value)
		if err != nil {
			return fmt.Errorf("теневой ИИ: удаление сводок исключённого: %w", err)
		}
		return s.record(ctx, tx, orgID, fn(tag.RowsAffected()))
	})
}

// RemoveExclusion — см. Store.
func (s *PGStore) RemoveExclusion(ctx context.Context, orgID, kind, value string, rec audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockWrites(ctx, tx, orgID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM shadow_ai_exclusions WHERE org_id = $1 AND kind = $2 AND value = $3`, orgID, kind, value)
		if err != nil {
			return fmt.Errorf("теневой ИИ: исключение: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrExclusionNotFound
		}
		return s.record(ctx, tx, orgID, rec)
	})
}

// Imports — см. Store.
func (s *PGStore) Imports(ctx context.Context, orgID string, limit int) ([]ImportRecord, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT id::text, created_at, created_by, format, sha256, catalog_version, lines, matched, unmatched,
		errors, outdated, error_lines, services, users_pseudonymized, period_from, period_to, excluded
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
			&r.Errors, &r.Outdated, &r.ErrorLines, &r.Services, &r.UsersPseudonymized, &r.From, &r.To, &r.Excluded); err != nil {
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
