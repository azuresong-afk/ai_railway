package inventory

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
	// pgDiscoverTimeout — предел на запуск пополнения (первое чтение всей
	// таблицы агрегатов).
	pgDiscoverTimeout = 2 * time.Minute
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
	// maxSeenRows — троек из агрегатов за один запуск.
	maxSeenRows = 2 * MaxUsage
	// maxKeysShown — ключей приложения в сводке (новые первыми, без
	// отозванных); остальные — только числом.
	maxKeysShown = 20
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0069_inventory). Приложения,
// ключи, провайдеры (0014) и агрегаты дашбордов (0037) только читаются.
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("реестр ИИ: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
}

func pgCtx(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// inTx — транзакция со сроком d; fn получает контекст со сроком и все
// запросы делает с ним (ревью 5.17: иначе срок действует только на
// Begin и Commit).
func (s *PGStore) inTx(ctx context.Context, d time.Duration, fn func(context.Context, pgx.Tx) error) error {
	ctx, cancel := pgCtx(ctx, d)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("реестр ИИ: начало транзакции: %w", err)
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
		return fmt.Errorf("реестр ИИ: фиксация: %w", err)
	}
	return nil
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, rec audit.Entry) error {
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("реестр ИИ: %w", err)
	}
	return nil
}

// lockOrg — блокировка реестра организации на транзакцию: пределы числа
// записей считаются без гонки, запуски пополнения не пересекаются.
func lockOrg(ctx context.Context, tx pgx.Tx, orgID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('aisec.inventory:' || $1, 0))`, orgID)
	return err
}

func dbErr(what string, err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrExists
	}
	return fmt.Errorf("реестр ИИ: %s: %w", what, err)
}

// Overview — сводка реестра.
func (s *PGStore) Overview(ctx context.Context, orgID string, now time.Time) (Overview, error) {
	ctx, cancel := pgCtx(ctx, pgTimeout)
	defer cancel()
	var o Overview
	rows, err := s.db.Query(ctx, `SELECT a.id, a.slug, a.name, a.env, a.department, p.slug, a.models, a.archived_at IS NOT NULL
		FROM applications a JOIN providers p ON p.id = a.provider_id WHERE a.org_id = $1 ORDER BY a.slug`, orgID)
	if err != nil {
		return Overview{}, dbErr("приложения", err)
	}
	idx := map[string]int{}
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.ID, &a.Slug, &a.Name, &a.Env, &a.Department, &a.Provider, &a.Models, &a.Archived); err != nil {
			rows.Close()
			return Overview{}, dbErr("приложения", err)
		}
		idx[a.ID] = len(o.Apps)
		a.Keys = []Key{}
		o.Apps = append(o.Apps, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Overview{}, dbErr("приложения", err)
	}
	// Ключи: действующие и истёкшие, новые первыми, не больше maxKeysShown
	// на приложение; хеш и секрет не читаются.
	rows, err = s.db.Query(ctx, `SELECT id, app_id, name, prefix, expires_at, created_at FROM (
			SELECT k.*, row_number() OVER (PARTITION BY k.app_id ORDER BY k.created_at DESC, k.id DESC) AS n
			FROM app_keys k WHERE k.org_id = $1 AND k.revoked_at IS NULL) t
		WHERE n <= $2 ORDER BY app_id, created_at DESC, id DESC`, orgID, maxKeysShown)
	if err != nil {
		return Overview{}, dbErr("ключи", err)
	}
	for rows.Next() {
		var k Key
		var app string
		if err := rows.Scan(&k.ID, &app, &k.Name, &k.Prefix, &k.ExpiresAt, &k.CreatedAt); err != nil {
			rows.Close()
			return Overview{}, dbErr("ключи", err)
		}
		k.State = KeyActive
		if !k.ExpiresAt.After(now) {
			k.State = KeyExpired
		}
		k.ExpiresAt, k.CreatedAt = k.ExpiresAt.UTC(), k.CreatedAt.UTC()
		if i, ok := idx[app]; ok {
			o.Apps[i].Keys = append(o.Apps[i].Keys, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Overview{}, dbErr("ключи", err)
	}
	rows, err = s.db.Query(ctx, `SELECT id, slug, name, type, external, credential IS NOT NULL, credential_set_at
		FROM providers WHERE org_id = $1 ORDER BY slug`, orgID)
	if err != nil {
		return Overview{}, dbErr("провайдеры", err)
	}
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.Type, &p.External, &p.CredentialSet, &p.CredentialSetAt); err != nil {
			rows.Close()
			return Overview{}, dbErr("провайдеры", err)
		}
		p.CredentialSetAt = utcPtr(p.CredentialSetAt)
		o.Providers = append(o.Providers, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Overview{}, dbErr("провайдеры", err)
	}
	err = s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM inventory_models WHERE org_id = $1),
			(SELECT count(*) FROM inventory_usage WHERE org_id = $1)`, orgID).Scan(&o.Models, &o.Usage)
	if err != nil {
		return Overview{}, dbErr("число записей", err)
	}
	var runAt time.Time
	err = s.db.QueryRow(ctx, `SELECT synced_upto, run_at, limit_reached, skipped FROM inventory_sync_state WHERE org_id = $1`, orgID).
		Scan(&o.Sync.SyncedUpto, &runAt, &o.Sync.LimitReached, &o.Sync.Skipped)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return Overview{}, dbErr("состояние пополнения", err)
	default:
		runAt = runAt.UTC()
		o.Sync.RunAt = &runAt
		o.Sync.SyncedUpto = utcPtr(o.Sync.SyncedUpto)
	}
	return o, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// ProviderExists — есть ли провайдер с этим ID в организации.
func (s *PGStore) ProviderExists(ctx context.Context, orgID, slug string) (bool, error) {
	ctx, cancel := pgCtx(ctx, pgTimeout)
	defer cancel()
	var ok bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM providers WHERE org_id = $1 AND slug = $2)`, orgID, slug).Scan(&ok); err != nil {
		return false, dbErr("провайдер", err)
	}
	return ok, nil
}

const modelCols = `m.id, m.org_id, m.kind, m.provider, m.name, m.version, m.title, m.description, m.owner, m.origin, m.status,
	m.first_seen, m.last_seen, m.created_at, m.created_by, m.updated_at, m.updated_by,
	(SELECT count(*) FROM inventory_model_files f WHERE f.model_id = m.id)`

func scanModel(r pgx.Row) (Model, error) {
	var m Model
	err := r.Scan(&m.ID, &m.OrgID, &m.Kind, &m.Provider, &m.Name, &m.Version, &m.Title, &m.Description, &m.Owner, &m.Origin,
		&m.Status, &m.FirstSeen, &m.LastSeen, &m.CreatedAt, &m.CreatedBy, &m.UpdatedAt, &m.UpdatedBy, &m.FileCount)
	m.FirstSeen, m.LastSeen = utcPtr(m.FirstSeen), utcPtr(m.LastSeen)
	m.CreatedAt, m.UpdatedAt = m.CreatedAt.UTC(), m.UpdatedAt.UTC()
	return m, err
}

// Models — страница моделей по (created_at, id).
func (s *PGStore) Models(ctx context.Context, orgID string, f Filter) ([]Model, error) {
	ctx, cancel := pgCtx(ctx, pgTimeout)
	defer cancel()
	var at *time.Time
	var after *string
	if f.After != nil {
		at, after = &f.After.CreatedAt, &f.After.ID
	}
	rows, err := s.db.Query(ctx, `SELECT `+modelCols+` FROM inventory_models m
		WHERE m.org_id = $1 AND ($2 = '' OR m.kind = $2) AND ($3 = '' OR m.origin = $3) AND ($4 = '' OR m.provider = $4)
			AND ($5 = '' OR strpos(lower(m.name), lower($5)) > 0 OR strpos(lower(m.title), lower($5)) > 0)
			AND ($6::timestamptz IS NULL OR (m.created_at, m.id) > ($6, $7::uuid))
		ORDER BY m.created_at, m.id LIMIT $8`, orgID, f.Kind, f.Origin, f.Provider, f.Query, at, after, f.Limit)
	if err != nil {
		return nil, dbErr("модели", err)
	}
	defer rows.Close()
	out := []Model{}
	for rows.Next() {
		m, err := scanModel(rows)
		if err != nil {
			return nil, dbErr("модели", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("модели", err)
	}
	return out, nil
}

func (s *PGStore) loadFiles(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, m *Model) error {
	rows, err := q.Query(ctx, `SELECT path, size, role, hash_alg, hash FROM inventory_model_files WHERE model_id = $1 ORDER BY path`, m.ID)
	if err != nil {
		return dbErr("файлы модели", err)
	}
	defer rows.Close()
	m.Files = []File{}
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.Path, &f.Size, &f.Role, &f.HashAlg, &f.Hash); err != nil {
			return dbErr("файлы модели", err)
		}
		m.Files = append(m.Files, f)
	}
	if err := rows.Err(); err != nil {
		return dbErr("файлы модели", err)
	}
	m.FileCount = len(m.Files)
	return nil
}

// Model — модель с файлами.
func (s *PGStore) Model(ctx context.Context, orgID, id string) (Model, error) {
	ctx, cancel := pgCtx(ctx, pgTimeout)
	defer cancel()
	m, err := scanModel(s.db.QueryRow(ctx, `SELECT `+modelCols+` FROM inventory_models m WHERE m.org_id = $1 AND m.id = $2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Model{}, ErrNotFound
	}
	if err != nil {
		return Model{}, dbErr("модель", err)
	}
	if err := s.loadFiles(ctx, s.db, &m); err != nil {
		return Model{}, err
	}
	return m, nil
}

func insertFiles(ctx context.Context, tx pgx.Tx, id string, fs []File) error {
	for _, f := range fs {
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_model_files (model_id, path, size, role, hash_alg, hash) VALUES ($1, $2, $3, $4, $5, $6)`,
			id, f.Path, f.Size, f.Role, f.HashAlg, f.Hash); err != nil {
			return dbErr("файлы модели", err)
		}
	}
	return nil
}

// CreateModel — ErrExists, ErrTooMany.
func (s *PGStore) CreateModel(ctx context.Context, m Model, rec audit.Entry) error {
	return s.inTx(ctx, pgTimeout, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockOrg(ctx, tx, m.OrgID); err != nil {
			return dbErr("блокировка", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM inventory_models WHERE org_id = $1`, m.OrgID).Scan(&n); err != nil {
			return dbErr("число моделей", err)
		}
		if n >= MaxModels {
			return ErrTooMany
		}
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_models (id, org_id, kind, provider, name, version, title, description, owner,
				origin, status, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			m.ID, m.OrgID, m.Kind, m.Provider, m.Name, m.Version, m.Title, m.Description, m.Owner, m.Origin, m.Status,
			m.CreatedAt, m.CreatedBy, m.UpdatedAt, m.UpdatedBy); err != nil {
			return dbErr("модель", err)
		}
		if err := insertFiles(ctx, tx, m.ID, m.Files); err != nil {
			return err
		}
		return s.record(ctx, tx, rec)
	})
}

// UpdateModel — файлы заменяются целиком.
func (s *PGStore) UpdateModel(ctx context.Context, orgID, id string, fn func(*Model) (audit.Entry, error)) (Model, error) {
	var out Model
	err := s.inTx(ctx, pgTimeout, func(ctx context.Context, tx pgx.Tx) error {
		m, err := scanModel(tx.QueryRow(ctx, `SELECT `+modelCols+` FROM inventory_models m WHERE m.org_id = $1 AND m.id = $2 FOR UPDATE`, orgID, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return dbErr("модель", err)
		}
		if err := s.loadFiles(ctx, tx, &m); err != nil {
			return err
		}
		oldFiles := m.Files
		rec, err := fn(&m)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE inventory_models SET kind = $3, version = $4, title = $5, description = $6, owner = $7,
				updated_at = $8, updated_by = $9 WHERE org_id = $1 AND id = $2`,
			orgID, id, m.Kind, m.Version, m.Title, m.Description, m.Owner, m.UpdatedAt, m.UpdatedBy); err != nil {
			return dbErr("модель", err)
		}
		if !sameFiles(oldFiles, m.Files) {
			if _, err := tx.Exec(ctx, `DELETE FROM inventory_model_files WHERE model_id = $1`, id); err != nil {
				return dbErr("файлы модели", err)
			}
			if err := insertFiles(ctx, tx, id, m.Files); err != nil {
				return err
			}
		}
		if err := s.record(ctx, tx, rec); err != nil {
			return err
		}
		out = m
		return nil
	})
	return out, err
}

// DeleteModel удаляет модель; файлы удаляются каскадом.
func (s *PGStore) DeleteModel(ctx context.Context, orgID, id string, fn func(Model) (audit.Entry, error)) (Model, error) {
	var out Model
	err := s.inTx(ctx, pgTimeout, func(ctx context.Context, tx pgx.Tx) error {
		m, err := scanModel(tx.QueryRow(ctx, `SELECT `+modelCols+` FROM inventory_models m WHERE m.org_id = $1 AND m.id = $2 FOR UPDATE`, orgID, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return dbErr("модель", err)
		}
		if err := s.loadFiles(ctx, tx, &m); err != nil {
			return err
		}
		rec, err := fn(m)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM inventory_models WHERE org_id = $1 AND id = $2`, orgID, id); err != nil {
			return dbErr("модель", err)
		}
		if err := s.record(ctx, tx, rec); err != nil {
			return err
		}
		out = m
		return nil
	})
	return out, err
}

// Usage — страница использования по ID.
func (s *PGStore) Usage(ctx context.Context, orgID string, f UsageFilter) ([]Usage, error) {
	ctx, cancel := pgCtx(ctx, pgTimeout)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT id, app, provider, model, first_seen, last_seen FROM inventory_usage
		WHERE org_id = $1 AND ($2 = '' OR app = $2) AND ($3 = '' OR provider = $3) AND ($4 = '' OR model = $4) AND id > $5
		ORDER BY id LIMIT $6`, orgID, f.App, f.Provider, f.Model, f.After, f.Limit)
	if err != nil {
		return nil, dbErr("использование", err)
	}
	defer rows.Close()
	out := []Usage{}
	for rows.Next() {
		var u Usage
		if err := rows.Scan(&u.ID, &u.App, &u.Provider, &u.Model, &u.FirstSeen, &u.LastSeen); err != nil {
			return nil, dbErr("использование", err)
		}
		u.FirstSeen, u.LastSeen = u.FirstSeen.UTC(), u.LastSeen.UTC()
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("использование", err)
	}
	return out, nil
}

// seenSQL — тройки из почасовых агрегатов дашбордов (миграция 0037) за
// окно: только SELECT, без содержимого. Строки Check API без провайдера и
// модели и значения, которые не поместятся в реестр, пропускаются.
const seenSQL = `SELECT app, provider, model, min(bucket), max(bucket) FROM dash_req_hour
	WHERE org_id = $1 AND ($2::timestamptz IS NULL OR bucket >= $2)
		AND provider ~ '^[a-z0-9][a-z0-9-]{0,62}$' AND char_length(app) BETWEEN 1 AND 256 AND char_length(model) BETWEEN 1 AND 256
	GROUP BY 1, 2, 3 ORDER BY 4, 1, 2, 3 LIMIT $3`

// Discover — пополнение по трафику под блокировкой реестра организации.
func (s *PGStore) Discover(ctx context.Context, orgID string, now time.Time, newID func() (string, error),
	rec func(DiscoverResult) *audit.Entry) (DiscoverResult, error) {
	var res DiscoverResult
	err := s.inTx(ctx, pgDiscoverTimeout, func(ctx context.Context, tx pgx.Tx) error {
		res = DiscoverResult{Names: []string{}}
		if err := lockOrg(ctx, tx, orgID); err != nil {
			return dbErr("блокировка", err)
		}
		var mark *time.Time
		err := tx.QueryRow(ctx, `SELECT synced_upto FROM inventory_sync_state WHERE org_id = $1`, orgID).Scan(&mark)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return dbErr("состояние пополнения", err)
		}
		var from *time.Time
		if mark != nil {
			f := mark.Add(-SyncOverlap)
			from = &f
		}
		seen, truncated, err := readSeen(ctx, tx, orgID, from)
		if err != nil {
			return err
		}
		var models, usage int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM inventory_models WHERE org_id = $1),
				(SELECT count(*) FROM inventory_usage WHERE org_id = $1)`, orgID).Scan(&models, &usage); err != nil {
			return dbErr("число записей", err)
		}
		type pair struct{ provider, model string }
		span := map[pair][2]time.Time{}
		var order []pair
		for _, v := range seen {
			// Окно перекрывается с прошлым запуском: строка меняется, только
			// если границы действительно расширились (ревью 5.17: без лишних
			// версий строк и блокировок на всё время пополнения).
			tag, err := tx.Exec(ctx, `UPDATE inventory_usage SET first_seen = LEAST(first_seen, $5), last_seen = GREATEST(last_seen, $6)
				WHERE org_id = $1 AND app = $2 AND provider = $3 AND model = $4 AND (first_seen > $5 OR last_seen < $6)`,
				orgID, v.App, v.Provider, v.Model, v.First, v.Last)
			if err != nil {
				return dbErr("использование", err)
			}
			if tag.RowsAffected() == 0 {
				switch {
				case usage < MaxUsage:
					tag, err := tx.Exec(ctx, `INSERT INTO inventory_usage (org_id, app, provider, model, first_seen, last_seen)
						VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (org_id, app, provider, model) DO NOTHING`,
						orgID, v.App, v.Provider, v.Model, v.First, v.Last)
					if err != nil {
						return dbErr("использование", err)
					}
					if tag.RowsAffected() > 0 {
						usage++
						res.Links++
					}
				default:
					var ok bool
					if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM inventory_usage WHERE org_id = $1 AND app = $2 AND provider = $3 AND model = $4)`,
						orgID, v.App, v.Provider, v.Model).Scan(&ok); err != nil {
						return dbErr("использование", err)
					}
					if !ok {
						res.Skipped++
					}
				}
			}
			p := pair{v.Provider, v.Model}
			sp, ok := span[p]
			if !ok {
				order = append(order, p)
				sp = [2]time.Time{v.First, v.Last}
			}
			if v.First.Before(sp[0]) {
				sp[0] = v.First
			}
			if v.Last.After(sp[1]) {
				sp[1] = v.Last
			}
			span[p] = sp
		}
		for _, p := range order {
			sp := span[p]
			var known bool
			if err := tx.QueryRow(ctx, `WITH u AS (UPDATE inventory_models SET first_seen = LEAST(COALESCE(first_seen, $4), $4),
					last_seen = GREATEST(COALESCE(last_seen, $5), $5)
				WHERE org_id = $1 AND provider = $2 AND name = $3
					AND (first_seen IS NULL OR last_seen IS NULL OR first_seen > $4 OR last_seen < $5) RETURNING 1)
				SELECT EXISTS (SELECT 1 FROM u) OR EXISTS (SELECT 1 FROM inventory_models WHERE org_id = $1 AND provider = $2 AND name = $3)`,
				orgID, p.provider, p.model, sp[0], sp[1]).Scan(&known); err != nil {
				return dbErr("модель", err)
			}
			if known {
				continue
			}
			if models >= MaxModels {
				res.Skipped++
				continue
			}
			id, err := newID()
			if err != nil {
				return err
			}
			// Модель с той же парой вставить нельзя: пара проверена выше под
			// блокировкой организации, а CreateModel берёт ту же блокировку.
			if _, err := tx.Exec(ctx, `INSERT INTO inventory_models (id, org_id, kind, provider, name, origin, status, first_seen, last_seen,
					created_at, created_by, updated_at, updated_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $10, $11)`,
				id, orgID, KindProvider, p.provider, p.model, OriginTraffic, StatusActive, sp[0], sp[1], now, systemRef); err != nil {
				return dbErr("модель", err)
			}
			models++
			res.Models++
			if len(res.Names) < MaxDiscoveredNames {
				res.Names = append(res.Names, p.provider+"/"+p.model)
			}
		}
		// Отметка — час запуска: следующее окно начинается от него минус
		// SyncOverlap, первое чтение всей таблицы больше не повторяется.
		upto := now.Truncate(time.Hour)
		res.SyncedUpto = &upto
		limit := res.Skipped > 0 || truncated
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_sync_state (org_id, synced_upto, run_at, limit_reached, skipped)
				VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (org_id) DO UPDATE SET synced_upto = EXCLUDED.synced_upto, run_at = EXCLUDED.run_at,
				limit_reached = EXCLUDED.limit_reached, skipped = EXCLUDED.skipped`, orgID, upto, now, limit, res.Skipped); err != nil {
			return dbErr("состояние пополнения", err)
		}
		if e := rec(res); e != nil {
			return s.record(ctx, tx, *e)
		}
		return nil
	})
	if err != nil {
		return DiscoverResult{}, err
	}
	return res, nil
}

// systemRef — created_by записей, добавленных пополнением.
const systemRef = "system:aisec-server"

func readSeen(ctx context.Context, tx pgx.Tx, orgID string, from *time.Time) ([]Seen, bool, error) {
	rows, err := tx.Query(ctx, seenSQL, orgID, from, maxSeenRows+1)
	if err != nil {
		return nil, false, dbErr("агрегаты", err)
	}
	defer rows.Close()
	var out []Seen
	for rows.Next() {
		var v Seen
		if err := rows.Scan(&v.App, &v.Provider, &v.Model, &v.First, &v.Last); err != nil {
			return nil, false, dbErr("агрегаты", err)
		}
		v.First, v.Last = v.First.UTC(), v.Last.UTC()
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, false, dbErr("агрегаты", err)
	}
	if len(out) > maxSeenRows {
		return out[:maxSeenRows], true, nil
	}
	return out, false, nil
}
