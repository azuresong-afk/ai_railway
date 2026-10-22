package incidents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

const (
	// pgTimeout — предел на операцию, если у контекста нет своего срока.
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

// PGStore — Store на PostgreSQL (миграция 0034_incidents). Оповещения
// блокируются и закрываются через alerting.PGStore в той же транзакции.
type PGStore struct {
	db     PGDB
	audit  *audit.Log
	alerts *alerting.PGStore
	ids    *ids.Generator
	clock  func() time.Time
}

// NewPGStore создаёт хранилище; журнал и оповещения работают через тот же пул.
func NewPGStore(db PGDB, a *audit.Log, alerts *alerting.PGStore, rnd aisecCrypto.Random) (*PGStore, error) {
	if db == nil || a == nil || alerts == nil || rnd == nil {
		return nil, errors.New("инциденты: нет БД, журнала аудита, оповещений или источника случайности")
	}
	return &PGStore{db: db, audit: a, alerts: alerts, ids: ids.NewGenerator(rnd), clock: time.Now}, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

// txAttempts — попыток транзакции при взаимоблокировке: закрытие инцидента
// блокирует его оповещения по порядку ID, приём событий — в порядке
// срабатываний; PostgreSQL обрывает одну из встречных транзакций (40P01).
const txAttempts = 3

func (s *PGStore) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var err error
	for range txAttempts {
		if err = s.tryTx(ctx, fn); !deadlock(err) {
			return err
		}
	}
	return err
}

func (s *PGStore) tryTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("инциденты: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после фиксации безвреден, ошибку скрывает исходная
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("инциденты: фиксация: %w", err)
	}
	return nil
}

// deadlock — транзакция оборвана из-за взаимоблокировки и её можно повторить.
func deadlock(err error) bool {
	var st interface{ SQLState() string }
	return err != nil && errors.As(err, &st) && st.SQLState() == "40P01"
}

// sqlError — ошибка СУБД без текста PostgreSQL: код и ограничение.
type sqlError struct{ code, constraint string }

func (e *sqlError) Error() string {
	return "инциденты: SQLSTATE " + e.code + " " + e.constraint
}
func (e *sqlError) SQLState() string { return e.code }

// dbErr заменяет ошибку СУБД кодом SQLSTATE и именем ограничения: текст
// PostgreSQL мог бы содержать значения полей.
func dbErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return &sqlError{code: pe.Code, constraint: pe.ConstraintName}
	}
	return err
}

const incidentCols = `id::text, org_id::text, number, title, severity, category, status, COALESCE(resolution, ''),
	resolution_comment, source, COALESCE(reopened_from::text, ''), COALESCE(assignee_id::text, ''), reaction_due_at,
	reacted_at, contained_at, created_at, created_by, updated_at, updated_by, closed_at, COALESCE(closed_by, ''), version`

func deref(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func scanIncident(row pgx.Row) (Incident, error) {
	var (
		i                          Incident
		reacted, contained, closed *time.Time
	)
	err := row.Scan(&i.ID, &i.OrgID, &i.Number, &i.Title, &i.Severity, &i.Category, &i.Status, &i.Resolution,
		&i.ResolutionComment, &i.Source, &i.ReopenedFrom, &i.AssigneeID, &i.ReactionDueAt, &reacted, &contained,
		&i.CreatedAt, &i.CreatedBy, &i.UpdatedAt, &i.UpdatedBy, &closed, &i.ClosedBy, &i.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Incident{}, ErrNotFound
	}
	if err != nil {
		return Incident{}, err
	}
	i.ReactedAt, i.ContainedAt, i.ClosedAt = deref(reacted), deref(contained), deref(closed)
	i.ReactionDueAt, i.CreatedAt, i.UpdatedAt = i.ReactionDueAt.UTC(), i.CreatedAt.UTC(), i.UpdatedAt.UTC()
	return i, nil
}

// querier — пул или транзакция.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func loadStages(ctx context.Context, q querier, inc *Incident) error {
	rows, err := q.Query(ctx, `SELECT key, position, done_at, COALESCE(done_by, ''), note FROM incident_stages
		WHERE incident_id = $1 ORDER BY position`, inc.ID)
	if err != nil {
		return err
	}
	inc.Stages, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Stage, error) {
		var (
			st   Stage
			done *time.Time
		)
		err := r.Scan(&st.Key, &st.Position, &done, &st.DoneBy, &st.Note)
		st.DoneAt = deref(done)
		return st, err
	})
	return err
}

// Incidents — см. Store. Фильтры передаются параметрами; пустой — без условия.
func (s *PGStore) Incidents(ctx context.Context, orgID string, q Query) ([]Incident, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var afterAt *time.Time
	var afterID *string
	if q.After != nil {
		afterAt, afterID = &q.After.CreatedAt, &q.After.ID
	}
	limit := q.Limit
	if limit <= 0 || limit > MaxListLimit+1 {
		limit = MaxListLimit + 1
	}
	rows, err := s.db.Query(ctx, `SELECT `+incidentCols+` FROM incidents
		WHERE org_id = $1 AND ($2 = '' OR status = $2 OR ($2 = 'open' AND status <> 'closed'))
			AND ($3 = '' OR severity = $3) AND ($4 = '' OR category = $4)
			AND ($5 = '' OR assignee_id::text = $5) AND ($6 = '' OR source = $6)
			AND ($7::timestamptz IS NULL OR (created_at, id) < ($7, $8::uuid))
		ORDER BY created_at DESC, id DESC LIMIT $9`,
		orgID, q.Status, q.Severity, q.Category, q.AssigneeID, q.Source, afterAt, afterID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Incident, error) { return scanIncident(r) })
}

// Incident — см. Store.
func (s *PGStore) Incident(ctx context.Context, orgID, id string) (Incident, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	inc, err := scanIncident(s.db.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE org_id = $1 AND id = $2`, orgID, id))
	if err != nil {
		return Incident{}, err
	}
	return inc, loadStages(ctx, s.db, &inc)
}

// Related — см. Store.
func (s *PGStore) Related(ctx context.Context, orgID, id string) (Related, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	// Один снимок на всю карточку: выгрузка (data.export) согласована.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Related{}, fmt.Errorf("инциденты: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: транзакция только на чтение, откат не меняет результат
	}()
	if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`); err != nil {
		return Related{}, dbErr(err)
	}
	return relatedTx(ctx, tx, s.alerts, orgID, id)
}

// relatedTx — записи карточки в транзакции tx; каждая выборка не больше
// своего предела (при параллельном приёме событий строк может быть чуть больше).
func relatedTx(ctx context.Context, tx pgx.Tx, alerts *alerting.PGStore, orgID, id string) (Related, error) {
	var r Related
	inc, err := scanIncident(tx.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE org_id = $1 AND id = $2`, orgID, id))
	if err != nil {
		return Related{}, err
	}
	if err := loadStages(ctx, tx, &inc); err != nil {
		return Related{}, err
	}
	r.Incident = inc
	rows, err := tx.Query(ctx, `SELECT id::text, incident_id::text, at, actor, kind, details FROM incident_timeline
		WHERE incident_id = $1 ORDER BY at, id LIMIT $2`, id, MaxTimeline)
	if err != nil {
		return Related{}, err
	}
	if r.Timeline, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (TimelineEntry, error) {
		var (
			e   TimelineEntry
			raw []byte
		)
		if err := row.Scan(&e.ID, &e.IncidentID, &e.At, &e.Actor, &e.Kind, &raw); err != nil {
			return e, err
		}
		e.At = e.At.UTC()
		return e, json.Unmarshal(raw, &e.Details)
	}); err != nil {
		return Related{}, err
	}
	rows, err = tx.Query(ctx, `SELECT id::text, incident_id::text, at, author, author_name, body, COALESCE(replaces::text, '')
		FROM incident_comments WHERE incident_id = $1 ORDER BY at, id LIMIT $2`, id, MaxComments)
	if err != nil {
		return Related{}, err
	}
	if r.Comments, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Comment, error) {
		var c Comment
		err := row.Scan(&c.ID, &c.IncidentID, &c.At, &c.Author, &c.AuthorName, &c.Body, &c.Replaces)
		c.At = c.At.UTC()
		return c, err
	}); err != nil {
		return Related{}, err
	}
	rows, err = tx.Query(ctx, `SELECT event_id::text, event_ts FROM incident_events WHERE incident_id = $1
		ORDER BY event_ts, event_id LIMIT $2`, id, MaxEvents)
	if err != nil {
		return Related{}, err
	}
	if r.Events, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (EventRef, error) {
		var e EventRef
		err := row.Scan(&e.ID, &e.TS)
		e.TS = e.TS.UTC()
		return e, err
	}); err != nil {
		return Related{}, err
	}
	r.Alerts, err = alerts.IncidentAlertsTx(ctx, tx, orgID, id)
	return r, err
}

// lockIncident — инцидент под блокировкой строки без блокировки ключа: приём
// событий добавляет хронологию и ссылки (внешний ключ берёт FOR KEY SHARE)
// и не ждёт действий консоли.
func lockIncident(ctx context.Context, tx pgx.Tx, orgID, id string) (Incident, error) {
	inc, err := scanIncident(tx.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE org_id = $1 AND id = $2
		FOR NO KEY UPDATE`, orgID, id))
	if err != nil {
		return Incident{}, err
	}
	return inc, loadStages(ctx, tx, &inc)
}

func countsTx(ctx context.Context, tx pgx.Tx, id string) (Counts, error) {
	var c Counts
	err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM incident_timeline WHERE incident_id = $1),
		(SELECT count(*) FROM incident_comments WHERE incident_id = $1),
		(SELECT count(*) FROM incident_events WHERE incident_id = $1),
		(SELECT count(*) FROM alerts WHERE incident_id = $1)`, id).Scan(&c.Timeline, &c.Comments, &c.Events, &c.Alerts)
	return c, err
}

// nextNumber — следующий сквозной номер организации (строка счётчика
// блокируется до конца транзакции).
func nextNumber(ctx context.Context, tx pgx.Tx, orgID string) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, `INSERT INTO incident_counters (org_id, last_number) VALUES ($1, 1)
		ON CONFLICT (org_id) DO UPDATE SET last_number = incident_counters.last_number + 1 RETURNING last_number`, orgID).Scan(&n)
	return n, err
}

func insertIncident(ctx context.Context, tx pgx.Tx, i *Incident) error {
	if _, err := tx.Exec(ctx, `INSERT INTO incidents (id, org_id, number, title, severity, category, status, resolution,
		resolution_comment, source, reopened_from, assignee_id, reaction_due_at, reacted_at, contained_at, created_at,
		created_by, updated_at, updated_by, closed_at, closed_by, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)`,
		i.ID, i.OrgID, i.Number, i.Title, i.Severity, i.Category, i.Status, nullStr(i.Resolution), i.ResolutionComment,
		i.Source, nullStr(i.ReopenedFrom), nullStr(i.AssigneeID), i.ReactionDueAt, nullTime(i.ReactedAt),
		nullTime(i.ContainedAt), i.CreatedAt, i.CreatedBy, i.UpdatedAt, i.UpdatedBy, nullTime(i.ClosedAt),
		nullStr(i.ClosedBy), i.Version); err != nil {
		return dbErr(err)
	}
	for _, st := range i.Stages {
		if _, err := tx.Exec(ctx, `INSERT INTO incident_stages (incident_id, key, position) VALUES ($1, $2, $3)`,
			i.ID, st.Key, st.Position); err != nil {
			return dbErr(err)
		}
	}
	return nil
}

// apply пишет записи изменения в транзакции tx.
func (s *PGStore) apply(ctx context.Context, tx pgx.Tx, inc *Incident, ch *Change) error {
	for _, e := range ch.Timeline {
		det, err := json.Marshal(e.Details)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO incident_timeline (id, incident_id, at, actor, kind, details)
			VALUES ($1, $2, $3, $4, $5, $6)`, e.ID, e.IncidentID, e.At, e.Actor, e.Kind, det); err != nil {
			return dbErr(err)
		}
	}
	if c := ch.Comment; c != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO incident_comments (id, incident_id, at, author, author_name, body, replaces)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, c.ID, c.IncidentID, c.At, c.Author, c.AuthorName, c.Body, nullStr(c.Replaces)); err != nil {
			return dbErr(err)
		}
	}
	if st := ch.Stage; st != nil {
		if _, err := tx.Exec(ctx, `UPDATE incident_stages SET done_at = $3, done_by = $4, note = $5
			WHERE incident_id = $1 AND key = $2`, inc.ID, st.Key, st.DoneAt, st.DoneBy, st.Note); err != nil {
			return dbErr(err)
		}
	}
	if err := addEvents(ctx, tx, inc.ID, ch.Events); err != nil {
		return err
	}
	if ch.CloseAlerts != nil {
		if _, err := s.alerts.CloseForIncidentTx(ctx, tx, inc.OrgID, inc.ID, ch.CloseAlerts.By, ch.CloseAlerts.Comment); err != nil {
			return err
		}
	}
	for _, rec := range ch.Audit {
		if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
			return err
		}
	}
	return nil
}

// addEvents добавляет ссылки на события, пока их меньше MaxEvents.
func addEvents(ctx context.Context, tx pgx.Tx, incidentID string, refs []EventRef) error {
	if len(refs) == 0 {
		return nil
	}
	var have int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incident_events WHERE incident_id = $1`, incidentID).Scan(&have); err != nil {
		return err
	}
	room := MaxEvents - have
	if room <= 0 {
		return nil
	}
	refs = refs[:min(room, len(refs))]
	idsList := make([]string, len(refs))
	ts := make([]time.Time, len(refs))
	for i, r := range refs {
		idsList[i], ts[i] = r.ID, r.TS
	}
	_, err := tx.Exec(ctx, `INSERT INTO incident_events (incident_id, event_id, event_ts, added_at)
		SELECT $1, e, t, now() FROM unnest($2::uuid[], $3::timestamptz[]) AS u(e, t)
		ON CONFLICT (incident_id, event_id) DO NOTHING`, incidentID, idsList, ts)
	return dbErr(err)
}

// Create — см. Store. Порядок блокировок: оповещение, прежний инцидент, счётчик.
func (s *PGStore) Create(ctx context.Context, c Creation) (Incident, bool, error) {
	var (
		out      Incident
		existing bool
	)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var src Source
		orgID := c.Incident.OrgID
		if c.AlertID != "" {
			a, refs, err := s.alerts.AlertForIncidentTx(ctx, tx, orgID, c.AlertID)
			if errors.Is(err, alerting.ErrNotFound) {
				return ErrAlertNotFound
			}
			if err != nil {
				return err
			}
			if a.IncidentID != "" {
				inc, err := scanIncident(tx.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE org_id = $1 AND id = $2`,
					orgID, a.IncidentID))
				if err != nil {
					return err
				}
				out, existing = inc, true
				return loadStages(ctx, tx, &out)
			}
			src.Alert, src.Refs = &a, refs
		}
		if c.ReopenOf != "" {
			prev, err := lockIncident(ctx, tx, orgID, c.ReopenOf)
			if err != nil {
				return err
			}
			inc, err := scanIncident(tx.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE org_id = $1 AND reopened_from = $2`,
				orgID, c.ReopenOf))
			if err == nil {
				out, existing = inc, true
				return loadStages(ctx, tx, &out)
			}
			if !errors.Is(err, ErrNotFound) {
				return err
			}
			refs, err := incidentRefs(ctx, tx, c.ReopenOf)
			if err != nil {
				return err
			}
			src.Previous, src.Refs = &prev, refs
		}
		inc := c.Incident.clone()
		n, err := nextNumber(ctx, tx, orgID)
		if err != nil {
			return err
		}
		inc.Number = n
		ch, err := c.Build(&inc, src)
		if err != nil {
			return err
		}
		if err := insertIncident(ctx, tx, &inc); err != nil {
			return err
		}
		if src.Alert != nil {
			if err := s.alerts.LinkIncidentTx(ctx, tx, orgID, src.Alert.ID, inc.ID); err != nil {
				return err
			}
		}
		if err := s.apply(ctx, tx, &inc, &ch); err != nil {
			return err
		}
		out = inc
		return nil
	})
	return out, existing, err
}

func incidentRefs(ctx context.Context, tx pgx.Tx, id string) ([]EventRef, error) {
	rows, err := tx.Query(ctx, `SELECT event_id::text, event_ts FROM incident_events WHERE incident_id = $1
		ORDER BY event_ts, event_id`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (EventRef, error) {
		var e EventRef
		err := row.Scan(&e.ID, &e.TS)
		e.TS = e.TS.UTC()
		return e, err
	})
}

func updateIncident(ctx context.Context, tx pgx.Tx, i *Incident) error {
	_, err := tx.Exec(ctx, `UPDATE incidents SET status = $3, resolution = $4, resolution_comment = $5, assignee_id = $6,
		reacted_at = $7, contained_at = $8, updated_at = $9, updated_by = $10, closed_at = $11, closed_by = $12, version = $13
		WHERE org_id = $1 AND id = $2`,
		i.OrgID, i.ID, i.Status, nullStr(i.Resolution), i.ResolutionComment, nullStr(i.AssigneeID), nullTime(i.ReactedAt),
		nullTime(i.ContainedAt), i.UpdatedAt, i.UpdatedBy, nullTime(i.ClosedAt), nullStr(i.ClosedBy), i.Version)
	return dbErr(err)
}

// checkReplaces — правится существующий комментарий инцидента, своим
// автором и только последняя версия.
func checkReplaces(ctx context.Context, tx pgx.Tx, incidentID string, c *Comment) error {
	var author string
	var superseded bool
	err := tx.QueryRow(ctx, `SELECT author, EXISTS (SELECT 1 FROM incident_comments n WHERE n.replaces = c.id)
		FROM incident_comments c WHERE c.incident_id = $1 AND c.id = $2`, incidentID, c.Replaces).Scan(&author, &superseded)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCommentNotFound
	}
	if err != nil {
		return err
	}
	if author != c.Author {
		return ErrNotAuthor
	}
	if superseded {
		return ErrSuperseded
	}
	return nil
}

// Update — см. Store.
func (s *PGStore) Update(ctx context.Context, orgID, id string, fn func(*Incident, Counts) (Change, error)) (Incident, error) {
	var out Incident
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		inc, err := lockIncident(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		c, err := countsTx(ctx, tx, id)
		if err != nil {
			return err
		}
		ch, err := fn(&inc, c)
		if err != nil {
			return err
		}
		if ch.Comment != nil && ch.Comment.Replaces != "" {
			if err := checkReplaces(ctx, tx, id, ch.Comment); err != nil {
				return err
			}
		}
		// Записи — до смены строки: после закрытия триггер
		// incident_child_of_closed не пускает дополнения.
		if err := s.apply(ctx, tx, &inc, &ch); err != nil {
			return err
		}
		inc.Version++
		if err := updateIncident(ctx, tx, &inc); err != nil {
			return err
		}
		out = inc
		return nil
	})
	return out, err
}

// LinkAlert — см. Store.
func (s *PGStore) LinkAlert(ctx context.Context, orgID, id, alertID string,
	fn func(*Incident, alerting.Alert, []EventRef, Counts) (Change, error)) (Incident, bool, error) {
	var (
		out      Incident
		existing bool
	)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, refs, err := s.alerts.AlertForIncidentTx(ctx, tx, orgID, alertID)
		if errors.Is(err, alerting.ErrNotFound) {
			return ErrAlertNotFound
		}
		if err != nil {
			return err
		}
		if a.IncidentID != "" && a.IncidentID != id {
			return ErrLinked
		}
		if a.IncidentID == id {
			// Уже связано: инцидент без блокировки. Закрытие держит
			// инцидент и ждёт его оповещения — встречная блокировка
			// дала бы взаимоблокировку.
			inc, err := scanIncident(tx.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE org_id = $1 AND id = $2`,
				orgID, id))
			if err != nil {
				return err
			}
			out, existing = inc, true
			return loadStages(ctx, tx, &out)
		}
		inc, err := lockIncident(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		c, err := countsTx(ctx, tx, id)
		if err != nil {
			return err
		}
		ch, err := fn(&inc, a, refs, c)
		if err != nil {
			return err
		}
		inc.Version++
		if err := updateIncident(ctx, tx, &inc); err != nil {
			return err
		}
		if err := s.alerts.LinkIncidentTx(ctx, tx, orgID, alertID, id); err != nil {
			return err
		}
		if err := s.apply(ctx, tx, &inc, &ch); err != nil {
			return err
		}
		out = inc
		return nil
	})
	return out, existing, err
}

// Instructions — см. Store: последняя версия по каждой категории.
func (s *PGStore) Instructions(ctx context.Context, orgID string) (map[string]Instruction, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT DISTINCT ON (category) category, body, version, created_at, created_by
		FROM incident_instructions WHERE org_id = $1 ORDER BY category, version DESC`, orgID)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Instruction, error) {
		var i Instruction
		err := r.Scan(&i.Category, &i.Body, &i.Version, &i.UpdatedAt, &i.UpdatedBy)
		i.UpdatedAt = i.UpdatedAt.UTC()
		return i, err
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]Instruction, len(list))
	for _, i := range list {
		out[i.Category] = i
	}
	return out, nil
}

// SetInstructions — см. Store. Параллельные правки разрешает первичный
// ключ (организация, категория, версия): проигравшая получает конфликт версии.
func (s *PGStore) SetInstructions(ctx context.Context, orgID, category string, fn func(cur Instruction) (Instruction, audit.Entry, error)) (Instruction, error) {
	var out Instruction
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var cur Instruction
		err := tx.QueryRow(ctx, `SELECT category, body, version, created_at, created_by FROM incident_instructions
			WHERE org_id = $1 AND category = $2 ORDER BY version DESC LIMIT 1`, orgID, category).
			Scan(&cur.Category, &cur.Body, &cur.Version, &cur.UpdatedAt, &cur.UpdatedBy)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		next, rec, err := fn(cur)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO incident_instructions (org_id, category, version, body, created_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6)`, orgID, category, next.Version, next.Body, next.UpdatedAt, next.UpdatedBy); err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "23505" {
				return ErrVersionConflict
			}
			return dbErr(err)
		}
		out = next
		return s.audit.RecordTx(ctx, tx, rec)
	})
	return out, err
}

// Record — см. Store.
func (s *PGStore) Record(ctx context.Context, e audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error { return s.audit.RecordTx(ctx, tx, e) })
}

func (s *PGStore) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

// OpenFromAlert — alerting.IncidentOpener: инцидент в транзакции приёма событий.
func (s *PGStore) OpenFromAlert(ctx context.Context, tx pgx.Tx, a alerting.Alert, refs []EventRef, category string) (string, error) {
	inc, build, err := autoIncident(s.ids, a.OrgID, s.now(), &a, refs, category)
	if err != nil {
		return "", err
	}
	if inc.Number, err = nextNumber(ctx, tx, a.OrgID); err != nil {
		return "", err
	}
	ch, err := build(&inc)
	if err != nil {
		return "", err
	}
	if err := insertIncident(ctx, tx, &inc); err != nil {
		return "", err
	}
	return inc.ID, s.apply(ctx, tx, &inc, &ch)
}

// NoteAlert — alerting.IncidentOpener: строка инцидента не блокируется,
// добавляются только хронология (до MaxTimeline) и ссылки.
func (s *PGStore) NoteAlert(ctx context.Context, tx pgx.Tx, incidentID string, a alerting.Alert, refs []EventRef) error {
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incident_timeline WHERE incident_id = $1`, incidentID).Scan(&n); err != nil {
		return err
	}
	ch := Change{Events: refs}
	if n < MaxTimeline {
		e, err := triggeredEntry(s.ids, incidentID, s.now(), &a, len(refs))
		if err != nil {
			return err
		}
		ch.Timeline = []TimelineEntry{e}
	}
	return s.apply(ctx, tx, &Incident{ID: incidentID, OrgID: a.OrgID}, &ch)
}
