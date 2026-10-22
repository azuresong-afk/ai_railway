package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

const (
	// pgTimeout — предел на операцию, если у контекста нет своего срока.
	pgTimeout = 10 * time.Second
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
	// raiseAttempts — попыток учесть срабатывание при гонке вставки.
	raiseAttempts = 3
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0028_alerts) и движок правил в
// транзакции приёма событий (events.IngestHook).
type PGStore struct {
	db     PGDB
	audit  *audit.Log
	orgID  string
	ids    *ids.Generator
	logger *slog.Logger
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
// Случайность профиля нужна для ID оповещений, создаваемых движком.
func NewPGStore(db PGDB, a *audit.Log, rnd aisecCrypto.Random, orgID string, logger *slog.Logger) (*PGStore, error) {
	if db == nil || a == nil || rnd == nil {
		return nil, errors.New("оповещения: нет БД, журнала аудита или источника случайности")
	}
	if orgID == "" {
		orgID = audit.DefaultOrgID
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PGStore{db: db, audit: a, orgID: orgID, ids: ids.NewGenerator(rnd), logger: logger}, nil
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
		return fmt.Errorf("оповещения: начало транзакции: %w", err)
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
		return fmt.Errorf("оповещения: фиксация: %w", err)
	}
	return nil
}

// OnIngest — events.IngestHook: правила «порог» и «новое» по впервые
// записанным событиям в транзакции приёма.
func (s *PGStore) OnIngest(ctx context.Context, tx pgx.Tx, gatewayID string, accepted []*events.Event) error {
	ops := pgOps{s: s, tx: tx}
	if err := process(ctx, ops, gatewayID, accepted, func(err error) {
		s.logger.Error("оповещения: правило пропущено", "error", err)
	}); err != nil {
		return err
	}
	return processAuthFailures(ctx, ops, accepted)
}

// pgOps — txOps в транзакции tx.
type pgOps struct {
	s  *PGStore
	tx pgx.Tx
}

const ruleCols = `id::text, org_id::text, COALESCE(builtin_key, ''), kind, name, description, enabled, severity, condition,
	group_by, suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by`

func scanRule(row pgx.Row) (Rule, error) {
	var (
		r          Rule
		cond, rcpt []byte
	)
	err := row.Scan(&r.ID, &r.OrgID, &r.BuiltinKey, &r.Kind, &r.Name, &r.Description, &r.Enabled, &r.Severity, &cond,
		&r.GroupBy, &r.SuppressMinutes, &r.GroupMinutes, &rcpt, &r.Version, &r.CreatedAt, &r.CreatedBy, &r.UpdatedAt, &r.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, err
	}
	if err := json.Unmarshal(cond, &r.Condition); err != nil {
		return Rule{}, fmt.Errorf("оповещения: условие правила %s: %w", r.ID, err)
	}
	if err := json.Unmarshal(rcpt, &r.Recipients); err != nil {
		return Rule{}, fmt.Errorf("оповещения: получатели правила %s: %w", r.ID, err)
	}
	if r.Recipients.Roles == nil {
		r.Recipients.Roles = []string{}
	}
	if r.Recipients.Users == nil {
		r.Recipients.Users = []string{}
	}
	if r.GroupBy == nil {
		r.GroupBy = []string{}
	}
	r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	return r, nil
}

func collectRules(rows pgx.Rows, err error) ([]Rule, error) {
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Rule, error) { return scanRule(r) })
}

func (o pgOps) activeRules(ctx context.Context, kinds ...string) ([]Rule, error) {
	return collectRules(o.tx.Query(ctx, `SELECT `+ruleCols+` FROM alert_rules
		WHERE org_id = $1 AND enabled AND kind = ANY($2) ORDER BY created_at, id`, o.s.orgID, kinds))
}

func (o pgOps) ruleByKey(ctx context.Context, key string) (Rule, bool, error) {
	r, err := scanRule(o.tx.QueryRow(ctx, `SELECT `+ruleCols+` FROM alert_rules WHERE org_id = $1 AND builtin_key = $2`,
		o.s.orgID, key))
	if errors.Is(err, ErrNotFound) {
		return Rule{}, false, nil
	}
	return r, err == nil, err
}

func (o pgOps) markSeen(ctx context.Context, ruleID string, values []string) ([]string, error) {
	rows, err := o.tx.Query(ctx, `INSERT INTO alert_seen (rule_id, value, first_seen)
		SELECT $1, v, now() FROM unnest($2::text[]) AS v
		ON CONFLICT (rule_id, value) DO NOTHING RETURNING value`, ruleID, values)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// raise — см. txOps и ADR-0020, п. 3: открытое оповещение по ключу
// дополняется, в окне подавления после закрытия растёт suppressed, иначе
// вставляется новое. Гонку двух вставок разрешает уникальный индекс
// alerts_open_key: проигравшая вставка повторяет поиск открытого.
func (o pgOps) raise(ctx context.Context, r *Rule, t *Trigger) error {
	details := t.Details
	if details == nil {
		details = map[string]any{}
	}
	for range raiseAttempts {
		if r.GroupMinutes > 0 {
			if _, err := o.tx.Exec(ctx, `UPDATE alerts SET open_key = NULL, updated_at = now()
				WHERE org_id = $1 AND rule_id = $2 AND open_key = $3 AND created_at < now() - make_interval(mins => $4)`,
				o.s.orgID, r.ID, t.Key, r.GroupMinutes); err != nil {
				return err
			}
		}
		done, err := o.attach(ctx, r, t)
		if err != nil || done {
			return err
		}
		if r.SuppressMinutes > 0 {
			tag, err := o.tx.Exec(ctx, `UPDATE alerts SET suppressed = suppressed + $4, updated_at = now()
				WHERE id = (SELECT id FROM alerts WHERE org_id = $1 AND rule_id = $2 AND dedup_key = $3 AND status = 'closed'
					AND closed_at > now() - make_interval(mins => $5) ORDER BY closed_at DESC LIMIT 1)`,
				o.s.orgID, r.ID, t.Key, t.Count, r.SuppressMinutes)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				return nil
			}
		}
		u, err := o.s.ids.New()
		if err != nil {
			return err
		}
		id := u.String()
		values, err := json.Marshal(t.Values)
		if err != nil {
			return err
		}
		det, err := json.Marshal(mergeDetails(nil, details))
		if err != nil {
			return err
		}
		tag, err := o.tx.Exec(ctx, `INSERT INTO alerts (id, org_id, rule_id, kind, severity, title, status, dedup_key, open_key,
			group_values, count, suppressed, first_event_at, last_event_at, created_at, last_triggered_at, updated_at, details)
			VALUES ($1, $2, $3, $4, $5, $6, 'new', $7, $7, $8, $9, 0, $10, $11, now(), now(), now(), $12)
			ON CONFLICT (org_id, rule_id, open_key) WHERE open_key IS NOT NULL DO NOTHING`,
			id, o.s.orgID, r.ID, r.Kind, r.Severity, title(r, t.Values), t.Key, values, t.Count,
			nullTime(t.FirstEvent), nullTime(t.LastEvent), det)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return o.addRefs(ctx, id, 0, t.Events)
		}
	}
	return errors.New("оповещения: не удалось учесть срабатывание: открытое оповещение меняется параллельно")
}

// attach дополняет открытое оповещение по ключу; false — открытого нет.
func (o pgOps) attach(ctx context.Context, r *Rule, t *Trigger) (bool, error) {
	var (
		id    string
		count int64
		raw   []byte
	)
	err := o.tx.QueryRow(ctx, `SELECT id::text, count, details FROM alerts
		WHERE org_id = $1 AND rule_id = $2 AND open_key = $3 FOR UPDATE`, o.s.orgID, r.ID, t.Key).Scan(&id, &count, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var cur map[string]any
	if err := json.Unmarshal(raw, &cur); err != nil {
		return false, err
	}
	det, err := json.Marshal(mergeDetails(cur, t.Details))
	if err != nil {
		return false, err
	}
	if _, err := o.tx.Exec(ctx, `UPDATE alerts SET count = count + $2, last_triggered_at = now(), updated_at = now(),
		first_event_at = CASE WHEN $3::timestamptz IS NULL THEN first_event_at ELSE LEAST(first_event_at, $3) END,
		last_event_at = CASE WHEN $4::timestamptz IS NULL THEN last_event_at ELSE GREATEST(last_event_at, $4) END,
		details = $5 WHERE id = $1`, id, t.Count, nullTime(t.FirstEvent), nullTime(t.LastEvent), det); err != nil {
		return false, err
	}
	return true, o.addRefs(ctx, id, count, t.Events)
}

// addRefs записывает ссылки на события, пока в оповещении меньше
// MaxAlertEvents срабатываний; prev — срабатываний до этого.
func (o pgOps) addRefs(ctx context.Context, alertID string, prev int64, refs []EventRef) error {
	room := MaxAlertEvents - int(min(prev, MaxAlertEvents))
	if room <= 0 || len(refs) == 0 {
		return nil
	}
	refs = refs[:min(room, len(refs))]
	idsList := make([]string, len(refs))
	ts := make([]time.Time, len(refs))
	for i, r := range refs {
		idsList[i], ts[i] = r.ID, r.TS
	}
	_, err := o.tx.Exec(ctx, `INSERT INTO alert_events (alert_id, event_id, event_ts)
		SELECT $1, e, t FROM unnest($2::uuid[], $3::timestamptz[]) AS u(e, t)
		ON CONFLICT (alert_id, event_id) DO NOTHING`, alertID, idsList, ts)
	return err
}

// Rules — см. Store.
func (s *PGStore) Rules(ctx context.Context, orgID string) ([]Rule, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return collectRules(s.db.Query(ctx, `SELECT `+ruleCols+` FROM alert_rules WHERE org_id = $1 ORDER BY created_at, id`, orgID))
}

// Rule — см. Store.
func (s *PGStore) Rule(ctx context.Context, orgID, id string) (Rule, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanRule(s.db.QueryRow(ctx, `SELECT `+ruleCols+` FROM alert_rules WHERE org_id = $1 AND id = $2`, orgID, id))
}

// CountRules — см. Store.
func (s *PGStore) CountRules(ctx context.Context, orgID string) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM alert_rules WHERE org_id = $1 AND builtin_key IS NULL`, orgID).Scan(&n)
	return n, err
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// CreateRule — см. Store.
func (s *PGStore) CreateRule(ctx context.Context, r Rule, rec audit.Entry) error {
	cond, err := json.Marshal(r.Condition)
	if err != nil {
		return err
	}
	rcpt, err := json.Marshal(r.Recipients)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO alert_rules (id, org_id, builtin_key, kind, name, description, enabled, severity,
			condition, group_by, suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
			ON CONFLICT (org_id, builtin_key) DO NOTHING`,
			r.ID, r.OrgID, nullStr(r.BuiltinKey), r.Kind, r.Name, r.Description, r.Enabled, r.Severity, cond, r.GroupBy,
			r.SuppressMinutes, r.GroupMinutes, rcpt, r.Version, r.CreatedAt, r.CreatedBy, r.UpdatedAt, r.UpdatedBy)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrExists
		}
		return s.audit.RecordTx(ctx, tx, rec)
	})
}

// UpdateRule — см. Store.
func (s *PGStore) UpdateRule(ctx context.Context, orgID, id string, fn func(*Rule) (audit.Entry, []Raise, error)) (Rule, error) {
	var out Rule
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		r, err := scanRule(tx.QueryRow(ctx, `SELECT `+ruleCols+` FROM alert_rules WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		rec, raises, err := fn(&r)
		if err != nil {
			return err
		}
		cond, err := json.Marshal(r.Condition)
		if err != nil {
			return err
		}
		rcpt, err := json.Marshal(r.Recipients)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE alert_rules SET name = $3, description = $4, enabled = $5, severity = $6,
			condition = $7, group_by = $8, suppress_minutes = $9, group_minutes = $10, recipients = $11, version = $12,
			updated_at = $13, updated_by = $14 WHERE org_id = $1 AND id = $2`,
			orgID, id, r.Name, r.Description, r.Enabled, r.Severity, cond, r.GroupBy, r.SuppressMinutes, r.GroupMinutes,
			rcpt, r.Version, r.UpdatedAt, r.UpdatedBy); err != nil {
			return err
		}
		if err := raiseBuiltin(ctx, pgOps{s: s, tx: tx}, raises); err != nil {
			return err
		}
		out = r
		return s.audit.RecordTx(ctx, tx, rec)
	})
	return out, err
}

const alertCols = `a.id::text, a.org_id::text, a.rule_id::text, r.name, a.kind, a.severity, a.title, a.status, a.dedup_key,
	a.open_key IS NOT NULL, a.group_values, a.count, a.suppressed, a.first_event_at, a.last_event_at, a.created_at,
	a.last_triggered_at, a.updated_at, COALESCE(a.assignee_id::text, ''), a.closed_at, COALESCE(a.closed_by, ''),
	COALESCE(a.incident_id::text, ''), a.details`

func derefT(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func scanAlert(row pgx.Row) (Alert, error) {
	var (
		a                     Alert
		values, details       []byte
		first, last, closedAt *time.Time
	)
	err := row.Scan(&a.ID, &a.OrgID, &a.RuleID, &a.RuleName, &a.Kind, &a.Severity, &a.Title, &a.Status, &a.DedupKey,
		&a.Open, &values, &a.Count, &a.Suppressed, &first, &last, &a.CreatedAt, &a.LastTriggeredAt, &a.UpdatedAt,
		&a.AssigneeID, &closedAt, &a.ClosedBy, &a.IncidentID, &details)
	if errors.Is(err, pgx.ErrNoRows) {
		return Alert{}, ErrNotFound
	}
	if err != nil {
		return Alert{}, err
	}
	if err := json.Unmarshal(values, &a.Values); err != nil {
		return Alert{}, err
	}
	if err := json.Unmarshal(details, &a.Details); err != nil {
		return Alert{}, err
	}
	a.FirstEventAt, a.LastEventAt, a.ClosedAt = derefT(first), derefT(last), derefT(closedAt)
	a.CreatedAt, a.LastTriggeredAt, a.UpdatedAt = a.CreatedAt.UTC(), a.LastTriggeredAt.UTC(), a.UpdatedAt.UTC()
	return a, nil
}

// Alerts — см. Store. Фильтры передаются параметрами; пустой — без условия.
func (s *PGStore) Alerts(ctx context.Context, orgID string, q AlertQuery) ([]Alert, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var afterAt *time.Time
	var afterID *string
	if q.After != nil {
		afterAt, afterID = &q.After.CreatedAt, &q.After.ID
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(ctx, `SELECT `+alertCols+` FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
		WHERE a.org_id = $1 AND ($2 = '' OR a.status = $2) AND ($3 = '' OR a.severity = $3)
			AND ($4 = '' OR a.rule_id::text = $4)
			AND ($5::timestamptz IS NULL OR (a.created_at, a.id) < ($5, $6::uuid))
		ORDER BY a.created_at DESC, a.id DESC LIMIT $7`,
		orgID, q.Status, q.Severity, q.RuleID, afterAt, afterID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) { return scanAlert(r) })
}

// Alert — см. Store.
func (s *PGStore) Alert(ctx context.Context, orgID, id string) (Alert, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanAlert(s.db.QueryRow(ctx, `SELECT `+alertCols+` FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
		WHERE a.org_id = $1 AND a.id = $2`, orgID, id))
}

// AlertEvents — см. Store.
func (s *PGStore) AlertEvents(ctx context.Context, orgID, id string) ([]EventRef, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT e.event_id::text, e.event_ts FROM alert_events e JOIN alerts a ON a.id = e.alert_id
		WHERE a.org_id = $1 AND e.alert_id = $2 ORDER BY e.event_ts, e.event_id`, orgID, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (EventRef, error) {
		var e EventRef
		err := r.Scan(&e.ID, &e.TS)
		e.TS = e.TS.UTC()
		return e, err
	})
}

// AlertHistory — см. Store.
func (s *PGStore) AlertHistory(ctx context.Context, orgID, id string) ([]History, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT h.id::text, h.alert_id::text, h.at, h.actor, h.from_status, h.to_status, h.comment
		FROM alert_history h JOIN alerts a ON a.id = h.alert_id WHERE a.org_id = $1 AND h.alert_id = $2 ORDER BY h.at, h.id`, orgID, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (History, error) {
		var h History
		err := r.Scan(&h.ID, &h.AlertID, &h.At, &h.Actor, &h.From, &h.To, &h.Comment)
		h.At = h.At.UTC()
		return h, err
	})
}

// UpdateAlert — см. Store.
func (s *PGStore) UpdateAlert(ctx context.Context, orgID, id string, fn func(*Alert) (History, audit.Entry, error)) (Alert, error) {
	var out Alert
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, err := scanAlert(tx.QueryRow(ctx, `SELECT `+alertCols+` FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
			WHERE a.org_id = $1 AND a.id = $2 FOR UPDATE OF a`, orgID, id))
		if err != nil {
			return err
		}
		h, rec, err := fn(&a)
		if err != nil {
			return err
		}
		openKey := nullStr(a.DedupKey)
		if !a.Open {
			openKey = nil
		}
		if _, err := tx.Exec(ctx, `UPDATE alerts SET status = $3, open_key = $4, assignee_id = $5, closed_at = $6, closed_by = $7,
			updated_at = $8 WHERE org_id = $1 AND id = $2`,
			orgID, id, a.Status, openKey, nullStr(a.AssigneeID), nullTime(a.ClosedAt), nullStr(a.ClosedBy), a.UpdatedAt); err != nil {
			return dbErr(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO alert_history (id, alert_id, at, actor, from_status, to_status, comment)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, h.ID, h.AlertID, h.At, h.Actor, h.From, h.To, h.Comment); err != nil {
			return dbErr(err)
		}
		out = a
		return s.audit.RecordTx(ctx, tx, rec)
	})
	return out, err
}

// dbErr заменяет ошибку СУБД кодом SQLSTATE и именем ограничения: текст
// PostgreSQL мог бы содержать значения полей.
func dbErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return fmt.Errorf("оповещения: SQLSTATE %s %s", pe.Code, pe.ConstraintName)
	}
	return err
}
