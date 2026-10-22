package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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

// PGStore — Store на PostgreSQL (миграция 0033_notify_channels).
type PGStore struct {
	db    PGDB
	audit *audit.Log
	orgID string
	ids   *ids.Generator
}

// NewPGStore создаёт хранилище; журнал аудита работает через тот же пул.
func NewPGStore(db PGDB, a *audit.Log, rnd aisecCrypto.Random, orgID string) (*PGStore, error) {
	if db == nil || a == nil || rnd == nil {
		return nil, errors.New("уведомления: нет БД, журнала аудита или источника случайности")
	}
	if orgID == "" {
		orgID = audit.DefaultOrgID
	}
	return &PGStore{db: db, audit: a, orgID: orgID, ids: ids.NewGenerator(rnd)}, nil
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
		return fmt.Errorf("уведомления: начало транзакции: %w", err)
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
		return fmt.Errorf("уведомления: фиксация: %w", err)
	}
	return nil
}

// dbErr — ошибка БД без значений строк.
func dbErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		if pe.Code == "23505" && pe.ConstraintName == "notify_channels_org_id_name_key" {
			return ErrNameTaken
		}
		return fmt.Errorf("уведомления: SQLSTATE %s %s", pe.Code, pe.ConstraintName)
	}
	return err
}

const channelCols = `id::text, org_id::text, name, type, enabled, min_severity, settings, secret_fields, secret,
	COALESCE(secret_key_id::text, ''), version, created_at, created_by, updated_at, updated_by`

func scanChannel(row pgx.Row) (Channel, error) {
	var c Channel
	var settings []byte
	if err := row.Scan(&c.ID, &c.OrgID, &c.Name, &c.Type, &c.Enabled, &c.MinSeverity, &settings, &c.SecretFields, &c.Secret,
		&c.SecretKeyID, &c.Version, &c.CreatedAt, &c.CreatedBy, &c.UpdatedAt, &c.UpdatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c, ErrNotFound
		}
		return c, err
	}
	if err := json.Unmarshal(settings, &c.Settings); err != nil {
		return c, fmt.Errorf("уведомления: настройки канала %s: %w", c.ID, err)
	}
	return c, nil
}

// Channels — см. Store.
func (s *PGStore) Channels(ctx context.Context) ([]Channel, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+channelCols+` FROM notify_channels WHERE org_id = $1 ORDER BY created_at, id LIMIT $2`,
		s.orgID, MaxChannels)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Channel — см. Store.
func (s *PGStore) Channel(ctx context.Context, id string) (Channel, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanChannel(s.db.QueryRow(ctx, `SELECT `+channelCols+` FROM notify_channels WHERE org_id = $1 AND id = $2`, s.orgID, id))
}

// CreateChannel — см. Store. Предел числа каналов проверяется под
// блокировкой организации.
func (s *PGStore) CreateChannel(ctx context.Context, c Channel, rec audit.Entry) error {
	settings, err := json.Marshal(c.Settings)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('notify_channels:' || $1::text))`, s.orgID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notify_channels WHERE org_id = $1`, s.orgID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxChannels {
			return ErrTooMany
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notify_channels (id, org_id, name, type, enabled, min_severity, settings,
			secret_fields, secret, secret_key_id, version, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, '')::uuid, $11, $12, $13, $14, $15)`,
			c.ID, s.orgID, c.Name, c.Type, c.Enabled, c.MinSeverity, settings, c.SecretFields, c.Secret, c.SecretKeyID,
			c.Version, c.CreatedAt, c.CreatedBy, c.UpdatedAt, c.UpdatedBy); err != nil {
			return dbErr(err)
		}
		return s.audit.RecordTx(ctx, tx, rec)
	})
}

// UpdateChannel — см. Store.
func (s *PGStore) UpdateChannel(ctx context.Context, id string, fn func(old Channel) (Channel, audit.Entry, error)) (Channel, error) {
	var out Channel
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		old, err := scanChannel(tx.QueryRow(ctx, `SELECT `+channelCols+` FROM notify_channels WHERE org_id = $1 AND id = $2 FOR UPDATE`,
			s.orgID, id))
		if err != nil {
			return err
		}
		c, rec, err := fn(old)
		if err != nil {
			return err
		}
		settings, err := json.Marshal(c.Settings)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE notify_channels SET name = $3, enabled = $4, min_severity = $5, settings = $6,
			secret_fields = $7, secret = $8, secret_key_id = NULLIF($9, '')::uuid, version = $10, updated_at = $11, updated_by = $12
			WHERE org_id = $1 AND id = $2`, s.orgID, id, c.Name, c.Enabled, c.MinSeverity, settings, c.SecretFields, c.Secret,
			c.SecretKeyID, c.Version, c.UpdatedAt, c.UpdatedBy); err != nil {
			return dbErr(err)
		}
		out = c
		return s.audit.RecordTx(ctx, tx, rec)
	})
	return out, err
}

func insertDelivery(ctx context.Context, tx pgx.Tx, d Delivery) error {
	var sent *time.Time
	if !d.SentAt.IsZero() {
		sent = &d.SentAt
	}
	_, err := tx.Exec(ctx, `INSERT INTO alert_deliveries (id, org_id, channel_id, alert_id, kind, status, attempts, next_at, error,
		created_at, updated_at, sent_at) VALUES ($1, $2, $3, NULLIF($4, '')::uuid, $5, $6, $7, $8, $9, $10, $11, $12)`,
		d.ID, d.OrgID, d.ChannelID, d.AlertID, d.Kind, d.Status, d.Attempts, d.NextAt, d.Error, d.CreatedAt, d.UpdatedAt, sent)
	return dbErr(err)
}

// RecordTest — см. Store.
func (s *PGStore) RecordTest(ctx context.Context, d Delivery, rec audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := insertDelivery(ctx, tx, d); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, rec)
	})
}

const deliveryCols = `id::text, org_id::text, channel_id::text, COALESCE(alert_id::text, ''), kind, status, attempts, next_at,
	error, created_at, updated_at, sent_at`

func scanDeliveries(rows pgx.Rows) ([]Delivery, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Delivery, error) {
		var d Delivery
		var sent *time.Time
		err := r.Scan(&d.ID, &d.OrgID, &d.ChannelID, &d.AlertID, &d.Kind, &d.Status, &d.Attempts, &d.NextAt, &d.Error,
			&d.CreatedAt, &d.UpdatedAt, &sent)
		if sent != nil {
			d.SentAt = *sent
		}
		return d, err
	})
}

// Deliveries — см. Store.
func (s *PGStore) Deliveries(ctx context.Context, channelID string, limit int) ([]Delivery, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+deliveryCols+` FROM alert_deliveries WHERE org_id = $1 AND channel_id = $2
		ORDER BY created_at DESC, id DESC LIMIT $3`, s.orgID, channelID, limit)
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

// ClaimDue — см. Store. Несколько экземпляров сервера не возьмут одну
// доставку: SKIP LOCKED и срок lease.
func (s *PGStore) ClaimDue(ctx context.Context, lease time.Duration, limit int) ([]Delivery, error) {
	var out []Delivery
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE alert_deliveries SET next_at = now() + make_interval(secs => $3), updated_at = now()
			WHERE id IN (SELECT id FROM alert_deliveries WHERE org_id = $1 AND status = 'pending' AND next_at <= now()
				ORDER BY next_at, id LIMIT $2 FOR UPDATE SKIP LOCKED)
			RETURNING `+deliveryCols, s.orgID, limit, lease.Seconds())
		if err != nil {
			return err
		}
		out, err = scanDeliveries(rows)
		return err
	})
	return out, err
}

// FinishDelivery — см. Store.
func (s *PGStore) FinishDelivery(ctx context.Context, d Delivery, rec *audit.Entry) error {
	var sent *time.Time
	if !d.SentAt.IsZero() {
		sent = &d.SentAt
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE alert_deliveries SET status = $3, attempts = $4, next_at = $5, error = $6,
			updated_at = $7, sent_at = $8 WHERE org_id = $1 AND id = $2 AND status = 'pending'`,
			s.orgID, d.ID, d.Status, d.Attempts, d.NextAt, d.Error, d.UpdatedAt, sent)
		if err != nil {
			return dbErr(err)
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		if rec == nil {
			return nil
		}
		return s.audit.RecordTx(ctx, tx, *rec)
	})
}

// AlertMessage — см. Store.
func (s *PGStore) AlertMessage(ctx context.Context, alertID string) (Message, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var m Message
	var group []byte
	err := s.db.QueryRow(ctx, `SELECT a.id::text, COALESCE(r.builtin_key, r.id::text), r.name, a.kind, a.severity, a.title,
		a.count, a.group_values, a.created_at FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
		WHERE a.org_id = $1 AND a.id = $2`, s.orgID, alertID).
		Scan(&m.ID, &m.Rule, &m.RuleName, &m.AlertKind, &m.Severity, &m.Title, &m.Count, &group, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, ErrNotFound
	}
	if err != nil {
		return m, err
	}
	m.Kind = KindAlert
	if err := json.Unmarshal(group, &m.Group); err != nil {
		return m, fmt.Errorf("уведомления: группировка оповещения %s: %w", alertID, err)
	}
	return m, nil
}

// EnqueueAlertTx ставит новое оповещение в очередь доставки по включённым
// каналам с порогом серьёзности не выше его, в транзакции tx создания
// оповещения (подключение к движку — задача 3.14). Возвращает число строк.
func (s *PGStore) EnqueueAlertTx(ctx context.Context, tx pgx.Tx, alertID, severity string) (int, error) {
	if SeverityRank(severity) == 0 {
		return 0, fmt.Errorf("уведомления: неизвестная серьёзность %q", severity)
	}
	rows, err := tx.Query(ctx, `SELECT id::text, min_severity FROM notify_channels WHERE org_id = $1 AND enabled
		ORDER BY created_at, id`, s.orgID)
	if err != nil {
		return 0, err
	}
	type ch struct{ id, min string }
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ch, error) {
		var c ch
		return c, r.Scan(&c.id, &c.min)
	})
	if err != nil {
		return 0, err
	}
	n := 0
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
		return 0, err
	}
	for _, c := range list {
		if SeverityRank(severity) < SeverityRank(c.min) {
			continue
		}
		id, err := s.ids.New()
		if err != nil {
			return 0, err
		}
		if err := insertDelivery(ctx, tx, Delivery{ID: id.String(), OrgID: s.orgID, ChannelID: c.id, AlertID: alertID,
			Kind: KindAlert, Status: StatusPending, NextAt: now, CreatedAt: now, UpdatedAt: now}); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}
