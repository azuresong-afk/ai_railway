package sysstatus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// maxGateways — предел выборки счётчиков (как в реестре шлюзов).
const maxGateways = 1000

// rollbackTimeout — предел на откат после отмены контекста.
const rollbackTimeout = 5 * time.Second

// PGStore — Store на PostgreSQL (миграции 0002_audit, 0010_events,
// 0011_system_status).
type PGStore struct {
	db    PGDB
	audit *audit.Log
	orgID string
}

// NewPGStore создаёт хранилище; журнал аудита должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log, orgID string) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("состояние системы: нет БД или журнала аудита")
	}
	if orgID == "" {
		orgID = audit.DefaultOrgID
	}
	return &PGStore{db: db, audit: a, orgID: orgID}, nil
}

// AuditSize — см. Store. Размер считает PostgreSQL по таблице и её индексам.
func (s *PGStore) AuditSize(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRow(ctx, "SELECT pg_total_relation_size('audit_log')").Scan(&n); err != nil {
		return 0, fmt.Errorf("размер журнала аудита: %w", err)
	}
	return n, nil
}

// EventStats — см. Store.
func (s *PGStore) EventStats(ctx context.Context) (map[string]GatewayEvents, error) {
	rows, err := s.db.Query(ctx, `SELECT gateway_id::text, dropped, rejected, started_at, reported_at
		FROM gateway_event_stats LIMIT $1`, maxGateways)
	if err != nil {
		return nil, fmt.Errorf("счётчики событий шлюзов: %w", err)
	}
	defer rows.Close()
	out := map[string]GatewayEvents{}
	for rows.Next() {
		var id string
		var dropped, rejected int64
		var ev GatewayEvents
		if err := rows.Scan(&id, &dropped, &rejected, &ev.StartedAt, &ev.ReportedAt); err != nil {
			return nil, fmt.Errorf("счётчики событий шлюзов: %w", err)
		}
		// CHECK таблицы не пускает отрицательные значения.
		ev.Dropped, ev.Rejected = uint64(max(dropped, 0)), uint64(max(rejected, 0))
		ev.StartedAt, ev.ReportedAt = ev.StartedAt.UTC(), ev.ReportedAt.UTC()
		out[id] = ev
	}
	return out, rows.Err()
}

// AuditCounts — см. Store.
func (s *PGStore) AuditCounts(ctx context.Context, since time.Time) (locked, denied int, err error) {
	err = s.db.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE action = 'auth.locked'),
		count(*) FILTER (WHERE action = 'access.denied')
		FROM audit_log WHERE org_id = $1 AND ts >= $2 AND action IN ('auth.locked', 'access.denied')`,
		s.orgID, since).Scan(&locked, &denied)
	if err != nil {
		return 0, 0, fmt.Errorf("счётчики журнала аудита: %w", err)
	}
	return locked, denied, nil
}

// AuditChain — см. Store. Последняя строка audit_verifications: её пишут
// фоновая проверка сервера и aisec-cli audit verify.
func (s *PGStore) AuditChain(ctx context.Context) (*AuditChainStatus, error) {
	var ch AuditChainStatus
	err := s.db.QueryRow(ctx, `SELECT ts, ok, checked, last_seq, reason, broken_seq
		FROM audit_verifications ORDER BY ts DESC, id DESC LIMIT 1`).
		Scan(&ch.CheckedAt, &ch.OK, &ch.Checked, &ch.LastSeq, &ch.Reason, &ch.BrokenSeq)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("проверка цепочки аудита: %w", err)
	}
	ch.CheckedAt = ch.CheckedAt.UTC()
	return &ch, nil
}

// AlertStates — см. Store.
func (s *PGStore) AlertStates(ctx context.Context) (map[string]AlertState, error) {
	rows, err := s.db.Query(ctx, "SELECT condition, active, since FROM system_alert_state WHERE org_id = $1", s.orgID)
	if err != nil {
		return nil, fmt.Errorf("состояния уведомлений: %w", err)
	}
	defer rows.Close()
	out := map[string]AlertState{}
	for rows.Next() {
		var code string
		var st AlertState
		if err := rows.Scan(&code, &st.Active, &st.Since); err != nil {
			return nil, fmt.Errorf("состояния уведомлений: %w", err)
		}
		out[code] = st
	}
	return out, rows.Err()
}

// Transition — см. Store. Строка условия блокируется на время транзакции:
// два сервера не запишут одно изменение дважды.
func (s *PGStore) Transition(ctx context.Context, condition string, active bool, now time.Time,
	rec func(active bool) audit.Entry) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("состояние уведомления: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после фиксации безвреден, ошибку скрывает исходная
	}()
	var cur bool
	err = tx.QueryRow(ctx, "SELECT active FROM system_alert_state WHERE org_id = $1 AND condition = $2 FOR UPDATE",
		s.orgID, condition).Scan(&cur)
	exists := !errors.Is(err, pgx.ErrNoRows)
	if err != nil && exists {
		return false, fmt.Errorf("состояние уведомления: чтение: %w", err)
	}
	changed := (exists && cur != active) || (!exists && active)
	switch {
	case !exists:
		if _, err := tx.Exec(ctx, `INSERT INTO system_alert_state (org_id, condition, active, since, updated_at)
			VALUES ($1, $2, $3, $4, $4) ON CONFLICT (org_id, condition) DO NOTHING`, s.orgID, condition, active, now); err != nil {
			return false, fmt.Errorf("состояние уведомления: запись: %w", err)
		}
	case changed:
		if _, err := tx.Exec(ctx, `UPDATE system_alert_state SET active = $3, since = $4, updated_at = $4
			WHERE org_id = $1 AND condition = $2`, s.orgID, condition, active, now); err != nil {
			return false, fmt.Errorf("состояние уведомления: обновление: %w", err)
		}
	default:
		return false, nil
	}
	if changed {
		e := rec(active)
		e.OrgID = s.orgID
		if err := s.audit.RecordTx(ctx, tx, e); err != nil {
			return false, fmt.Errorf("состояние уведомления: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("состояние уведомления: фиксация: %w", err)
	}
	return changed, nil
}
