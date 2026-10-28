package alerting

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// OnAudit — audit.RecordHook: системные правила и правила безопасности по
// записи журнала аудита в транзакции её записи (ADR-0020, п. 1).
func (s *PGStore) OnAudit(ctx context.Context, tx pgx.Tx, r *audit.Record) error {
	return auditRules(ctx, pgOps{s: s, tx: tx}, r)
}

// countAudit — см. secOps. Окно короткое, а индекс audit_log_action
// (org_id, action, ts) отбирает записи без просмотра журнала.
func (o pgOps) countAudit(ctx context.Context, orgID string, q auditCount) (int, error) {
	if orgID == "" {
		orgID = o.s.orgID
	}
	var ip *string
	if q.SourceIP.IsValid() {
		v := q.SourceIP.String()
		ip = &v
	}
	var n int
	err := o.tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = ANY($2) AND ts >= $3
		AND ($4::inet IS NULL OR source_ip = $4::inet) AND ($5 = '' OR (actor_type = $5 AND actor_id = $6))
		AND ($7 = '' OR (object_type = $7 AND object_id = $8))`,
		orgID, q.Actions, q.Since, ip, q.ActorType, q.ActorID, q.ObjectType, q.ObjectID).Scan(&n)
	return n, err
}

// Audit — запись журнала аудита в Memory: правила 3.11 по ней (для тестов
// без PostgreSQL; время окон — по времени записей).
func (m *Memory) Audit(ctx context.Context, r audit.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeErr(); err != nil {
		return err
	}
	if r.OrgID == "" {
		r.OrgID = audit.DefaultOrgID
	}
	m.audited = append(m.audited, r)
	return auditRules(ctx, memOps{m}, &r)
}

func (o memOps) countAudit(_ context.Context, orgID string, q auditCount) (int, error) {
	n := 0
	for i := range o.m.audited {
		r := &o.m.audited[i]
		if r.OrgID != orgID || !slices.Contains(q.Actions, r.Action) || r.TS.Before(q.Since) {
			continue
		}
		if q.SourceIP.IsValid() && r.SourceIP != q.SourceIP {
			continue
		}
		if q.ActorType != "" && (string(r.Actor.Type) != q.ActorType || r.Actor.ID != q.ActorID) {
			continue
		}
		if q.ObjectType != "" && (r.Object.Type != q.ObjectType || r.Object.ID != q.ObjectID) {
			continue
		}
		n++
	}
	return n, nil
}
