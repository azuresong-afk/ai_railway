package alerting

import (
	"context"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Встроенные правила очереди подтверждений (ТЗ 5.10, DM-22; задача 4.10
// этапа 4, ADR-0023, разделы 5 и 8). Срабатывают по записям аудита, которые
// сервер пишет при создании запроса шлюзом и при переполнении очереди. В
// оповещение и уведомление уходят приложение, агент, инструмент, риск и
// срок — аргументы вызова никогда: каналы могут быть внешними.
const (
	// BuiltinApprovalRequested — вызов ждёт решения дежурного: одно
	// уведомление на запрос; больше ApprovalBurst запросов за
	// ApprovalBurstWindow объединяются в одно оповещение со списком.
	BuiltinApprovalRequested = "agents.approval_requested"
	// BuiltinApprovalQueueFull — очередь шлюза или агента переполнена,
	// вызовы отклоняются без подтверждения.
	BuiltinApprovalQueueFull = "agents.approval_queue_full"
	// ApprovalBurst и ApprovalBurstWindow — порог объединения уведомлений.
	ApprovalBurst       = 20
	ApprovalBurstWindow = 10 * time.Minute
	// approvalBurstKey — ключ объединённого оповещения.
	approvalBurstKey = "burst"
)

// approvalRules — встроенные правила задачи 4.10. Получатели по умолчанию
// — аналитики (дежурные) сверх обязательных ролей.
func approvalRules() []Rule {
	analysts := Recipients{Roles: []string{string(auth.RoleAnalyst)}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinApprovalRequested, Kind: KindSystem, Name: "Вызов инструмента ждёт подтверждения",
			Description: "DM-22: политика вызовов требует подтверждения человеком (require_approval). Вызов ждёт в шлюзе до " +
				"решения в консоли или до срока approval_timeout, затем отклоняется. Больше 20 запросов за 10 минут — " +
				"одно оповещение со списком.",
			Enabled: true, Severity: "high", GroupBy: []string{"tool"}, GroupMinutes: int(ApprovalBurstWindow / time.Minute),
			Recipients: analysts},
		{BuiltinKey: BuiltinApprovalQueueFull, Kind: KindSystem, Name: "Очередь подтверждений переполнена",
			Description: "DM-22: на шлюзе 256 ожидающих подтверждения вызовов или 16 у одного агента. Новые вызовы, требующие " +
				"подтверждения, отклоняются сразу. Возможна атака на очередь или зацикливание агента.",
			Enabled: true, Severity: "high", GroupBy: []string{"gateway", "agent"}, GroupMinutes: 10, Recipients: analysts},
	}
}

// approvalRaise — срабатывание по записи agent.approval.requested или
// agent.approval.queue_full от шлюза.
func approvalRaise(ctx context.Context, ops secOps, r *audit.Record, d map[string]any) ([]Raise, error) {
	if r.Actor.Type != audit.ActorGateway {
		return nil, nil
	}
	tool := str(d["server"], "") + "/" + str(d["tool"], "")
	extra := map[string]any{"app": d["app"], "tool": tool, "risk": d["risk"], "gateway": r.Actor.ID}
	if a := str(d["agent"], ""); a != "" {
		extra["agent"] = a
	}
	if r.Action == "agent.approval.queue_full" {
		extra["scope"], extra["limit"] = d["scope"], d["limit"]
		agent := str(d["app"], "") + "/" + str(d["agent"], "")
		keys := map[string]string{"gateway": r.Actor.ID, "agent": agent}
		return []Raise{raiseOf(BuiltinApprovalQueueFull, keys, keys, 1, map[string]any{"items": []any{item(r, extra)}})}, nil
	}
	extra["approval_id"], extra["deadline"] = r.Object.ID, d["deadline"]
	// Запись agent.approval.requested пишет только сервер от имени шлюза:
	// считаются запросы всех шлюзов организации.
	n, err := ops.countAudit(ctx, r.OrgID, auditCount{Actions: []string{"agent.approval.requested"},
		Since: r.TS.Add(-ApprovalBurstWindow)})
	if err != nil {
		return nil, err
	}
	// Одно уведомление на запрос: ключ — ID запроса; сверх порога —
	// общее оповещение, которое собирает запросы окна.
	key, values := r.Object.ID, map[string]string{ToolField: tool}
	if n > ApprovalBurst {
		key, values = approvalBurstKey, map[string]string{}
	}
	return []Raise{raiseOf(BuiltinApprovalRequested, map[string]string{"approval": key}, values, 1,
		map[string]any{"items": []any{item(r, extra)}})}, nil
}
