package alerting

import (
	"context"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Встроенные правила по событиям агентов (ТЗ 5.10, 5.16; задача 4.11 этапа
// 4, ADR-0023, раздел 8): блокировки вызовов инструментов и отравленные
// описания инструментов, увиденные MCP-прокси шлюза.
const (
	// BuiltinToolBlocked — серия заблокированных вызовов одного инструмента
	// одним агентом (DM-20, DM-21, DM-23). Вид «частота».
	BuiltinToolBlocked = "agents.tool_blocked"
	// BuiltinToolPoisoning — в описании инструмента MCP-сервера найдены
	// инструкции для модели или скрытые символы (DM-24). Правило
	// безопасности, не отключается; поднимается и в режиме monitor.
	BuiltinToolPoisoning = "agents.tool_poisoning"
	// ToolBlockedCount и ToolBlockedWindow — порог правила
	// agents.tool_blocked: одна блокировка — обычная работа политики,
	// серия — агент упорно пытается выполнить запрещённое (ADR-0023, раздел 8).
	ToolBlockedCount  = 3
	ToolBlockedWindow = 10
)

// Поля группировки по разделу agent события.
const (
	agentField  = "agent"
	serverField = "mcp_server"
)

// agentCallRules — встроенные правила задачи 4.11.
func agentCallRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinToolBlocked, Kind: KindFrequency, Name: "Серия заблокированных вызовов инструмента",
			Description: "DM-20, DM-21, DM-23: шлюз заблокировал 3 и более вызова одного инструмента одним агентом за 10 минут — " +
				"неодобренный или изменённый инструмент, опасные аргументы или превышение частоты вызовов.",
			Enabled: true, Severity: "high",
			Condition: Condition{Filter: canonical(`type = "agent_tool_call" and action = "block" and threat in ("DM-20", "DM-21", "DM-23")`),
				Count: ToolBlockedCount, WindowMinutes: ToolBlockedWindow},
			GroupBy: []string{agentField, serverField, ToolField}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinToolPoisoning, Kind: KindSecurity, Name: "Отравленное описание инструмента",
			Description: "DM-24: в описании инструмента MCP-сервера — инструкции для модели или скрытые символы (tool poisoning). " +
				"Шлюз убирает такой инструмент из списка, пока его описание не одобрит администратор безопасности.",
			Enabled: true, Severity: "high", GroupBy: []string{serverField, ToolField}, Recipients: none},
	}
}

// agentFieldValue — значение поля группировки из раздела agent события.
func agentFieldValue(rec *events.Record, field string) string {
	if rec.Details == nil || rec.Details.Agent == nil {
		return ""
	}
	a := rec.Details.Agent
	switch field {
	case agentField:
		return a.Agent
	case serverField:
		return a.Server
	case ToolField:
		return a.Tool
	}
	return ""
}

// processToolPoisoning — DM-24 по принятым событиям agent_mcp в транзакции
// приёма: одно оповещение на MCP-сервер и инструмент. Имена инструментов в
// событии уже проверены (events.Agent), описаний в оповещении нет.
func processToolPoisoning(ctx context.Context, ops txOps, evs []*events.Event) error {
	g := group{by: map[string]*Trigger{}}
	for _, e := range evs {
		if e.Type != events.TypeAgentMCP || e.Agent == nil || len(e.Agent.Poisoned) == 0 || e.Agent.Server == "" {
			continue
		}
		ts, err := events.PartitionTime(e.ID)
		if err != nil {
			continue
		}
		for _, name := range e.Agent.Poisoned {
			values := map[string]string{serverField: e.Agent.Server, ToolField: name}
			t := g.get(GroupKey([]string{serverField, ToolField}, values), values)
			t.add(EventRef{ID: e.ID, TS: ts}, e.Time)
			if t.Details == nil {
				t.Details = map[string]any{"agent": e.Agent.Agent, "app": e.App}
			}
		}
	}
	if len(g.order) == 0 {
		return nil
	}
	keys := slices.Clone(g.order)
	// Порядок ключей фиксирован: блокировки строк — в одном порядке.
	slices.Sort(keys)
	raises := make([]Raise, 0, len(keys))
	for _, k := range keys {
		raises = append(raises, Raise{Key: BuiltinToolPoisoning, Trigger: *g.by[k]})
	}
	return raiseBuiltin(ctx, ops, raises)
}
