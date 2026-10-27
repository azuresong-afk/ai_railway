package alerting

import (
	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Встроенные правила реестра инструментов агентов (ТЗ 5.10, 5.16; задача
// 4.8 этапа 4, ADR-0023, раздел 12). Срабатывают по записям аудита, которые
// сервер пишет при приёме сообщения шлюза tools:observe.
const (
	// BuiltinToolNew — шлюз увидел новый инструмент: вызовы получают
	// действие unapproved до решения администратора безопасности. Вид
	// «новое»: правило можно отключить.
	BuiltinToolNew = "agents.tool_new"
	// BuiltinToolChanged — описание одобренного инструмента изменилось
	// (DM-25): вызовы блокируются до повторного одобрения. Правило
	// безопасности, не отключается; поднимается и в режиме monitor.
	BuiltinToolChanged = "agents.tool_changed"
	// ToolField — поле правила «новое» для BuiltinToolNew: сервер и имя
	// инструмента.
	ToolField = "tool"
)

// agentRules — встроенные правила задачи 4.8.
func agentRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinToolNew, Kind: KindNew, Name: "Новый инструмент агента",
			Description: "Шлюз впервые увидел инструмент MCP-сервера или функцию агента. До одобрения администратором " +
				"безопасности вызовы получают действие unapproved политики вызовов.",
			Enabled: true, Severity: "medium", Condition: Condition{Field: ToolField}, GroupBy: []string{ToolField},
			SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinToolChanged, Kind: KindSecurity, Name: "Изменилось описание одобренного инструмента",
			Description: "DM-25: описание инструмента отличается от одобренного (подмена инструмента, rug pull). " +
				"Вызовы блокируются до повторного одобрения с проверкой разницы описаний.",
			Enabled: true, Severity: "high", GroupBy: []string{ToolField}, Recipients: none},
	}
}

// agentToolRaise — срабатывание по записи аудита agent_tool.discovered или
// agent_tool.changed. Ключ — сервер (или агент для функций) и имя
// инструмента; в подробностях — хеши описаний, без самих описаний.
func agentToolRaise(r *audit.Record, d map[string]any) (Raise, bool) {
	if r.Result != audit.ResultSuccess || r.Actor.Type != audit.ActorGateway {
		return Raise{}, false
	}
	name := str(d["name"], "")
	if name == "" {
		return Raise{}, false
	}
	owner := str(d["mcp_server"], "")
	if owner == "" {
		owner = "function@" + str(d["agent"], r.Object.ID)
	}
	tool := owner + "/" + name
	extra := map[string]any{"tool": tool, "hash": d["hash"], "hash_alg": d["hash_alg"], "status": d["status"],
		"gateway": r.Actor.ID}
	key := BuiltinToolNew
	if r.Action == "agent_tool.changed" {
		key = BuiltinToolChanged
		extra["approved_hash"] = d["approved_hash"]
	}
	// Ключ — ID записи реестра: одноимённые функции разных агентов различаются.
	return raiseOf(key, map[string]string{ToolField: r.Object.ID}, map[string]string{ToolField: tool}, 1,
		map[string]any{"items": []any{item(r, extra)}}), true
}
