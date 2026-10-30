package alerting

import (
	"strconv"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Встроенное правило теневого ИИ (ТЗ 5.11, 5.16, DM-37; задача 4.23 этапа
// 4, ADR-0027, дополнение 1). Срабатывает по записи аудита
// shadow_ai.new_service, которую сервер пишет в транзакции записи сводок,
// когда в журналах прокси появился сервис каталога, которого не было в
// сводках за предыдущие 30 суток. Одно оповещение на сервис: «новизну»
// определяет теневой ИИ, ключ дедупликации — ID сервиса.
const (
	// BuiltinShadowNewService — новый ИИ-сервис в журналах прокси. Вид
	// «новое»: правило можно отключить и сменить получателей.
	BuiltinShadowNewService = "shadow_ai.new_service"
	// ShadowServiceField — поле правила «новое» для BuiltinShadowNewService:
	// сервис каталога. В событиях шлюза такого поля нет.
	ShadowServiceField = "shadow_ai_service"
	// BuiltinShadowAliasProbe — перебор псевдонимов импортом журнала (4В27
	// ревью 4.r3, DM-37): журнал, где каждому подобранному логину отведён
	// свой час, даёт таблицу «логин → псевдоним» и для событий шлюза.
	// Правило безопасности: не отключается.
	BuiltinShadowAliasProbe = "security.shadow_ai_alias_probe"
	// ShadowAliasProbeThreshold — больше стольких новых для организации
	// псевдонимов за импорт или за сутки — перебор. Исходный состав (первый
	// импорт с пользователями) тоже считается (4В28): пустые сводки бывают
	// и после очистки по сроку.
	ShadowAliasProbeThreshold = 500
)

// shadowAIRules — встроенные правила задачи 4.23.
func shadowAIRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinShadowNewService, Kind: KindNew, Name: "Новый ИИ-сервис в журналах прокси",
			Description: "DM-37: сотрудники обратились к публичному ИИ-сервису каталога, которого не было в сводках теневого ИИ " +
				"за предыдущие 30 суток. В оповещении — сервис и число пользователей, без логинов и псевдонимов.",
			Enabled: true, Severity: "medium", Condition: Condition{Field: ShadowServiceField}, GroupBy: []string{ShadowServiceField},
			SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinShadowAliasProbe, Kind: KindSecurity, Name: "Перебор псевдонимов импортом журнала",
			Description: "DM-37: импорт журнала прокси добавил больше " + strconv.Itoa(ShadowAliasProbeThreshold) +
				" новых для организации псевдонимов пользователей за импорт или за сутки — возможно " +
				"сопоставление логинов с псевдонимами. Первый импорт с пользователями (исходный состав) тоже считается: " +
				"при подключении прокси оповещение ожидаемо.",
			Enabled: true, Severity: "high", GroupBy: []string{"actor"}, Recipients: none},
	}
}

// serverRaisedField — поле правила «новое», которое поднимает сервер по
// записям аудита, а не события шлюза: tool (agents.tool_new) и
// shadow_ai_service. Такие правила не создаются через API и не меняют поле.
func serverRaisedField(f string) bool { return f == ToolField || f == ShadowServiceField }

// shadowNewServiceRaise — срабатывание по записи shadow_ai.new_service.
// В подробностях — число пользователей и обращений, первый час, источник;
// псевдонимов в записи нет.
func shadowNewServiceRaise(r *audit.Record, d map[string]any) (Raise, bool) {
	if r.Result != audit.ResultSuccess {
		return Raise{}, false
	}
	id := str(d["service"], r.Object.ID)
	if id == "" {
		return Raise{}, false
	}
	name := str(d["service_name"], id)
	users := 0
	if v, ok := d["users"].(float64); ok && v >= 0 {
		users = int(v)
	}
	extra := map[string]any{"service": id, "service_name": name, "users": users, "requests": d["requests"],
		"first_seen": d["first_seen"], "source": d["source"]}
	return raiseOf(BuiltinShadowNewService, map[string]string{ShadowServiceField: id},
		map[string]string{ShadowServiceField: name + " (пользователей: " + strconv.Itoa(users) + ")"}, 1,
		map[string]any{"items": []any{item(r, extra)}}), true
}

// shadowAliasProbeRaise — срабатывание по записи shadow_ai.import, если
// новых псевдонимов за импорт или за сутки больше порога (4В27). Исходный
// состав не освобождается (4В28) — в подробностях помечен baseline.
func shadowAliasProbeRaise(r *audit.Record, d map[string]any) (Raise, bool) {
	if r.Result != audit.ResultSuccess {
		return Raise{}, false
	}
	num := func(k string) int64 {
		v, _ := d[k].(float64)
		return int64(v)
	}
	n, day := num("new_users"), num("new_users_day")
	if max(n, day) <= ShadowAliasProbeThreshold {
		return Raise{}, false
	}
	base, _ := d["baseline"].(bool)
	return raiseOf(BuiltinShadowAliasProbe, map[string]string{"actor": actorKey(r.Actor)},
		map[string]string{"actor": actorName(r.Actor)}, 1,
		map[string]any{"items": []any{item(r, map[string]any{"users": num("users"), "new_users": n, "new_users_day": day, "baseline": base})}}), true
}
