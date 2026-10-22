package alerting

import "github.com/azuresong-afk/ai_railway/internal/events"

// Ключи встроенных правил. Правила создаёт сервер при запуске, если их нет
// (Service.EnsureBuiltins); удаления нет. «Порог» и «новое» можно менять и
// отключать, у правил безопасности меняются только получатели.
const (
	// BuiltinInjectionBlocked — блокировка промпт-инъекции (DM-01).
	BuiltinInjectionBlocked = "threshold.injection_blocked"
	// BuiltinNewModel, BuiltinNewProvider, BuiltinNewRiskyUser — DM-34.
	BuiltinNewModel     = "new.model"
	BuiltinNewProvider  = "new.provider"
	BuiltinNewRiskyUser = "new.risky_user"
	// BuiltinRecipientsChanged — изменение получателей правила (ТЗ 5.6).
	BuiltinRecipientsChanged = "security.recipients_changed"
)

// canonical — каноническая запись фильтра встроенного правила.
func canonical(filter string) string {
	f, err := events.ParseFilter(filter)
	if err != nil {
		panic("alerting: неверный фильтр встроенного правила: " + err.Error())
	}
	return f.String()
}

// builtinRules — встроенные правила этапа 3 (задача 3.10). Системные
// правила и правила безопасности DM-38–DM-44 добавляет задача 3.11.
func builtinRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinInjectionBlocked, Kind: KindThreshold, Name: "Промпт-инъекция заблокирована",
			Description: "DM-01: политика заблокировала запрос с инъекцией или джейлбрейком (в режиме monitor — заблокировала бы). " +
				"Одно оповещение на приложение, пока оно не закрыто.",
			Enabled: true, Severity: "high", Condition: Condition{Filter: canonical(`threat = "DM-01" and action = "block"`)},
			GroupBy: []string{"app"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinNewModel, Kind: KindNew, Name: "Новая модель",
			Description: "DM-34: к модели обратились впервые с создания правила.",
			Enabled:     true, Severity: "medium", Condition: Condition{Field: "model"}, GroupBy: []string{"model"},
			SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinNewProvider, Kind: KindNew, Name: "Новый провайдер",
			Description: "DM-34: запрос впервые ушёл к этому провайдеру.",
			Enabled:     true, Severity: "medium", Condition: Condition{Field: "provider"}, GroupBy: []string{"provider"},
			SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinNewRiskyUser, Kind: KindNew, Name: "Новый пользователь с высоким риском",
			Description: "DM-34: первое событие пользователя с серьёзностью «высокая» или «критическая». Пользователь — псевдоним.",
			Enabled:     true, Severity: "medium", Condition: Condition{Field: "user", MinSeverity: "high"}, GroupBy: []string{"user"},
			SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinRecipientsChanged, Kind: KindSecurity, Name: "Изменены получатели оповещений",
			Description: "Изменение получателей правила оповещения (ТЗ 5.6). Изменения одного пользователя за 10 минут — одно оповещение.",
			Enabled:     true, Severity: "high", GroupBy: []string{"actor"}, GroupMinutes: 10, Recipients: none},
	}
}
