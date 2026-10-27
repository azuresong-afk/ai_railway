package alerting

import (
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Ключи встроенных правил. Правила создаёт сервер при запуске, если их нет
// (Service.EnsureBuiltins); удаления нет. «Порог» и «новое» можно менять и
// отключать, у правил безопасности меняются только получатели.
const (
	// BuiltinInjectionBlocked — блокировка промпт-инъекции (DM-01).
	BuiltinInjectionBlocked = "threshold.injection_blocked"
	// Сессии и целостность промпта (задачи 4.13, 4.14 этапа 4):
	// эскалация в сессии (DM-06), подмена системного промпта (DM-26) и
	// истории диалога (DM-03).
	BuiltinSessionRisk      = "threshold.session_risk"
	BuiltinPromptIntegrity  = "threshold.prompt_integrity"
	BuiltinHistoryIntegrity = "threshold.history_integrity"
	// BuiltinNewModel, BuiltinNewProvider, BuiltinNewRiskyUser — DM-34.
	BuiltinNewModel     = "new.model"
	BuiltinNewProvider  = "new.provider"
	BuiltinNewRiskyUser = "new.risky_user"
	// BuiltinRecipientsChanged — изменение получателей правила (ТЗ 5.6).
	BuiltinRecipientsChanged = "security.recipients_changed"
	// Правила фоновой задачи (задача 3.12): серия срабатываний (DM-16),
	// серия отказов по квотам и резкий рост запросов (DM-36), объём ответов
	// модели (DM-17), бюджет 80 % и 100 % (DM-15). Их можно менять и
	// отключать, как «порог» и «новое».
	BuiltinProbingSeries    = "frequency.probing"
	BuiltinQuotaExceeded    = "frequency.quota_exceeded"
	BuiltinActivitySpike    = "anomaly.activity_spike"
	BuiltinExtractionVolume = "anomaly.extraction_volume"
	BuiltinBudget           = "budget.monthly"
)

// canonical — каноническая запись фильтра встроенного правила.
func canonical(filter string) string {
	f, err := events.ParseFilter(filter)
	if err != nil {
		panic("alerting: неверный фильтр встроенного правила: " + err.Error())
	}
	return f.String()
}

// builtinRules — встроенные правила этапа 3: задача 3.10, «частота»,
// «аномалия» и «бюджет» задачи 3.12 (periodicRules), системные правила и
// правила безопасности DM-38–DM-44 задачи 3.11 (securityRules) и правила с
// признаком «инцидент» задачи 3.16 (incidentRules).
func builtinRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return append([]Rule{
		{BuiltinKey: BuiltinInjectionBlocked, Kind: KindThreshold, Name: "Промпт-инъекция заблокирована",
			Description: "DM-01: политика заблокировала запрос с инъекцией или джейлбрейком (в режиме monitor — заблокировала бы). " +
				"Одно оповещение на приложение, пока оно не закрыто.",
			Enabled: true, Severity: "high", Condition: Condition{Filter: canonical(`threat = "DM-01" and action = "block"`)},
			GroupBy: []string{"app"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinSessionRisk, Kind: KindThreshold, Name: "Эскалация атаки в сессии",
			Description: "DM-06: накопленная оценка находок сессии (session.risk) достигла порога правила политики — серия попыток " +
				"обхода защиты в одном диалоге. Одно оповещение на приложение, пока оно не закрыто.",
			Enabled: true, Severity: "high", Condition: Condition{Filter: canonical(`threat = "DM-06"`)},
			GroupBy: []string{"app"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinPromptIntegrity, Kind: KindThreshold, Name: "Системный промпт отличается от эталона",
			Description: "DM-26: системный промпт запроса не совпал с эталоном приложения или отсутствует (prompt.integrity). " +
				"Одно оповещение на приложение, пока оно не закрыто.",
			Enabled: true, Severity: "high", Condition: Condition{Filter: canonical(`threat = "DM-26"`)},
			GroupBy: []string{"app"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinHistoryIntegrity, Kind: KindThreshold, Name: "Подмена истории диалога",
			Description: "DM-03: в истории запроса — реплика ассистента, которой шлюз в этой сессии не выдавал (history.integrity, " +
				"проверка на сервере после ответа). Одно оповещение на приложение, пока оно не закрыто.",
			Enabled: true, Severity: "high", Condition: Condition{Filter: canonical(`threat = "DM-03"`)},
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
	}, slices.Concat(periodicRules(), securityRules(), incidentRules())...)
}

// periodicRules — встроенные правила «частота», «аномалия» и «бюджет»
// задачи 3.12. Пороги обоснованы в ADR-0020, п. 14.
func periodicRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinProbingSeries, Kind: KindFrequency, Name: "Серия срабатываний от одного пользователя",
			Description: "DM-16: 10 и более событий серьёзности «средняя» и выше от одного пользователя приложения за 10 минут — " +
				"признак подбора обхода защиты. Без идентификатора пользователя ключ — приложение (его ключ).",
			Enabled: true, Severity: "high", Condition: Condition{MinSeverity: "medium", Count: 10, WindowMinutes: 10},
			GroupBy: []string{"app", "user"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinQuotaExceeded, Kind: KindFrequency, Name: "Серия отказов по квотам",
			Description: "DM-36: 20 и более запросов приложения за 10 минут отклонены квотами шлюза (quota_exceeded).",
			Enabled:     true, Severity: "medium",
			Condition: Condition{Filter: canonical(`threat = "DM-36" and action = "block"`), Count: 20, WindowMinutes: 10},
			GroupBy:   []string{"app"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinActivitySpike, Kind: KindAnomaly, Name: "Резкий рост запросов приложения",
			Description: "DM-36: запросов приложения за последний час втрое больше медианы того же часа недели за прошлые недели " +
				"и не меньше 100. Первые 14 суток данных приложения — обучение, правило по нему молчит.",
			Enabled: true, Severity: "medium",
			Condition: Condition{Metric: MetricRequests, Factor: DefaultAnomalyFactor, MinVolume: metricMinVolume[MetricRequests]},
			GroupBy:   []string{"app"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinExtractionVolume, Kind: KindAnomaly, Name: "Аномальный объём ответов модели",
			Description: "DM-17: токенов ответов модели за последний час втрое больше медианы того же часа недели и не меньше 100 000 — " +
				"возможное массовое извлечение знаний модели (дистилляция). Первые 14 суток данных — обучение.",
			Enabled: true, Severity: "high",
			Condition: Condition{Metric: MetricCompletionTokens, Factor: DefaultAnomalyFactor,
				MinVolume: metricMinVolume[MetricCompletionTokens]},
			GroupBy: []string{"app"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinBudget, Kind: KindBudget, Name: "Расход бюджета приложения",
			Description: "DM-15: израсходовано 80 % и 100 % месячного бюджета приложения (мягкого и жёсткого). " +
				"Одно оповещение на порог в месяц; месяц — в часовом поясе установки.",
			Enabled: true, Severity: "high", Condition: Condition{WarnPercent: DefaultWarnPercent}, GroupBy: []string{"app"},
			SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
	}
}
