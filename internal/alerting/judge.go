package alerting

// Встроенные правила judge.llm (ТЗ 5.2, DM-18 и DM-19 «LLM — 5»; задача
// 5.28 этапа 5, ADR-0030, раздел 7). Находка оценщика — нарушение правила
// политики на естественном языке; в режиме async (по умолчанию) она
// появляется после ответа приложению, и оповещение — главный способ о ней
// узнать. Признак judge_unchecked — оценка не получена: серия таких событий
// значит, что оценщик недоступен, перегружен, исчерпан его бюджет или текст
// отвергается как инъекция.
const (
	// BuiltinJudgeViolation — находка judge.llm.
	BuiltinJudgeViolation = "threshold.judge_violation"
	// BuiltinJudgeUnchecked — всплеск событий с judge_unchecked на шлюзе.
	BuiltinJudgeUnchecked = "frequency.judge_unchecked"
	// JudgeUncheckedCount и JudgeUncheckedWindow — порог правила.
	JudgeUncheckedCount  = 20
	JudgeUncheckedWindow = 10
)

// judgeRules — встроенные правила задачи 5.28.
func judgeRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinJudgeViolation, Kind: KindThreshold, Name: "Нарушение правила по оценке модели",
			Description: "DM-18, DM-19: модель-оценщик заказчика (judge.llm) нашла нарушение правила политики на естественном " +
				"языке — недопустимый контент или бизнес-правило (обещания, консультации). В режиме async запрос уже обработан: " +
				"оповещение — повод проверить диалог. Одно оповещение на приложение, пока оно не закрыто.",
			Enabled: true, Severity: "high", Condition: Condition{Filter: canonical(`detector = "judge.llm"`)},
			GroupBy: []string{"app"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
		{BuiltinKey: BuiltinJudgeUnchecked, Kind: KindFrequency, Name: "Проверки без модели-оценщика",
			Description: "DM-18, DM-19: 20 и более событий шлюза за 10 минут с признаком judge_unchecked — оценка judge.llm " +
				"не получена: оценщик недоступен или вне частной сети, перегружен, не уложился в срок, исчерпан бюджет политики, " +
				"ответ не по формату или текст отвергнут детекторами инъекций. Запросы обрабатываются по on_failure правил.",
			Enabled: true, Severity: "medium",
			Condition: Condition{Filter: canonical(`judge_unchecked = true`), Count: JudgeUncheckedCount, WindowMinutes: JudgeUncheckedWindow},
			GroupBy:   []string{"gateway"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
	}
}
