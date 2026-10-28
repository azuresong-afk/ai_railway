package alerting

// Встроенное правило по признаку ml_unavailable (задача 4.19 этапа 4,
// ADR-0024, раздел 4): ML-детекторы политики не дали результата — aisec-ml
// остановлен, перегружен, нарушена его целостность или нет пакета моделей.
// Трафик при этом идёт (fail-open для ML), решение принимают эвристики;
// правило делает пропуск ML-проверки видимым.
const (
	// BuiltinMLUnavailable — всплеск событий с ml_unavailable на одном
	// шлюзе. Вид «частота»: одиночный пропуск (срок вывода, перегрузка
	// на секунду) — не повод для оповещения, серия — отказ aisec-ml.
	BuiltinMLUnavailable = "frequency.ml_unavailable"
	// MLUnavailableCount и MLUnavailableWindow — порог правила.
	MLUnavailableCount  = 20
	MLUnavailableWindow = 10
)

// mlRules — встроенное правило задачи 4.19.
func mlRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinMLUnavailable, Kind: KindFrequency, Name: "Проверки без ML-детекторов",
			Description: "DM-01, DM-18: 20 и более событий шлюза за 10 минут с признаком ml_unavailable — ML-детекторы политики " +
				"не дали результата (процесс aisec-ml остановлен, перегружен, не прошёл проверку целостности или пакета моделей). " +
				"Запросы проходят, решение принимают остальные детекторы.",
			Enabled: true, Severity: "medium",
			Condition: Condition{Filter: canonical(`ml_unavailable = true`), Count: MLUnavailableCount, WindowMinutes: MLUnavailableWindow},
			GroupBy:   []string{"gateway"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
	}
}
