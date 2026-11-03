package alerting

// Встроенное правило по признаку media_unavailable (задача 5.44 этапа 5,
// DM-50; ADR-0032, раздел 8): изображения запросов не проверены из-за сбоя
// анализатора aisec-media — он остановлен, очередь заполнена тяжёлыми
// файлами, анализ не укладывается в срок или падает. Запросы обрабатываются
// по режиму при отказе (sync) или по non_text; правило делает перегрузку
// видимой — её цель как раз провести изображения непроверенными.
const (
	// BuiltinMediaUnavailable — серия событий с media_unavailable на одном
	// шлюзе. Вид «частота»: одиночный срок на тяжёлом изображении — не
	// повод для оповещения, серия — перегрузка или отказ анализатора.
	BuiltinMediaUnavailable = "frequency.media_unavailable"
	// MediaUnavailableCount и MediaUnavailableWindow — порог правила.
	MediaUnavailableCount  = 10
	MediaUnavailableWindow = 10
)

// mediaRules — встроенное правило задачи 5.44.
func mediaRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinMediaUnavailable, Kind: KindFrequency, Name: "Изображения без проверки: анализатор перегружен или недоступен",
			Description: "DM-50: 10 и более событий шлюза за 10 минут с признаком media_unavailable — изображения запросов не проверены " +
				"из-за сбоя анализатора aisec-media (остановлен, очередь заполнена, анализ не уложился в срок или завершился ошибкой). " +
				"Перегрузку анализатора тяжёлыми файлами используют, чтобы изображения прошли непроверенными: в режиме sync запросы " +
				"обрабатываются по режиму приложения при отказе, в async и off — по non_text.",
			Enabled: true, Severity: "high",
			Condition: Condition{Filter: canonical(`media_unavailable = true`), Count: MediaUnavailableCount, WindowMinutes: MediaUnavailableWindow},
			GroupBy:   []string{"gateway"}, SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
	}
}
