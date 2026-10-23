package incidents

import (
	"regexp"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Category — категория инцидента (ТЗ 5.7, по разделу угроз ИИ БДУ ФСТЭК).
// Rows — строки матрицы обнаружения (ТЗ 5.16), из которых она выводится;
// то же соответствие — в последней колонке docs/taxonomy.md.
type Category struct {
	ID    string
	Title string
	Rows  []string
	// Instructions — инструкция реагирования по умолчанию; администратор
	// безопасности заменяет её своей (версия 2 и дальше).
	Instructions string
}

// Ключи категорий.
const (
	CategoryPromptInjection  = "prompt_injection"
	CategoryPIILeak          = "pii_leak"
	CategorySystemPromptLeak = "system_prompt_leak"
	CategoryQuotaAbuse       = "quota_abuse"
	CategoryAnomaly          = "anomalous_activity"
	CategoryAgentViolation   = "agent_policy_violation"
	CategoryModelCompromise  = "model_compromise"
	CategoryPlatformAccess   = "platform_access"
	CategoryOther            = "other"
)

var categories = []Category{
	{ID: CategoryPromptInjection, Title: "Промпт-инъекция (прямая или косвенная)",
		Rows: []string{"DM-01", "DM-02", "DM-03", "DM-04", "DM-05", "DM-06", "DM-07", "DM-14", "DM-16", "DM-24", "DM-45", "DM-47", "DM-48"},
		Instructions: "1. Откройте связанные события и блок «Почему принято решение»: какие детекторы сработали и в каком режиме политика.\n" +
			"2. Определите источник: пользователь, документ RAG, ответ инструмента. Для серии попыток проверьте ключ и псевдоним пользователя.\n" +
			"3. Если запрос не был заблокирован (режим мониторинга), оцените, что модель ответила, — содержимое открывается с указанием причины.\n" +
			"4. Локализация: включите блокировку для приложения или правила, при серии — отзовите ключ приложения.\n" +
			"5. Ложное срабатывание — закройте с резолюцией «ложное срабатывание» и создайте исключение со сроком."},
	{ID: CategoryPIILeak, Title: "Утечка ПДн",
		Rows: []string{"DM-09", "DM-10", "DM-11", "DM-13", "DM-31", "DM-32", "DM-46", "DM-49"},
		Instructions: "1. По событиям определите типы данных (ПДн, секреты), приложение и направление: запрос к провайдеру или ответ модели.\n" +
			"2. Проверьте, были ли данные замаскированы или псевдонимизированы до отправки провайдеру.\n" +
			"3. Если данные ушли внешнему провайдеру, сообщите ответственному за обработку ПДн: возможно, нужно уведомление Роскомнадзора (152-ФЗ, ст. 21).\n" +
			"4. Локализация: включите маскирование или блокировку для типа данных, при утечке секрета — смените его.\n" +
			"5. Утечки секретов и коммерческой тайны разбираются в этой же категории."},
	{ID: CategorySystemPromptLeak, Title: "Утечка системного промпта",
		Rows: []string{"DM-08"},
		Instructions: "1. Канарейка системного промпта найдена в ответе модели: значит, модель раскрыла инструкции приложения.\n" +
			"2. По связанным событиям найдите запрос, который привёл к раскрытию, и пользователя (псевдоним).\n" +
			"3. Проверьте, был ли ответ заблокирован. В режиме мониторинга ответ ушёл пользователю — считайте промпт раскрытым.\n" +
			"4. Локализация: включите блокировку ответа с канарейкой, при раскрытии — смените канарейку и секреты в системном промпте.\n" +
			"5. Сообщите владельцу приложения: системный промпт не должен содержать секретов и внутренних адресов."},
	{ID: CategoryQuotaAbuse, Title: "Злоупотребление квотами",
		Rows: []string{"DM-15", "DM-36", "DM-50"},
		Instructions: "1. Определите приложение, ключ и пользователя с ростом расхода.\n" +
			"2. Сравните расход с бюджетом и базовой линией на дашборде «Потребление».\n" +
			"3. Локализация: включите жёсткий бюджет или квоту, при подозрении на кражу — отзовите ключ приложения.\n" +
			"4. Сообщите владельцу приложения."},
	{ID: CategoryAnomaly, Title: "Аномальная активность",
		Rows: []string{"DM-17", "DM-34", "DM-37"},
		Instructions: "1. Определите, что изменилось: новый пользователь, модель, провайдер или объём запросов.\n" +
			"2. Подтвердите у владельца приложения, ожидаемо ли изменение.\n" +
			"3. Неожиданное — ограничьте квотой или отзовите ключ; ожидаемое — закройте с резолюцией «риск принят»."},
	{ID: CategoryAgentViolation, Title: "Нарушение политики агентом",
		Rows: []string{"DM-20", "DM-21", "DM-22", "DM-23", "DM-25"},
		Instructions: "1. По событиям определите агента, инструмент и аргументы вызова.\n" +
			"2. Проверьте, был ли вызов выполнен или остановлен политикой.\n" +
			"3. Локализация: запретите инструмент или ужесточите ограничения аргументов, при выполненном опасном действии — сообщите владельцу системы."},
	{ID: CategoryModelCompromise, Title: "Компрометация модели или RAG",
		Rows: []string{"DM-26", "DM-27", "DM-28", "DM-29", "DM-30"},
		Instructions: "1. Определите затронутую модель, расширение или базу RAG и время изменения.\n" +
			"2. Локализация: выведите модель или базу из работы, верните проверенную версию по реестру хешей.\n" +
			"3. Соберите сведения для расследования: кто и когда загрузил изменённый файл."},
	{ID: CategoryPlatformAccess, Title: "Несанкционированный доступ к платформе и ослабление защиты",
		Rows: []string{"DM-38", "DM-39", "DM-40", "DM-41", "DM-42", "DM-43", "DM-44"},
		Instructions: "1. Откройте журнал аудита за период: кто, откуда и что сделал.\n" +
			"2. Проверьте, подтверждает ли владелец учётной записи действие.\n" +
			"3. Локализация: завершите сессии и заблокируйте учётную запись, отзовите токены и ключи, верните ослабленные настройки.\n" +
			"4. При нарушении целостности или цепочки аудита — остановите компонент и проверьте его по руководству администратора."},
	{ID: CategoryOther, Title: "Прочее",
		Rows: []string{"DM-12", "DM-18", "DM-19", "DM-33", "DM-35"},
		Instructions: "1. Опишите, что произошло, и приложите ссылки на события.\n" +
			"2. Определите владельца приложения и согласуйте меры."},
}

var categoryIndex = func() map[string]Category {
	m := make(map[string]Category, len(categories))
	rows := map[string]bool{}
	for _, c := range categories {
		if _, dup := m[c.ID]; dup || !categoryKeyRe.MatchString(c.ID) {
			panic("incidents: неверная или повторная категория: " + c.ID)
		}
		for _, r := range c.Rows {
			if rows[r] {
				panic("incidents: строка матрицы в двух категориях: " + r)
			}
			rows[r] = true
		}
		m[c.ID] = c
	}
	return m
}()

var categoryKeyRe = regexp.MustCompile(`^[a-z][a-z_]{1,39}$`)

// Categories — справочник категорий в порядке ТЗ 5.7.
func Categories() []Category {
	out := make([]Category, len(categories))
	for i, c := range categories {
		out[i] = c
		out[i].Rows = slices.Clone(c.Rows)
	}
	return out
}

// LookupCategory — категория по ключу.
func LookupCategory(id string) (Category, bool) {
	c, ok := categoryIndex[id]
	return c, ok
}

// CategoryOfRow — категория строки матрицы обнаружения (DM-NN).
func CategoryOfRow(row string) string {
	for _, c := range categories {
		if slices.Contains(c.Rows, row) {
			return c.ID
		}
	}
	return CategoryOther
}

// CategoryOfAlert — категория инцидента по оповещению: автоматическая
// категория встроенного правила; строка матрицы из условия правила
// («threat = …»); правила безопасности и системные — доступ к платформе;
// иначе «прочее».
func CategoryOfAlert(r alerting.Rule) string {
	if c, ok := alerting.AutoIncidentCategory(r.BuiltinKey); ok {
		return c
	}
	if r.Condition.Filter != "" {
		if f, err := events.ParseFilter(r.Condition.Filter); err == nil {
			for _, c := range f.Conds {
				if c.Field == "threat" && (c.Op == events.OpEq || c.Op == events.OpIn) && len(c.Values) > 0 {
					return CategoryOfRow(c.Values[0])
				}
			}
		}
	}
	if alerting.Locked(r.Kind) {
		return CategoryPlatformAccess
	}
	return CategoryOther
}
