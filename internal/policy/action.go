package policy

// Action — действие правила (ТЗ, 5.3).
type Action string

// Действия. require_approval — этап 4: в политиках этапа 1 отвергается.
const (
	Allow           Action = "allow"
	Log             Action = "log"
	Redact          Action = "redact"       // необратимое маскирование
	Pseudonymize    Action = "pseudonymize" // обратимое: псевдоним и обратная подстановка
	RequireApproval Action = "require_approval"
	Block           Action = "block"
)

// priority — таблица приоритетов (ТЗ, 5.3): чем больше, тем сильнее.
// block > require_approval > redact > pseudonymize > log > allow.
// Таблица зафиксирована в docs/cert/security-functions.md и тесте
// TestPriorityTable; менять её можно только вместе с ними.
var priority = map[Action]int{
	Allow:           1,
	Log:             2,
	Pseudonymize:    3,
	Redact:          4,
	RequireApproval: 5,
	Block:           6,
}

// Priority — место действия в таблице приоритетов; 0 — неизвестное действие.
func Priority(a Action) int { return priority[a] }

// Stronger — a сильнее b по таблице приоритетов.
func Stronger(a, b Action) bool { return priority[a] > priority[b] }

// protects — действие защищает данные: выполняется над запросом к внешнему
// провайдеру и в режиме monitor (ТЗ, 5.3).
func protects(a Action) bool { return a == Redact || a == Pseudonymize }

// supported — действия, доступные на этапе 1.
func supported(a Action) bool { return priority[a] > 0 && a != RequireApproval }

// Mode — режим политики.
type Mode string

// Режимы.
const (
	// Monitor вычисляет решение, но применяет только защиту данных в запросе
	// к внешнему провайдеру.
	Monitor Mode = "monitor"
	// Enforce применяет решение целиком.
	Enforce Mode = "enforce"
)

// Severity — серьёзность находки по правилу (шкала ТЗ, 6.2).
type Severity string

// Уровни серьёзности по возрастанию.
const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

var severityRank = map[Severity]int{Info: 1, Low: 2, Medium: 3, High: 4, Critical: 5}

// NonText — обработка нетекстовых частей запроса (ТЗ, 5.1 и 5.3; DM-14).
type NonText string

// Значения non_text.
const (
	// NonTextAllowUnchecked — пропустить с отметкой в событии «содержит
	// непроверенные части» (по умолчанию).
	NonTextAllowUnchecked NonText = "allow_unchecked"
	// NonTextAllowInline — пропустить с отметкой только данные в самом
	// запросе (base64), а ссылки на медиа блокировать: ссылку загружает
	// провайдер, и через неё можно обратиться к внутренним адресам его
	// контура (docs/cert/threat-model.md, SSRF руками провайдера).
	NonTextAllowInline NonText = "allow_inline"
	// NonTextBlock — блокировать запрос с нетекстовыми частями.
	NonTextBlock NonText = "block"
)

// ResponseCheck — проверка ответа при потоковой передаче (ТЗ, 5.1).
// Выполняется в задаче 1.23; здесь — только параметр политики.
type ResponseCheck string

// Режимы проверки ответа.
const (
	ResponseBuffered    ResponseCheck = "buffered"
	ResponseIncremental ResponseCheck = "incremental" // по умолчанию (решение Р7)
	ResponseMonitor     ResponseCheck = "monitor"
)

// Endpoint — интерфейс шлюза, для которого вычисляется решение.
type Endpoint string

// Интерфейсы.
const (
	EndpointChat Endpoint = "chat"
	// EndpointEmbeddings — /v1/embeddings: из вектора псевдоним не
	// восстановить, поэтому pseudonymize выполняется как redact (ТЗ, 5.1).
	EndpointEmbeddings Endpoint = "embeddings"
	EndpointCheck      Endpoint = "check"
)
