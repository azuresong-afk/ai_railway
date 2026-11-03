package policy

import (
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

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

// SeverityAbove — серьёзность a выше b (неизвестная — ниже любой).
func SeverityAbove(a, b Severity) bool { return severityRank[a] > severityRank[b] }

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

// MediaCheck — проверка изображений запроса анализатором aisec-media (ТЗ,
// 5.3 и 5.17; ADR-0032, раздел 8).
type MediaCheck string

// Значения media_check.
const (
	// MediaCheckOff — изображения не анализируются, только non_text (как до
	// этапа 5; значение по умолчанию).
	MediaCheckOff MediaCheck = "off"
	// MediaCheckAsync — запрос уходит провайдеру сразу, изображения
	// проверяются в фоне: находки попадают в событие после отправки. Решение
	// по запросу принимается без итога анализа, изображения для non_text —
	// непроверенные.
	MediaCheckAsync MediaCheck = "async"
	// MediaCheckSync — запрос ждёт итога анализа до отправки провайдеру не
	// дольше media_check_timeout_ms; недоступность анализатора — по режиму
	// приложения при отказе (ТЗ, 4.4).
	MediaCheckSync MediaCheck = "sync"
)

// Срок анализа изображений в режиме sync (media_check_timeout_ms).
const (
	DefaultMediaTimeout = 2 * time.Second // цель p95 ТЗ 5.17 для 2 Мпикс с OCR
	MinMediaTimeoutMS   = 100
	// MaxMediaTimeoutMS — предел срока анализатора (-max-run-timeout по
	// умолчанию, ADR-0032, раздел 5).
	MaxMediaTimeoutMS = 10_000
)

// SourceImage — источник текста, извлечённого из изображения запроса
// (aisec-media, ТЗ 5.17, п. 5). Находку с этим источником нельзя
// замаскировать в самом изображении: защита данных redact и pseudonymize
// по ней выполняется блокировкой (решение Р9 этапа 5: закрашивания нет).
const SourceImage detect.Source = "image"

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
	// EndpointCheck — /guard/v1/check: ответа модели, в котором можно
	// подставить исходные значения, нет, поэтому pseudonymize тоже
	// выполняется как redact.
	EndpointCheck Endpoint = "check"
)
