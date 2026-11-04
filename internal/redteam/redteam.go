// Пакет redteam — тестирование устойчивости (ТЗ 5.13; задача 5.32 этапа 5,
// ADR-0031): цели, запуск сценариев атак из служебной базы, оценка ответов
// и хранение результатов.
//
// Исполнитель работает в процессе сервера. Цель — приложение продукта
// (запросы через шлюз с ключом запуска; события помечаются test и не
// поднимают оповещений) или точный адрес приложения заказчика, добавленный
// администратором безопасности. Соединение с адресом цели — только если
// все адреса имени разрешены правилом internal/netguard, при каждом
// соединении; перенаправления и прокси не используются. Ответы оцениваются
// встроенными детекторами, канарейкой и judge.llm; в БД — вердикты без
// промптов и ответов (ТЗ 5.5). Пакет — в NET_CLIENT_ALLOWED.
package redteam

import (
	"errors"
	"time"
)

// Виды целей.
const (
	KindGateway  = "gateway"
	KindEndpoint = "endpoint"
)

// Режимы хранения примеров (ADR-0031, раздел 7).
const (
	StorageNone   = "none"
	StorageMasked = "masked"
)

// Состояния запуска.
const (
	RunQueued    = "queued"
	RunRunning   = "running"
	RunDone      = "done"
	RunFailed    = "failed"
	RunCancelled = "cancelled"
)

// Причины неуспешного запуска.
const (
	ReasonInterrupted     = "interrupted"
	ReasonDeadline        = "deadline"
	ReasonKeyNotDelivered = "key_not_delivered"
	ReasonNoScenarios     = "no_scenarios"
	ReasonInternal        = "internal"
)

// Итоги сценария (ADR-0031, раздел 6).
const (
	VerdictBlocked   = "blocked"
	VerdictSucceeded = "succeeded"
	VerdictDefended  = "defended"
	VerdictUnchecked = "unchecked"
	VerdictError     = "error"
	VerdictSkipped   = "skipped"
)

// Verdicts — все итоги (порядок счётчиков запуска).
var Verdicts = []string{VerdictSucceeded, VerdictBlocked, VerdictDefended, VerdictUnchecked, VerdictError, VerdictSkipped}

// Коды ошибок шага.
const (
	ErrCodeBlockedAddr = "blocked_address"
	ErrCodeDial        = "dial"
	ErrCodeTimeout     = "timeout"
	ErrCodeRedirect    = "redirect"
	ErrCodeHTTP        = "http_status"
	ErrCodeTooLarge    = "too_large"
	ErrCodeBadResponse = "bad_response"
	ErrCodeRequest     = "request"
)

// Пределы целей и запусков (ADR-0031, раздел 4).
const (
	MinRate, MaxRate, DefaultRate                      = 1, 600, 30
	MinConcurrency, MaxConcurrency, DefaultConcurrency = 1, 8, 2
	MinRequestTimeout, MaxRequestTimeout               = 5, 120
	DefaultRequestTimeout                              = 30
	MinRunTimeout, MaxRunTimeout, DefaultRunTimeout    = 1, 120, 30

	// MaxResponse — ответ цели, байты.
	MaxResponse = 1 << 20
	// MaxRequestBody — тело запроса к цели, байты.
	MaxRequestBody = 256 << 10
	// MaxRunScenarios — сценариев в запуске.
	MaxRunScenarios = 1000
	// MaxParallelRuns — запусков одновременно на сервере.
	MaxParallelRuns = 2
	// MaxTargets — целей в организации.
	MaxTargets = 100
	// MaxExample — выдержка ответа в режиме masked, байты.
	MaxExample = 1 << 10
)

// Ошибки.
var (
	ErrNotFound = errors.New("не найдено")
	// ErrBusy — у цели уже идёт запуск или достигнут предел запусков.
	ErrBusy = errors.New("запуск невозможен: у цели уже идёт запуск или сервер выполняет наибольшее число запусков")
	// ErrNotRunning — запуск уже завершён.
	ErrNotRunning = errors.New("запуск уже завершён")
	// ErrNoScenarios — база сценариев не загружена или фильтр ничего не выбрал.
	ErrNoScenarios = errors.New("нет сценариев: база не загружена или под условия запуска не подходит ни один сценарий")
	// ErrGatewayNotConfigured — адрес шлюза для тестирования не задан.
	ErrGatewayNotConfigured = errors.New("адрес шлюза для тестирования не задан (флаг сервера -redteam-gateway-url)")
	// ErrConfirmRequired — нужна повторная проверка в сессии консоли.
	ErrConfirmRequired = errors.New("нужна повторная проверка паролем или кодом в сессии консоли")
	// ErrTooManyTargets — достигнут предел целей.
	ErrTooManyTargets = errors.New("достигнут предел числа целей")
)

// InputError — неверные данные; текст показывается пользователю.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

func invalid(errs ...error) error { return &InputError{Errs: errs} }

func invalidf(format string, args ...any) error {
	var l errList
	l.add(format, args...)
	return l.err()
}

// Limits — пределы цели.
type Limits struct {
	RatePerMinute     int `json:"rate_per_minute"`
	Concurrency       int `json:"concurrency"`
	RequestTimeoutSec int `json:"request_timeout_sec"`
	RunTimeoutMin     int `json:"run_timeout_min"`
}

// Header — постоянный заголовок цели endpoint (без секретов).
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Target — цель тестирования.
type Target struct {
	ID    string
	OrgID string
	Name  string
	Kind  string
	// AppID и Model — цель gateway: приложение продукта и модель.
	AppID string
	Model string
	// Цель endpoint: точный адрес, шаблон тела, путь к ответу, заголовки,
	// имя секретного заголовка (значение — только в запросе запуска),
	// корневой сертификат, основание для тестирования адреса.
	URL               string
	RequestTemplate   string
	ResponsePath      string
	Headers           []Header
	AuthHeader        string
	CAPEM             string
	AuthorizationNote string
	// Storage — режим хранения примеров (none, masked).
	Storage string
	// JudgeProvider и JudgeModel — оценщик judge.llm (slug провайдера с
	// признаком on_premise); пусто — без оценщика.
	JudgeProvider string
	JudgeModel    string
	Limits        Limits
	CreatedAt     time.Time
	CreatedBy     string
	UpdatedAt     time.Time
	UpdatedBy     string
}

// Counts — итоги сценариев запуска.
type Counts map[string]int

// Run — запуск.
type Run struct {
	ID         string
	OrgID      string
	TargetID   string
	TargetName string
	TargetKind string
	// AppID — приложение цели gateway (ключ запуска).
	AppID      string
	Status     string
	Reason     string
	Scenarios  int
	Counts     Counts
	DBVersion  uint64
	StartedAt  time.Time
	StartedBy  string
	FinishedAt *time.Time
	// Deadline — срок запуска; KeyPrefix и KeyHash — ключ запуска (цель
	// gateway), сам ключ — только в памяти исполнителя.
	Deadline  time.Time
	KeyPrefix string
	KeyHash   []byte
}

// Finding — находка детектора в ответе: без позиций и текста.
type Finding struct {
	Detector string `json:"detector"`
	Category string `json:"category"`
	Threat   string `json:"threat"`
}

// Result — итог сценария запуска.
type Result struct {
	RunID      string
	ScenarioID string
	Lang       string
	Threat     string
	Category   string
	Verdict    string
	// Step — шаг (с 1), на котором получен итог; 0 — ни одного.
	Step int
	// Matched — сработавшие условия успеха: canary, contains, findings,
	// judge.
	Matched  []string
	Findings []Finding
	// Judge — итог оценщика: violated, ok или причина «не проверено».
	Judge string
	// EventIDs — события шлюза (цель gateway).
	EventIDs   []string
	HTTPStatus int
	LatencyMS  int64
	ErrorCode  string
	// Example — выдержка ответа (только endpoint, masked, succeeded),
	// запечатанная ключом данных (5В3 ревью 5.r3); открытый текст — только
	// Service.Examples.
	Example *Sealed
}

// Sealed — шифротекст ключа данных (internal/keyring) с ID версии ключа и
// алгоритмом. AAD — место хранения: redteam_results|example|<запуск>/<сценарий>.
type Sealed struct {
	Data  []byte
	KeyID string
	Alg   string
}
