package events

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Типы событий (ТЗ, 5.5).
const (
	TypeGatewayRequest = "gateway_request" // обработка запроса шлюзом
	TypeCheck          = "check"           // проверка через Check API
	TypeAuthFailure    = "auth_failure"    // неудачная аутентификация на шлюзе (DM-38)
	// TypeAgentToolCall и TypeAgentMCP — события агентов (agent.go).
)

// Режимы хранения содержимого (ТЗ, 5.5). Содержимое full хранится только на
// сервере и только зашифрованным (ЗИ.1, задача 2.15); шлюз без сервера
// (приёмник JSONL) режим full не принимает.
const (
	StorageNone   = "none"
	StorageMasked = "masked"
	StorageFull   = "full"
)

// Режимы политики.
const (
	ModeMonitor = "monitor"
	ModeEnforce = "enforce"
)

// Finding — находка детектора без исходных чувствительных значений.
type Finding struct {
	Detector string  `json:"detector"`
	Version  string  `json:"version"`
	Category string  `json:"category"`
	Score    float64 `json:"score"`
	Start    int     `json:"start"`
	End      int     `json:"end"`
	// Location — где найдено: сообщение запроса, ответ, аргументы tool_calls.
	Location string `json:"location"`
	// Threat — ID строки матрицы обнаружения (DM-NN).
	Threat string `json:"threat"`
	Rule   string `json:"rule,omitempty"`
	// Fragment — хеш текста находки (HMAC на ключе шлюза, 32 hex): условие
	// исключения по фрагменту без самого текста (ТЗ 5.3, задача 3.22).
	Fragment string `json:"fragment,omitempty"`
	// Exception — ID исключения, по которому находка пропущена: в решении
	// она не участвовала.
	Exception string `json:"exception,omitempty"`
	// Source — источник текста находки: user, rag, tool, output. Черновик
	// исключения берёт его в условие (3В24 ревью 3.r3, ТЗ 5.3); у событий
	// прежних версий пусто.
	Source string `json:"source,omitempty"`
}

var (
	fragmentRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	exceptionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// TraceStep — шаг трассировки решения: какое правило и почему сработало
// (основа экрана «Почему принято решение», ТЗ, 4.3).
type TraceStep struct {
	Rule     string `json:"rule"`
	Detector string `json:"detector"`
	Matched  bool   `json:"matched"`
	Action   string `json:"action"`
	Note     string `json:"note,omitempty"`
}

// Decision — решение политики.
type Decision struct {
	// Action — итоговое действие по таблице приоритетов, как в режиме enforce.
	Action string `json:"action"`
	// Applied — действия, которые фактически применены (в monitor — только
	// защита данных для внешнего провайдера, ТЗ, 5.3).
	Applied []string    `json:"applied"`
	Trace   []TraceStep `json:"trace,omitempty"`
	// Policy и PolicyVersion — политика, по которой принято решение.
	Policy        string `json:"policy,omitempty"`
	PolicyVersion int    `json:"policy_version,omitempty"`
	// Rule — правило, давшее итог Action; служебные имена: non_text,
	// fail_closed, model_not_allowed, quota.<имя квоты>.
	Rule     string `json:"rule,omitempty"`
	Severity string `json:"severity,omitempty"`
	// FailMode — режим приложения при сбое проверки (ТЗ, 4.4); Failures —
	// детекторы, которые не дали результата.
	FailMode string            `json:"fail_mode,omitempty"`
	Failures []DetectorFailure `json:"failures,omitempty"`
	// MLUnavailable — ML-детекторы политики не дали результата: aisec-ml
	// недоступен, перегружен или проверил не весь текст. Решение принято по
	// остальным детекторам (fail-open для ML, ADR-0024).
	MLUnavailable bool `json:"ml_unavailable,omitempty"`
}

// Причины сбоя детектора.
const (
	FailureTimeout = "timeout" // не уложился в срок
	FailureError   = "error"   // ошибка, паника или некорректная находка
)

// DetectorFailure — сбой детектора на фрагменте. Текст ошибки не пишется:
// в нём может оказаться фрагмент проверяемого текста.
type DetectorFailure struct {
	Detector string `json:"detector"`
	Location string `json:"location"`
	Reason   string `json:"reason"`
}

// Tokens — расход токенов.
type Tokens struct {
	Prompt     int `json:"prompt"`
	Completion int `json:"completion"`
}

// Content — содержимое по режиму хранения: в masked ПДн и секреты заменены.
type Content struct {
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
}

// Режимы проверки ответа модели (ТЗ, 5.1).
const (
	ResponseBuffered    = "buffered"
	ResponseIncremental = "incremental"
	ResponseMonitor     = "monitor"
)

// Response — проверка ответа модели (ТЗ, 4.3, шаг 7). Находки ответа — в
// Event.Findings (место — choices[0].…), категории угроз — в Event.Threats.
type Response struct {
	// Mode — как проверялся ответ: buffered (в том числе ответ без потока),
	// incremental или monitor (проверка после передачи, только журнал).
	Mode     string    `json:"mode"`
	Decision *Decision `json:"decision,omitempty"`
	// Cut — поток ответа оборван политикой или сбоем проверки (incremental).
	Cut bool `json:"cut,omitempty"`
}

// Pseudonyms — счётчики псевдонимизации запроса и обратной подстановки
// (ТЗ, 5.1). Значений и псевдонимов не содержит.
type Pseudonyms struct {
	Issued        int `json:"issued"`
	Pseudonymized int `json:"pseudonymized"`
	Redacted      int `json:"redacted"`
	Fallback      int `json:"fallback,omitempty"`
	Restored      int `json:"restored"`
	// Failed — неудачные подстановки: сумма Unknown, Mangled, Unsafe, Limited.
	Failed  int `json:"failed"`
	Unknown int `json:"unknown,omitempty"`
	Mangled int `json:"mangled,omitempty"`
	Unsafe  int `json:"unsafe,omitempty"`
	Limited int `json:"limited,omitempty"`
	// Withheld — тексты ответа, в которых подстановка отменена: после неё
	// output.exfil нашёл новую ссылку (значение осталось замаскированным).
	Withheld int `json:"withheld,omitempty"`
}

// AuthFailure — подробности неудачной аутентификации. Сам ключ не пишется.
type AuthFailure struct {
	RemoteAddr string `json:"remote_addr"`
	KeyPrefix  string `json:"key_prefix,omitempty"`
	Reason     string `json:"reason"`
}

// Event — запись об обработанном запросе или проверке (ТЗ, 5.5).
type Event struct {
	ID               string           `json:"id"`
	Time             time.Time        `json:"time"`
	Type             string           `json:"type"`
	App              string           `json:"app,omitempty"`
	Env              string           `json:"env,omitempty"`
	User             string           `json:"user,omitempty"` // псевдоним (HMAC), не исходный идентификатор
	Provider         string           `json:"provider,omitempty"`
	Model            string           `json:"model,omitempty"`
	Source           string           `json:"source,omitempty"` // для Check API: user, rag, tool, output
	PolicyMode       string           `json:"policy_mode,omitempty"`
	Decision         *Decision        `json:"decision,omitempty"`
	Findings         []Finding        `json:"findings,omitempty"`
	Threats          []string         `json:"threats,omitempty"`
	LatencyMS        map[string]int64 `json:"latency_ms,omitempty"`
	Tokens           *Tokens          `json:"tokens,omitempty"`
	Stream           bool             `json:"stream,omitempty"`
	NonTextUnchecked bool             `json:"non_text_unchecked,omitempty"`
	Storage          string           `json:"storage,omitempty"`
	Content          *Content         `json:"content,omitempty"`
	Response         *Response        `json:"response,omitempty"`
	Pseudonyms       *Pseudonyms      `json:"pseudonyms,omitempty"`
	AuthFailure      *AuthFailure     `json:"auth_failure,omitempty"`
	// Session — сессия запроса чата (задачи 4.13, 4.14 этапа 4).
	Session *Session `json:"session,omitempty"`
	// Agent — событие агента: вызов инструмента или метод MCP (задача 4.11).
	Agent *Agent `json:"agent,omitempty"`
}

var threatRe = regexp.MustCompile(`^DM-\d{2}$`)

// Validate проверяет согласованность события перед отправкой: обязательные
// поля по типу, режим хранения и отсутствие содержимого там, где его быть
// не должно.
func (e *Event) Validate() error {
	var errs []error
	if e.ID == "" || e.Time.IsZero() {
		errs = append(errs, errors.New("нет ID или времени"))
	}
	switch e.Type {
	case TypeGatewayRequest, TypeCheck:
		if e.App == "" || e.Decision == nil || e.Decision.Action == "" {
			errs = append(errs, fmt.Errorf("%s: нужны приложение и решение", e.Type))
		}
		if e.Decision != nil {
			for _, f := range e.Decision.Failures {
				if f.Reason != FailureTimeout && f.Reason != FailureError {
					errs = append(errs, fmt.Errorf("сбой детектора %s: неизвестная причина %q", f.Detector, f.Reason))
				}
			}
		}
		if r := e.Response; r != nil {
			if r.Mode != ResponseBuffered && r.Mode != ResponseIncremental && r.Mode != ResponseMonitor {
				errs = append(errs, fmt.Errorf("неизвестный режим проверки ответа %q", r.Mode))
			}
			if r.Decision != nil {
				if r.Decision.Action == "" {
					errs = append(errs, errors.New("решение по ответу без действия"))
				}
				for _, f := range r.Decision.Failures {
					if f.Reason != FailureTimeout && f.Reason != FailureError {
						errs = append(errs, fmt.Errorf("сбой детектора %s на ответе: неизвестная причина %q", f.Detector, f.Reason))
					}
				}
			}
		}
		if e.PolicyMode != ModeMonitor && e.PolicyMode != ModeEnforce {
			errs = append(errs, fmt.Errorf("%s: неизвестный режим политики %q", e.Type, e.PolicyMode))
		}
		if e.Agent != nil {
			errs = append(errs, fmt.Errorf("%s: раздел agent — только у событий агентов", e.Type))
		}
		if e.Session != nil {
			if e.Type != TypeGatewayRequest {
				errs = append(errs, fmt.Errorf("%s: сессия бывает только у запроса чата", e.Type))
			}
			// Хеши сессии сервер пишет в session_history по ID приложения:
			// неверный ID не должен доходить до ограничения СУБД (повтор
			// пакета шлюзом без конца).
			if !exceptionRe.MatchString(e.App) {
				errs = append(errs, fmt.Errorf("%s: у события с сессией ID приложения — строчные латинские буквы, цифры и «-», до 63 символов", e.Type))
			}
			errs = append(errs, e.Session.validate()...)
		}
	case TypeAgentToolCall, TypeAgentMCP:
		errs = append(errs, e.validateAgent()...)
		if r := e.Response; r != nil {
			errs = append(errs, fmt.Errorf("%s: проверка ответа модели бывает только у запроса чата", e.Type))
		}
	case TypeAuthFailure:
		if e.AuthFailure == nil || e.AuthFailure.Reason == "" {
			errs = append(errs, errors.New("auth_failure: нужна причина"))
		}
		if e.Content != nil {
			errs = append(errs, errors.New("auth_failure: событие не содержит содержимого запроса"))
		}
		if e.Session != nil {
			errs = append(errs, errors.New("auth_failure: у события нет сессии"))
		}
		if e.Agent != nil {
			errs = append(errs, errors.New("auth_failure: у события нет раздела agent"))
		}
		// Столбец policy_mode принимает только monitor и enforce: чужое значение
		// не должно доходить до СУБД (В10 ревью 2.r3a).
		if e.PolicyMode != "" && e.PolicyMode != ModeMonitor && e.PolicyMode != ModeEnforce {
			errs = append(errs, fmt.Errorf("auth_failure: неизвестный режим политики %q", e.PolicyMode))
		}
	default:
		errs = append(errs, fmt.Errorf("неизвестный тип события %q", e.Type))
	}
	switch e.Storage {
	case "", StorageNone:
		if e.Content != nil {
			errs = append(errs, errors.New("режим хранения none: содержимое не сохраняется"))
		}
	case StorageMasked, StorageFull:
	default:
		errs = append(errs, fmt.Errorf("неизвестный режим хранения %q", e.Storage))
	}
	for _, t := range e.Threats {
		if !threatRe.MatchString(t) {
			errs = append(errs, fmt.Errorf("категория угрозы %q — не ID строки матрицы", t))
		}
	}
	for _, f := range e.Findings {
		if f.Threat != "" && !threatRe.MatchString(f.Threat) {
			errs = append(errs, fmt.Errorf("находка %s: категория %q — не ID строки матрицы", f.Detector, f.Threat))
		}
		if f.Fragment != "" && !fragmentRe.MatchString(f.Fragment) {
			errs = append(errs, fmt.Errorf("находка %s: fragment — 32 шестнадцатеричные цифры", f.Detector))
		}
		if f.Exception != "" && !exceptionRe.MatchString(f.Exception) {
			errs = append(errs, fmt.Errorf("находка %s: exception — ID исключения", f.Detector))
		}
		switch f.Source {
		case "", "user", "rag", "tool", "tool_args", "output":
		default:
			errs = append(errs, fmt.Errorf("находка %s: source — user, rag, tool, tool_args или output", f.Detector))
		}
	}
	return errors.Join(errs...)
}
