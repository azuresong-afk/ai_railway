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
)

// Режимы хранения содержимого (ТЗ, 5.5). Режим full на этапе 1 недоступен:
// нужно шифрование при хранении (ЗИ.1, этап 2).
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
}

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
	AuthFailure      *AuthFailure     `json:"auth_failure,omitempty"`
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
		if e.App == "" || e.Decision == nil {
			errs = append(errs, fmt.Errorf("%s: нужны приложение и решение", e.Type))
		}
		if e.PolicyMode != ModeMonitor && e.PolicyMode != ModeEnforce {
			errs = append(errs, fmt.Errorf("%s: неизвестный режим политики %q", e.Type, e.PolicyMode))
		}
	case TypeAuthFailure:
		if e.AuthFailure == nil || e.AuthFailure.Reason == "" {
			errs = append(errs, errors.New("auth_failure: нужна причина"))
		}
		if e.Content != nil {
			errs = append(errs, errors.New("auth_failure: событие не содержит содержимого запроса"))
		}
	default:
		errs = append(errs, fmt.Errorf("неизвестный тип события %q", e.Type))
	}
	switch e.Storage {
	case "", StorageNone:
		if e.Content != nil {
			errs = append(errs, errors.New("режим хранения none: содержимое не сохраняется"))
		}
	case StorageMasked:
	case StorageFull:
		errs = append(errs, errors.New("режим хранения full недоступен до шифрования при хранении (ЗИ.1, этап 2)"))
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
	}
	return errors.Join(errs...)
}
