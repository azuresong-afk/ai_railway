package events

import (
	"fmt"
	"slices"
)

// Оценка judge.llm (ТЗ 5.2, ADR-0030, раздел 7; задача 5.28): по оценке на
// направление и режим — получены ли вердикты и почему нет. Текста запроса,
// критериев и ответа оценщика здесь нет: нарушения — в Findings (детектор
// judge.llm, DM-18 или DM-19), содержимое — только по режиму хранения.

// MaxJudge — предел записей об оценке в событии (вход и выход, async и sync).
const MaxJudge = 4

// Направления и режимы оценки.
const (
	JudgeModeAsync = "async"
	JudgeModeSync  = "sync"
)

// Причины, по которым оценка не получена (JudgeCheck.Reason).
const (
	JudgeReasonUnavailable = "unavailable" // нет провайдера «у заказчика», отказ соединения, адрес вне частной сети
	JudgeReasonTimeout     = "timeout"
	JudgeReasonOverloaded  = "overloaded"
	JudgeReasonBudget      = "budget"
	JudgeReasonInjection   = "injection" // текст отвергнут детекторами инъекций до отправки
	JudgeReasonTooLarge    = "too_large"
	JudgeReasonBadResponse = "bad_response" // ответ не строгий JSON judge-prompt/1
	JudgeReasonError       = "error"
)

// JudgeReasons — все причины.
var JudgeReasons = []string{JudgeReasonUnavailable, JudgeReasonTimeout, JudgeReasonOverloaded, JudgeReasonBudget,
	JudgeReasonInjection, JudgeReasonTooLarge, JudgeReasonBadResponse, JudgeReasonError}

// JudgeCheck — итог одной оценки.
type JudgeCheck struct {
	// Direction — input или output; Mode — async или sync.
	Direction string `json:"direction"`
	Mode      string `json:"mode"`
	Checked   bool   `json:"checked"`
	Reason    string `json:"reason,omitempty"`
	Cached    bool   `json:"cached,omitempty"`
	// Rules — правил judge.llm в оценке.
	Rules     int   `json:"rules"`
	LatencyMS int64 `json:"latency_ms,omitempty"`
	// Tokens — расход оценщика (prompt + completion).
	Tokens int `json:"tokens,omitempty"`
}

func (j *JudgeCheck) validate(i int) []error {
	var errs []error
	if j.Direction != "input" && j.Direction != "output" {
		errs = append(errs, fmt.Errorf("judge[%d]: направление — input или output", i))
	}
	if j.Mode != JudgeModeAsync && j.Mode != JudgeModeSync {
		errs = append(errs, fmt.Errorf("judge[%d]: режим — async или sync", i))
	}
	switch {
	case j.Checked && j.Reason != "":
		errs = append(errs, fmt.Errorf("judge[%d]: у полученной оценки нет причины", i))
	case !j.Checked && !slices.Contains(JudgeReasons, j.Reason):
		errs = append(errs, fmt.Errorf("judge[%d]: неизвестная причина %q", i, j.Reason))
	}
	if j.Rules < 1 || j.Rules > 16 || j.LatencyMS < 0 || j.Tokens < 0 {
		errs = append(errs, fmt.Errorf("judge[%d]: правил — от 1 до 16, задержка и расход — неотрицательные", i))
	}
	return errs
}

// validateJudge — записи об оценке и признак judge_unchecked.
func (e *Event) validateJudge() []error {
	var errs []error
	if len(e.Judge) > 0 && e.Type != TypeGatewayRequest {
		errs = append(errs, fmt.Errorf("%s: оценка judge.llm бывает только у запроса чата", e.Type))
	}
	if len(e.Judge) > MaxJudge {
		errs = append(errs, fmt.Errorf("judge: не больше %d записей", MaxJudge))
	}
	unchecked := false
	for i := range e.Judge {
		errs = append(errs, e.Judge[i].validate(i)...)
		unchecked = unchecked || !e.Judge[i].Checked
	}
	if d := e.Decision; d != nil && d.JudgeUnchecked != unchecked {
		errs = append(errs, fmt.Errorf("%s: judge_unchecked не совпадает с записями об оценке", e.Type))
	}
	return errs
}
