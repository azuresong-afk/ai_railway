package events

import (
	"encoding/json"
	"strings"
	"testing"
)

// Оценка judge.llm в событии (задача 5.28, ADR-0030, раздел 7).

func withJudge() *Event {
	e := request()
	e.Judge = []JudgeCheck{
		{Direction: "input", Mode: JudgeModeSync, Checked: true, Rules: 2, LatencyMS: 300, Tokens: 150},
		{Direction: "output", Mode: JudgeModeAsync, Reason: JudgeReasonTimeout, Rules: 1},
	}
	e.Decision.JudgeUnchecked = true
	return e
}

func TestValidateJudge(t *testing.T) {
	if err := withJudge().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Event){
		"тип события":          func(e *Event) { e.Type = TypeCheck },
		"направление":          func(e *Event) { e.Judge[0].Direction = "both" },
		"режим":                func(e *Event) { e.Judge[0].Mode = "later" },
		"получено с причиной":  func(e *Event) { e.Judge[0].Reason = JudgeReasonBudget },
		"неизвестная причина":  func(e *Event) { e.Judge[1].Reason = "other" },
		"без причины":          func(e *Event) { e.Judge[1].Reason = "" },
		"правил 0":             func(e *Event) { e.Judge[0].Rules = 0 },
		"правил 17":            func(e *Event) { e.Judge[0].Rules = 17 },
		"отрицательный расход": func(e *Event) { e.Judge[0].Tokens = -1 },
		"признак без записи":   func(e *Event) { e.Judge[1].Checked, e.Judge[1].Reason = true, "" },
		"запись без признака":  func(e *Event) { e.Decision.JudgeUnchecked = false },
		"больше 4 записей":     func(e *Event) { e.Judge = append(e.Judge, e.Judge[0], e.Judge[0], e.Judge[0]) },
	}
	for name, mutate := range cases {
		e := withJudge()
		mutate(e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: событие принято", name)
		}
	}
}

func TestJudgeInDetailsAndFilter(t *testing.T) {
	e := withJudge()
	raw, err := json.Marshal(e.Details())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"judge":[`) || !strings.Contains(string(raw), `"judge_unchecked":true`) {
		t.Fatalf("в подробностях нет оценки: %s", raw)
	}
	f, err := ParseFilter(`judge_unchecked = true`)
	if err != nil {
		t.Fatal(err)
	}
	d := e.Details()
	if !f.Match(&Record{Details: &d}) {
		t.Fatal("judge_unchecked = true не совпало")
	}
	if f.Match(&Record{Details: &Details{Decision: &Decision{}}}) {
		t.Fatal("judge_unchecked = true совпало без признака")
	}
}
