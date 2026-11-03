package alerting

import (
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Задача 5.28 (ADR-0030, раздел 7): находка judge.llm — оповещение
// threshold.judge_violation; серия событий с judge_unchecked на шлюзе —
// frequency.judge_unchecked.
func TestJudgeViolationAlert(t *testing.T) {
	e := newEnv(t)
	ev := e.event(t, "crm-bot", "gigachat", "allow")
	ev.Findings = append(ev.Findings, events.Finding{Detector: "judge.llm", Version: "1.0.0", Category: "judge.business",
		Score: 0.9, Location: "choices[0].message.content", Threat: "DM-19", Rule: "no-refunds", Source: "output"})
	ev.Threats = append(ev.Threats, "DM-19")
	e.ingest(t, e.event(t, "crm-bot", "gigachat", "allow"))
	if got := e.alerts(t, BuiltinJudgeViolation); len(got) != 0 {
		t.Fatalf("без находки оценщика — оповещение: %+v", got)
	}
	e.ingest(t, ev)
	if got := e.alerts(t, BuiltinJudgeViolation); len(got) != 1 || got[0].Values["app"] != "crm-bot" {
		t.Fatalf("находка оценщика: %+v", got)
	}
}

func TestJudgeUncheckedSpikeAlert(t *testing.T) {
	e := newEnv(t)
	unchecked := func() *events.Event {
		ev := e.event(t, "crm-bot", "gigachat", "allow")
		ev.Decision.JudgeUnchecked = true
		ev.Judge = []events.JudgeCheck{{Direction: "output", Mode: events.JudgeModeAsync, Reason: events.JudgeReasonUnavailable, Rules: 1}}
		return ev
	}
	e.ingest(t, repeat(JudgeUncheckedCount-1, unchecked)...)
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinJudgeUnchecked); len(got) != 0 {
		t.Fatalf("%d неполученных оценок — оповещение: %+v", JudgeUncheckedCount-1, got)
	}
	e.ingest(t, unchecked())
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinJudgeUnchecked); len(got) != 1 || got[0].Values["gateway"] != testGateway {
		t.Fatalf("всплеск judge_unchecked: %+v", got)
	}
}
