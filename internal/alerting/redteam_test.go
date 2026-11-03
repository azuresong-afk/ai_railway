package alerting

import (
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Тестовые события (запросы исполнителя тестирования устойчивости с ключом
// запуска, задача 5.32, ADR-0031, раздел 2) оповещений не поднимают:
// блокировка инъекции с test — ни оповещения, ни счёта; то же событие без
// test — оповещение.
func TestTestEventsRaiseNoAlerts(t *testing.T) {
	e := newEnv(t)
	tst := e.event(t, "crm-bot", "gigachat", "block", "DM-01")
	tst.Test = true
	tst2 := e.event(t, "crm-bot", "gigachat", "block", "DM-01")
	tst2.Test = true
	e.ingest(t, tst, tst2)
	if got := e.alerts(t, BuiltinInjectionBlocked); len(got) != 0 {
		t.Fatalf("оповещение по тестовым событиям: %+v", got)
	}
	mixed := e.event(t, "crm-bot", "gigachat", "block", "DM-01")
	mixed.Test = true
	e.ingest(t, e.event(t, "crm-bot", "gigachat", "block", "DM-01"), mixed)
	got := e.alerts(t, BuiltinInjectionBlocked)
	if len(got) != 1 || got[0].Count != 1 {
		t.Fatalf("оповещение по настоящему событию: %+v", got)
	}
}

func TestWithoutTest(t *testing.T) {
	e := newEnv(t)
	a, b := e.event(t, "a", "m", "allow"), e.event(t, "b", "m", "allow")
	b.Test = true
	in := []*events.Event{a, b}
	out := withoutTest(in)
	if len(out) != 1 || out[0] != a || in[1] != b {
		t.Fatalf("без тестовых: %v, исходный: %v", out, in)
	}
	only := []*events.Event{a}
	if got := withoutTest(only); &got[0] != &only[0] {
		t.Fatal("срез без тестовых событий должен возвращаться как есть")
	}
}
