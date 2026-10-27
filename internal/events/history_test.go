package events

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// hx — синтетический хеш реплики (32 hex).
func hx(n int) string { return fmt.Sprintf("%032x", n) }

// turn — событие хода сессии sess приложения app с правилом
// history.integrity: history — хеши реплик истории (номера сообщений
// 1, 3, 5…), issued — выданные ответы.
func turn(id int, app, sess string, history []string, issued ...string) Event {
	s := &Session{ID: sess, Source: SessionHeader, HistoryRule: "history", HistoryAction: "log", HistorySeverity: "high", Issued: issued}
	for i, h := range history {
		s.History = append(s.History, Reply{Message: 2*i + 1, Hash: h})
	}
	return Event{ID: fmt.Sprintf("0192f1a0-7b3c-7d4e-8f00-%012d", id), Time: time.Date(2026, 10, 27, 12, 0, id, 0, time.UTC),
		Type: TypeGatewayRequest, App: app, PolicyMode: ModeEnforce,
		Decision: &Decision{Action: "allow", Severity: "low"}, Session: s}
}

func forged(e Event) []Finding {
	var out []Finding
	for _, f := range e.Findings {
		if f.Detector == "history.integrity" {
			out = append(out, f)
		}
	}
	return out
}

// Покрывает: DM-03
// Подмена истории: реплика ассистента, которой шлюз в сессии не выдавал, —
// находка history.forged в событии, угроза DM-03, шаг трассировки и итог
// правила (allow → log); выданные ответы, в том числе в том же пакете, —
// известны.
func TestDM03_ForgedHistoryDetected(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	sess := strings.Repeat("a", 32)
	evs := []Event{
		turn(1, "crm", sess, nil, hx(1)),
		turn(2, "crm", sess, []string{hx(1)}, hx(2)),
		turn(3, "crm", sess, []string{hx(1), hx(99), hx(2)}, hx(3)),
	}
	if _, err := m.Insert(ctx, Ingest{GatewayID: "gw", ReceivedAt: time.Now(), Events: evs}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if got, _ := m.Get(evs[i].ID); len(forged(got.Event)) != 0 {
			t.Fatalf("ход %d: ложная находка %+v", i+1, got.Event.Findings)
		}
	}
	got, _ := m.Get(evs[2].ID)
	e := got.Event
	fs := forged(e)
	if len(fs) != 1 || fs[0].Location != "messages[3].content" || fs[0].Threat != "DM-03" || fs[0].Category != "history.forged" || fs[0].Score != 1 {
		t.Fatalf("находки: %+v", e.Findings)
	}
	if !slices.Contains(e.Threats, "DM-03") || e.Decision.Action != "log" || e.Decision.Rule != "history" || e.Decision.Severity != "high" {
		t.Fatalf("решение: %+v, угрозы %v", e.Decision, e.Threats)
	}
	if n := len(e.Decision.Trace); n != 1 || e.Decision.Trace[0].Detector != "history.integrity" || !e.Decision.Trace[0].Matched {
		t.Fatalf("трассировка: %+v", e.Decision.Trace)
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Покрывает: DM-03
// Граничные случаи: впервые увиденная сессия принимает историю как
// известную; пустая история; та же сессия в другом приложении — другая;
// без правила хеши не учитываются; повтор пакета — тот же итог; блок не
// ослабляется до log.
func TestDM03_HistoryEdgeCases(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	sess := strings.Repeat("b", 32)
	insert := func(evs ...Event) []Event {
		t.Helper()
		if _, err := m.Insert(ctx, Ingest{GatewayID: "gw", ReceivedAt: time.Now(), Events: evs}); err != nil {
			t.Fatal(err)
		}
		out := make([]Event, 0, len(evs))
		for _, e := range evs {
			got, _ := m.Get(e.ID)
			out = append(out, got.Event)
		}
		return out
	}
	// Первый ход — история до включения правила.
	if e := insert(turn(1, "crm", sess, []string{hx(7), hx(8)}, hx(9)))[0]; len(forged(e)) != 0 {
		t.Fatalf("первый ход: %+v", e.Findings)
	}
	if e := insert(turn(2, "crm", sess, []string{hx(7), hx(8), hx(9)}))[0]; len(forged(e)) != 0 {
		t.Fatalf("известная история: %+v", e.Findings)
	}
	if e := insert(turn(3, "crm", sess, nil))[0]; len(forged(e)) != 0 || e.Decision.Action != "allow" {
		t.Fatalf("пустая история: %+v", e)
	}
	// Тот же псевдоним в другом приложении — своя сессия (первый ход).
	if e := insert(turn(4, "hr", sess, []string{hx(50)}))[0]; len(forged(e)) != 0 {
		t.Fatalf("другое приложение: %+v", e.Findings)
	}
	if e := insert(turn(5, "hr", sess, []string{hx(50), hx(9)}))[0]; len(forged(e)) != 1 {
		t.Fatalf("реплика другого приложения принята: %+v", e.Findings)
	}
	// Без правила — не учитывается и не проверяется.
	plain := turn(6, "crm", strings.Repeat("c", 32), nil)
	plain.Session = &Session{ID: plain.Session.ID, Source: SessionHeader}
	insert(plain)
	if e := insert(turn(7, "crm", strings.Repeat("c", 32), []string{hx(1)}))[0]; len(forged(e)) != 0 {
		t.Fatalf("сессия без правила считалась увиденной: %+v", e.Findings)
	}
	// Решение block не ослабляется, серьёзность не понижается.
	b := turn(8, "crm", sess, []string{hx(404)})
	b.Decision = &Decision{Action: "block", Rule: "injection", Severity: "critical"}
	if e := insert(b)[0]; len(forged(e)) != 1 || e.Decision.Action != "block" || e.Decision.Rule != "injection" || e.Decision.Severity != "critical" {
		t.Fatalf("блок: %+v", e.Decision)
	}
}

// Событие с сессией и неверным ID приложения отклоняется при разборе, а не
// ограничением session_history в СУБД (иначе 503 и бесконечный повтор
// пакета шлюзом; ревью B2, п. 1).
func TestSessionEventAppValidated(t *testing.T) {
	sess := strings.Repeat("a", 32)
	for _, app := range []string{"crm", "a", "crm-2"} {
		e := turn(1, app, sess, nil)
		if err := e.Validate(); err != nil {
			t.Fatalf("%q: %v", app, err)
		}
	}
	for _, app := range []string{"", "CRM", "-crm", "crm app", strings.Repeat("a", 64)} {
		e := turn(1, app, sess, nil)
		if err := e.Validate(); err == nil {
			t.Fatalf("%q принят", app)
		}
	}
}
