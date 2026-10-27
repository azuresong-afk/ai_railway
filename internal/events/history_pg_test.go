package events_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// history.integrity на живой БД (миграция 0053): ответы, выданные в
// сессии, известны следующим ходам, в том числе в другом пакете;
// подмена — находка в сохранённом событии; повтор пакета не меняет итог;
// хешей нет в хранимых подробностях события; роль сервера не меняет
// сессию и источник хеша.
func TestPGSessionHistoryCheck(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	sess := strings.Repeat("d", 32)
	hash := func(n int) string { return fmt.Sprintf("%032x", n) }
	turn := func(history []string, issued ...string) events.Event {
		ev := e.event(t, events.StorageNone, nil)
		ev.Decision = &events.Decision{Action: "allow", Severity: "low"}
		ev.Findings, ev.Threats = nil, nil
		s := &events.Session{ID: sess, Source: events.SessionFingerprint, HistoryRule: "history", HistoryAction: "log",
			HistorySeverity: "high", Issued: issued}
		for i, h := range history {
			s.History = append(s.History, events.Reply{Message: 2*i + 1, Hash: h})
		}
		ev.Session = s
		return ev
	}
	insert := func(evs ...events.Event) {
		t.Helper()
		if _, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, Events: evs}); err != nil {
			t.Fatal(err)
		}
	}
	card := func(id string) events.Record {
		t.Helper()
		r, err := e.st.Card(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	t1, t2 := turn(nil, hash(1)), turn([]string{hash(1)}, hash(2))
	insert(t1, t2)
	t3 := turn([]string{hash(1), hash(2), hash(3)})
	insert(t3)
	insert(t3) // повтор пакета
	r := card(t3.ID)
	if r.Details == nil || len(r.Details.Findings) != 1 || r.Details.Findings[0].Location != "messages[5].content" ||
		!slices.Contains(r.Threats, "DM-03") || r.Action != "log" || r.Rule != "history" || r.Severity != "high" {
		t.Fatalf("подмена: %+v %+v", r, r.Details)
	}
	if s := r.Details.Session; s == nil || s.ID != sess || len(s.History) != 0 || len(s.Issued) != 0 || s.HistoryRule != "" {
		t.Fatalf("сессия в хранимых подробностях: %+v", r.Details.Session)
	}
	if r := card(t2.ID); len(r.Details.Findings) != 0 || r.Action != "allow" {
		t.Fatalf("известная история: %+v", r.Details)
	}
	var n int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM session_replies WHERE session = $1`, sess).Scan(&n); err != nil || n != 2 {
		t.Fatalf("хешей сессии %d: %v", n, err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE session_replies SET source = 'issued'`); sqlState(err) != "42501" {
		t.Fatalf("изменение источника хеша ролью сервера: %v", err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE session_history SET first_seen = now()`); sqlState(err) != "42501" {
		t.Fatalf("изменение first_seen ролью сервера: %v", err)
	}
}
