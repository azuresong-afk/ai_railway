package events_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Отметки аналитиков (задача 3.22 этапа 3): хранятся отдельно от
// неизменяемого события, каждая смена — запись аудита той же транзакцией,
// фильтр mark и exception.

var markBy = audit.Actor{Type: audit.ActorUser, ID: testUser, Name: "Аналитик"}

func TestCleanMark(t *testing.T) {
	if m, c, err := events.CleanMark(events.MarkConfirmed, "  строка 1\nстрока 2 "); err != nil || m != "confirmed" || c != "строка 1\nстрока 2" {
		t.Fatalf("%q %q %v", m, c, err)
	}
	if _, _, err := events.CleanMark(events.MarkFalsePositive, strings.Repeat("я", events.MaxMarkComment)); err != nil {
		t.Fatalf("граница длины: %v", err)
	}
	for _, c := range [][2]string{
		{"none", ""}, {"", ""}, {"FALSE_POSITIVE", ""},
		{"confirmed", strings.Repeat("я", events.MaxMarkComment+1)},
		{"confirmed", "a\x07b"}, {"confirmed", "a\u200bb"}, {"confirmed", "\xff"},
	} {
		if _, _, err := events.CleanMark(c[0], c[1]); !errors.Is(err, events.ErrBadMark) {
			t.Errorf("%q %q принято", c[0], c[1])
		}
	}
}

func TestMemoryMarks(t *testing.T) {
	ctx := context.Background()
	m := events.NewMemory()
	var recs []audit.Entry
	now := time.Now().UTC()
	ms := now.Add(-time.Minute).UnixMilli()
	ev := events.Event{ID: fmt.Sprintf("%08x-%04x-7000-8000-%012x", ms>>16, ms&0xffff, 1), Time: now.Add(-time.Minute), Type: events.TypeGatewayRequest,
		App: "crm", PolicyMode: events.ModeEnforce, Storage: events.StorageNone,
		Decision: &events.Decision{Action: "allow", Applied: []string{}},
		Findings: []events.Finding{{Detector: "injection.heuristic", Category: "injection", Exception: "exc-1"}}}
	if _, err := m.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: now, Events: []events.Event{ev}}); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	if _, err := m.SetMark(ctx, ev.ID, events.Mark{Mark: events.MarkConfirmed}, markBy, ip); err == nil {
		t.Fatal("отметка без приёмника аудита")
	}
	m.SetRetentionAudit(func(e audit.Entry) error { recs = append(recs, e); return nil })
	if _, err := m.SetMark(ctx, "01900000-0000-7000-8000-000000000002", events.Mark{Mark: events.MarkConfirmed}, markBy, ip); !errors.Is(err, events.ErrNotFound) {
		t.Fatalf("нет события: %v", err)
	}
	prev, err := m.SetMark(ctx, ev.ID, events.Mark{Mark: events.MarkFalsePositive, Comment: "шаблон письма"}, markBy, ip)
	if err != nil || prev != nil {
		t.Fatalf("отметка: %v %v", prev, err)
	}
	prev, err = m.SetMark(ctx, ev.ID, events.Mark{Mark: events.MarkConfirmed}, markBy, ip)
	if err != nil || prev == nil || prev.Mark != events.MarkFalsePositive {
		t.Fatalf("замена: %v %v", prev, err)
	}
	card, err := m.Card(ctx, ev.ID)
	if err != nil || card.Mark == nil || card.Mark.Mark != events.MarkConfirmed || card.Mark.By != "user:"+testUser || card.Mark.ByName != "Аналитик" {
		t.Fatalf("карточка: %+v %v", card.Mark, err)
	}
	if len(recs) != 2 || recs[1].Action != events.ActionMarkSet || recs[1].Object.ID != ev.ID {
		t.Fatalf("аудит: %+v", recs)
	}
	if d := recs[1].Details.(map[string]any); d["previous"] != events.MarkFalsePositive || d["mark"] != events.MarkConfirmed {
		t.Fatalf("подробности: %v", d)
	}
	if d := recs[0].Details.(map[string]any); d["comment_chars"] != 13 {
		t.Fatalf("подробности: %v", d)
	}
	for _, e := range recs {
		if _, err := audit.CanonicalDetails(e.Details); err != nil {
			t.Fatal(err)
		}
	}
	for f, want := range map[string]int{
		`mark = "confirmed"`: 1, `mark = "none"`: 0, `mark in ("false_positive", "none")`: 0, `mark != "false_positive"`: 1,
		`exception = "exc-1"`: 1, `exception != "exc-1"`: 0, `exception = "exc-2"`: 0,
	} {
		flt, err := events.ParseFilter(f)
		if err != nil {
			t.Fatal(f, err)
		}
		got, err := m.List(ctx, events.Query{From: now.Add(-time.Hour), To: now.Add(time.Minute), Filter: flt})
		if err != nil || len(got) != want {
			t.Errorf("%s: %d %v", f, len(got), err)
		}
	}
	if err := m.DeleteMark(ctx, ev.ID, markBy, ip); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteMark(ctx, ev.ID, markBy, ip); !errors.Is(err, events.ErrNoMark) {
		t.Fatalf("повторное снятие: %v", err)
	}
	if recs[len(recs)-1].Action != events.ActionMarkRemoved {
		t.Fatalf("аудит снятия: %+v", recs[len(recs)-1])
	}
}

func TestParseFilterMarkRejects(t *testing.T) {
	for _, f := range []string{`mark = "fp"`, `exception = "EXC 1"`, `mark = 1`} {
		if _, err := events.ParseFilter(f); err == nil {
			t.Errorf("%s принят", f)
		}
	}
}

func TestPGEventMarks(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	evs := seed(t, e, 3)
	ip := netip.MustParseAddr("192.0.2.10")
	if _, err := e.st.SetMark(ctx, "01900000-0000-7000-8000-000000000099", events.Mark{Mark: events.MarkConfirmed}, markBy, ip); !errors.Is(err, events.ErrNotFound) {
		t.Fatalf("нет события: %v", err)
	}
	if _, err := e.st.SetMark(ctx, "not-uuid", events.Mark{Mark: events.MarkConfirmed}, markBy, ip); !errors.Is(err, events.ErrNotFound) {
		t.Fatalf("неверный ID: %v", err)
	}
	if _, err := e.st.SetMark(ctx, evs[0].ID, events.Mark{Mark: "bad"}, markBy, ip); !errors.Is(err, events.ErrBadMark) {
		t.Fatalf("неверная отметка: %v", err)
	}
	if _, err := e.st.SetMark(ctx, evs[0].ID, events.Mark{Mark: events.MarkFalsePositive, Comment: "шаблон"}, markBy, ip); err != nil {
		t.Fatal(err)
	}
	prev, err := e.st.SetMark(ctx, evs[0].ID, events.Mark{Mark: events.MarkConfirmed, Comment: "проверено"}, markBy, ip)
	if err != nil || prev == nil || prev.Mark != events.MarkFalsePositive || prev.Comment != "шаблон" {
		t.Fatalf("замена: %+v %v", prev, err)
	}
	if _, err := e.st.SetMark(ctx, evs[1].ID, events.Mark{Mark: events.MarkFalsePositive}, markBy, ip); err != nil {
		t.Fatal(err)
	}
	card, err := e.st.Card(ctx, evs[0].ID)
	if err != nil || card.Mark == nil || card.Mark.Mark != events.MarkConfirmed || card.Mark.Comment != "проверено" || card.Mark.By != "user:"+testUser {
		t.Fatalf("карточка: %+v %v", card.Mark, err)
	}
	if c, err := e.st.Card(ctx, evs[2].ID); err != nil || c.Mark != nil {
		t.Fatalf("без отметки: %+v %v", c.Mark, err)
	}
	for f, want := range map[string]int{
		`mark = "confirmed"`: 1, `mark = "false_positive"`: 1, `mark = "none"`: 1, `mark != "none"`: 2,
		`mark in ("confirmed", "none") and app = "crm"`: 2,
	} {
		flt, err := events.ParseFilter(f)
		if err != nil {
			t.Fatal(f, err)
		}
		q := lastHour()
		q.Filter = flt
		got, err := e.st.List(ctx, q)
		if err != nil || len(got) != want {
			t.Errorf("%s: %d (%v), ожидалось %d", f, len(got), err, want)
		}
		if n, err := e.st.Count(ctx, q, 100); err != nil || n != want {
			t.Errorf("%s: подсчёт %d (%v)", f, n, err)
		}
	}
	all, err := e.st.List(ctx, lastHour())
	if err != nil {
		t.Fatal(err)
	}
	marked := 0
	for _, r := range all {
		if r.Mark != nil {
			marked++
		}
	}
	if marked != 2 {
		t.Fatalf("отметки в списке: %d", marked)
	}
	// Аудит той же транзакцией: значения без комментария.
	var n int
	var details string
	if err := e.owner.QueryRow(ctx, `SELECT count(*), max(details::text) FILTER (WHERE details::jsonb ? 'previous')
		FROM audit_log WHERE action = 'events.mark_set'`).Scan(&n, &details); err != nil {
		t.Fatal(err)
	}
	if n != 3 || details != `{"comment_chars":9,"mark":"confirmed","previous":"false_positive"}` {
		t.Fatalf("аудит: %d %s", n, details)
	}
	if err := e.st.DeleteMark(ctx, evs[1].ID, markBy, ip); err != nil {
		t.Fatal(err)
	}
	if err := e.st.DeleteMark(ctx, evs[1].ID, markBy, ip); !errors.Is(err, events.ErrNoMark) {
		t.Fatalf("повторное снятие: %v", err)
	}
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'events.mark_removed'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("аудит снятия: %d %v", n, err)
	}
	// Ограничения таблицы — вторая линия защиты.
	if _, err := e.app.Exec(ctx, `UPDATE event_marks SET mark = 'maybe'`); err == nil {
		t.Fatal("неизвестная отметка принята БД")
	}
}
