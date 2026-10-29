package reports

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/compliance"
)

type fakeCompliance struct {
	o   compliance.Overview
	err error
}

func (f fakeCompliance) Evaluate(context.Context, compliance.Filter) (compliance.Overview, error) {
	return f.o, f.err
}

func complianceOverview() compliance.Overview {
	pct := 50
	mark := &compliance.Mark{RequirementID: "m.one", Status: compliance.StatusMet, Comment: "=cmd|' /C calc'!A0", Document: "Приказ № 5", ReviewBy: "2027-01-01",
		SetAt: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC), SetBy: "user:u1"}
	item := func(id string, draft bool, st compliance.Status, m *compliance.Mark) compliance.Item {
		return compliance.Item{Requirement: compliance.Requirement{ID: id, Source: "s", Clause: "п. 1", Title: "Требование " + id, Applies: []string{"ispdn"}, Draft: draft,
			Evidence: []compliance.Evidence{{Kind: "events", Title: "События", Path: "/events", Query: map[string]string{"f": "type = auth_failure"}}}},
			SourceTitle: "Источник", Status: st, Mark: m,
			Checks: []compliance.CheckResult{{Name: "content_storage", Title: "Хранение", Status: compliance.StatusMet, Detail: "режим хранения: masked"}}}
	}
	return compliance.Overview{GeneratedAt: time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC),
		Base:    compliance.BaseInfo{Version: 3, Date: "2026-10-28", Origin: "uploaded", Requirements: 3},
		Summary: compliance.Summary{Percent: &pct, Counts: compliance.Counts{Met: 1, Partial: 1}, Counted: 2, Drafts: 1},
		Items:   []compliance.Item{item("a.one", false, compliance.StatusMet, nil), item("m.one", false, compliance.StatusPartial, mark), item("d.one", true, compliance.StatusNotMet, nil)}}
}

// Отчёт «Соответствие»: проекты — отдельным разделом, ручные отметки с датой,
// доказательства ссылками на разделы консоли; все три формата без ошибок.
func TestComplianceReportDoc(t *testing.T) {
	b := &Builder{Compliance: fakeCompliance{o: complianceOverview()}}
	d, err := b.complianceReport(context.Background(), Params{Kind: KindCompliance, Period: Period{Loc: time.UTC}})
	if err != nil {
		t.Fatal(err)
	}
	var reg, drafts *Section
	for i := range d.Sections {
		switch d.Sections[i].Title {
		case "Требования":
			reg = &d.Sections[i]
		case "Требования из проектов документов":
			drafts = &d.Sections[i]
		}
	}
	if reg == nil || drafts == nil || len(reg.Rows) != 2 || len(drafts.Rows) != 1 {
		t.Fatalf("разделы: %+v", d.Sections)
	}
	row := reg.Rows[1]
	if !strings.Contains(row[7].Text, "Приказ № 5") || !strings.Contains(row[7].Text, "20.10.2026") || !strings.Contains(row[8].Text, "[раздел консоли /events]") {
		t.Fatalf("отметка и доказательства: %q | %q", row[7].Text, row[8].Text)
	}
	for name, w := range map[string]func(*bytes.Buffer) error{
		"html": func(b *bytes.Buffer) error { return WriteHTML(b, d) },
		"csv":  func(b *bytes.Buffer) error { return WriteCSV(b, d, ';') },
		"xlsx": func(b *bytes.Buffer) error { return WriteXLSX(b, d) },
	} {
		var buf bytes.Buffer
		if err := w(&buf); err != nil || buf.Len() == 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
	// В CSV комментарий-формула не исполняется: префикс «'».
	var csv bytes.Buffer
	if err := WriteCSV(&csv, d, ';'); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(csv.String(), ";=cmd") || strings.Contains(csv.String(), "\n=cmd") {
		t.Fatalf("формула в CSV без защиты: %s", csv.String())
	}
}

func TestComplianceReportNoSourceAndScope(t *testing.T) {
	ctx := context.Background()
	if _, err := (&Builder{}).complianceReport(ctx, Params{Kind: KindCompliance}); !errors.Is(err, ErrNoSource) {
		t.Fatalf("без модуля: %v", err)
	}
	boom := errors.New("сбой")
	if _, err := (&Builder{Compliance: fakeCompliance{err: boom}}).complianceReport(ctx, Params{Kind: KindCompliance}); !errors.Is(err, boom) {
		t.Fatalf("ошибка модуля: %v", err)
	}
	if (Scope{}).Allows(KindCompliance) {
		t.Fatal("пустая область пускает отчёт «Соответствие»")
	}
	if !(Scope{Compliance: true}).Allows(KindCompliance) {
		t.Fatal("область с Compliance не пускает отчёт")
	}
}
