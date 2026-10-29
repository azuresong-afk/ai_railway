package compliance

import (
	"testing"
	"time"
)

func req(manual bool, checks ...string) Requirement {
	r := Requirement{ID: "x.one", Source: "src-a", Clause: "п.", Title: "t", Summary: "s", Applies: []string{AppliesGIS}, Manual: manual}
	for _, c := range checks {
		r.Checks = append(r.Checks, CheckRef{Name: c})
	}
	return r
}

func miniParsed(t *testing.T) *Base {
	t.Helper()
	b, err := ParseBase([]byte(miniBase(1, "2026-10-28")))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEvaluateStatuses(t *testing.T) {
	b := miniParsed(t)
	snapGood := goodSnapshot()
	snapBad := goodSnapshot()
	snapBad.Apps[0].Storage = "none"
	mk := func(st Status) *Mark { return &Mark{RequirementID: "x.one", Status: st, Comment: "c", SetAt: testNow} }
	overdue := &Mark{RequirementID: "x.one", Status: StatusMet, Comment: "c", ReviewBy: "2026-10-27", SetAt: testNow}
	lastDay := &Mark{RequirementID: "x.one", Status: StatusMet, Comment: "c", ReviewBy: "2026-10-28", SetAt: testNow}
	cases := []struct {
		name string
		r    Requirement
		snap *Snapshot
		mark *Mark
		want Status
	}{
		{"только проверки, выполнено", req(false, "content_storage"), snapGood, nil, StatusMet},
		{"только проверки, не выполнено", req(false, "content_storage"), snapBad, nil, StatusNotMet},
		{"проверки: отметка «выполнено» ничего не меняет", req(false, "content_storage"), snapBad, mk(StatusMet), StatusNotMet},
		{"проверки: «не применимо» решает человек", req(false, "content_storage"), snapBad, mk(StatusNotApplicable), StatusNotApplicable},
		{"ручной без отметки", req(true), snapGood, nil, StatusManual},
		{"ручной с отметкой", req(true), snapGood, mk(StatusPartial), StatusPartial},
		{"ручной: срок пересмотра истёк", req(true), snapGood, overdue, StatusManual},
		{"ручной: последний день срока", req(true), snapGood, lastDay, StatusMet},
		{"смешанный: проверки выполнены, отметки нет", req(true, "content_storage"), snapGood, nil, StatusManual},
		{"смешанный: проверки не выполнены, отметки нет", req(true, "content_storage"), snapBad, nil, StatusNotMet},
		{"смешанный: оба выполнены", req(true, "content_storage"), snapGood, mk(StatusMet), StatusMet},
		{"смешанный: отметка хуже проверок", req(true, "content_storage"), snapGood, mk(StatusPartial), StatusPartial},
		{"смешанный: проверки хуже отметки", req(true, "content_storage"), snapBad, mk(StatusMet), StatusNotMet},
		{"смешанный: проверки не применимы", req(true, "filter_enforced"), &Snapshot{Now: testNow, Unavailable: map[string]bool{}}, nil, StatusManual},
		{"смешанный: проверки не применимы, отметка есть", req(true, "filter_enforced"), &Snapshot{Now: testNow, Unavailable: map[string]bool{}}, mk(StatusMet), StatusMet},
	}
	for _, c := range cases {
		it := Evaluate(c.r, b, c.snap, c.mark, testNow)
		if it.Status != c.want {
			t.Errorf("%s: %s, ожидалось %s", c.name, it.Status, c.want)
		}
	}
}

func TestAggregate(t *testing.T) {
	r := func(s ...Status) []CheckResult {
		var out []CheckResult
		for _, x := range s {
			out = append(out, CheckResult{Status: x})
		}
		return out
	}
	for want, in := range map[Status][]CheckResult{
		StatusMet:           r(StatusMet, StatusMet),
		StatusNotMet:        r(StatusNotMet, StatusNotMet),
		StatusPartial:       r(StatusMet, StatusNotMet),
		StatusNotApplicable: r(StatusNotApplicable),
	} {
		if got := aggregate(in); got != want {
			t.Errorf("%v: %s, ожидалось %s", in, got, want)
		}
	}
	if got := aggregate(r(StatusMet, StatusNotApplicable)); got != StatusMet {
		t.Errorf("«не применимо» не должно мешать: %s", got)
	}
	if got := aggregate(r(StatusPartial)); got != StatusPartial {
		t.Errorf("частично: %s", got)
	}
	if got := aggregate(nil); got != StatusNotApplicable {
		t.Errorf("пусто: %s", got)
	}
}

// Процент не учитывает «проект» и «не применимо»; частично — половина.
func TestSummarizePercent(t *testing.T) {
	it := func(st Status, draft bool) Item { return Item{Requirement: Requirement{Draft: draft}, Status: st} }
	s := Summarize([]Item{it(StatusMet, false), it(StatusNotMet, false), it(StatusPartial, false), it(StatusNotApplicable, false), it(StatusManual, false),
		it(StatusNotMet, true), it(StatusNotMet, true)})
	// Учтены 4: 1 + 0 + 0,5 + 0 = 1,5 из 4 → 37 %.
	if s.Percent == nil || *s.Percent != 37 || s.Counted != 4 || s.Drafts != 2 {
		t.Fatalf("итог: %+v %v", s, s.Percent)
	}
	if s.Counts.Met != 1 || s.Counts.NotMet != 1 || s.Counts.Manual != 1 || s.Counts.NotApplicable != 1 || s.Counts.Partial != 1 {
		t.Fatalf("счётчики (без проектов): %+v", s.Counts)
	}
	// Проекты не меняют процент.
	s2 := Summarize([]Item{it(StatusMet, false), it(StatusMet, true), it(StatusNotMet, true)})
	if *s2.Percent != 100 {
		t.Fatalf("проекты повлияли на процент: %d", *s2.Percent)
	}
	// Нечего считать — процента нет (граничный случай).
	for _, items := range [][]Item{nil, {it(StatusNotApplicable, false)}, {it(StatusMet, true)}} {
		if s := Summarize(items); s.Percent != nil {
			t.Errorf("процент без учтённых пунктов: %d", *s.Percent)
		}
	}
}

func TestMarkOverdue(t *testing.T) {
	m := Mark{ReviewBy: "2026-10-28"}
	if m.Overdue(time.Date(2026, 10, 28, 23, 59, 0, 0, time.UTC)) || !m.Overdue(time.Date(2026, 10, 29, 0, 0, 1, 0, time.UTC)) {
		t.Fatal("граница срока пересмотра")
	}
	if (Mark{}).Overdue(testNow) {
		t.Fatal("без срока отметка бессрочна")
	}
}

func TestSelectFilter(t *testing.T) {
	b := miniParsed(t)
	snap := goodSnapshot()
	var items []Item
	for _, r := range b.Requirements {
		items = append(items, Evaluate(r, b, snap, nil, testNow))
	}
	if got := Select(items, Filter{Applies: AppliesISPDn}); len(got) != 1 || got[0].ID != "manual.one" {
		t.Fatalf("по применимости: %+v", got)
	}
	if got := Select(items, Filter{Source: "src-a"}); len(got) != 3 {
		t.Fatalf("по источнику: %d", len(got))
	}
	if got := Select(items, Filter{Source: "other"}); len(got) != 0 {
		t.Fatalf("чужой источник: %d", len(got))
	}
}
