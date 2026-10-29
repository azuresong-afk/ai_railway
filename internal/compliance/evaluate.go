package compliance

import (
	"slices"
	"time"
)

// Mark — ручная отметка по пункту (организационные меры): статус,
// комментарий, документ-основание и срок пересмотра. Ставит
// администратор безопасности; каждое изменение — в журнале аудита.
type Mark struct {
	RequirementID string    `json:"requirement_id"`
	Status        Status    `json:"status"`
	Comment       string    `json:"comment"`
	Document      string    `json:"document,omitempty"`
	ReviewBy      string    `json:"review_by,omitempty"` // YYYY-MM-DD
	SetAt         time.Time `json:"set_at"`
	SetBy         string    `json:"set_by"`
}

// Overdue — срок пересмотра отметки истёк: отметка не засчитывается.
func (m Mark) Overdue(now time.Time) bool {
	if m.ReviewBy == "" {
		return false
	}
	d, err := time.Parse(baseDateLayout, m.ReviewBy)
	if err != nil {
		return false
	}
	// Срок — последний день, в который отметка ещё действует (по UTC).
	return now.UTC().After(d.Add(24 * time.Hour))
}

// Item — пункт с вычисленным статусом.
type Item struct {
	Requirement
	SourceTitle string `json:"source_title"`
	// Status — итог: из проверок и отметки.
	Status Status `json:"status"`
	// Auto — итог проверок; nil, если у пункта их нет.
	Auto   *AutoResult   `json:"auto,omitempty"`
	Checks []CheckResult `json:"checks,omitempty"`
	Mark   *Mark         `json:"mark,omitempty"`
	// MarkOverdue — отметка есть, но срок пересмотра истёк.
	MarkOverdue bool `json:"mark_overdue,omitempty"`
}

// AutoResult — сводный итог автоматических проверок пункта.
type AutoResult struct {
	Status Status `json:"status"`
}

// Counts — число пунктов по статусам.
type Counts struct {
	Met           int `json:"met"`
	Partial       int `json:"partial"`
	NotMet        int `json:"not_met"`
	NotApplicable int `json:"not_applicable"`
	Manual        int `json:"manual"`
}

func (c *Counts) add(s Status) {
	switch s {
	case StatusMet:
		c.Met++
	case StatusPartial:
		c.Partial++
	case StatusNotMet:
		c.NotMet++
	case StatusNotApplicable:
		c.NotApplicable++
	case StatusManual:
		c.Manual++
	}
}

// aggregate сводит статусы проверок: все выполнены — выполнено, выполнена
// часть — частично, ни одна — не выполнено; «не применимо» не считается,
// а если не применимы все — не применимо.
func aggregate(rs []CheckResult) Status {
	var met, partial, notMet int
	for _, r := range rs {
		switch r.Status {
		case StatusMet:
			met++
		case StatusPartial:
			partial++
		case StatusNotMet:
			notMet++
		}
	}
	switch {
	case met+partial+notMet == 0:
		return StatusNotApplicable
	case notMet == 0 && partial == 0:
		return StatusMet
	case met == 0 && partial == 0:
		return StatusNotMet
	}
	return StatusPartial
}

// worse — меньший из двух статусов в порядке «выполнено > частично > не
// выполнено»; «не применимо» уступает любому другому.
func worse(a, b Status) Status {
	rank := map[Status]int{StatusMet: 3, StatusPartial: 2, StatusNotMet: 1}
	switch {
	case a == StatusNotApplicable:
		return b
	case b == StatusNotApplicable:
		return a
	}
	if rank[a] <= rank[b] {
		return a
	}
	return b
}

// Evaluate вычисляет статус пункта. Правила (Р10):
//   - только проверки: статус проверок;
//   - только ручной пункт: отметка, а без действующей отметки — «нужна
//     ручная отметка»;
//   - проверки и ручная отметка: оба условия, меньший из статусов; без
//     действующей отметки при выполненных проверках — «нужна ручная отметка».
//
// Отметка «не применимо» снимает и ручное условие, и проверки: решение
// принимает человек с комментарием.
func Evaluate(r Requirement, base *Base, snap *Snapshot, mark *Mark, now time.Time) Item {
	it := Item{Requirement: r, SourceTitle: base.SourceTitle(r.Source)}
	for _, c := range r.Checks {
		it.Checks = append(it.Checks, RunCheck(snap, c))
	}
	if len(it.Checks) > 0 {
		it.Auto = &AutoResult{Status: aggregate(it.Checks)}
	}
	if mark != nil {
		m := *mark
		it.Mark = &m
		it.MarkOverdue = m.Overdue(now)
	}
	active := it.Mark != nil && !it.MarkOverdue
	switch {
	case active && it.Mark.Status == StatusNotApplicable:
		it.Status = StatusNotApplicable
	case it.Auto != nil && !r.Manual:
		it.Status = it.Auto.Status
	case it.Auto == nil:
		if active {
			it.Status = it.Mark.Status
		} else {
			it.Status = StatusManual
		}
	default: // проверки и ручная отметка
		switch {
		case it.Auto.Status == StatusNotApplicable && !active:
			it.Status = StatusManual
		case !active:
			if it.Auto.Status == StatusMet {
				it.Status = StatusManual
			} else {
				it.Status = it.Auto.Status
			}
		default:
			it.Status = worse(it.Auto.Status, it.Mark.Status)
		}
	}
	return it
}

// Filter — отбор пунктов в обзоре.
type Filter struct {
	// Source и Applies — пусто значит «все».
	Source  string
	Applies string
}

func (f Filter) match(r Requirement) bool {
	if f.Source != "" && r.Source != f.Source {
		return false
	}
	if f.Applies != "" && !slices.Contains(r.Applies, f.Applies) {
		return false
	}
	return true
}

// Summary — итог по набору пунктов.
type Summary struct {
	// Percent — доля выполнения по пунктам без признака «проект» и без
	// «не применимо»: выполнено — 1, частично — 0,5; nil, если считать
	// нечего. Целая часть вниз.
	Percent *int   `json:"percent"`
	Counts  Counts `json:"counts"`
	// Counted — пунктов, вошедших в процент.
	Counted int `json:"counted"`
	// Drafts — пунктов-проектов (в процент не входят).
	Drafts int `json:"drafts"`
}

// Summarize считает процент и счётчики. Пункты-проекты считаются отдельно
// (Drafts): ни в процент, ни в счётчики статусов они не входят.
func Summarize(items []Item) Summary {
	var s Summary
	var score2 int // удвоенная сумма: выполнено — 2, частично — 1
	for _, it := range items {
		if it.Draft {
			s.Drafts++
			continue
		}
		s.Counts.add(it.Status)
		if it.Status == StatusNotApplicable {
			continue
		}
		s.Counted++
		switch it.Status {
		case StatusMet:
			score2 += 2
		case StatusPartial:
			score2++
		}
	}
	if s.Counted > 0 {
		p := score2 * 100 / (2 * s.Counted)
		s.Percent = &p
	}
	return s
}

// Select оставляет пункты, подходящие под фильтр, в порядке базы.
func Select(items []Item, f Filter) []Item {
	out := make([]Item, 0, len(items))
	for _, it := range items {
		if f.match(it.Requirement) {
			out = append(out, it)
		}
	}
	return out
}
