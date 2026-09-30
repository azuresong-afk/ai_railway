package main

import (
	"fmt"
	"sort"
	"strings"
)

// Статусы требования в отчёте.
const (
	StatusCovered    = "покрыто"
	StatusMissing    = "не покрыто"
	StatusFailing    = "тест не проходит"
	StatusLater      = "позже"
	StatusOnRequest  = "по запросу"
	StatusUnexpected = "покрыто заранее"
)

// Item — требование покрытия: основная часть строки или часть с отдельным этапом.
type Item struct {
	ID     string   `json:"id"`
	What   string   `json:"what"`
	Part   string   `json:"part,omitempty"`
	Stage  int      `json:"stage"`
	Tests  []string `json:"tests"`
	Status string   `json:"status"`
}

// Report — итог сверки.
type Report struct {
	Stage    int      `json:"current_stage"`
	Items    []Item   `json:"items"`
	Problems []string `json:"problems"`
}

// topLevel возвращает имя функции теста без подтестов.
func topLevel(name string) string {
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[:i]
	}
	return name
}

// Compute сверяет матрицу с результатами тестов и маркерами покрытия.
func Compute(rows []Row, stage int, results []Result, markers map[string][]Coverage) Report {
	type key struct{ id, part string }
	type hit struct {
		name   string
		passed bool
	}
	hits := map[key][]hit{}
	var problems []string

	byID := map[string]Row{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	partExists := func(id, part string) bool {
		for _, p := range byID[id].Parts {
			if p.Name == part {
				return true
			}
		}
		return false
	}

	markerUsed := map[string]bool{}
	for _, res := range results {
		for _, id := range IDsInName(res.Name) {
			if _, ok := byID[id]; !ok {
				problems = append(problems, fmt.Sprintf("тест %s ссылается на несуществующую строку %s", res.Name, id))
				continue
			}
			hits[key{id, ""}] = append(hits[key{id, ""}], hit{res.Name, res.Passed})
		}
		fn := topLevel(res.Name)
		if res.Name != fn {
			continue // маркеры относятся к функции теста целиком
		}
		for _, c := range markers[fn] {
			markerUsed[fn] = true
			if _, ok := byID[c.ID]; !ok {
				problems = append(problems, fmt.Sprintf("тест %s: маркер ссылается на несуществующую строку %s", fn, c.ID))
				continue
			}
			if c.Part != "" && !partExists(c.ID, c.Part) {
				problems = append(problems, fmt.Sprintf("тест %s: у строки %s нет части «%s»", fn, c.ID, c.Part))
				continue
			}
			hits[key{c.ID, c.Part}] = append(hits[key{c.ID, c.Part}], hit{fn, res.Passed})
		}
	}
	for fn := range markers {
		if !markerUsed[fn] {
			problems = append(problems, fmt.Sprintf("тест %s размечен маркером «Покрывает:», но не запускался", fn))
		}
	}

	var items []Item
	add := func(r Row, part string, st int) {
		it := Item{ID: r.ID, What: r.What, Part: part, Stage: st, Tests: []string{}}
		passed, failed := false, false
		for _, h := range hits[key{r.ID, part}] {
			it.Tests = append(it.Tests, h.name)
			if h.passed {
				passed = true
			} else {
				failed = true
			}
		}
		sort.Strings(it.Tests)
		required := st != OnRequest && st <= stage
		switch {
		case failed:
			it.Status = StatusFailing
		case passed && required:
			it.Status = StatusCovered
		case passed:
			it.Status = StatusUnexpected
		case st == OnRequest:
			it.Status = StatusOnRequest
		case required:
			it.Status = StatusMissing
		default:
			it.Status = StatusLater
		}
		if it.Status == StatusMissing {
			problems = append(problems, fmt.Sprintf("%s%s: этап %d, нет прошедшего теста", r.ID, partSuffix(part), st))
		}
		if it.Status == StatusFailing {
			problems = append(problems, fmt.Sprintf("%s%s: тест не проходит (%s)", r.ID, partSuffix(part), strings.Join(it.Tests, ", ")))
		}
		items = append(items, it)
	}
	for _, r := range rows {
		add(r, "", r.Stage)
		for _, p := range r.Parts {
			add(r, p.Name, p.Stage)
		}
	}
	sort.Strings(problems)
	return Report{Stage: stage, Items: items, Problems: problems}
}

func partSuffix(part string) string {
	if part == "" {
		return ""
	}
	return " (" + part + ")"
}

// Markdown форматирует отчёт.
func (r Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Покрытие матрицы обнаружения (ТЗ, 5.16)\n\nТекущий этап: %d. Тесты обязательны для строк и частей с этапом не выше текущего.\n\n", r.Stage)
	counts := map[string]int{}
	for _, it := range r.Items {
		counts[it.Status]++
	}
	fmt.Fprintf(&b, "Покрыто: %d, не покрыто: %d, тест не проходит: %d, позже: %d, по запросу: %d, покрыто заранее: %d.\n\n",
		counts[StatusCovered], counts[StatusMissing], counts[StatusFailing], counts[StatusLater], counts[StatusOnRequest], counts[StatusUnexpected])
	if len(r.Problems) > 0 {
		b.WriteString("## Проблемы\n\n")
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "- %s\n", p)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Строки\n\n| ID | Что выявляется | Часть | Этап | Тесты | Статус |\n|---|---|---|---|---|---|\n")
	for _, it := range r.Items {
		st := "по запросу"
		if it.Stage != OnRequest {
			st = fmt.Sprint(it.Stage)
		}
		tests := "—"
		if len(it.Tests) > 0 {
			tests = "`" + strings.Join(it.Tests, "`, `") + "`"
		}
		part := "основная"
		if it.Part != "" {
			part = it.Part
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", it.ID, strings.ReplaceAll(it.What, "|", "\\|"), part, st, tests, it.Status)
	}
	return b.String()
}
