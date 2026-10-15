package main

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// OnRequest — этап «по запросу»: тест не требуется, пока строка не реализована.
const OnRequest = -1

// Part — часть строки со своим этапом: «оповещение — 3».
type Part struct {
	Name  string
	Stage int
}

// Row — строка матрицы обнаружения.
type Row struct {
	ID    string // «DM-07»
	What  string // что выявляется, кратко
	Stage int    // этап основной части или OnRequest
	Parts []Part // части с отдельными этапами
}

var (
	rowIDRe   = regexp.MustCompile(`^DM-(\d{2})$`)
	baseRe    = regexp.MustCompile(`^(\d)( частично)?$`)
	partRe    = regexp.MustCompile(`^(.+?) — (\d)$`)
	maxMatrix = 4 << 20
)

// Заголовки, между которыми лежит матрица в ТЗ.
const (
	matrixStart = "### 5.16 "
	matrixEnd   = "### 5.17 "
)

// ParseMatrix извлекает строки матрицы 5.16 из текста ТЗ.
func ParseMatrix(spec string) ([]Row, error) {
	if len(spec) > maxMatrix {
		return nil, fmt.Errorf("ТЗ больше %d байт", maxMatrix)
	}
	start := strings.Index(spec, matrixStart)
	if start < 0 {
		return nil, fmt.Errorf("в ТЗ нет раздела %q", strings.TrimSpace(matrixStart))
	}
	section := spec[start:]
	if end := strings.Index(section, matrixEnd); end >= 0 {
		section = section[:end]
	}
	var rows []Row
	var errs []error
	seen := map[string]bool{}
	for n, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| DM-") {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) != 7 {
			errs = append(errs, fmt.Errorf("строка %d раздела 5.16: ожидается 7 колонок, получено %d", n+1, len(cells)))
			continue
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		id := cells[0]
		if !rowIDRe.MatchString(id) {
			errs = append(errs, fmt.Errorf("строка %d раздела 5.16: неверный ID %q", n+1, id))
			continue
		}
		if seen[id] {
			errs = append(errs, fmt.Errorf("%s: ID повторяется в матрице", id))
			continue
		}
		seen[id] = true
		stage, parts, err := ParseStage(cells[4])
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		what := cells[1]
		if i := strings.Index(what, ":"); i > 0 {
			what = what[:i]
		}
		rows = append(rows, Row{ID: id, What: what, Stage: stage, Parts: parts})
	}
	if len(rows) == 0 && len(errs) == 0 {
		errs = append(errs, errors.New("в разделе 5.16 нет строк матрицы"))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, errors.Join(errs...)
}

// ParseStage разбирает колонку «Этап»: «1», «5», «по запросу», «1 частично»,
// «1; оповещение — 3; ML — 4».
func ParseStage(cell string) (int, []Part, error) {
	items := strings.Split(cell, ";")
	base := strings.TrimSpace(items[0])
	var stage int
	switch {
	case base == "по запросу":
		stage = OnRequest
	case baseRe.MatchString(base):
		n, err := strconv.Atoi(baseRe.FindStringSubmatch(base)[1])
		if err != nil {
			return 0, nil, err
		}
		stage = n
	default:
		return 0, nil, fmt.Errorf("не разобран этап %q", cell)
	}
	var parts []Part
	for _, it := range items[1:] {
		m := partRe.FindStringSubmatch(strings.TrimSpace(it))
		if m == nil {
			return 0, nil, fmt.Errorf("не разобрана часть этапа %q (ожидается «название — N»)", strings.TrimSpace(it))
		}
		n, err := strconv.Atoi(m[2])
		if err != nil {
			return 0, nil, err
		}
		if stage != OnRequest && n <= stage {
			return 0, nil, fmt.Errorf("часть %q с этапом %d не позже основного этапа %d", m[1], n, stage)
		}
		parts = append(parts, Part{Name: m[1], Stage: n})
	}
	return stage, parts, nil
}
