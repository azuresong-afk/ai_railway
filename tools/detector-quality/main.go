// Команда detector-quality проверяет качество встроенных детекторов на
// корпусах (ТЗ, 5.2): считает точность и полноту по testdata/corpus/<ID>/ и
// сверяет их с таблицей «Детекторы» в docs/detectors.md. Падает, если
// метрика ниже зафиксированной больше чем на порог регрессии, если у
// детектора нет строки в таблице или корпуса, если в таблице есть детектор,
// которого нет в коде, или если версия в таблице не совпадает с кодом.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/corpus"
)

func main() {
	doc := flag.String("doc", "docs/detectors.md", "документ с таблицей детекторов")
	corpusDir := flag.String("corpus", "testdata/corpus", "каталог корпусов")
	out := flag.String("out", "build/detector-quality.md", "куда записать отчёт")
	flag.Parse()
	if err := run(*doc, *corpusDir, *out, builtin.All()); err != nil {
		fmt.Fprintln(os.Stderr, "detector-quality:", err)
		os.Exit(1)
	}
}

// Row — строка таблицы детекторов.
type Row struct {
	ID, Version         string
	Precision, Recall   float64
	Threshold           float64
	PrecisionSet, Fixed bool // метрики зафиксированы (не «—»)
}

const maxDoc = 4 << 20

// ParseTable читает таблицу «## Детекторы» документа.
func ParseTable(doc string) (map[string]Row, error) {
	start := strings.Index(doc, "\n## Детекторы\n")
	if start < 0 {
		return nil, errors.New("нет раздела «## Детекторы»")
	}
	section := doc[start+1:]
	if end := strings.Index(section[3:], "\n## "); end >= 0 {
		section = section[:end+3]
	}
	rows := map[string]Row{}
	header := true
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if header {
			if len(cells) != 8 || cells[0] != "ID" || cells[5] != "Точность" || cells[6] != "Полнота" || cells[7] != "Порог регрессии" {
				return nil, errors.New("заголовок таблицы: ID | Версия | Направления | Строки матрицы | Корпус | Точность | Полнота | Порог регрессии")
			}
			header = false
			continue
		}
		if strings.HasPrefix(cells[0], "---") {
			continue
		}
		if len(cells) != 8 {
			return nil, fmt.Errorf("строка %q: ожидается 8 колонок", line)
		}
		r := Row{ID: strings.Trim(cells[0], "`"), Version: cells[1]}
		var err error
		if r.Precision, r.PrecisionSet, err = metric(cells[5]); err != nil {
			return nil, fmt.Errorf("%s: точность: %w", r.ID, err)
		}
		var recallSet bool
		if r.Recall, recallSet, err = metric(cells[6]); err != nil {
			return nil, fmt.Errorf("%s: полнота: %w", r.ID, err)
		}
		if r.Threshold, _, err = metric(cells[7]); err != nil {
			return nil, fmt.Errorf("%s: порог: %w", r.ID, err)
		}
		r.Fixed = r.PrecisionSet && recallSet
		if _, dup := rows[r.ID]; dup {
			return nil, fmt.Errorf("детектор %s в таблице дважды", r.ID)
		}
		rows[r.ID] = r
	}
	return rows, nil
}

// metric — число 0–1 с запятой или точкой; «—» — ещё не зафиксировано.
func metric(s string) (float64, bool, error) {
	if s == "—" || s == "-" || s == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseFloat(strings.Replace(s, ",", ".", 1), 64)
	if err != nil || v < 0 || v > 1 {
		return 0, false, fmt.Errorf("%q — число от 0 до 1", s)
	}
	return v, true, nil
}

func run(docPath, corpusDir, out string, dets []detect.Detector) error {
	raw, err := readLimited(docPath)
	if err != nil {
		return err
	}
	rows, err := ParseTable(string(raw))
	if err != nil {
		return fmt.Errorf("%s: %w", docPath, err)
	}
	var problems []string
	var report strings.Builder
	report.WriteString("# Качество детекторов на корпусах\n\n| ID | Примеров | Точность | Полнота | Зафиксировано | Порог | Итог |\n|---|---|---|---|---|---|---|\n")
	seen := map[string]bool{}
	for _, d := range dets {
		seen[d.ID()] = true
		row, ok := rows[d.ID()]
		if !ok {
			problems = append(problems, fmt.Sprintf("детектора %s нет в таблице %s", d.ID(), docPath))
			continue
		}
		if row.Version != d.Version() {
			problems = append(problems, fmt.Sprintf("%s: версия в таблице %s, в коде %s", d.ID(), row.Version, d.Version()))
		}
		samples, err := corpus.Load(filepath.Join(corpusDir, d.ID()))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: корпус: %v", d.ID(), err))
			continue
		}
		rep, err := corpus.Evaluate(context.Background(), d, samples, 5*time.Second)
		if err != nil {
			return err
		}
		p, r := rep.Total.Precision(), rep.Total.Recall()
		verdict := "ок"
		switch {
		case len(rep.Errors) > 0:
			verdict = "сбои детектора"
			problems = append(problems, fmt.Sprintf("%s: сбои на примерах %s", d.ID(), strings.Join(rep.Errors, ", ")))
		case !row.Fixed:
			verdict = "метрики не зафиксированы"
			problems = append(problems, fmt.Sprintf("%s: зафиксируйте в таблице точность %.3f и полноту %.3f", d.ID(), p, r))
		case p < row.Precision-row.Threshold || r < row.Recall-row.Threshold:
			verdict = "регрессия"
			problems = append(problems, fmt.Sprintf("%s: точность %.3f (было %.3f), полнота %.3f (было %.3f), порог %.3f",
				d.ID(), p, row.Precision, r, row.Recall, row.Threshold))
		}
		fmt.Fprintf(&report, "| `%s` | %d | %.3f | %.3f | %.3f / %.3f | %.3f | %s |\n", d.ID(), rep.Samples, p, r, row.Precision, row.Recall, row.Threshold, verdict)
		writeDetails(&report, rep)
	}
	for id := range rows {
		if !seen[id] {
			problems = append(problems, fmt.Sprintf("в таблице %s детектор %s, которого нет в коде (internal/detect/builtin)", docPath, id))
		}
	}
	sort.Strings(problems)
	if len(dets) == 0 {
		report.WriteString("\nВстроенных детекторов пока нет.\n")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(out, []byte(report.String()), 0o600); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(os.Stdout, "detector-quality: детекторов %d, проблем %d (%s)\n", len(dets), len(problems), out); err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New("проверка качества не пройдена:\n" + strings.Join(problems, "\n"))
	}
	return nil
}

func writeDetails(b *strings.Builder, rep *corpus.Report) {
	cats := make([]string, 0, len(rep.ByCategory))
	for c := range rep.ByCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	fmt.Fprintf(b, "\n<details><summary>%s: по категориям, наибольшее время %s</summary>\n\n| Категория | TP | FP | FN | Точность | Полнота |\n|---|---|---|---|---|---|\n",
		rep.Detector, rep.MaxDuration.Round(time.Microsecond))
	for _, c := range cats {
		x := rep.ByCategory[c]
		fmt.Fprintf(b, "| %s | %d | %d | %d | %.3f | %.3f |\n", c, x.TP, x.FP, x.FN, x.Precision(), x.Recall())
	}
	fmt.Fprintf(b, "\nЛожные срабатывания: %s\n\nПропуски: %s\n\n</details>\n\n", list(rep.FalsePos), list(rep.Missed))
}

func list(ids []string) string {
	if len(ids) == 0 {
		return "нет"
	}
	return strings.Join(ids, ", ")
}

func readLimited(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxDoc {
		return nil, fmt.Errorf("%s больше %d байт", path, maxDoc)
	}
	return os.ReadFile(path) //nolint:gosec // G304: путь к документу задаёт Makefile
}
