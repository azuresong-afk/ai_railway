package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

type wordDetector struct{ version string }

func (d wordDetector) ID() string                   { return "test.word" }
func (d wordDetector) Version() string              { return d.version }
func (wordDetector) Directions() []detect.Direction { return []detect.Direction{detect.Input} }
func (d wordDetector) Detect(_ context.Context, t detect.Text) ([]detect.Finding, error) {
	if i := strings.Index(t.Text, "секрет"); i >= 0 {
		return []detect.Finding{{Detector: d.ID(), Version: d.version, Category: "test.secret", Threat: "DM-31", Score: 1, Start: i, End: i + len("секрет")}}, nil
	}
	return nil, nil
}

const corpusData = `{"id":"p1","direction":"input","text":"секрет","expect":["test.secret"]}
{"id":"p2","direction":"input","text":"скрытое","expect":["test.secret"]}
{"id":"n1","direction":"input","text":"обычный текст","expect":[]}
`

func docWith(rows ...string) string {
	return "# Детекторы\n\n## Детекторы\n| ID | Версия | Направления | Строки матрицы | Корпус | Точность | Полнота | Порог регрессии |\n" +
		"|---|---|---|---|---|---|---|---|\n" + strings.Join(rows, "\n") + "\n\n## Бенчмарки\n| a | b |\n"
}

func setup(t *testing.T, doc string) (docPath, corpusDir, out string) {
	t.Helper()
	dir := t.TempDir()
	docPath, corpusDir, out = filepath.Join(dir, "detectors.md"), filepath.Join(dir, "corpus"), filepath.Join(dir, "out", "q.md")
	if err := os.MkdirAll(filepath.Join(corpusDir, "test.word"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corpusDir, "test.word", "a.jsonl"), []byte(corpusData), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(docPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return docPath, corpusDir, out
}

func TestRun(t *testing.T) {
	d := wordDetector{version: "1.0.0"}
	// Точность 1, полнота 0,5 на корпусе.
	cases := []struct {
		name, row string
		dets      []detect.Detector
		problem   string
	}{
		{"ок", "| `test.word` | 1.0.0 | вход | DM-31 | 3 | 1,00 | 0,50 | 0,02 |", []detect.Detector{d}, ""},
		{"регрессия", "| `test.word` | 1.0.0 | вход | DM-31 | 3 | 1,00 | 0,60 | 0,05 |", []detect.Detector{d}, "полнота 0.500"},
		{"в пределах порога", "| `test.word` | 1.0.0 | вход | DM-31 | 3 | 1,00 | 0,52 | 0,05 |", []detect.Detector{d}, ""},
		{"не зафиксировано", "| `test.word` | 1.0.0 | вход | DM-31 | 3 | — | — | 0,05 |", []detect.Detector{d}, "зафиксируйте"},
		{"версия", "| `test.word` | 0.9.0 | вход | DM-31 | 3 | 1,00 | 0,50 | 0,02 |", []detect.Detector{d}, "версия в таблице 0.9.0"},
		{"нет в коде", "| `test.word` | 1.0.0 | вход | DM-31 | 3 | 1,00 | 0,50 | 0,02 |", nil, "которого нет в коде"},
		{"нет в таблице", "", []detect.Detector{d}, "нет в таблице"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, corp, out := setup(t, docWith(c.row))
			err := run(doc, corp, out, c.dets)
			if c.problem == "" && err != nil {
				t.Fatal(err)
			}
			if c.problem != "" && (err == nil || !strings.Contains(err.Error(), c.problem)) {
				t.Fatalf("ожидалась проблема %q: %v", c.problem, err)
			}
			if _, serr := os.Stat(out); serr != nil {
				t.Fatalf("отчёт не записан: %v", serr)
			}
		})
	}
	// Нет корпуса.
	doc, corp, out := setup(t, docWith("| `test.word` | 1.0.0 | вход | DM-31 | 3 | 1,00 | 0,50 | 0,02 |"))
	if err := os.RemoveAll(filepath.Join(corp, "test.word")); err != nil {
		t.Fatal(err)
	}
	if err := run(doc, corp, out, []detect.Detector{d}); err == nil || !strings.Contains(err.Error(), "корпус") {
		t.Fatalf("без корпуса: %v", err)
	}
}

func TestParseTable(t *testing.T) {
	rows, err := ParseTable(docWith("| `a.b` | 1.2.3 | вход | DM-31 | x | 0.98 | 0,9 | 0,02 |", "| c | 1.0.0 | выход | DM-13 | x | — | — | 0,02 |"))
	if err != nil {
		t.Fatal(err)
	}
	if r := rows["a.b"]; r.Version != "1.2.3" || r.Precision != 0.98 || r.Recall != 0.9 || r.Threshold != 0.02 || !r.Fixed || rows["c"].Fixed {
		t.Fatalf("%+v", rows)
	}
	for name, doc := range map[string]string{
		"нет раздела":  "# x\n",
		"заголовок":    strings.Replace(docWith(), "Точность", "Precision", 1),
		"колонки":      docWith("| a | 1 | 2 |"),
		"число":        docWith("| a | 1.0.0 | в | DM-31 | x | много | 0,9 | 0,02 |"),
		"больше 1":     docWith("| a | 1.0.0 | в | DM-31 | x | 1,5 | 0,9 | 0,02 |"),
		"дубль строки": docWith("| a | 1.0.0 | в | DM-31 | x | 1 | 1 | 0 |", "| a | 1.0.0 | в | DM-31 | x | 1 | 1 | 0 |"),
	} {
		if _, err := ParseTable(doc); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
	// Настоящий документ разбирается.
	raw, err := os.ReadFile("../../docs/detectors.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTable(string(raw)); err != nil {
		t.Fatalf("docs/detectors.md: %v", err)
	}
}

// Разбор таблицы детекторов — цель фаззинга (ТЗ, 8.5).
func FuzzParseTable(f *testing.F) {
	f.Add(docWith("| `a.b` | 1.2.3 | вход | DM-31 | x | 0.98 | 0,9 | 0,02 |"))
	f.Add("\n## Детекторы\n|")
	f.Fuzz(func(t *testing.T, doc string) {
		rows, err := ParseTable(doc)
		if err != nil {
			return
		}
		for id, r := range rows {
			if r.ID != id || r.Precision < 0 || r.Precision > 1 || r.Recall < 0 || r.Recall > 1 || r.Threshold < 0 || r.Threshold > 1 {
				t.Fatalf("%+v", r)
			}
		}
	})
}
