package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDistance(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"", "", 0}, {"abc", "", 3}, {"", "абв", 3}, {"кот", "кит", 1}, {"ИНН", "ИHH", 2}, {"абв", "абвг", 1}, {"kitten", "sitting", 3},
	} {
		if got := distance(tc.a, tc.b); got != tc.want {
			t.Errorf("distance(%q, %q) = %d, ожидалось %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	if got := normalize("  I кв. 41   II кв. 57 \n\n\tитого \n"); got != "I кв. 41 II кв. 57\nитого" {
		t.Fatalf("%q", got)
	}
}

// Подпись и значение в отдельных рамках на одной высоте — одна строка.
func TestReadingOrder(t *testing.T) {
	ls := []line{
		{Text: "14.06.1991", Box: [4]int{300, 102, 120, 26}},
		{Text: "Дата рождения:", Box: [4]int{40, 100, 200, 30}},
		{Text: "Карточка клиента", Box: [4]int{40, 20, 300, 40}},
		{Text: "Паспорт:", Box: [4]int{40, 140, 120, 30}},
		{Text: "00 38 365207", Box: [4]int{300, 141, 150, 28}},
	}
	want := "Карточка клиента\nДата рождения: 14.06.1991\nПаспорт: 00 38 365207"
	if got := readingOrder(ls); got != want {
		t.Fatalf("%q", got)
	}
	if readingOrder(nil) != "" {
		t.Fatal("пустой список")
	}
}

func TestQuantile(t *testing.T) {
	v := []float64{5, 1, 4, 2, 3}
	if quantile(v, 0.5) != 3 || quantile(v, 0.95) != 5 || quantile(nil, 0.5) != 0 {
		t.Fatal(quantile(v, 0.5), quantile(v, 0.95))
	}
}

// Отчёт по корпусу: распознанный текст, равный эталону, даёт CER 0 и все
// ожидаемые находки OCR без ложных.
func TestReportPerfectEngine(t *testing.T) {
	corpus := filepath.Join("..", "..", "testdata", "corpus", "media")
	samples, err := loadSamples(corpus)
	if err != nil {
		t.Fatal(err)
	}
	rf := runFile{Threads: 4, CPUs: []int{0, 1, 2, 3}}
	for _, id := range []string{"card-01", "scan-04", "clean-01"} {
		var ls []line
		for i, l := range strings.Split(samples[id].ref, "\n") {
			ls = append(ls, line{Text: l, Score: 1, Box: [4]int{10, 10 + 40*i, 500, 30}})
		}
		p := pass{Lines: ls, MS: 100}
		rf.Images = append(rf.Images, runImage{ID: id, Engines: map[string]map[string]pass{"ideal": {passNormal: p, passContrast: p}}})
	}
	dir := t.TempDir()
	b, err := json.Marshal(rf)
	if err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(dir, "run.json")
	if err := os.WriteFile(run, b, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "report.md")
	if err := report(run, corpus, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out) //nolint:gosec // G304: временный каталог теста
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "| ideal | 0.0 % | 0.0 % | — | — | 1/1 | 5/5 | 0 | 200 / 200 | — |") {
		t.Fatalf("отчёт:\n%s", got)
	}
}

func TestReportRejects(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "run.json")
	if err := os.WriteFile(bad, []byte(`{"images":[{"id":"нет-такого","engines":{}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	corpus := filepath.Join("..", "..", "testdata", "corpus", "media")
	if err := report(bad, corpus, ""); err == nil {
		t.Fatal("неизвестное изображение принято")
	}
	if err := report("", corpus, ""); err == nil {
		t.Fatal("без -run")
	}
}

// FuzzReadingOrder — сборка строк из рамок распознавания (итог run_ocr.py):
// без паники, результат нормализован и содержит все непустые слова.
func FuzzReadingOrder(f *testing.F) {
	f.Add("Дата рождения:", 40, 100, 200, 30, "14.06.1991", 300, 102, 120, 26)
	f.Add("", 0, 0, 0, 0, " ", -5, -5, -1, -1)
	f.Fuzz(func(t *testing.T, t1 string, x1, y1, w1, h1 int, t2 string, x2, y2, w2, h2 int) {
		ls := []line{{Text: t1, Box: [4]int{x1, y1, w1, h1}}, {Text: t2, Box: [4]int{x2, y2, w2, h2}}}
		got := readingOrder(ls)
		if normalize(got) != got {
			t.Fatalf("не нормализовано: %q", got)
		}
		words := strings.Fields(got)
		for _, w := range append(strings.Fields(t1), strings.Fields(t2)...) {
			found := false
			for _, g := range words {
				if g == w {
					found = true
				}
			}
			if !found {
				t.Fatalf("потеряно слово %q: %q", w, got)
			}
		}
	})
}
