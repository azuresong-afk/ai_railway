package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Разметка корпуса pii.ner: границы сущностей в символах указывают на
// подставленные значения, примеры детерминированы, повторов нет.
func TestNERSpans(t *testing.T) {
	var a, b strings.Builder
	if err := runNER(&a, "train", "spans", 1, 300); err != nil {
		t.Fatal(err)
	}
	if err := runNER(&b, "train", "spans", 1, 300); err != nil || a.String() != b.String() {
		t.Fatal("корпус не детерминирован")
	}
	labels := map[string]int{}
	texts := map[string]bool{}
	for line := range strings.Lines(a.String()) {
		var r struct {
			Text     string  `json:"text"`
			Entities [][]any `json:"entities"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if texts[r.Text] {
			t.Fatalf("повтор: %q", r.Text)
		}
		texts[r.Text] = true
		rs := []rune(r.Text)
		prev := 0
		for _, e := range r.Entities {
			s, end, l := int(e[0].(float64)), int(e[1].(float64)), e[2].(string)
			if s < prev || end <= s || end > len(rs) {
				t.Fatalf("%q: сущность %v", r.Text, e)
			}
			frag := string(rs[s:end])
			if frag != strings.TrimSpace(frag) || strings.ContainsAny(frag[:1], ",.") {
				t.Fatalf("%q: границы %q", r.Text, frag)
			}
			labels[l]++
			prev = end
		}
	}
	for _, l := range []string{"per", "org", "addr", "loc"} {
		if labels[l] == 0 {
			t.Errorf("нет сущностей %s: %v", l, labels)
		}
	}
	for _, bad := range [][2]string{{"dev", "spans"}, {"train", "csv"}} {
		if err := runNER(&a, bad[0], bad[1], 1, 1); err == nil {
			t.Errorf("%v: ожидалась ошибка", bad)
		}
	}
}

// Проверочная часть не видит словарей обучения: ни имя, ни фамилия, ни
// организация, ни город части train не встречаются в части check.
func TestNERSplitsDisjoint(t *testing.T) {
	var b strings.Builder
	if err := runNER(&b, "check", "spans", 1, 300); err != nil {
		t.Fatal(err)
	}
	// Только размеченные фрагменты: «Роман» в «Роман состоит из трёх
	// частей» — не имя.
	var frags strings.Builder
	for line := range strings.Lines(b.String()) {
		var r struct {
			Text     string  `json:"text"`
			Entities [][]any `json:"entities"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		for _, e := range r.Entities {
			frags.WriteString(" " + string([]rune(r.Text)[int(e[0].(float64)):int(e[1].(float64))]) + "\n")
		}
	}
	check := frags.String()
	var words []string
	words = append(words, nerTrain.male...)
	words = append(words, nerTrain.female...)
	words = append(words, nerTrain.surOv...)
	words = append(words, nerTrain.surEnko...)
	words = append(words, nerTrain.orgs...)
	words = append(words, nerTrain.towns...)
	words = append(words, nerTrain.streets...)
	for _, w := range words {
		if strings.Contains(check, w) {
			t.Errorf("%q из обучения — в проверочной части", w)
		}
	}
	for _, w := range append(append([]string{}, nerTrain.surSky...), nerTrain.patr...) {
		if strings.Contains(check, " "+w) {
			t.Errorf("основа %q из обучения — в проверочной части", w)
		}
	}
}

// testdata/corpus/pii.ner/validation.jsonl — вывод synth-pii -kind ner
// -split check -format corpus -n 300 (корпус воспроизводим).
func TestNERCorpusUpToDate(t *testing.T) {
	var b strings.Builder
	if err := runNER(&b, "check", "corpus", 1, 300); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("../../testdata/corpus/pii.ner/validation.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // только чтение
	var got strings.Builder
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		got.WriteString(sc.Text() + "\n")
	}
	if got.String() != b.String() {
		t.Fatal("корпус устарел: go run ./tools/synth-pii -kind ner -split check -format corpus -n 300 > testdata/corpus/pii.ner/validation.jsonl")
	}
}
