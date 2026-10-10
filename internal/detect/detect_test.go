package detect

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// fakeDetector находит слово «секрет» (категория test.secret) или ведёт себя
// как задано: зависает, паникует, возвращает ошибку или неверную находку.
type fakeDetector struct {
	id   string
	dirs []Direction
	mode string
}

func (f fakeDetector) ID() string      { return f.id }
func (f fakeDetector) Version() string { return "1.0.0" }
func (f fakeDetector) Directions() []Direction {
	if f.dirs == nil {
		return []Direction{Input, Output}
	}
	return f.dirs
}

func (f fakeDetector) Detect(ctx context.Context, t Text) ([]Finding, error) {
	switch f.mode {
	case "hang":
		time.Sleep(time.Second) // не смотрит на контекст
	case "panic":
		panic("секрет из текста")
	case "error":
		return nil, errors.New("сбой")
	case "bad":
		return []Finding{{Detector: f.id, Version: "1.0.0", Category: "test.secret", Threat: "DM-31", Score: 1, Start: 0, End: len(t.Text) + 1}}, nil
	}
	var out []Finding
	if i := strings.Index(t.Text, "секрет"); i >= 0 {
		out = append(out, Finding{Detector: f.id, Version: "1.0.0", Category: "test.secret", Threat: "DM-31", Score: 0.9, Start: i, End: i + len("секрет"), Rule: "word"})
	}
	return out, nil
}

func TestNewRegistryValidation(t *testing.T) {
	if _, err := NewRegistry(fakeDetector{id: "pii.ru"}, fakeDetector{id: "secrets"}); err != nil {
		t.Fatal(err)
	}
	for name, ds := range map[string][]Detector{
		"дубль":        {fakeDetector{id: "a"}, fakeDetector{id: "a"}},
		"ID":           {fakeDetector{id: "Pii.RU"}},
		"пустой ID":    {fakeDetector{id: ""}},
		"направлений":  {fakeDetector{id: "a", dirs: []Direction{}}},
		"точка в ID":   {fakeDetector{id: "a..b"}},
		"версия знака": {badVersion{fakeDetector{id: "a"}}},
	} {
		if _, err := NewRegistry(ds...); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

type badVersion struct{ fakeDetector }

func (badVersion) Version() string { return "v1" }

func TestRegistryRun(t *testing.T) {
	r, err := NewRegistry(
		fakeDetector{id: "ok"}, fakeDetector{id: "outonly", dirs: []Direction{Output}},
		fakeDetector{id: "hang", mode: "hang"}, fakeDetector{id: "panic", mode: "panic"},
		fakeDetector{id: "err", mode: "error"}, fakeDetector{id: "bad", mode: "bad"},
	)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	fs, errs, err := r.Run(context.Background(), r.IDs(), Text{Text: "это секрет", Direction: Input}, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	// Детекторы работают параллельно: общее время — около срока, а не сумма.
	if el := time.Since(start); el > 600*time.Millisecond {
		t.Fatalf("запуск занял %s", el)
	}
	if len(fs) != 1 || fs[0].Detector != "ok" || "это секрет"[fs[0].Start:fs[0].End] != "секрет" {
		t.Fatalf("находки: %+v", fs)
	}
	got := map[string]string{}
	for _, e := range errs {
		got[e.Detector] = e.Err.Error()
	}
	if len(got) != 4 || got["hang"] != ErrDetectorTimeout.Error() || got["err"] != "сбой" || got["bad"] == "" ||
		strings.Contains(got["panic"], "секрет") {
		t.Fatalf("сбои: %v", got)
	}
	if _, ok := got["outonly"]; ok {
		t.Fatal("детектор только для ответа запущен на запросе")
	}
	if _, _, err := r.Run(context.Background(), []string{"нет"}, Text{Direction: Input}, time.Second); err == nil {
		t.Fatal("неизвестный детектор принят")
	}
	if d, ok := r.Get("ok"); !ok || d.ID() != "ok" {
		t.Fatal("Get")
	}
}

func TestValidateFinding(t *testing.T) {
	d := fakeDetector{id: "a"}
	ok := Finding{Detector: "a", Version: "1.0.0", Category: "pii.snils", Threat: "DM-31", Score: 0.5, Start: 1, End: 3}
	if err := ValidateFinding(ok, d, 3); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Finding){
		"детектор":    func(f *Finding) { f.Detector = "b" },
		"версия":      func(f *Finding) { f.Version = "2.0.0" },
		"категория":   func(f *Finding) { f.Category = "snils" },
		"угроза":      func(f *Finding) { f.Threat = "DM-1" },
		"оценка > 1":  func(f *Finding) { f.Score = 1.01 },
		"оценка NaN":  func(f *Finding) { f.Score = math.NaN() },
		"начало < 0":  func(f *Finding) { f.Start = -1 },
		"конец > len": func(f *Finding) { f.End = 4 },
		"конец < нач": func(f *Finding) { f.Start, f.End = 2, 1 },
		"правило":     func(f *Finding) { f.Rule = "Правило с пробелом" },
	} {
		f := ok
		mod(&f)
		if err := ValidateFinding(f, d, 3); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

// Накладные расходы реестра на запуск одного быстрого детектора (горутина и
// таймер): часть бюджета p95 ≤ 30 мс (ТЗ, 5.1).
func BenchmarkRegistryRun(b *testing.B) {
	r, err := NewRegistry(fakeDetector{id: "a"}, fakeDetector{id: "b"}, fakeDetector{id: "c"})
	if err != nil {
		b.Fatal(err)
	}
	text := Text{Text: strings.Repeat("обычный текст без находок ", 300), Direction: Input}
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := r.Run(context.Background(), r.IDs(), text, time.Second); err != nil {
			b.Fatal(err)
		}
	}
}
