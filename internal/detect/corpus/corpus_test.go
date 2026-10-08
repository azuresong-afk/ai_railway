package corpus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// wordDetector находит слово «секрет» (test.secret) и, в тексте ответа,
// слово «пароль» (test.password).
type wordDetector struct{}

func (wordDetector) ID() string      { return "test" }
func (wordDetector) Version() string { return "1.0.0" }
func (wordDetector) Directions() []detect.Direction {
	return []detect.Direction{detect.Input, detect.Output}
}
func (wordDetector) Detect(_ context.Context, t detect.Text) ([]detect.Finding, error) {
	var out []detect.Finding
	for word, cat := range map[string]string{"секрет": "test.secret", "пароль": "test.password"} {
		if i := strings.Index(t.Text, word); i >= 0 {
			out = append(out, detect.Finding{Detector: "test", Version: "1.0.0", Category: cat, Threat: "DM-31", Score: 0.9, Start: i, End: i + len(word)})
		}
	}
	return out, nil
}

const sample = `{"id":"p1","lang":"ru","direction":"input","source":"user","text":"это секрет","expect":["test.secret"]}
{"id":"p2","lang":"ru","direction":"input","text":"тут ничего","expect":["test.secret"],"note":"пропуск"}

{"id":"n1","lang":"ru","direction":"output","text":"мой пароль простой","expect":[]}
{"id":"n2","lang":"en","direction":"input","text":"nothing here","expect":[]}
`

func TestEvaluate(t *testing.T) {
	ss, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Evaluate(context.Background(), wordDetector{}, ss, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// p1 — TP, p2 — FN, n1 — FP по test.password, n2 — без находок.
	if rep.Samples != 4 || rep.Total != (Counts{TP: 1, FP: 1, FN: 1}) || rep.Total.Precision() != 0.5 || rep.Total.Recall() != 0.5 {
		t.Fatalf("%+v", rep)
	}
	if rep.ByCategory["test.secret"] != (Counts{TP: 1, FN: 1}) || rep.ByCategory["test.password"] != (Counts{FP: 1}) {
		t.Fatalf("по категориям: %+v", rep.ByCategory)
	}
	if strings.Join(rep.FalsePos, ",") != "n1" || strings.Join(rep.Missed, ",") != "p2" || len(rep.Errors) != 0 {
		t.Fatalf("%+v", rep)
	}
	if (Counts{}).Precision() != 1 || (Counts{}).Recall() != 1 {
		t.Fatal("пустые счётчики")
	}
}

func TestParseRejects(t *testing.T) {
	ok := `{"id":"a","direction":"input","text":"x","expect":[]}`
	for name, line := range map[string]string{
		"не JSON":         `{`,
		"лишнее поле":     `{"id":"a","direction":"input","text":"x","expect":[],"extra":1}`,
		"id":              strings.Replace(ok, `"a"`, `"A B"`, 1),
		"direction":       strings.Replace(ok, `"input"`, `"both"`, 1),
		"lang":            strings.Replace(ok, `"id"`, `"lang":"de","id"`, 1),
		"source":          strings.Replace(ok, `"id"`, `"source":"web","id"`, 1),
		"пустой текст":    strings.Replace(ok, `"x"`, `""`, 1),
		"категория":       strings.Replace(ok, `[]`, `["snils"]`, 1),
		"длинный текст":   strings.Replace(ok, `"x"`, `"`+strings.Repeat("x", MaxTextBytes+1)+`"`, 1),
		"два объекта":     ok + ok,
		"слишком длинная": `{"id":"a","direction":"input","text":"` + strings.Repeat("я", MaxLineBytes) + `","expect":[]}`,
	} {
		if _, err := Parse(strings.NewReader(line)); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
	if ss, err := Parse(strings.NewReader(ok)); err != nil || len(ss) != 1 {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("пустой каталог принят")
	}
	write := func(name, s string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.jsonl", sample)
	write("b.jsonl", `{"id":"x1","direction":"input","text":"x","expect":[]}`)
	write("readme.md", "не корпус")
	ss, err := Load(dir)
	if err != nil || len(ss) != 5 {
		t.Fatalf("%d %v", len(ss), err)
	}
	write("c.jsonl", `{"id":"p1","direction":"input","text":"x","expect":[]}`)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "p1") {
		t.Fatalf("повтор id: %v", err)
	}
}

// Разбор корпуса — цель фаззинга (ТЗ, 8.5): без паники, принятые примеры
// проходят проверку схемы.
func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Add(`{"id":"a","direction":"output","text":"x","expect":["a.b"]}`)
	f.Fuzz(func(t *testing.T, in string) {
		ss, err := Parse(strings.NewReader(in))
		if err != nil {
			return
		}
		for _, s := range ss {
			if err := s.validate(); err != nil {
				t.Fatalf("принят неверный пример: %v", err)
			}
		}
	})
}
