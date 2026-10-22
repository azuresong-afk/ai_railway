package policy

import (
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const sample = `id: support-strict
name: Бот поддержки — строго
version: 2
mode: enforce
non_text: allow_inline
response_check: buffered
block_message: Запрос отклонён. Обратитесь в поддержку.
rules:
  - id: injection-rag
    detector: injection.heuristic
    directions: [input]
    sources: [rag, tool]
    threshold: 0.4
    action: block
    severity: high
    message: Документ не прошёл проверку.
  - id: cards
    detector: pii.ru
    directions: [input]
    categories: [pii.card, pii.account]
    action: pseudonymize
    severity: medium
`

func TestParseSample(t *testing.T) {
	s, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "support-strict" || s.Version != 2 || s.NonText != NonTextAllowInline || len(s.Rules) != 2 ||
		*s.Rules[0].Threshold != 0.4 || s.Rules[1].threshold() != DefaultThreshold || s.Rules[1].Categories[1] != "pii.account" {
		t.Fatalf("разбор: %+v", s)
	}
	if _, err := Compile(s, catalog(t)); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string][2]string{
		"неизвестное поле":      {"version: 2\n", "version: 2\noverrides: []\n"},
		"неизвестное в правиле": {"    severity: high\n", "    severity: high\n    enabled: true\n"},
		"id":                           {"id: support-strict", "id: Support Strict"},
		"пустое имя":                   {"name: Бот поддержки — строго", "name: \" \""},
		"длинное имя":                  {"name: Бот поддержки — строго", "name: " + strings.Repeat("я", MaxNameLen+1)},
		"управляющий символ":           {"name: Бот поддержки — строго", `name: "Бот\u0007"`},
		"скрытый символ":               {"message: Документ не прошёл проверку.", "message: \"Документ\\u200b\""},
		"версия":                       {"version: 2", "version: 0"},
		"режим":                        {"mode: enforce", "mode: audit"},
		"non_text":                     {"non_text: allow_inline", "non_text: allow"},
		"response_check":               {"response_check: buffered", "response_check: async"},
		"порог 0":                      {"threshold: 0.4", "threshold: 0"},
		"порог больше 1":               {"threshold: 0.4", "threshold: 1.5"},
		"порог NaN":                    {"threshold: 0.4", "threshold: .nan"},
		"порог строкой":                {"threshold: 0.4", "threshold: high"},
		"действие":                     {"action: block", "action: drop"},
		"require_approval":             {"action: block", "action: require_approval"},
		"серьёзность":                  {"severity: high", "severity: severe"},
		"направление":                  {"directions: [input]\n    sources", "directions: [inbound]\n    sources"},
		"повтор направления":           {"directions: [input]\n    sources", "directions: [input, input]\n    sources"},
		"источник":                     {"sources: [rag, tool]", "sources: [web]"},
		"категория":                    {"categories: [pii.card, pii.account]", "categories: [card]"},
		"повтор категории":             {"categories: [pii.card, pii.account]", "categories: [pii.card, pii.card]"},
		"детектор":                     {"detector: pii.ru", "detector: PII"},
		"повтор правила":               {"id: cards", "id: injection-rag"},
		"pseudonymize в ответе":        {"    directions: [input]\n    categories", "    directions: [input, output]\n    categories"},
		"pseudonymize без направлений": {"    directions: [input]\n    categories", "    categories"},
		"два документа":                {"version: 2\n", "version: 2\n---\nid: x\n"},
		"не YAML":                      {"rules:", "rules: ["},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(sample, c[0]) {
				t.Fatalf("образец не содержит %q", c[0])
			}
			if _, err := Parse(strings.NewReader(strings.Replace(sample, c[0], c[1], 1))); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
	if _, err := Parse(strings.NewReader(strings.Repeat("#", MaxSpecSize+1))); err == nil {
		t.Fatal("слишком большой документ")
	}
	var many strings.Builder
	many.WriteString("id: p\nname: П\nversion: 1\nmode: monitor\nrules:\n")
	for i := 0; i <= MaxRules; i++ {
		many.WriteString("  - {id: r" + strings.Repeat("x", i%10) + strconv.Itoa(i) + ", detector: pii.ru, action: log, severity: info}\n")
	}
	if _, err := Parse(strings.NewReader(many.String())); err == nil || !strings.Contains(err.Error(), "правил") {
		t.Fatalf("больше %d правил: %v", MaxRules, err)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	specs := []*Spec{}
	s, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	specs = append(specs, s)
	for _, id := range TemplateIDs() {
		tpl, _ := Template(id)
		specs = append(specs, tpl)
	}
	for _, s := range specs {
		data, err := Marshal(s)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		back, err := Parse(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: повторный разбор: %v\n%s", s.ID, err, data)
		}
		if !reflect.DeepEqual(s, back) {
			t.Fatalf("%s: экспорт и импорт разошлись:\n%+v\n%+v", s.ID, s, back)
		}
	}
	bad := &Spec{ID: "Bad"}
	if _, err := Marshal(bad); err == nil {
		t.Fatal("непроверенная политика не выгружается")
	}
}

// FuzzParse — разбор политики из недоверенного YAML (импорт, ТЗ, 5.3):
// без паники; принятая политика выгружается и разбирается в ту же.
func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	for _, id := range TemplateIDs() {
		s, _ := Template(id)
		data, err := Marshal(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte("id: p\nname: x\nversion: 1\nmode: monitor\nrules: [{id: a, detector: x, action: log, severity: info, threshold: .inf}]"))
	f.Add([]byte("a: &a [*a, *a]"))
	f.Add([]byte(sample + "exceptions:\n  - {id: e1, detector: injection.heuristic, app: support, reason: r, author: user:u1, " +
		"created_at: 2026-10-01T03:00:00+03:00, expires_at: 2026-10-31T00:00:00Z}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Parse(bytes.NewReader(data))
		if err != nil {
			return
		}
		out, err := Marshal(s)
		if err != nil {
			t.Fatalf("принятая политика не выгружается: %v", err)
		}
		back, err := Parse(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("выгруженная политика не разбирается: %v\n%s", err, out)
		}
		if !reflect.DeepEqual(s, back) {
			t.Fatalf("экспорт и импорт разошлись:\n%+v\n%+v", s, back)
		}
	})
}
