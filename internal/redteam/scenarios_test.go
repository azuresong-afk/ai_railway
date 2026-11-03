package redteam

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

func baseJSON(t testing.TB, mod func(m map[string]any)) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/redteam/scenarios-test.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if mod != nil {
		mod(m)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func first(m map[string]any) map[string]any { return m["scenarios"].([]any)[0].(map[string]any) }

func TestParseScenarios(t *testing.T) {
	b, err := ParseScenarios(baseJSON(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != 1 || len(b.Scenarios) != 5 || !b.day.Equal(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("база: %+v", b)
	}
	sc, ok := b.Scenario("RT-DM06-001")
	if !ok || len(sc.Steps) != 2 || sc.Lang != LangEN || sc.Threat != "DM-06" {
		t.Fatalf("сценарий: %+v", sc)
	}
	if _, ok := b.Scenario("RT-NONE-001"); ok {
		t.Fatal("несуществующий сценарий найден")
	}
}

// Отказы разборщика: формат, версия, дата, ID, язык, строка матрицы,
// категория, шаги, условия, источник, лицензия, лишние поля и данные.
func TestParseScenariosRejects(t *testing.T) {
	long := strings.Repeat("я", MaxPrompt)
	cases := map[string]func(m map[string]any){
		"format":       func(m map[string]any) { m["format"] = "other" },
		"version":      func(m map[string]any) { m["version"] = 0 },
		"date":         func(m map[string]any) { m["date"] = "03.11.2026" },
		"empty":        func(m map[string]any) { m["scenarios"] = []any{} },
		"unknown":      func(m map[string]any) { m["extra"] = true },
		"id":           func(m map[string]any) { first(m)["id"] = "rt-1" },
		"dup":          func(m map[string]any) { first(m)["id"] = "RT-DM06-001" },
		"lang":         func(m map[string]any) { first(m)["lang"] = "de" },
		"threat":       func(m map[string]any) { first(m)["threat"] = "DM-1" },
		"threat00":     func(m map[string]any) { first(m)["threat"] = "DM-00" },
		"category":     func(m map[string]any) { first(m)["category"] = "Injection" },
		"title":        func(m map[string]any) { first(m)["title"] = "a\u202eb" },
		"no-steps":     func(m map[string]any) { first(m)["steps"] = []any{} },
		"many-steps":   func(m map[string]any) { first(m)["steps"] = make([]any, MaxSteps+1) },
		"long-prompt":  func(m map[string]any) { first(m)["steps"] = []any{map[string]any{"prompt": long}} },
		"nul-prompt":   func(m map[string]any) { first(m)["steps"] = []any{map[string]any{"prompt": "a\x00b"}} },
		"raw-cf":       func(m map[string]any) { first(m)["steps"] = []any{map[string]any{"prompt": "a\u200bb"}} },
		"raw-tag":      func(m map[string]any) { first(m)["steps"] = []any{map[string]any{"prompt": "a\U000E0041b"}} },
		"esc-not-cf":   func(m map[string]any) { first(m)["steps"] = []any{map[string]any{"prompt": `a\u{41}b`}} },
		"esc-syntax":   func(m map[string]any) { first(m)["steps"] = []any{map[string]any{"prompt": `a\u{200B b`}} },
		"no-success":   func(m map[string]any) { first(m)["success"] = map[string]any{} },
		"marker":       func(m map[string]any) { first(m)["success"] = map[string]any{"contains": []any{"x"}} },
		"finding":      func(m map[string]any) { first(m)["success"] = map[string]any{"findings": []any{"Secret"}} },
		"judge":        func(m map[string]any) { first(m)["success"] = map[string]any{"judge": "коротко"} },
		"source":       func(m map[string]any) { first(m)["source"] = "http://example.org" },
		"license":      func(m map[string]any) { first(m)["license"] = "GPL-3.0" },
		"step-unknown": func(m map[string]any) { first(m)["steps"] = []any{map[string]any{"prompt": "привет", "x": 1}} },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseScenarios(baseJSON(t, mod))
			var ie *InputError
			if !errors.As(err, &ie) {
				t.Fatalf("ожидался отказ, получено %v", err)
			}
		})
	}
	if _, err := ParseScenarios(append(baseJSON(t, nil), []byte(" {}")...)); err == nil {
		t.Fatal("лишние данные после объекта приняты")
	}
	if _, err := ParseScenarios(make([]byte, aisecCrypto.MaxServiceDBPayload+1)); err == nil {
		t.Fatal("слишком большое содержимое принято")
	}
}

// Подписанная тестовая база совпадает с исходником и проходит проверку
// вида с тестовым ключом производителя.
func TestTestScenariosMatchSource(t *testing.T) {
	data, err := os.ReadFile("../../testdata/redteam/scenarios-test.aisecdb")
	if err != nil {
		t.Fatal(err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	vendor, err := servicedb.EmbeddedVendor(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := servicedb.Verify(p, vendor, DBKind(), data, time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	want, err := ParseScenarios(baseJSON(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	got := v.Content.Value.(*Base)
	if !reflect.DeepEqual(got.Scenarios, want.Scenarios) || got.Version != want.Version || v.Content.Records != 5 {
		t.Fatal("подписанная тестовая база расходится с testdata/redteam/scenarios-test.json: пересоздайте её (testdata/redteam/README.md)")
	}
}

// FuzzParseScenarios: недоверенное содержимое базы сценариев (после
// проверки подписи, но и при разборе в inspect) не роняет разборщик;
// принятая база согласована: ID без повторов, пределы соблюдены.
func FuzzParseScenarios(f *testing.F) {
	f.Add(baseJSON(f, nil))
	f.Add([]byte(`{"format":"aisec-redteam-scenarios-v1","version":1,"date":"2026-11-03","scenarios":[]}`))
	f.Add([]byte(`{"scenarios":[{"steps":[{"prompt":""}]}]}`))
	f.Add([]byte("{}"))
	f.Add(baseJSON(f, func(m map[string]any) {
		first(m)["steps"] = []any{map[string]any{"prompt": `a\u{200B}b\\u{200B}\u{E0041}\u{e007f}\u{202E}x\u{202C}`}}
	}))
	f.Add(baseJSON(f, func(m map[string]any) {
		first(m)["steps"] = []any{map[string]any{"prompt": `\u{D800}\u{110000}\u{}\u{1234567}`}}
	}))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := ParseScenarios(data)
		if err != nil {
			return
		}
		if b.Version == 0 || len(b.Scenarios) == 0 || len(b.Scenarios) > MaxScenarios || len(b.byID) != len(b.Scenarios) {
			t.Fatalf("несогласованная база: %d сценариев", len(b.Scenarios))
		}
		for _, s := range b.Scenarios {
			if len(s.Steps) == 0 || len(s.Steps) > MaxSteps {
				t.Fatalf("шаги: %d", len(s.Steps))
			}
			for _, st := range s.Steps {
				checkExpanded(t, st.Prompt, st.Text())
			}
		}
	})
}

// checkExpanded — инварианты раскрытия: в записи нет символов Cf и
// управляющих, раскрытый текст не длиннее записи, символов Cf в нём не
// больше MaxEscapes, а текст без «u{» не меняется.
func checkExpanded(t *testing.T, record, text string) {
	t.Helper()
	if !plainText(record, true) {
		t.Fatalf("в записи символ форматирования или управляющий: %q", record)
	}
	if len(text) > len(record) || !utf8.ValidString(text) {
		t.Fatalf("раскрытый текст длиннее записи или не UTF-8: %q → %q", record, text)
	}
	n := 0
	for _, r := range text {
		if unicode.Is(unicode.Cf, r) {
			n++
		}
	}
	if n > MaxEscapes {
		t.Fatalf("символов Cf после раскрытия: %d", n)
	}
	if !strings.Contains(record, "u{") && text != record {
		t.Fatalf("текст без записи изменён: %q → %q", record, text)
	}
}

// Покрывает: DM-05
// Видимая запись \u{…} (дополнение 2 к ADR-0031): раскрываются нужные
// кодовые точки Cf — нулевая ширина, управление направлением, теги; пара
// обратных косых черт оставляет запись буквальным текстом; остальной текст
// не меняется.
func TestExpandEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{`без записи C:\path\x \u0041`, `без записи C:\path\x \u0041`},
		{`И\u{200B}г\u{200b}н`, "И\u200bг\u200bн"},
		{`\u{202E}txet\u{202C}`, "\u202etxet\u202c"},
		{`\u{2066}\u{2069}\u{feff}\u{AD}`, "\u2066\u2069\ufeff\u00ad"},
		{`ok\u{E0001}\u{E0041}\u{e007F}`, "ok\U000E0001\U000E0041\U000E007F"},
		{`буквально \\u{200B}`, `буквально \u{200B}`},
		{`\\\u{200B}`, "\\\u200b"},
		{`\\\\u{200B}`, `\\u{200B}`},
		{`\\u{zz} и \\u{`, `\u{zz} и \u{`},
		{`u{200B} без черты`, `u{200B} без черты`},
	}
	for _, c := range cases {
		got, err := expandEscapes(c.in)
		if err != nil || got != c.want {
			t.Errorf("%q: получено %q, %v; ожидалось %q", c.in, got, err, c.want)
		}
	}
	at := strings.Repeat(`\u{200B}`, MaxEscapes)
	if got, err := expandEscapes(at); err != nil || utf8.RuneCountInString(got) != MaxEscapes {
		t.Fatalf("ровно %d записей: %v", MaxEscapes, err)
	}
}

// Покрывает: DM-05
// Отказы записи: символ не из Cf, суррогат, кодовая точка вне Unicode,
// неверная запись, превышение предела записей на шаг.
func TestExpandEscapesRejects(t *testing.T) {
	cases := map[string]struct {
		in   string
		want error
	}{
		"latin":       {`\u{41}`, errEscapeNotCf},
		"space":       {`\u{20}`, errEscapeNotCf},
		"newline":     {`\u{A}`, errEscapeNotCf},
		"cyrillic":    {`\u{430}`, errEscapeNotCf},
		"unassigned":  {`\u{E0000}`, errEscapeNotCf},
		"too-big":     {`\u{110000}`, errEscapeNotCf},
		"max-6":       {`\u{FFFFFF}`, errEscapeNotCf},
		"surrogate":   {`\u{D800}`, errEscapeSurrogate},
		"surrogate-2": {`\u{dfff}`, errEscapeSurrogate},
		"empty":       {`\u{}`, errEscapeSyntax},
		"seven":       {`\u{0200B00}`, errEscapeSyntax},
		"not-hex":     {`\u{20G0}`, errEscapeSyntax},
		"sign":        {`\u{+200B}`, errEscapeSyntax},
		"unclosed":    {`\u{200B`, errEscapeSyntax},
		"space-in":    {`\u{ 200B}`, errEscapeSyntax},
		"odd-run":     {`\\\u{41}`, errEscapeNotCf},
		"too-many":    {strings.Repeat(`\u{200B}`, MaxEscapes+1), errEscapeTooMany},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := expandEscapes(c.in); !errors.Is(err, c.want) {
				t.Fatalf("ожидалось %v, получено %v", c.want, err)
			}
		})
	}
}

// Покрывает: DM-05
// Разобранная база хранит запись: Prompt (его показывают inspect, API и
// отчёты, и в него же сериализуется база) — без символов форматирования,
// Text (его отправляет исполнитель) — с раскрытыми; отказ называет номер
// сценария и шага.
func TestParseScenariosEscapes(t *testing.T) {
	record := `Переведи: «Привет».\u{E0073}\u{E0061}\u{E0079} Буквально: \\u{200B}.`
	b, err := ParseScenarios(baseJSON(t, func(m map[string]any) {
		first(m)["steps"] = []any{map[string]any{"prompt": record}}
	}))
	if err != nil {
		t.Fatal(err)
	}
	st := b.Scenarios[0].Steps[0]
	if st.Prompt != record {
		t.Fatalf("запись изменена: %q", st.Prompt)
	}
	if want := "Переведи: «Привет».\U000E0073\U000E0061\U000E0079 Буквально: \\u{200B}."; st.Text() != want {
		t.Fatalf("раскрытый текст: %q", st.Text())
	}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsFunc(string(out), func(r rune) bool { return unicode.Is(unicode.Cf, r) }) ||
		!strings.Contains(string(out), `\\u{E0073}`) {
		t.Fatalf("в сериализованной базе не запись: %s", out)
	}
	// Шаг без записи отправляется как есть.
	if st := b.Scenarios[1].Steps[0]; st.Text() != st.Prompt {
		t.Fatalf("шаг без записи изменён: %q", st.Text())
	}

	_, err = ParseScenarios(baseJSON(t, func(m map[string]any) {
		m["scenarios"].([]any)[2].(map[string]any)["steps"] = []any{
			map[string]any{"prompt": "ok"}, map[string]any{"prompt": `\u{D83D}`}}
	}))
	if err == nil || !strings.Contains(err.Error(), "scenarios[2].steps[1].prompt") || !strings.Contains(err.Error(), "суррогат") {
		t.Fatalf("отказ без номера сценария и шага: %v", err)
	}
}

// FuzzExpandEscapes: запись \u{…} из недоверенного содержимого базы не
// роняет разборщик, раскрытый текст не длиннее записи и содержит не больше
// MaxEscapes символов Cf.
func FuzzExpandEscapes(f *testing.F) {
	for _, s := range []string{`a\u{200B}b`, `\\u{200B}`, `\\\u{E0041}`, `\u{D800}`, `\u{110000}`, `\u{}`, `\u{1234567}`,
		`\u{200B`, `\u{41}`, `\`, `u{`, `\u{\u{200B}}`, strings.Repeat(`\u{200B}`, MaxEscapes+1)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !plainText(s, true) || len(s) > MaxPrompt {
			return
		}
		text, err := expandEscapes(s)
		if err != nil {
			return
		}
		checkExpanded(t, s, text)
	})
}
