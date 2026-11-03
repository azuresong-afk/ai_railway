package redteam

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

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
		}
	})
}
