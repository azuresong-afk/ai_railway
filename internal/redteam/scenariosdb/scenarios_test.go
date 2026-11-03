package scenariosdb_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
)

// Исходник служебной базы сценариев тестирования устойчивости (задача 5.31
// этапа 5, ADR-0031, раздел 5): формат aisec-redteam-scenarios-v1. Эти тесты
// проверяют содержание базы по правилам ADR независимо от исполнителя
// (internal/redteam, задача 5.32): пределы формата, существование строки
// матрицы, покрытие, честность критериев успеха.

const file = "scenarios.json"

type step struct {
	Prompt string `json:"prompt"`
}

type success struct {
	Canary   bool     `json:"canary,omitempty"`
	Contains []string `json:"contains,omitempty"`
	Findings []string `json:"findings,omitempty"`
	Judge    string   `json:"judge,omitempty"`
}

type scenario struct {
	ID       string  `json:"id"`
	Lang     string  `json:"lang"`
	Threat   string  `json:"threat"`
	Category string  `json:"category"`
	Title    string  `json:"title"`
	Steps    []step  `json:"steps"`
	Success  success `json:"success"`
	Source   string  `json:"source"`
	License  string  `json:"license"`
}

type database struct {
	Format    string     `json:"format"`
	Version   int        `json:"version"`
	Date      string     `json:"date"`
	Scenarios []scenario `json:"scenarios"`
}

var (
	idRe       = regexp.MustCompile(`^[A-Z][A-Z0-9-]{2,63}$`)
	threatRe   = regexp.MustCompile(`^DM-\d{2}$`)
	categoryRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
	dateRe     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	sourceRe   = regexp.MustCompile(`^https://[a-z0-9.-]+(/[^\s]*)?$`)
	// licenses — разрешённые для данных (ADR-0031, раздел 5) и собственный корпус производителя.
	licenses = []string{"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "CC0-1.0", "CC-BY-4.0", "proprietary"}
	// findingPrefixes — префиксы категорий находок встроенных детекторов выхода.
	findingPrefixes = []string{"secret", "pii", "exfil", "canary", "injection", "unicode"}
)

func load(t *testing.T) (database, []byte) {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var db database
	if err := dec.Decode(&db); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if dec.More() {
		t.Fatalf("%s: после объекта есть лишние данные", file)
	}
	return db, raw
}

// matrixRows — строки DM-NN матрицы обнаружения (docs/SPEC.md, 5.16).
func matrixRows(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]bool{}
	re := regexp.MustCompile(`(?m)^\| (DM-\d{2}) \|`)
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		rows[m[1]] = true
	}
	if len(rows) < 40 {
		t.Fatalf("в матрице ТЗ найдено строк: %d, ожидалось не меньше 40", len(rows))
	}
	return rows
}

// Формат, пределы и поля — по ADR-0031, раздел 5.
func TestScenarioFormat(t *testing.T) {
	db, _ := load(t)
	if db.Format != "aisec-redteam-scenarios-v1" || db.Version < 1 || !dateRe.MatchString(db.Date) {
		t.Fatalf("заголовок базы: формат %q, версия %d, дата %q", db.Format, db.Version, db.Date)
	}
	if n := len(db.Scenarios); n == 0 || n > 5000 {
		t.Fatalf("сценариев %d, допустимо от 1 до 5000", n)
	}
	matrix := matrixRows(t)
	seen := map[string]bool{}
	for _, s := range db.Scenarios {
		bad := func(format string, a ...any) { t.Errorf("%s: "+format, append([]any{s.ID}, a...)...) }
		switch {
		case !idRe.MatchString(s.ID):
			bad("ID не по шаблону")
		case seen[s.ID]:
			bad("ID повторяется")
		}
		seen[s.ID] = true
		if s.Lang != "ru" && s.Lang != "en" {
			bad("lang — ru или en, получено %q", s.Lang)
		}
		if !threatRe.MatchString(s.Threat) || !matrix[s.Threat] {
			bad("threat %q — нет такой строки матрицы ТЗ 5.16", s.Threat)
		}
		if !categoryRe.MatchString(s.Category) {
			bad("category %q не по шаблону", s.Category)
		}
		if n := utf8.RuneCountInString(s.Title); n == 0 || n > 200 {
			bad("title — от 1 до 200 символов")
		}
		if len(s.Steps) < 1 || len(s.Steps) > 8 {
			bad("шагов %d, допустимо от 1 до 8", len(s.Steps))
		}
		for i, st := range s.Steps {
			switch {
			case strings.TrimSpace(st.Prompt) == "" || len(st.Prompt) > 16<<10:
				bad("шаг %d: prompt — непустой, не больше 16 КиБ", i+1)
			case strings.ContainsRune(st.Prompt, 0):
				bad("шаг %d: нулевой символ в prompt", i+1)
			case !utf8.ValidString(st.Prompt):
				bad("шаг %d: prompt не UTF-8", i+1)
			}
		}
		checkSuccess(t, s)
		if !sourceRe.MatchString(s.Source) {
			bad("source — адрес https")
		}
		if !slices.Contains(licenses, s.License) {
			bad("license %q не из разрешённых для данных", s.License)
		}
	}
}

func checkSuccess(t *testing.T, s scenario) {
	t.Helper()
	bad := func(format string, a ...any) { t.Errorf("%s: success: "+format, append([]any{s.ID}, a...)...) }
	c := s.Success
	if !c.Canary && len(c.Contains) == 0 && len(c.Findings) == 0 && c.Judge == "" {
		bad("нужно хотя бы одно условие")
	}
	if len(c.Contains) > 8 || len(c.Findings) > 8 {
		bad("contains и findings — до 8 элементов")
	}
	for _, m := range c.Contains {
		if n := utf8.RuneCountInString(m); n < 2 || n > 200 {
			bad("contains %q — от 2 до 200 символов", m)
		}
	}
	for _, f := range c.Findings {
		if !slices.ContainsFunc(findingPrefixes, func(p string) bool { return f == p || strings.HasPrefix(f, p+".") }) {
			bad("findings %q — не категория встроенных детекторов", f)
		}
	}
	if c.Judge != "" {
		if n := utf8.RuneCountInString(c.Judge); n < 10 || n > 1000 {
			bad("judge — от 10 до 1000 символов, сейчас %d", n)
		}
	}
}

// Охват (ТЗ 5.13, 5.16): строки матрицы, которые продукт обнаруживает по тексту запроса или ответа, и оба языка.
func TestScenarioCoverage(t *testing.T) {
	db, _ := load(t)
	byThreat := map[string][]scenario{}
	langs := map[string]int{}
	for _, s := range db.Scenarios {
		byThreat[s.Threat] = append(byThreat[s.Threat], s)
		langs[s.Lang]++
	}
	// Строки, которые достижимы текстовым запросом цели: инъекции, структура, обфускация, скрытый Unicode, эскалация,
	// косвенные инъекции, утечка системного промпта, ПДн, секреты, эксфильтрация, инструменты, бизнес-правила, RAG.
	required := []string{"DM-01", "DM-02", "DM-04", "DM-05", "DM-06", "DM-07", "DM-08", "DM-09", "DM-10", "DM-11", "DM-12", "DM-13",
		"DM-18", "DM-19", "DM-20", "DM-21", "DM-22", "DM-23", "DM-24", "DM-30", "DM-31", "DM-32"}
	for _, th := range required {
		if len(byThreat[th]) == 0 {
			t.Errorf("нет сценариев для строки %s", th)
		}
	}
	// Основные классы атак — на обоих языках.
	for _, th := range []string{"DM-01", "DM-07", "DM-08", "DM-09", "DM-10", "DM-11", "DM-19"} {
		l := map[string]bool{}
		for _, s := range byThreat[th] {
			l[s.Lang] = true
		}
		if !l["ru"] || !l["en"] {
			t.Errorf("строка %s: сценарии нужны и на русском, и на английском", th)
		}
	}
	if langs["ru"] < 25 || langs["en"] < 25 {
		t.Errorf("сценариев ru %d, en %d — нужно не меньше 25 на язык", langs["ru"], langs["en"])
	}
	// Многошаговые сценарии есть.
	multi := 0
	for _, s := range db.Scenarios {
		if len(s.Steps) > 1 {
			multi++
		}
	}
	if multi < 5 {
		t.Errorf("многошаговых сценариев %d, нужно не меньше 5", multi)
	}
}

// Маркер из contains не должен лежать в тексте шагов: иначе ответ, который цитирует запрос или отказывается словами
// «я не могу написать X», засчитывался бы как удавшаяся атака. Маркеры собираются из частей, которые модель обязана
// соединить сама.
func TestMarkersAreNotInPrompts(t *testing.T) {
	db, _ := load(t)
	for _, s := range db.Scenarios {
		var all strings.Builder
		for _, st := range s.Steps {
			all.WriteString(strings.ToLower(st.Prompt))
			all.WriteString("\n")
		}
		for _, m := range s.Success.Contains {
			if strings.Contains(all.String(), strings.ToLower(m)) {
				t.Errorf("%s: маркер %q встречается в тексте шагов: отказ с цитатой запроса засчитался бы как успех атаки", s.ID, m)
			}
		}
	}
}

// Условие findings достижимо: данные, которые сценарий подсовывает модели или просит вывести, находят встроенные
// детекторы выхода. Проверка на тексте шагов (его модель и должна была бы повторить), а не на ответе настоящей модели.
func TestFindingsAreReachable(t *testing.T) {
	db, _ := load(t)
	var outs []detect.Detector
	for _, d := range builtin.All() {
		if slices.Contains(d.Directions(), detect.Output) {
			outs = append(outs, d)
		}
	}
	for _, s := range db.Scenarios {
		if len(s.Success.Findings) == 0 {
			continue
		}
		var text strings.Builder
		for _, st := range s.Steps {
			text.WriteString(st.Prompt)
			text.WriteString("\n")
		}
		var cats []string
		for _, d := range outs {
			fs, err := d.Detect(context.Background(), detect.Text{Text: text.String(), Direction: detect.Output, Source: detect.SourceOutput, Lang: s.Lang})
			if err != nil {
				t.Fatalf("%s: детектор %s: %v", s.ID, d.ID(), err)
			}
			for _, f := range fs {
				cats = append(cats, f.Category)
			}
		}
		ok := false
		for _, want := range s.Success.Findings {
			if slices.ContainsFunc(cats, func(c string) bool { return c == want || strings.HasPrefix(c, want+".") }) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: ни одна категория из %v не находится детекторами в тексте сценария (нашлись %v): условие успеха недостижимо", s.ID, s.Success.Findings, cats)
		}
	}
}

// Невидимые и форматирующие символы в базе версии 1 не допускаются: разборщик 5.32 (redteam.ParseScenarios)
// отвергает категорию Cf. Сценарии скрытого Unicode вернутся после расширения формата (см. README).
func TestNoFormatCharacters(t *testing.T) {
	db, raw := load(t)
	for i, r := range string(raw) {
		if unicode.Is(unicode.Cf, r) || (r >= 0xE0000 && r <= 0xE007F) || (unicode.IsControl(r) && r != '\n') {
			t.Fatalf("смещение %d: сырой невидимый символ U+%04X", i, r)
		}
	}
	for _, s := range db.Scenarios {
		for _, st := range s.Steps {
			if strings.ContainsFunc(st.Prompt, func(r rune) bool { return unicode.Is(unicode.Cf, r) }) {
				t.Errorf("%s: в шаге символ форматирования, разборщик базы его отвергнет", s.ID)
			}
		}
	}
}

// ПДн и секреты в сценариях — только синтетические: адреса почты и узлы на зарезервированных или тестовых доменах.
func TestSyntheticOnly(t *testing.T) {
	db, _ := load(t)
	hostRe := regexp.MustCompile(`[A-Za-z0-9._-]+@([A-Za-z0-9.-]+)`)
	for _, s := range db.Scenarios {
		for _, st := range s.Steps {
			for _, m := range hostRe.FindAllStringSubmatch(st.Prompt, -1) {
				h := strings.TrimRight(m[1], ".")
				if !strings.HasSuffix(h, ".example") && !strings.HasSuffix(h, ".test") && !strings.HasSuffix(h, "example.com") {
					t.Errorf("%s: адрес с узлом %q не на зарезервированном домене", s.ID, h)
				}
			}
		}
	}
}
