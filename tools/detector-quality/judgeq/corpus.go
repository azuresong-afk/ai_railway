// Пакет judgeq — замер judge.llm на корпусе бизнес-правил против словарной
// эвристики lists (задача 5.29 этапа 5, ADR-0030, docs/detectors.md,
// раздел «judge.llm»). По образцу замера Р4 (пакет p4): одна разметка, два
// способа проверки, полнота, доля ложных и точность по парам «пример —
// правило». judge.llm — детектор уровня запроса, поэтому корпус не в
// testdata/corpus/<ID детектора> и не в таблице docs/detectors.md.
//
// Корпус — testdata/corpus/judge: rules.json (правила на естественном
// языке), samples.jsonl (размеченные примеры) и lists-baseline.json
// (словарь, который заказчик написал бы сам). ПДн в корпусе — только
// синтетические (CLAUDE.md).
package judgeq

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Имена файлов корпуса.
const (
	RulesFile    = "rules.json"
	SamplesFile  = "samples.jsonl"
	BaselineFile = "lists-baseline.json"
)

// Пределы входа: файлы корпуса свои, но читаются с пределом, как любой вход.
const (
	maxFileBytes = 4 << 20
	maxLineBytes = 1 << 20
	maxSamples   = 5000
)

// Классы примеров. plain — нарушение, которое находит словарь; paraphrase —
// то же по смыслу другими словами (словарь не находит); near_miss — текст на
// ту же тему без нарушения (словарь может сработать ложно); neutral —
// обычный разговор.
const (
	ClassPlain      = "plain"
	ClassParaphrase = "paraphrase"
	ClassNearMiss   = "near_miss"
	ClassNeutral    = "neutral"
)

// Classes — классы в порядке отчёта.
var Classes = []string{ClassPlain, ClassParaphrase, ClassNearMiss, ClassNeutral}

// DirBoth — правило применяется и ко входу, и к ответу.
const DirBoth = "both"

// Rule — правило на естественном языке: те же поля, что у правила judge.llm
// в политике (kind, criterion), плюс направление применения.
type Rule struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Direction string `json:"direction"`
	Criterion string `json:"criterion"`
}

// Applies — правило проверяет текст этого направления.
func (r Rule) Applies(dir detect.Direction) bool {
	return r.Direction == DirBoth || r.Direction == string(dir)
}

// Sample — размеченный пример. Violates — ID правил, которые нарушает текст;
// пусто — нарушений нет. About — у near_miss правило, на тему которого
// написан текст без нарушения.
type Sample struct {
	ID        string           `json:"id"`
	Lang      string           `json:"lang"`
	Direction detect.Direction `json:"direction"`
	Class     string           `json:"class"`
	Text      string           `json:"text"`
	Violates  []string         `json:"violates"`
	About     string           `json:"about,omitempty"`
	Note      string           `json:"note,omitempty"`
}

// Corpus — правила и примеры.
type Corpus struct {
	Rules   []Rule
	Samples []Sample
}

var (
	idRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	sampleRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	langs    = []string{"ru", "en", "mixed"}
)

// ParseRules читает rules.json со строгой схемой.
func ParseRules(r io.Reader) ([]Rule, error) {
	data, err := readLimited(r)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rules []Rule
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("%s: %w", RulesFile, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: лишние данные после списка", RulesFile)
	}
	if len(rules) == 0 || len(rules) > judge.MaxCriteria {
		return nil, fmt.Errorf("%s: правил от 1 до %d", RulesFile, judge.MaxCriteria)
	}
	seen := map[string]bool{}
	for _, r := range rules {
		switch {
		case !idRe.MatchString(r.ID):
			return nil, fmt.Errorf("правило %q: ID — латиница в нижнем регистре, цифры и «-»", r.ID)
		case seen[r.ID]:
			return nil, fmt.Errorf("правило %s повторяется", r.ID)
		case !judge.ValidKind(r.Kind):
			return nil, fmt.Errorf("правило %s: kind — content или business", r.ID)
		case r.Direction != DirBoth && r.Direction != string(detect.Input) && r.Direction != string(detect.Output):
			return nil, fmt.Errorf("правило %s: direction — input, output или both", r.ID)
		}
		if n := utf8.RuneCountInString(strings.TrimSpace(r.Criterion)); n < policy.MinJudgeCriterion || n > policy.MaxJudgeCriterion {
			return nil, fmt.Errorf("правило %s: criterion — от %d до %d символов", r.ID, policy.MinJudgeCriterion, policy.MaxJudgeCriterion)
		}
		if strings.ContainsFunc(r.Criterion, unicode.IsControl) {
			return nil, fmt.Errorf("правило %s: criterion содержит управляющие символы", r.ID)
		}
		seen[r.ID] = true
	}
	return rules, nil
}

// ParseSamples читает samples.jsonl: каждая строка — один пример.
func ParseSamples(r io.Reader, rules []Rule) ([]Sample, error) {
	data, err := readLimited(r)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), maxLineBytes)
	var out []Sample
	seen := map[string]bool{}
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var s Sample
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("%s, строка %d: %w", SamplesFile, n, err)
		}
		if dec.More() {
			return nil, fmt.Errorf("%s, строка %d: лишние данные", SamplesFile, n)
		}
		if err := checkSample(s, byID, seen); err != nil {
			return nil, fmt.Errorf("%s, строка %d: %w", SamplesFile, n, err)
		}
		seen[s.ID] = true
		out = append(out, s)
		if len(out) > maxSamples {
			return nil, fmt.Errorf("%s: больше %d примеров", SamplesFile, maxSamples)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", SamplesFile, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: нет примеров", SamplesFile)
	}
	return out, nil
}

func checkSample(s Sample, rules map[string]Rule, seen map[string]bool) error {
	switch {
	case !sampleRe.MatchString(s.ID):
		return fmt.Errorf("ID %q: латиница в нижнем регистре, цифры, «-», «_» и «.»", s.ID)
	case seen[s.ID]:
		return fmt.Errorf("пример %s повторяется", s.ID)
	case !slices.Contains(langs, s.Lang):
		return fmt.Errorf("%s: lang — ru, en или mixed", s.ID)
	case s.Direction != detect.Input && s.Direction != detect.Output:
		return fmt.Errorf("%s: direction — input или output", s.ID)
	case !slices.Contains(Classes, s.Class):
		return fmt.Errorf("%s: class — plain, paraphrase, near_miss или neutral", s.ID)
	case strings.TrimSpace(s.Text) == "" || len(s.Text) > judge.MaxText || !utf8.ValidString(s.Text):
		return fmt.Errorf("%s: text — непустой UTF-8 не длиннее %d байт", s.ID, judge.MaxText)
	}
	positive := s.Class == ClassPlain || s.Class == ClassParaphrase
	if positive != (len(s.Violates) > 0) {
		return fmt.Errorf("%s: у классов plain и paraphrase violates не пуст, у near_miss и neutral пуст", s.ID)
	}
	if (s.Class == ClassNearMiss) != (s.About != "") {
		return fmt.Errorf("%s: about задаётся у класса near_miss и только у него", s.ID)
	}
	if r, ok := rules[s.About]; s.About != "" && (!ok || !r.Applies(s.Direction)) {
		return fmt.Errorf("%s: about — неизвестное правило или правило не для направления %s", s.ID, s.Direction)
	}
	for i, id := range s.Violates {
		r, ok := rules[id]
		switch {
		case !ok:
			return fmt.Errorf("%s: violates — неизвестное правило %q", s.ID, id)
		case !r.Applies(s.Direction):
			return fmt.Errorf("%s: правило %s не применяется к направлению %s", s.ID, id, s.Direction)
		case slices.Contains(s.Violates[:i], id):
			return fmt.Errorf("%s: правило %s повторяется в violates", s.ID, id)
		}
	}
	return nil
}

func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("файл больше %d байт", maxFileBytes)
	}
	return data, nil
}

// Load читает корпус из каталога.
func Load(dir string) (*Corpus, error) {
	rf, err := os.Open(filepath.Join(dir, RulesFile)) //nolint:gosec // G304: путь к корпусу задаёт вызывающий (тест или командная строка)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rf.Close() }() //nolint:gosec // G104: закрытие файла, открытого на чтение
	rules, err := ParseRules(rf)
	if err != nil {
		return nil, err
	}
	sf, err := os.Open(filepath.Join(dir, SamplesFile)) //nolint:gosec // G304: см. выше
	if err != nil {
		return nil, err
	}
	defer func() { _ = sf.Close() }() //nolint:gosec // G104: закрытие файла, открытого на чтение
	samples, err := ParseSamples(sf, rules)
	if err != nil {
		return nil, err
	}
	return &Corpus{Rules: rules, Samples: samples}, nil
}

// readSpecs читает словарь и проверяет, что у каждого списка есть правило
// корпуса с тем же ID.
func readSpecs(path string, rules []Rule) ([]lists.Spec, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: путь к словарю задаёт вызывающий
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s больше %d байт", path, maxFileBytes)
	}
	var specs []lists.Spec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	known := map[string]bool{}
	for _, r := range rules {
		known[r.ID] = true
	}
	for _, s := range specs {
		if !known[s.ID] {
			return nil, errors.New(path + ": список " + s.ID + " — нет правила с таким ID")
		}
	}
	return specs, nil
}

// Baseline — словарная эвристика (детектор lists со словарём из JSON): то,
// что заказчик настроил бы сам, не имея оценщика. Каждый список называется
// ID правила корпуса, поэтому находка списка — ответ эвристики на это
// правило.
func Baseline(path string, rules []Rule) (detect.Detector, error) {
	specs, err := readSpecs(path, rules)
	if err != nil {
		return nil, err
	}
	return lists.Compile(specs)
}

// StandMarkers — слова-маркеры стенда-оценщика (judge.Stand): первое слово
// или фраза списка каждого правила. Стенд — проверка разметки и отчёта без
// модели; цифры качества он не показывает.
func StandMarkers(path string, rules []Rule) (map[string]string, error) {
	specs, err := readSpecs(path, rules)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, s := range specs {
		if len(s.Words) > 0 {
			out[s.ID] = s.Words[0]
		}
	}
	return out, nil
}
