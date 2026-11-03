package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
)

// Раздел judge и правила judge.llm (ADR-0030, раздел 2).

func judgeCatalog(t *testing.T) *detect.Registry {
	t.Helper()
	r, err := detect.NewRegistry(append(registryDetectors(catalog(t)), judge.New())...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const judgeYAML = `id: support
name: Поддержка
version: 1
mode: enforce
judge:
  provider: local-llm
  model: qwen3-14b-instruct
rules:
  - id: no-refunds
    detector: judge.llm
    directions: [output]
    action: block
    severity: high
    judge:
      kind: business
      criterion: "Ассистент не обещает возврат денег, скидки и компенсации."
      mode: sync
      timeout_ms: 3000
      on_failure: block
  - id: no-insults
    detector: judge.llm
    action: log
    severity: medium
    judge:
      kind: content
      criterion: "Ассистент не оскорбляет и не унижает пользователя."
`

func TestJudgeSpecParseCompile(t *testing.T) {
	s, err := Parse(strings.NewReader(judgeYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(s, judgeCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	j := p.Judge()
	if j == nil || j.Provider != "local-llm" || j.CallsPerMinute != DefaultJudgeCalls || j.TokensPerHour != DefaultJudgeTokens {
		t.Fatalf("оценщик: %+v", j)
	}
	out := p.JudgeRules(detect.Output)
	in := p.JudgeRules(detect.Input)
	if len(out) != 2 || len(in) != 1 || in[0].ID != "no-insults" || in[0].Sync {
		t.Fatalf("правила: вход %+v, выход %+v", in, out)
	}
	if !out[0].Sync || out[0].Timeout != 3*time.Second || !out[0].BlockOnFailure || out[0].Kind != judge.KindBusiness {
		t.Fatalf("правило sync: %+v", out[0])
	}
	// Выгрузка и повторный разбор дают ту же политику.
	data, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Parse(strings.NewReader(string(data)))
	if err != nil || s2.Judge == nil || s2.Rules[0].Judge == nil || *s2.Rules[0].Judge != *s.Rules[0].Judge {
		t.Fatalf("повторный разбор: %v", err)
	}
	if Detectors := p.Detectors(detect.Output); len(Detectors) != 1 || Detectors[0] != JudgeDetector {
		t.Fatalf("детекторы выхода: %v", Detectors)
	}
}

// Находку оценщика сопоставляет только её правило: одно правило — один
// критерий.
func TestJudgeFindingMatchesOwnRule(t *testing.T) {
	s, err := Parse(strings.NewReader(judgeYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(s, judgeCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	hit := func(rule string, score float64) Hit {
		return Hit{Finding: detect.Finding{Detector: JudgeDetector, Version: judge.Version, Category: judge.CategoryContent,
			Threat: judge.ThreatContent, Score: score, Rule: rule}, Source: detect.SourceOutput}
	}
	d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Output, Hits: []Hit{hit("no-insults", 0.9)}})
	if d.Block || d.Action != Log || d.Rule != "no-insults" {
		t.Fatalf("находка no-insults: %+v", d)
	}
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Output, Hits: []Hit{hit("no-refunds", 0.9)}})
	if !d.Block || d.Rule != "no-refunds" {
		t.Fatalf("находка no-refunds: %+v", d)
	}
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Output, Hits: []Hit{hit("no-refunds", 0.3)}})
	if d.Block || len(d.Matches) != 0 {
		t.Fatalf("уверенность ниже порога: %+v", d)
	}
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Output, Hits: []Hit{hit("other", 0.9)}})
	if len(d.Matches) != 0 {
		t.Fatalf("находка чужого правила совпала: %+v", d)
	}
}

func TestJudgeSpecValidation(t *testing.T) {
	cases := map[string]func(s *Spec){
		"нет раздела judge": func(s *Spec) { s.Judge = nil },
		"нет подраздела":    func(s *Spec) { s.Rules[0].Judge = nil },
		"подраздел у pii.ru": func(s *Spec) {
			s.Rules = append(s.Rules, RuleSpec{ID: "p", Detector: "pii.ru", Action: Log, Severity: Low, Judge: &JudgeRuleSpec{Kind: "content", Criterion: "Десять символов"}})
		},
		"неизвестный вид":   func(s *Spec) { s.Rules[0].Judge.Kind = "other" },
		"короткий критерий": func(s *Spec) { s.Rules[0].Judge.Criterion = "Коротко" },
		"длинный критерий":  func(s *Spec) { s.Rules[0].Judge.Criterion = strings.Repeat("я", MaxJudgeCriterion+1) },
		"управляющий символ": func(s *Spec) {
			s.Rules[0].Judge.Criterion = "Ассистент не\u0007 обещает скидок."
		},
		"перевод строки":    func(s *Spec) { s.Rules[0].Judge.Criterion = "Ассистент не\nобещает скидок." },
		"неизвестный режим": func(s *Spec) { s.Rules[0].Judge.Mode = "later" },
		"срок вне пределов": func(s *Spec) { s.Rules[0].Judge.TimeoutMS = 100 },
		"on_failure":        func(s *Spec) { s.Rules[0].Judge.OnFailure = "ignore" },
		"block в async":     func(s *Spec) { s.Rules[1].Action = Block },
		"срок в async":      func(s *Spec) { s.Rules[1].Judge.TimeoutMS = 1000 },
		"категории":         func(s *Spec) { s.Rules[1].Categories = []string{"judge.content"} },
		"источники":         func(s *Spec) { s.Rules[1].Sources = []detect.Source{detect.SourceUser} },
		"провайдер":         func(s *Spec) { s.Judge.Provider = "Local LLM" },
		"модель с пробелом": func(s *Spec) { s.Judge.Model = "qwen 14b" },
		"модель пустая":     func(s *Spec) { s.Judge.Model = "" },
		"бюджет вызовов":    func(s *Spec) { s.Judge.MaxCallsPerMinute = MaxJudgeCalls + 1 },
		"бюджет токенов":    func(s *Spec) { s.Judge.MaxTokensPerHour = 10 },
		"redact":            func(s *Spec) { s.Rules[1].Action = Redact },
		"больше 16 правил": func(s *Spec) {
			for i := range MaxJudgeRules {
				r := s.Rules[1]
				j := *r.Judge
				r.Judge, r.ID = &j, "extra-"+string(rune('a'+i))
				s.Rules = append(s.Rules, r)
			}
		},
	}
	for name, mutate := range cases {
		s, err := Parse(strings.NewReader(judgeYAML))
		if err != nil {
			t.Fatal(err)
		}
		mutate(s)
		if _, err := Compile(s, judgeCatalog(t)); err == nil {
			t.Errorf("%s: политика принята", name)
		}
	}
	// Раздел judge без правил допустим: оценщик не вызывается.
	s, _ := Parse(strings.NewReader(judgeYAML))
	s.Rules = nil
	if p, err := Compile(s, judgeCatalog(t)); err != nil || len(p.JudgeRules(detect.Output)) != 0 {
		t.Fatalf("раздел без правил: %v", err)
	}
}

// Виды правил политики совпадают с видами пакета judge.
func TestJudgeKindsMatchDetector(t *testing.T) {
	if JudgeDetector != judge.ID || JudgeKindContent != judge.KindContent || JudgeKindBusiness != judge.KindBusiness ||
		MaxJudgeRules != judge.MaxCriteria {
		t.Fatal("константы политики и internal/detect/judge расходятся")
	}
}
