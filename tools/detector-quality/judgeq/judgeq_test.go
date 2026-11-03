package judgeq

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

const corpusDir = "../../../testdata/corpus/judge"

func loadCorpus(t *testing.T) *Corpus {
	t.Helper()
	c, err := Load(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func loadBaseline(t *testing.T, c *Corpus) detect.Detector {
	t.Helper()
	d, err := Baseline(corpusDir+"/"+BaselineFile, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// engine — оценщик на стенде в памяти: маркеры правил задают, что стенд
// считает нарушением.
func engine(t *testing.T, st judge.Stand) *judge.Engine {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	e, err := judge.NewEngine(judge.Config{Provider: "stand", Model: "stand", Client: st, Hasher: h, Random: rnd,
		Shared: judge.NewShared(), BudgetKey: "judgeq", Limits: judge.Limits{CallsPerMinute: 6000, TokensPerHour: 100_000_000}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Покрывает: DM-19 (LLM)
func TestCorpusShape(t *testing.T) {
	c := loadCorpus(t)
	if len(c.Samples) < 70 {
		t.Fatalf("примеров %d, нужно не меньше 70", len(c.Samples))
	}
	kinds := map[string]bool{}
	for _, r := range c.Rules {
		kinds[r.Kind] = true
		// У каждого правила: нарушение словами словаря, нарушение другими словами, текст на ту же тему без нарушения.
		count := map[string]int{}
		for _, s := range c.Samples {
			if !r.Applies(s.Direction) {
				continue
			}
			if slices.Contains(s.Violates, r.ID) {
				count[s.Class]++
			} else if s.Class == ClassNearMiss && s.About == r.ID {
				count[s.Class]++
			}
		}
		if count[ClassPlain] < 1 || count[ClassParaphrase] < 2 || count[ClassNearMiss] < 2 {
			t.Errorf("правило %s: plain %d, paraphrase %d, near_miss %d — нужно 1, 2 и 2", r.ID, count[ClassPlain], count[ClassParaphrase], count[ClassNearMiss])
		}
	}
	if !kinds[judge.KindBusiness] || !kinds[judge.KindContent] {
		t.Error("в корпусе должны быть правила обоих видов: business (DM-19) и content (DM-18)")
	}
	langSeen := map[string]int{}
	classSeen := map[string]int{}
	for _, s := range c.Samples {
		langSeen[s.Lang]++
		classSeen[s.Class]++
	}
	for _, l := range langs {
		if langSeen[l] == 0 {
			t.Errorf("нет примеров языка %s", l)
		}
	}
	for _, cl := range Classes {
		if classSeen[cl] == 0 {
			t.Errorf("нет примеров класса %s", cl)
		}
	}
}

// Классы примеров честны по отношению к словарю: plain находит словарь,
// paraphrase — нет, neutral словарь не трогает, а на near_miss словарь
// срабатывает ложно (иначе корпус не проверяет точность).
// Покрывает: DM-19 (LLM)
func TestBaselineAgreesWithClasses(t *testing.T) {
	c := loadCorpus(t)
	bl := loadBaseline(t, c)
	ctx := context.Background()
	falseHits := 0
	for _, s := range c.Samples {
		fs, err := bl.Detect(ctx, detect.Text{Text: s.Text, Direction: s.Direction, Source: detect.SourceUser, Lang: s.Lang})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range c.Rules {
			if !r.Applies(s.Direction) {
				continue
			}
			hit := listsHit(fs, r.ID)
			violates := slices.Contains(s.Violates, r.ID)
			switch {
			case s.Class == ClassPlain && violates && !hit:
				t.Errorf("%s: класс plain, а словарь не нашёл нарушение %s", s.ID, r.ID)
			case s.Class == ClassParaphrase && violates && hit:
				t.Errorf("%s: класс paraphrase, а словарь нашёл нарушение %s", s.ID, r.ID)
			case s.Class == ClassNeutral && hit:
				t.Errorf("%s: класс neutral, а словарь сработал на правило %s", s.ID, r.ID)
			case s.Class == ClassNearMiss && hit:
				falseHits++
			}
		}
	}
	if falseHits < len(c.Rules) {
		t.Errorf("ложных срабатываний словаря на near_miss %d, нужно не меньше %d (по одному на правило)", falseHits, len(c.Rules))
	}
}

// Содержимое корпуса — только синтетические данные: адреса почты только на
// зарезервированном домене example.com.
func TestCorpusSyntheticOnly(t *testing.T) {
	c := loadCorpus(t)
	for _, s := range c.Samples {
		for _, w := range strings.Fields(s.Text) {
			if i := strings.Index(w, "@"); i >= 0 {
				if !strings.Contains(w[i:], "example.com") {
					t.Errorf("%s: адрес %q не на example.com", s.ID, w)
				}
			}
		}
	}
}

// Правила корпуса проходят ту же проверку, что правила judge.llm в политике.
// Покрывает: DM-19 (LLM)
func TestRulesFitPolicy(t *testing.T) {
	c := loadCorpus(t)
	reg, err := detect.NewRegistry(judge.New())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range c.Rules {
		spec := policy.Spec{ID: "judgeq", Version: 1, Name: "judgeq", Mode: policy.Monitor,
			Judge: &policy.JudgeSpec{Provider: "local-llm", Model: "m"},
			Rules: []policy.RuleSpec{{ID: r.ID, Detector: policy.JudgeDetector, Action: policy.Log, Severity: policy.Medium,
				Judge: &policy.JudgeRuleSpec{Kind: r.Kind, Criterion: r.Criterion}}}}
		if _, err := policy.Compile(&spec, reg); err != nil {
			t.Errorf("правило %s не принимается политикой: %v", r.ID, err)
		}
	}
}

// Замер на стенде: оценщик находит нарушение по маркеру правила. Проверяет
// разметку, счёт и отчёт, а не качество настоящей модели.
// Покрывает: DM-19 (LLM)
func TestRunOnStand(t *testing.T) {
	c := loadCorpus(t)
	markers := map[string]string{"no-refund-promises": "вернём деньги", "no-insults": "идиот"}
	res, err := Run(context.Background(), Config{Corpus: c, Engine: engine(t, judge.Stand{Markers: markers}), Baseline: loadBaseline(t, c), Mode: "стенд"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Calls != len(c.Samples) || res.Unchecked != 0 {
		t.Fatalf("вызовов %d (примеров %d), не проверено %d", res.Calls, len(c.Samples), res.Unchecked)
	}
	// Пары: каждое правило, применимое к направлению примера.
	want := 0
	for _, s := range c.Samples {
		for _, r := range c.Rules {
			if r.Applies(s.Direction) {
				want++
			}
		}
	}
	if got := res.Total.Judge.Pairs(); got != want || res.Total.Lists.Pairs() != want {
		t.Errorf("пар у оценщика %d и у словаря %d, ожидалось %d", got, res.Total.Lists.Pairs(), want)
	}
	// Стенд знает два маркера: «вернём деньги» есть в refund-p01 и multi-01 (правило возврата), «идиот» — в ins-p01 и в ins-n01 (ложно).
	rf := res.ByRule["no-refund-promises"].Judge
	if rf.TP != 2 || rf.FP != 0 {
		t.Errorf("no-refund-promises у стенда: TP %d (ждали 2), FP %d (ждали 0)", rf.TP, rf.FP)
	}
	in := res.ByRule["no-insults"].Judge
	if in.TP != 1 || in.FP != 1 {
		t.Errorf("no-insults у стенда: TP %d (ждали 1), FP %d (ждали 1)", in.TP, in.FP)
	}
	md := res.Markdown()
	for _, s := range []string{"# Замер judge.llm против lists", "| `lists` (словарь заказчика)", "| `judge.llm`", "По правилам", "По классам примеров", "no-refund-promises", "Ориентир"} {
		if !strings.Contains(md, s) {
			t.Errorf("в отчёте нет %q", s)
		}
	}
	if res.Meets {
		t.Error("стенд с двумя маркерами не должен выдерживать ориентир по полноте")
	}
}

// Оценщик недоступен: все оценки «не проверено» с причиной, ориентир не
// выдержан, замер не падает.
// Покрывает: DM-19 (LLM)
func TestRunUnavailable(t *testing.T) {
	c := loadCorpus(t)
	res, err := Run(context.Background(), Config{Corpus: c, Engine: engine(t, judge.Stand{Err: errors.New("нет связи")}), Baseline: loadBaseline(t, c), Mode: "стенд"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Unchecked != res.Calls || res.Total.Judge.TP != 0 || res.Total.Judge.Unchecked != res.Total.Judge.Pairs() {
		t.Fatalf("не проверено %d из %d, TP %d", res.Unchecked, res.Calls, res.Total.Judge.TP)
	}
	if res.Reasons[judge.ReasonUnavailable] != res.Calls {
		t.Errorf("причины: %v", res.Reasons)
	}
	if res.Meets || !strings.Contains(res.Markdown(), "unavailable") {
		t.Error("отчёт обязан показать причину и не выдерживать ориентир")
	}
}

func TestRunCanceled(t *testing.T) {
	c := loadCorpus(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Config{Corpus: c, Engine: engine(t, judge.Stand{}), Baseline: loadBaseline(t, c)}); err == nil {
		t.Error("отменённый замер должен вернуть ошибку")
	}
}

func TestRunRequiresInputs(t *testing.T) {
	if _, err := Run(context.Background(), Config{}); err == nil {
		t.Error("пустая конфигурация должна вернуть ошибку")
	}
}

const okRules = `[{"id":"r1","kind":"business","direction":"output","criterion":"Ассистент не обещает возврат денег."},
{"id":"r2","kind":"content","direction":"both","criterion":"Текст не содержит оскорблений."}]`

func TestParseRulesNegative(t *testing.T) {
	cases := map[string]string{
		"пусто":              `[]`,
		"не список":          `{}`,
		"лишнее поле":        `[{"id":"r1","kind":"business","direction":"output","criterion":"Ассистент не обещает возврат.","x":1}]`,
		"плохой ID":          `[{"id":"R1","kind":"business","direction":"output","criterion":"Ассистент не обещает возврат."}]`,
		"повтор":             `[{"id":"r1","kind":"business","direction":"output","criterion":"Ассистент не обещает возврат."},{"id":"r1","kind":"business","direction":"output","criterion":"Ассистент не обещает возврат."}]`,
		"вид":                `[{"id":"r1","kind":"x","direction":"output","criterion":"Ассистент не обещает возврат."}]`,
		"направление":        `[{"id":"r1","kind":"business","direction":"x","criterion":"Ассистент не обещает возврат."}]`,
		"короткий критерий":  `[{"id":"r1","kind":"business","direction":"output","criterion":"коротко"}]`,
		"управляющий символ": "[{\"id\":\"r1\",\"kind\":\"business\",\"direction\":\"output\",\"criterion\":\"Ассистент не\\u0000 обещает возврат.\"}]",
		"хвост":              okRules + ` []`,
	}
	for name, in := range cases {
		if _, err := ParseRules(strings.NewReader(in)); err == nil {
			t.Errorf("%s: разбор должен отклонить %q", name, in)
		}
	}
	if _, err := ParseRules(strings.NewReader(okRules)); err != nil {
		t.Fatal(err)
	}
}

func TestParseSamplesNegative(t *testing.T) {
	rules, err := ParseRules(strings.NewReader(okRules))
	if err != nil {
		t.Fatal(err)
	}
	base := func(mod string) string {
		return `{"id":"s1","lang":"ru","direction":"output","class":"plain","text":"Вернём деньги.","violates":["r1"]` + mod + `}`
	}
	if _, err := ParseSamples(strings.NewReader(base("")), rules); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"пусто":                   ``,
		"лишнее поле":             base(`,"x":1`),
		"плохой ID":               strings.Replace(base(""), `"s1"`, `"S 1"`, 1),
		"повтор":                  base("") + "\n" + base(""),
		"язык":                    strings.Replace(base(""), `"ru"`, `"de"`, 1),
		"направление":             strings.Replace(base(""), `"output"`, `"both"`, 1),
		"класс":                   strings.Replace(base(""), `"plain"`, `"x"`, 1),
		"пустой текст":            strings.Replace(base(""), `"Вернём деньги."`, `"  "`, 1),
		"plain без нарушений":     strings.Replace(base(""), `["r1"]`, `[]`, 1),
		"neutral с нарушением":    strings.Replace(base(""), `"plain"`, `"neutral"`, 1),
		"неизвестное правило":     strings.Replace(base(""), `["r1"]`, `["r9"]`, 1),
		"правило не для входа":    strings.Replace(base(""), `"output"`, `"input"`, 1),
		"about без near_miss":     base(`,"about":"r1"`),
		"near_miss без about":     strings.Replace(strings.Replace(base(""), `"plain"`, `"near_miss"`, 1), `["r1"]`, `[]`, 1),
		"повтор в violates":       strings.Replace(base(""), `["r1"]`, `["r1","r1"]`, 1),
		"лишние данные в строке":  base("") + ` {}`,
		"строка не JSON":          `не json`,
		"слишком длинный текст":   strings.Replace(base(""), `Вернём деньги.`, strings.Repeat("я", judge.MaxText), 1),
		"неизвестное правило two": strings.Replace(base(""), `["r1"]`, `["r1","nope"]`, 1),
	}
	for name, in := range cases {
		if _, err := ParseSamples(strings.NewReader(in), rules); err == nil {
			t.Errorf("%s: разбор должен отклонить пример", name)
		}
	}
}

func TestBaselineRejectsUnknownRule(t *testing.T) {
	c := loadCorpus(t)
	if _, err := Baseline(corpusDir+"/"+SamplesFile, c.Rules); err == nil {
		t.Error("файл не со словарём должен отклоняться")
	}
	if _, err := Baseline(corpusDir+"/nope.json", c.Rules); err == nil {
		t.Error("нет файла — ошибка")
	}
}

func TestMetrics(t *testing.T) {
	c := Counts{TP: 3, FN: 1, FP: 1, TN: 5}
	if c.Recall() != 0.75 || c.Precision() != 0.75 || c.FPR() != 1.0/6 || c.Pairs() != 10 {
		t.Errorf("метрики: %+v %v %v %v", c, c.Recall(), c.Precision(), c.FPR())
	}
	if (Counts{}).Precision() != 1 || (Counts{}).Recall() != 0 || (Counts{}).FPR() != 0 {
		t.Error("пустой счёт: точность 1, остальное 0")
	}
}

// Покрывает: DM-19 (LLM)
func FuzzParseSamples(f *testing.F) {
	rules, err := ParseRules(strings.NewReader(okRules))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(`{"id":"s1","lang":"ru","direction":"output","class":"plain","text":"Вернём деньги.","violates":["r1"]}`)
	f.Add(`{"id":"s2","lang":"en","direction":"input","class":"neutral","text":"hi","violates":[]}` + "\n\n")
	f.Add(`{"id":"s1","violates":["r1","r1"]}`)
	f.Add("\xff")
	f.Fuzz(func(t *testing.T, in string) {
		got, err := ParseSamples(strings.NewReader(in), rules)
		if err != nil {
			return
		}
		// Принятый пример всегда согласован с правилами: класс и нарушения, направление, ID.
		ids := map[string]bool{}
		for _, s := range got {
			if ids[s.ID] {
				t.Fatalf("повтор ID %s", s.ID)
			}
			ids[s.ID] = true
			if (s.Class == ClassPlain || s.Class == ClassParaphrase) != (len(s.Violates) > 0) {
				t.Fatalf("%s: класс %s и нарушения %v не согласованы", s.ID, s.Class, s.Violates)
			}
			for _, id := range s.Violates {
				r := Rule{Direction: DirBoth}
				for _, x := range rules {
					if x.ID == id {
						r = x
					}
				}
				if !r.Applies(s.Direction) {
					t.Fatalf("%s: правило %s не применяется к %s", s.ID, id, s.Direction)
				}
			}
		}
	})
}

// Покрывает: DM-19 (LLM)
func FuzzParseRules(f *testing.F) {
	f.Add(okRules)
	f.Add(`[]`)
	f.Add(`[{"id":"a","kind":"content","direction":"both","criterion":"0123456789"}]`)
	f.Fuzz(func(t *testing.T, in string) {
		got, err := ParseRules(strings.NewReader(in))
		if err != nil {
			return
		}
		if len(got) == 0 || len(got) > judge.MaxCriteria {
			t.Fatalf("принято правил: %d", len(got))
		}
		seen := map[string]bool{}
		for _, r := range got {
			if seen[r.ID] || !judge.ValidKind(r.Kind) {
				t.Fatalf("правило %+v принято зря", r)
			}
			seen[r.ID] = true
		}
	})
}
