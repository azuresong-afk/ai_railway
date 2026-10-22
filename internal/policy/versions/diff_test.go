package versions_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

func kinds(d versions.Diff) []string {
	var out []string
	for _, w := range d.Weakening {
		out = append(out, w.Kind+":"+w.Rule)
	}
	return out
}

func th(v float64) *float64 { return &v }

// Каждое ослабление защиты из плана 2.12 распознаётся (основа DM-40), а
// усиление ослаблением не считается.
func TestCompareWeakening(t *testing.T) {
	base := func() *policy.Spec {
		return &policy.Spec{Name: "P", Mode: policy.Enforce, NonText: policy.NonTextBlock, ResponseCheck: policy.ResponseBuffered,
			Rules: []policy.RuleSpec{ruleInjection, rulePII}}
	}
	cases := map[string]struct {
		edit func(s *policy.Spec)
		want []string
	}{
		"режим monitor":          {func(s *policy.Spec) { s.Mode = policy.Monitor }, []string{versions.WeakModeMonitor + ":"}},
		"non_text":               {func(s *policy.Spec) { s.NonText = policy.NonTextAllowInline }, []string{versions.WeakNonText + ":"}},
		"проверка ответа":        {func(s *policy.Spec) { s.ResponseCheck = policy.ResponseMonitor }, []string{versions.WeakResponseCheck + ":"}},
		"удалено правило block":  {func(s *policy.Spec) { s.Rules = s.Rules[1:] }, []string{versions.WeakRuleRemoved + ":injection"}},
		"block → log":            {func(s *policy.Spec) { s.Rules[0].Action = policy.Log }, []string{versions.WeakActionWeakened + ":injection"}},
		"порог выше":             {func(s *policy.Spec) { s.Rules[1].Threshold = th(0.9) }, []string{versions.WeakThresholdRaised + ":pii"}},
		"категории сужены":       {func(s *policy.Spec) { s.Rules[1].Categories = []string{"pii.card"} }, []string{versions.WeakScopeNarrowed + ":pii"}},
		"источники сужены":       {func(s *policy.Spec) { s.Rules[0].Sources = []detect.Source{detect.SourceUser} }, []string{versions.WeakScopeNarrowed + ":injection"}},
		"сменён детектор защиты": {func(s *policy.Spec) { s.Rules[1].Detector = "secrets" }, []string{versions.WeakDetectorChanged + ":pii"}},
		// Усиление и нейтральные изменения.
		"порог ниже":       {func(s *policy.Spec) { s.Rules[1].Threshold = th(0.3) }, nil},
		"redact → block":   {func(s *policy.Spec) { s.Rules[1].Action = policy.Block }, nil},
		"направления шире": {func(s *policy.Spec) { s.Rules[1].Directions = nil }, nil},
		"новое правило": {func(s *policy.Spec) {
			s.Rules = append(s.Rules, policy.RuleSpec{ID: "c", Detector: "canary", Action: policy.Block, Severity: policy.High})
		}, nil},
		"сообщение и имя": {func(s *policy.Spec) { s.Name, s.Rules[0].Message = "Q", "Нельзя" }, nil},
	}
	for name, c := range cases {
		b := base()
		c.edit(b)
		d := versions.Compare(base(), b)
		if got := kinds(d); !slices.Equal(got, c.want) {
			t.Errorf("%s: ослабления %v, ожидалось %v", name, got, c.want)
		}
		if d.Empty() {
			t.Errorf("%s: изменение не найдено", name)
		}
	}
	// Удаление правила log не ослабляет защиту.
	a := base()
	a.Rules[0].Action = policy.Log
	b := base()
	b.Rules = b.Rules[1:]
	if d := versions.Compare(a, b); d.Weakened() || len(d.Removed) != 1 {
		t.Fatalf("удаление правила log: %+v", d)
	}
}

func TestCompareStructure(t *testing.T) {
	a := &policy.Spec{Name: "P", Mode: policy.Monitor, Rules: []policy.RuleSpec{ruleInjection, rulePII}}
	b := &policy.Spec{Name: "P2", Mode: policy.Monitor, Rules: []policy.RuleSpec{rulePII, ruleInjection,
		{ID: "c", Detector: "canary", Action: policy.Block, Severity: policy.High}}}
	b.Rules[0].Severity = policy.High
	d := versions.Compare(a, b)
	if len(d.Fields) != 1 || d.Fields[0].Field != "name" || len(d.Added) != 1 || d.Added[0].ID != "c" || len(d.Removed) != 0 ||
		len(d.Changed) != 1 || d.Changed[0].ID != "pii" || !slices.Equal(d.Changed[0].Fields, []string{"severity"}) || !d.Reordered {
		t.Fatalf("сравнение: %+v", d)
	}
	if d := versions.Compare(a, a); !d.Empty() || d.Weakened() {
		t.Fatalf("сравнение с собой: %+v", d)
	}
}

// FuzzDiff: сравнение двух произвольных разобранных политик — без паники;
// сравнение с собой пустое; ослабление всегда указывает на поле или
// правило первой версии.
func FuzzDiff(f *testing.F) {
	y := "id: p\nname: P\nversion: 1\nmode: enforce\nnon_text: block\nrules:\n  - id: a\n    detector: pii.ru\n    action: block\n    severity: high\n"
	f.Add(y, strings.Replace(y, "action: block", "action: log", 1))
	f.Add(y, strings.Replace(y, "mode: enforce", "mode: monitor", 1))
	f.Add(y, "id: p\nname: Q\nversion: 2\nmode: monitor\nrules: []\n")
	f.Fuzz(func(t *testing.T, x, z string) {
		a, err := policy.Parse(strings.NewReader(x))
		if err != nil {
			return
		}
		b, err := policy.Parse(strings.NewReader(z))
		if err != nil {
			return
		}
		if d := versions.Compare(a, a); !d.Empty() || d.Weakened() {
			t.Fatalf("сравнение с собой не пустое: %+v", d)
		}
		d := versions.Compare(a, b)
		for _, w := range d.Weakening {
			if w.Rule != "" && !slices.ContainsFunc(a.Rules, func(r policy.RuleSpec) bool { return r.ID == w.Rule }) {
				t.Fatalf("ослабление по правилу %s, которого не было", w.Rule)
			}
		}
	})
}
