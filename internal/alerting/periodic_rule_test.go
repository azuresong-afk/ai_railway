package alerting

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"
)

// Разбор правил «частота», «аномалия» и «бюджет»: умолчания, границы и
// отказы.
func TestParsePeriodicRules(t *testing.T) {
	f, err := ParseRuleInput(RuleInput{Kind: KindFrequency, Name: "Серия", Condition: Condition{MinSeverity: "medium",
		Count: MinFrequencyCount, WindowMinutes: MaxWindowMinutes}, GroupBy: []string{"user"}}, "")
	if err != nil || f.Severity != "high" || f.Condition.Count != 2 || !slices.Equal(f.GroupBy, []string{"user"}) {
		t.Fatalf("частота: %+v %v", f, err)
	}
	a, err := ParseRuleInput(RuleInput{Kind: KindAnomaly, Name: "Рост", Condition: Condition{Metric: MetricTokens},
		GroupBy: []string{"app"}}, "")
	if err != nil || a.Severity != "medium" || a.Condition.Factor != DefaultAnomalyFactor ||
		a.Condition.MinVolume != metricMinVolume[MetricTokens] {
		t.Fatalf("аномалия: %+v %v", a, err)
	}
	if a, err := ParseRuleInput(RuleInput{Kind: KindAnomaly, Name: "Вся установка",
		Condition: Condition{Metric: MetricRequests, Factor: MinAnomalyFactor, MinVolume: 1}}, ""); err != nil || len(a.GroupBy) != 0 {
		t.Fatalf("аномалия без группировки: %+v %v", a, err)
	}
	b, err := ParseRuleInput(RuleInput{Kind: KindBudget, Name: "Бюджет"}, "")
	if err != nil || b.Condition.WarnPercent != DefaultWarnPercent || !slices.Equal(b.GroupBy, []string{"app"}) {
		t.Fatalf("бюджет: %+v %v", b, err)
	}
	for name, in := range map[string]RuleInput{
		"частота без порога":     {Kind: KindFrequency, Name: "x", Condition: Condition{MinSeverity: "high", WindowMinutes: 10}},
		"частота порог 1":        {Kind: KindFrequency, Name: "x", Condition: Condition{MinSeverity: "high", Count: 1, WindowMinutes: 10}},
		"частота большой порог":  {Kind: KindFrequency, Name: "x", Condition: Condition{MinSeverity: "high", Count: MaxFrequencyCount + 1, WindowMinutes: 10}},
		"частота без окна":       {Kind: KindFrequency, Name: "x", Condition: Condition{MinSeverity: "high", Count: 5}},
		"частота окно > суток":   {Kind: KindFrequency, Name: "x", Condition: Condition{MinSeverity: "high", Count: 5, WindowMinutes: MaxWindowMinutes + 1}},
		"частота без условия":    {Kind: KindFrequency, Name: "x", Condition: Condition{Count: 5, WindowMinutes: 5}},
		"частота с метрикой":     {Kind: KindFrequency, Name: "x", Condition: Condition{MinSeverity: "high", Count: 5, WindowMinutes: 5, Metric: MetricTokens}},
		"частота по угрозе":      {Kind: KindFrequency, Name: "x", Condition: Condition{MinSeverity: "high", Count: 5, WindowMinutes: 5}, GroupBy: []string{"threat"}},
		"аномалия без метрики":   {Kind: KindAnomaly, Name: "x"},
		"аномалия метрика":       {Kind: KindAnomaly, Name: "x", Condition: Condition{Metric: "content"}},
		"аномалия множитель":     {Kind: KindAnomaly, Name: "x", Condition: Condition{Metric: MetricRequests, Factor: 1.2}},
		"аномалия множитель max": {Kind: KindAnomaly, Name: "x", Condition: Condition{Metric: MetricRequests, Factor: MaxAnomalyFactor + 0.5}},
		"аномалия NaN":           {Kind: KindAnomaly, Name: "x", Condition: Condition{Metric: MetricRequests, Factor: math.NaN()}},
		"аномалия объём":         {Kind: KindAnomaly, Name: "x", Condition: Condition{Metric: MetricRequests, MinVolume: -1}},
		"аномалия большой объём": {Kind: KindAnomaly, Name: "x", Condition: Condition{Metric: MetricRequests, MinVolume: MaxMinVolume + 1}},
		"аномалия с фильтром":    {Kind: KindAnomaly, Name: "x", Condition: Condition{Metric: MetricRequests, Filter: `app = "a"`}},
		"аномалия по модели":     {Kind: KindAnomaly, Name: "x", Condition: Condition{Metric: MetricRequests}, GroupBy: []string{"model"}},
		"аномалия со счётом":     {Kind: KindAnomaly, Name: "x", Condition: Condition{Metric: MetricRequests, Count: 3}},
		"бюджет 49":              {Kind: KindBudget, Name: "x", Condition: Condition{WarnPercent: MinWarnPercent - 1}},
		"бюджет 100":             {Kind: KindBudget, Name: "x", Condition: Condition{WarnPercent: 100}},
		"бюджет по модели":       {Kind: KindBudget, Name: "x", GroupBy: []string{"model"}},
		"бюджет с фильтром":      {Kind: KindBudget, Name: "x", Condition: Condition{MinSeverity: "high"}},
		"порог со счётом":        {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high", Count: 3}},
		"порог с бюджетом":       {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high", WarnPercent: 80}},
		"новое с метрикой":       {Kind: KindNew, Name: "x", Condition: Condition{Field: "model", Metric: MetricRequests}},
	} {
		if _, err := ParseRuleInput(in, ""); !isInput(err) {
			t.Errorf("%s: ожидалась ошибка ввода, получено %v", name, err)
		}
	}
	// Границы бюджета.
	for _, p := range []int{MinWarnPercent, MaxWarnPercent} {
		if _, err := ParseRuleInput(RuleInput{Kind: KindBudget, Name: "x", Condition: Condition{WarnPercent: p}}, ""); err != nil {
			t.Fatalf("бюджет %d: %v", p, err)
		}
	}
}

// Ослабление правил фоновой задачи (DM-40): порог выше, окно короче,
// множитель и наименьший объём выше, порог бюджета выше, смена метрики.
func TestPeriodicRuleWeakening(t *testing.T) {
	base := Rule{Enabled: true, Severity: "high", Condition: Condition{MinSeverity: "medium", Count: 10, WindowMinutes: 10}}
	for name, tc := range map[string]struct {
		change func(*Rule)
		want   string
	}{
		"порог":     {func(r *Rule) { r.Condition.Count = 11 }, WeakCountRaised},
		"окно":      {func(r *Rule) { r.Condition.WindowMinutes = 5 }, WeakWindowShortened},
		"множитель": {func(r *Rule) { r.Condition.Factor = 4 }, WeakFactorRaised},
		"объём":     {func(r *Rule) { r.Condition.MinVolume = 1000 }, WeakMinVolumeRaised},
		"бюджет":    {func(r *Rule) { r.Condition.WarnPercent = 90 }, WeakWarnRaised},
		"метрика":   {func(r *Rule) { r.Condition.Metric = MetricTokens }, WeakConditionChanged},
	} {
		after := base.clone()
		tc.change(&after)
		if got := Weakening(&base, &after); !slices.Contains(got, tc.want) {
			t.Errorf("%s: %v", name, got)
		}
	}
	// Усиление — не ослабление.
	after := base.clone()
	after.Condition.Count, after.Condition.WindowMinutes = 5, 30
	if got := Weakening(&base, &after); len(got) != 0 {
		t.Fatalf("усиление: %v", got)
	}
}

// Создание и изменение правил фоновой задачи через сервис: ослабление
// встроенного правила требует повторной проверки.
func TestPeriodicRuleService(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r, err := e.svc.CreateRule(ctx, e.admin, RuleInput{Kind: KindAnomaly, Name: "Токены", Condition: Condition{Metric: MetricTokens}})
	if err != nil || r.Kind != KindAnomaly {
		t.Fatalf("создание: %+v %v", r, err)
	}
	b := e.rule(t, BuiltinProbingSeries)
	noConfirm := e.admin
	noConfirm.Confirm = nil
	in := RuleInput{Name: b.Name, Description: b.Description, Severity: b.Severity, GroupBy: b.GroupBy,
		Condition: Condition{MinSeverity: "medium", Count: 50, WindowMinutes: 10}, SuppressMinutes: &b.SuppressMinutes,
		Recipients: b.Recipients, Version: b.Version}
	if _, err := e.svc.UpdateRule(ctx, noConfirm, b.ID, in); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("ослабление без проверки: %v", err)
	}
	if got, err := e.svc.UpdateRule(ctx, e.admin, b.ID, in); err != nil || got.Condition.Count != 50 {
		t.Fatalf("ослабление с проверкой: %+v %v", got, err)
	}
}
