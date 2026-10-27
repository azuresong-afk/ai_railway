package versions_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

func toolKinds(d versions.Diff) []string {
	var out []string
	for _, w := range d.Weakening {
		out = append(out, w.Kind+":"+w.ToolRule)
	}
	slices.Sort(out)
	return out
}

func baseTools() *policy.Spec {
	return &policy.Spec{Name: "P", Mode: policy.Enforce, Tools: &policy.ToolsSpec{
		Unapproved: policy.Block, Default: policy.Block, ApprovalTimeout: policy.Duration(10 * time.Minute),
		Limits: policy.ToolLimits{AgentPerMinute: 120, SessionCalls: 500, Repeat: 5, RepeatWindow: policy.Duration(10 * time.Minute)},
		Rules: []policy.ToolRuleSpec{
			{ID: "read", Agents: []string{"bot"}, Tool: "files/read_*", Action: policy.Allow, Severity: policy.Medium,
				Args: map[string]any{"type": "object", "properties": map[string]any{
					"path": map[string]any{"type": "string", "x-aisec-path-prefix": []any{"/data/"}}}},
				Rate: &policy.ToolRate{PerMinute: 30}},
			{ID: "risky", Risk: []policy.ToolRisk{policy.RiskHigh, policy.RiskCritical}, Action: policy.RequireApproval, Severity: policy.High},
			{ID: "deny", Tool: "files/delete", Action: policy.Block, Severity: policy.Critical},
		}}}
}

// Каждая причина ослабления политики вызовов (ADR-0023, раздел 2)
// распознаётся, а усиление ослаблением не считается.
func TestCompareToolsWeakening(t *testing.T) {
	cases := map[string]struct {
		edit func(s *policy.ToolsSpec)
		want []string
	}{
		"unapproved block → log": {func(s *policy.ToolsSpec) { s.Unapproved = policy.Log }, []string{versions.WeakToolsUnapproved + ":"}},
		"default block → log":    {func(s *policy.ToolsSpec) { s.Default = policy.Log }, []string{versions.WeakToolsUnapproved + ":"}},
		"новое правило allow": {func(s *policy.ToolsSpec) {
			s.Rules = append(s.Rules, policy.ToolRuleSpec{ID: "mail", Tool: "mail/send", Action: policy.Allow, Severity: policy.Low})
		}, []string{versions.WeakToolRuleAdded + ":mail"}},
		"новое правило require_approval при default block": {func(s *policy.ToolsSpec) {
			s.Rules = append(s.Rules, policy.ToolRuleSpec{ID: "mail", Tool: "mail/send", Action: policy.RequireApproval, Severity: policy.Low})
		}, []string{versions.WeakToolRuleAdded + ":mail"}},
		"действие слабее":    {func(s *policy.ToolsSpec) { s.Rules[1].Action = policy.Log }, []string{versions.WeakToolActionWeakened + ":risky"}},
		"агенты шире":        {func(s *policy.ToolsSpec) { s.Rules[0].Agents = nil }, []string{versions.WeakToolScopeWidened + ":read"}},
		"шаблон шире":        {func(s *policy.ToolsSpec) { s.Rules[0].Tool = "files/*" }, []string{versions.WeakToolScopeWidened + ":read"}},
		"риск шире у allow":  {func(s *policy.ToolsSpec) { s.Rules[0].Risk = nil; s.Rules[0].Agents = []string{"bot", "x"} }, []string{versions.WeakToolScopeWidened + ":read"}},
		"запрет уже":         {func(s *policy.ToolsSpec) { s.Rules[2].Agents = []string{"bot"} }, []string{versions.WeakToolScopeNarrowed + ":deny"}},
		"подтверждение уже":  {func(s *policy.ToolsSpec) { s.Rules[1].Risk = []policy.ToolRisk{policy.RiskCritical} }, []string{versions.WeakToolScopeNarrowed + ":risky"}},
		"аргументы сняты":    {func(s *policy.ToolsSpec) { s.Rules[0].Args = nil }, []string{versions.WeakToolArgsRelaxed + ":read"}},
		"аргументы изменены": {func(s *policy.ToolsSpec) { s.Rules[0].Args["required"] = []any{"path"} }, []string{versions.WeakToolArgsRelaxed + ":read"}},
		"rate выше":          {func(s *policy.ToolsSpec) { s.Rules[0].Rate.PerMinute = 60 }, []string{versions.WeakToolRateRaised + ":read"}},
		"rate снят":          {func(s *policy.ToolsSpec) { s.Rules[0].Rate = nil }, []string{versions.WeakToolRateRaised + ":read"}},
		"лимит агента выше":  {func(s *policy.ToolsSpec) { s.Limits.AgentPerMinute = 0 }, []string{versions.WeakToolRateRaised + ":"}},
		"окно repeat короче": {func(s *policy.ToolsSpec) { s.Limits.RepeatWindow = policy.Duration(time.Minute) }, []string{versions.WeakToolRateRaised + ":"}},
		"таймаут больше": {func(s *policy.ToolsSpec) { s.ApprovalTimeout = policy.Duration(30 * time.Minute) },
			[]string{versions.WeakApprovalTimeoutRaise + ":"}},
		"удалено подтверждение": {func(s *policy.ToolsSpec) { s.Rules = slices.Delete(s.Rules, 1, 2) }, []string{versions.WeakToolRuleRemoved + ":risky"}},
		"удалён allow с ограничениями": {func(s *policy.ToolsSpec) { s.Rules = s.Rules[1:] },
			[]string{versions.WeakToolRuleRemoved + ":read"}},
		// Вызов вне сужённого allow может попасть под require_approval
		// правила risky вместо block за нарушение аргументов.
		"allow с ограничениями уже": {func(s *policy.ToolsSpec) { s.Rules[0].Tool = "files/read_report" },
			[]string{versions.WeakToolScopeNarrowed + ":read"}},
		// Усиление и нейтральные изменения.
		"log → block": {func(s *policy.ToolsSpec) { s.Rules[0].Action = policy.Block }, nil},
		"новое правило block": {func(s *policy.ToolsSpec) {
			s.Rules = append(s.Rules, policy.ToolRuleSpec{ID: "x", Action: policy.Block, Severity: policy.Low})
		}, nil},
		"аргументы добавлены": {func(s *policy.ToolsSpec) { s.Rules[1].Args = map[string]any{"type": "object"} }, nil},
		"rate ниже":           {func(s *policy.ToolsSpec) { s.Rules[0].Rate.PerMinute = 10 }, nil},
		"таймаут меньше":      {func(s *policy.ToolsSpec) { s.ApprovalTimeout = policy.Duration(5 * time.Minute) }, nil},
		"блок уже при запрете остальным": {func(s *policy.ToolsSpec) {
			s.Rules = s.Rules[2:]
			s.Rules[0].Agents = []string{"bot"}
		}, nil},
		"сообщение и важность": {func(s *policy.ToolsSpec) { s.Rules[2].Message, s.Rules[2].Severity = "Нельзя", policy.Low }, nil},
	}
	for name, c := range cases {
		b := baseTools()
		c.edit(b.Tools)
		d := versions.Compare(baseTools(), b)
		want := slices.Clone(c.want)
		slices.Sort(want)
		if got := toolKinds(d); !slices.Equal(got, want) {
			t.Errorf("%s: ослабления %v, ожидалось %v", name, got, want)
		}
		if d.Empty() {
			t.Errorf("%s: изменение не найдено", name)
		}
	}
	if d := versions.Compare(baseTools(), baseTools()); !d.Empty() || d.Weakened() {
		t.Errorf("одинаковые версии: %+v", d)
	}
}

// Раздел tools добавлен к старой политике — усиление; снят — ослабление
// по каждому пункту (сравнение с умолчаниями совместимости).
func TestCompareToolsSectionAddedRemoved(t *testing.T) {
	old := &policy.Spec{Name: "P", Mode: policy.Enforce}
	d := versions.Compare(old, baseTools())
	if d.Weakened() {
		t.Errorf("добавление раздела tools — ослабление: %v", toolKinds(d))
	}
	if len(d.ToolRulesAdded) != 3 || len(d.ToolsFields) == 0 {
		t.Errorf("различия: %+v", d)
	}
	d = versions.Compare(baseTools(), old)
	got := toolKinds(d)
	for _, k := range []string{versions.WeakToolsUnapproved + ":", versions.WeakToolRateRaised + ":", versions.WeakToolRuleRemoved + ":deny"} {
		if !slices.Contains(got, k) {
			t.Errorf("снятие раздела: нет %s в %v", k, got)
		}
	}
	// Сводка различий называет раздел tools.
	var names []string
	for _, f := range d.ToolsFields {
		names = append(names, f.Field)
	}
	if s := strings.Join(names, ","); !strings.Contains(s, "tools") {
		t.Errorf("поля: %s", s)
	}
}
