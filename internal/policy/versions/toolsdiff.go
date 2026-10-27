package versions

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

// Сравнение раздела tools (ADR-0023, раздел 2; задача 4.9). Правило
// сравнения консервативное: изменение, усиление которого не доказано,
// считается ослаблением (DM-40). Версия без раздела сравнивается как раздел
// совместимости (policy.CompatTools).

// Виды ослабления политики вызовов.
const (
	WeakToolsUnapproved      = "tools_unapproved_weakened" // unapproved или default стали слабее
	WeakToolRuleAdded        = "tool_rule_added"           // новое правило слабее прежнего default — расширение allowlist
	WeakToolActionWeakened   = "tool_action_weakened"      // действие правила стало слабее
	WeakToolScopeWidened     = "tool_scope_widened"        // шире agents, tool или risk у правила слабее default
	WeakToolScopeNarrowed    = "tool_scope_narrowed"       // уже agents, tool или risk у запрещающего или ограничивающего правила
	WeakToolArgsRelaxed      = "tool_args_relaxed"         // ограничения аргументов сняты или изменены
	WeakToolRateRaised       = "tool_rate_raised"          // выросли rate или limits, сократилось окно repeat
	WeakApprovalTimeoutRaise = "approval_timeout_raised"   // вырос срок ожидания подтверждения
	WeakToolRuleRemoved      = "tool_rule_removed"         // удалено правило, которое запрещало или ограничивало
)

// ToolRuleChange — правило tools с тем же ID в обеих версиях, у которого
// изменились поля Fields.
type ToolRuleChange struct {
	ID     string
	Before policy.ToolRuleSpec
	After  policy.ToolRuleSpec
	Fields []string
}

// effectiveTools — раздел или умолчания совместимости.
func effectiveTools(t *policy.ToolsSpec) policy.ToolsSpec {
	if t == nil {
		return policy.CompatTools()
	}
	return *t
}

// toolActionRank — сила действия политики вызовов (ТЗ 5.3).
func toolActionRank(a policy.Action) int { return policy.Priority(a) }

func approvalTimeout(t policy.ToolsSpec) time.Duration {
	if t.ApprovalTimeout == 0 {
		return policy.DefaultApprovalTimeout
	}
	return time.Duration(t.ApprovalTimeout)
}

// raised — предел b выше a; 0 — без предела.
func raised(a, b int) bool {
	switch {
	case b == 0:
		return a != 0
	case a == 0:
		return false
	}
	return b > a
}

// compareTools — различия раздела tools a (раньше) и b (позже).
func (d *Diff) compareTools(at, bt *policy.ToolsSpec) {
	a, b := effectiveTools(at), effectiveTools(bt)
	field := func(name, x, y string) {
		if x != y {
			d.ToolsFields = append(d.ToolsFields, FieldChange{Field: name, Before: x, After: y})
		}
	}
	weak := func(kind, rule string) { d.Weakening = append(d.Weakening, Weakening{Kind: kind, ToolRule: rule}) }
	field("tools", strconv.FormatBool(at != nil), strconv.FormatBool(bt != nil))
	field("tools.unapproved", string(a.Unapproved), string(b.Unapproved))
	field("tools.default", string(a.Default), string(b.Default))
	field("tools.approval_timeout", policy.Duration(approvalTimeout(a)).String(), policy.Duration(approvalTimeout(b)).String())
	field("tools.limits.agent_per_minute", strconv.Itoa(a.Limits.AgentPerMinute), strconv.Itoa(b.Limits.AgentPerMinute))
	field("tools.limits.session_calls", strconv.Itoa(a.Limits.SessionCalls), strconv.Itoa(b.Limits.SessionCalls))
	field("tools.limits.repeat", strconv.Itoa(a.Limits.Repeat), strconv.Itoa(b.Limits.Repeat))
	field("tools.limits.repeat_window", a.Limits.RepeatWindow.String(), b.Limits.RepeatWindow.String())
	if toolActionRank(b.Unapproved) < toolActionRank(a.Unapproved) || toolActionRank(b.Default) < toolActionRank(a.Default) {
		weak(WeakToolsUnapproved, "")
	}
	if approvalTimeout(b) > approvalTimeout(a) {
		weak(WeakApprovalTimeoutRaise, "")
	}
	if raised(a.Limits.AgentPerMinute, b.Limits.AgentPerMinute) || raised(a.Limits.SessionCalls, b.Limits.SessionCalls) ||
		raised(a.Limits.Repeat, b.Limits.Repeat) || b.Limits.Repeat != 0 && b.Limits.RepeatWindow < a.Limits.RepeatWindow {
		weak(WeakToolRateRaised, "")
	}

	after := make(map[string]policy.ToolRuleSpec, len(b.Rules))
	for _, r := range b.Rules {
		after[r.ID] = r
	}
	before := make(map[string]bool, len(a.Rules))
	for _, r := range a.Rules {
		before[r.ID] = true
		n, ok := after[r.ID]
		if !ok {
			d.ToolRulesRemoved = append(d.ToolRulesRemoved, r)
			// Вызовы, которые подходили под правило, получат прежние
			// правила или default новой версии.
			if restrictive(r, floor(b, r.ID)) {
				weak(WeakToolRuleRemoved, r.ID)
			}
			continue
		}
		fs := toolRuleFields(r, n)
		if len(fs) == 0 {
			continue
		}
		d.ToolRulesChanged = append(d.ToolRulesChanged, ToolRuleChange{ID: r.ID, Before: r, After: n, Fields: fs})
		if policy.Stronger(r.Action, n.Action) {
			weak(WeakToolActionWeakened, r.ID)
		}
		// Расширение: новые вызовы получают действие правила вместо
		// прежнего default. Сужение: вызовы теряют действие и проверки
		// правила.
		if !scopeCovers(r, n) && policy.Stronger(a.Default, n.Action) {
			weak(WeakToolScopeWidened, r.ID)
		}
		if !scopeCovers(n, r) && restrictive(r, floor(b, r.ID)) {
			weak(WeakToolScopeNarrowed, r.ID)
		}
		if r.Args != nil && !sameArgs(r.Args, n.Args) {
			weak(WeakToolArgsRelaxed, r.ID)
		}
		if raised(rate(r).PerMinute, rate(n).PerMinute) || raised(rate(r).PerHour, rate(n).PerHour) {
			weak(WeakToolRateRaised, r.ID)
		}
	}
	for _, r := range b.Rules {
		if before[r.ID] {
			continue
		}
		d.ToolRulesAdded = append(d.ToolRulesAdded, r)
		// Новое правило может только поднять итог для вызовов, которые уже
		// подходили под правила; для остальных оно заменяет прежний default.
		if policy.Stronger(a.Default, r.Action) {
			weak(WeakToolRuleAdded, r.ID)
		}
	}
}

// restrictive — без правила r вызовы, которые под него подходили, могут
// получить более слабый итог: его действие сильнее самого слабого из
// оставшихся (low), или у него есть ограничения аргументов либо частоты
// (их нарушение — block), а оставшиеся не блокируют всё.
func restrictive(r policy.ToolRuleSpec, low policy.Action) bool {
	if policy.Stronger(r.Action, low) {
		return true
	}
	return (r.Args != nil || rate(r) != (policy.ToolRate{})) && policy.Stronger(policy.Block, low)
}

// floor — самое слабое действие, которое вызов может получить в версии t
// без правила skip: default или действие любого другого правила. Оценка
// осторожная: пересечение областей правил не вычисляется.
func floor(t policy.ToolsSpec, skip string) policy.Action {
	low := t.Default
	for _, r := range t.Rules {
		if r.ID != skip && policy.Stronger(low, r.Action) {
			low = r.Action
		}
	}
	return low
}

func rate(r policy.ToolRuleSpec) policy.ToolRate {
	if r.Rate == nil {
		return policy.ToolRate{}
	}
	return *r.Rate
}

// scopeCovers — каждый вызов, подходящий под b, подходит и под a.
func scopeCovers(a, b policy.ToolRuleSpec) bool {
	return setCovers(a.Agents, b.Agents) && setCovers(a.Risk, b.Risk) && patternCovers(a.Tool, b.Tool)
}

// setCovers — список a (пустой — всё) содержит всё из b.
func setCovers[T comparable](a, b []T) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			return false
		}
	}
	return true
}

// patternCovers — шаблон инструмента a (пустой — любой) покрывает b.
func patternCovers(a, b string) bool {
	if a == "" {
		return true
	}
	if b == "" {
		return false
	}
	if p, ok := strings.CutSuffix(a, "*"); ok {
		return strings.HasPrefix(strings.TrimSuffix(b, "*"), p)
	}
	return a == b
}

// sameArgs — схемы аргументов совпадают по смыслу JSON.
func sameArgs(a, b map[string]any) bool {
	if b == nil {
		return false
	}
	lim := argschema.Limits{MaxSize: argschema.MaxSchemaSize, MaxDepth: 64, MaxValues: 1 << 16, MaxString: 1 << 16}
	va, err1 := argschema.FromAny(a, lim)
	vb, err2 := argschema.FromAny(b, lim)
	return err1 == nil && err2 == nil && argschema.Equal(va, vb)
}

func toolRuleFields(a, b policy.ToolRuleSpec) []string {
	var fs []string
	add := func(name string, changed bool) {
		if changed {
			fs = append(fs, name)
		}
	}
	add("agents", !slices.Equal(a.Agents, b.Agents))
	add("tool", a.Tool != b.Tool)
	add("risk", !slices.Equal(a.Risk, b.Risk))
	add("action", a.Action != b.Action)
	add("args", (a.Args == nil) != (b.Args == nil) || a.Args != nil && !sameArgs(a.Args, b.Args))
	add("rate", rate(a) != rate(b))
	add("severity", a.Severity != b.Severity)
	add("message", a.Message != b.Message)
	return fs
}

func toolRuleIDs(rs []policy.ToolRuleSpec) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func changedToolRuleIDs(cs []ToolRuleChange) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}
