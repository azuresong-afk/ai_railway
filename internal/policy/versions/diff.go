package versions

import (
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Сравнение версий (ТЗ 5.3) и признаки ослабления защиты (основа DM-40).

// FieldChange — изменение поля политики.
type FieldChange struct {
	Field  string
	Before string
	After  string
}

// RuleChange — правило с тем же ID в обеих версиях, у которого изменились
// поля Fields (имена полей YAML).
type RuleChange struct {
	ID     string
	Before policy.RuleSpec
	After  policy.RuleSpec
	Fields []string
}

// Виды ослабления защиты.
const (
	WeakModeMonitor     = "mode_monitor"            // enforce → monitor
	WeakNonText         = "non_text_weakened"       // block → allow_*, allow_inline → allow_unchecked
	WeakResponseCheck   = "response_check_weakened" // buffered → incremental → monitor
	WeakRuleRemoved     = "rule_removed"            // удалено правило с block, redact или pseudonymize
	WeakActionWeakened  = "action_weakened"         // действие ниже по таблице приоритетов
	WeakThresholdRaised = "threshold_raised"        // порог выше
	WeakScopeNarrowed   = "scope_narrowed"          // меньше направлений, источников или категорий
	WeakDetectorChanged = "detector_changed"        // у правила с защитой сменился детектор
)

// Weakening — ослабление защиты; Rule пуст для полей политики.
type Weakening struct {
	Kind string
	Rule string
}

// Diff — различия двух версий: поля политики, правила добавленные,
// удалённые и изменённые (по ID правила), смена порядка правил.
type Diff struct {
	From, To  int
	Fields    []FieldChange
	Added     []policy.RuleSpec
	Removed   []policy.RuleSpec
	Changed   []RuleChange
	Reordered bool
	Weakening []Weakening
}

// Empty — версии не различаются.
func (d Diff) Empty() bool {
	return len(d.Fields) == 0 && len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0 && !d.Reordered
}

// Weakened — изменение ослабляет защиту.
func (d Diff) Weakened() bool { return len(d.Weakening) > 0 }

// Сила проверки ответа и нетекстового содержимого: больше — строже.
var (
	responseRank = map[policy.ResponseCheck]int{"": 2, policy.ResponseMonitor: 1, policy.ResponseIncremental: 2, policy.ResponseBuffered: 3}
	nonTextRank  = map[policy.NonText]int{"": 1, policy.NonTextAllowUnchecked: 1, policy.NonTextAllowInline: 2, policy.NonTextBlock: 3}
)

// Compare сравнивает спецификации a (раньше) и b (позже). ID и номер версии
// не сравниваются.
func Compare(a, b *policy.Spec) Diff {
	var d Diff
	field := func(name, x, y string) {
		if x != y {
			d.Fields = append(d.Fields, FieldChange{Field: name, Before: x, After: y})
		}
	}
	field("name", a.Name, b.Name)
	field("mode", string(a.Mode), string(b.Mode))
	field("non_text", string(a.NonText), string(b.NonText))
	field("response_check", string(a.ResponseCheck), string(b.ResponseCheck))
	field("block_message", a.BlockMessage, b.BlockMessage)
	if a.Mode == policy.Enforce && b.Mode == policy.Monitor {
		d.Weakening = append(d.Weakening, Weakening{Kind: WeakModeMonitor})
	}
	if nonTextRank[b.NonText] < nonTextRank[a.NonText] {
		d.Weakening = append(d.Weakening, Weakening{Kind: WeakNonText})
	}
	if responseRank[b.ResponseCheck] < responseRank[a.ResponseCheck] {
		d.Weakening = append(d.Weakening, Weakening{Kind: WeakResponseCheck})
	}

	after := make(map[string]policy.RuleSpec, len(b.Rules))
	for _, r := range b.Rules {
		after[r.ID] = r
	}
	before := make(map[string]bool, len(a.Rules))
	var common []string
	for _, r := range a.Rules {
		before[r.ID] = true
		n, ok := after[r.ID]
		if !ok {
			d.Removed = append(d.Removed, r)
			if protective(r.Action) {
				d.Weakening = append(d.Weakening, Weakening{Kind: WeakRuleRemoved, Rule: r.ID})
			}
			continue
		}
		common = append(common, r.ID)
		if fs := ruleFields(r, n); len(fs) > 0 {
			d.Changed = append(d.Changed, RuleChange{ID: r.ID, Before: r, After: n, Fields: fs})
			d.Weakening = append(d.Weakening, ruleWeakening(r, n)...)
		}
	}
	var order []string
	for _, r := range b.Rules {
		if !before[r.ID] {
			d.Added = append(d.Added, r)
			continue
		}
		order = append(order, r.ID)
	}
	d.Reordered = !slices.Equal(common, order)
	return d
}

// protective — правило защищает: блокирует или скрывает данные.
func protective(a policy.Action) bool {
	return a == policy.Block || a == policy.Redact || a == policy.Pseudonymize
}

func threshold(r policy.RuleSpec) float64 {
	if r.Threshold == nil {
		return policy.DefaultThreshold
	}
	return *r.Threshold
}

func ruleFields(a, b policy.RuleSpec) []string {
	var fs []string
	add := func(name string, changed bool) {
		if changed {
			fs = append(fs, name)
		}
	}
	add("detector", a.Detector != b.Detector)
	add("directions", !slices.Equal(a.Directions, b.Directions))
	add("categories", !slices.Equal(a.Categories, b.Categories))
	add("sources", !slices.Equal(a.Sources, b.Sources))
	add("threshold", threshold(a) != threshold(b))
	add("action", a.Action != b.Action)
	add("severity", a.Severity != b.Severity)
	add("message", a.Message != b.Message)
	return fs
}

// narrowed — область правила b уже области a. Пустой список — «все».
func narrowed[T comparable](a, b []T) bool {
	switch {
	case len(b) == 0:
		return false
	case len(a) == 0:
		return true
	}
	return slices.ContainsFunc(a, func(x T) bool { return !slices.Contains(b, x) })
}

func ruleWeakening(a, b policy.RuleSpec) []Weakening {
	var out []Weakening
	w := func(kind string) { out = append(out, Weakening{Kind: kind, Rule: a.ID}) }
	if policy.Stronger(a.Action, b.Action) {
		w(WeakActionWeakened)
	}
	if threshold(b) > threshold(a) {
		w(WeakThresholdRaised)
	}
	if narrowed[detect.Direction](a.Directions, b.Directions) || narrowed[detect.Source](a.Sources, b.Sources) ||
		narrowed[string](a.Categories, b.Categories) {
		w(WeakScopeNarrowed)
	}
	if a.Detector != b.Detector && protective(a.Action) {
		w(WeakDetectorChanged)
	}
	return out
}

// details — сводка для журнала аудита: без содержимого правил и сообщений.
func (d Diff) details() map[string]any {
	fields := make([]string, 0, len(d.Fields))
	for _, f := range d.Fields {
		fields = append(fields, f.Field)
	}
	kinds := make([]map[string]string, 0, len(d.Weakening))
	for _, w := range d.Weakening {
		m := map[string]string{"kind": w.Kind}
		if w.Rule != "" {
			m["rule"] = w.Rule
		}
		kinds = append(kinds, m)
	}
	return map[string]any{
		"fields": fields, "rules_added": ruleIDs(d.Added), "rules_removed": ruleIDs(d.Removed), "rules_changed": changedIDs(d.Changed),
		"reordered": d.Reordered, "weakening": d.Weakened(), "weakening_reasons": kinds,
	}
}

func ruleIDs(rs []policy.RuleSpec) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func changedIDs(cs []RuleChange) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}
