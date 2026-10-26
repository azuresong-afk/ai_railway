package versions

import (
	"encoding/json"
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
	// Исключения (решение Р8 этапа 3): новое, продлённое или с изменённым
	// условием исключение ослабляет защиту (ТЗ 5.16, DM-40).
	WeakExceptionAdded    = "exception_added"
	WeakExceptionExtended = "exception_extended"
	WeakExceptionChanged  = "exception_changed"
)

// Weakening — ослабление защиты; Rule пуст для полей политики, Exception —
// ID исключения для ослаблений исключениями.
type Weakening struct {
	Kind      string
	Rule      string
	Exception string
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
	// Исключения: добавленные, удалённые и изменённые (по ID исключения).
	ExceptionsAdded   []policy.ExceptionSpec
	ExceptionsRemoved []policy.ExceptionSpec
	ExceptionsChanged []ExceptionChange
	Weakening         []Weakening
}

// ExceptionChange — исключение с тем же ID в обеих версиях, у которого
// изменились поля Fields.
type ExceptionChange struct {
	ID     string
	Before policy.ExceptionSpec
	After  policy.ExceptionSpec
	Fields []string
}

// Empty — версии не различаются.
func (d Diff) Empty() bool {
	return len(d.Fields) == 0 && len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0 && !d.Reordered &&
		len(d.ExceptionsAdded) == 0 && len(d.ExceptionsRemoved) == 0 && len(d.ExceptionsChanged) == 0
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
	d.compareExceptions(a.Exceptions, b.Exceptions)
	return d
}

// compareExceptions — различия исключений a (раньше) и b (позже).
// Удаление и сокращение срока — усиление; добавление, продление и смена
// условия — ослабление.
func (d *Diff) compareExceptions(a, b []policy.ExceptionSpec) {
	before := make(map[string]policy.ExceptionSpec, len(a))
	for _, e := range a {
		before[e.ID] = e
	}
	after := make(map[string]bool, len(b))
	for _, e := range b {
		after[e.ID] = true
		old, ok := before[e.ID]
		if !ok {
			d.ExceptionsAdded = append(d.ExceptionsAdded, e)
			d.Weakening = append(d.Weakening, Weakening{Kind: WeakExceptionAdded, Exception: e.ID})
			continue
		}
		fs := exceptionFields(old, e)
		if len(fs) == 0 {
			continue
		}
		d.ExceptionsChanged = append(d.ExceptionsChanged, ExceptionChange{ID: e.ID, Before: old, After: e, Fields: fs})
		if old.Condition() != e.Condition() {
			d.Weakening = append(d.Weakening, Weakening{Kind: WeakExceptionChanged, Exception: e.ID})
		}
		if e.ExpiresAt.After(old.ExpiresAt) {
			d.Weakening = append(d.Weakening, Weakening{Kind: WeakExceptionExtended, Exception: e.ID})
		}
	}
	for _, e := range a {
		if !after[e.ID] {
			d.ExceptionsRemoved = append(d.ExceptionsRemoved, e)
		}
	}
}

// exceptionFields — имена изменённых полей исключения (как в YAML).
func exceptionFields(a, b policy.ExceptionSpec) []string {
	var fs []string
	add := func(name string, changed bool) {
		if changed {
			fs = append(fs, name)
		}
	}
	add("detector", a.Detector != b.Detector)
	add("category", a.Category != b.Category)
	add("pattern", a.Pattern != b.Pattern)
	add("fragment", a.Fragment != b.Fragment)
	add("app", a.App != b.App)
	add("user", a.User != b.User)
	add("source", a.Source != b.Source)
	add("reason", a.Reason != b.Reason)
	add("author", a.Author != b.Author)
	add("created_at", !a.CreatedAt.Equal(b.CreatedAt))
	add("expires_at", !a.ExpiresAt.Equal(b.ExpiresAt))
	add("event", a.Event != b.Event)
	return fs
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

// auditListMax — не больше ID в каждом списке подробностей записи аудита,
// auditDetailsBudget — предел сводки целиком: запись ограничена 16 КиБ
// (audit.maxDetailsSize), а списков семь (шесть списков ID и причины) и в
// версии до 1000 исключений и 256 правил с ID до 63 символов. Если сводка
// не укладывается, списки урезаются все вместе и ставится truncated; полный
// состав — в неизменяемой версии (spec_hash), счётчики остаются полными
// (3В26 ревью 3.r3). Остаток 4 КиБ — под slug, номера версий, хеш и ID
// исключения, которые добавляет вызывающий.
const (
	auditListMax       = 50
	auditDetailsBudget = 12 << 10
)

// details — сводка для журнала аудита: без содержимого правил и сообщений.
func (d Diff) details() map[string]any {
	for _, limit := range []int{auditListMax, 25, 10, 5, 1, 0} {
		m, cut := d.detailsCapped(limit)
		if limit == 0 {
			m["truncated"] = true
			return m
		}
		raw, err := json.Marshal(m)
		if err == nil && len(raw) <= auditDetailsBudget {
			if cut {
				m["truncated"] = true
			}
			return m
		}
	}
	return nil // недостижимо: последний шаг возвращает сводку
}

// detailsCapped — сводка с не более чем limit элементами в каждом списке;
// cut — какой-то список урезан.
func (d Diff) detailsCapped(limit int) (map[string]any, bool) {
	fields := make([]string, 0, len(d.Fields))
	for _, f := range d.Fields {
		fields = append(fields, f.Field)
	}
	cut := false
	capped := func(ids []string) []string {
		if len(ids) > limit {
			cut = true
			return ids[:limit]
		}
		return ids
	}
	// Причины ослабления: по правилам — каждая (до limit), по исключениям —
	// одна каждого вида с первым ID; число — по видам.
	kinds := make([]map[string]string, 0, min(len(d.Weakening), limit))
	counts := map[string]int{}
	for _, w := range d.Weakening {
		counts[w.Kind]++
		if w.Exception != "" && seenKind(kinds, w.Kind, true) {
			continue
		}
		if len(kinds) >= limit {
			cut = true
			continue
		}
		m := map[string]string{"kind": w.Kind}
		if w.Rule != "" {
			m["rule"] = w.Rule
		}
		if w.Exception != "" {
			m["exception"] = w.Exception
		}
		kinds = append(kinds, m)
	}
	added, removed, changed := exceptionIDs(d.ExceptionsAdded), exceptionIDs(d.ExceptionsRemoved), changedExceptionIDs(d.ExceptionsChanged)
	rAdded, rRemoved, rChanged := ruleIDs(d.Added), ruleIDs(d.Removed), changedIDs(d.Changed)
	return map[string]any{
		"fields": fields, "rules_added": capped(rAdded), "rules_removed": capped(rRemoved), "rules_changed": capped(rChanged),
		"rules_added_count": len(rAdded), "rules_removed_count": len(rRemoved), "rules_changed_count": len(rChanged),
		"reordered": d.Reordered, "weakening": d.Weakened(), "weakening_reasons": kinds, "weakening_counts": counts,
		"exceptions_added": capped(added), "exceptions_removed": capped(removed), "exceptions_changed": capped(changed),
		"exceptions_added_count": len(added), "exceptions_removed_count": len(removed), "exceptions_changed_count": len(changed),
	}, cut
}

// seenKind — среди причин уже есть причина вида kind (по исключению, если exc).
func seenKind(kinds []map[string]string, kind string, exc bool) bool {
	return slices.ContainsFunc(kinds, func(m map[string]string) bool {
		_, isExc := m["exception"]
		return m["kind"] == kind && isExc == exc
	})
}

func exceptionIDs(es []policy.ExceptionSpec) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.ID)
	}
	return out
}

func changedExceptionIDs(cs []ExceptionChange) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
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
