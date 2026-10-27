package policy

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

// Политика вызовов инструментов агентами (ТЗ 5.10; ADR-0023, раздел 2;
// задача 4.9 этапа 4) — раздел tools версии политики. Он попадает в
// подписанный пакет вместе с правилами детекторов. Версия без раздела
// (все политики до этапа 4) читается как unapproved: log, default: allow,
// без лимитов: поведение прежних приложений не меняется.

// Пределы раздела tools. Верхние границы лимитов зашиты в код: значение
// больше — ошибка, а не тихое урезание.
const (
	MaxToolRules     = 256 // правил в разделе
	MaxToolAgents    = 64  // агентов в одном правиле
	MaxAgentPerMin   = 100000
	MaxSessionCalls  = 1000000
	MaxRepeat        = 1000
	MaxRuleRateMin   = 100000
	MaxRuleRateHour  = 1000000
	MinRepeatWindow  = time.Minute
	MaxRepeatWindow  = 24 * time.Hour
	MinApprovalWait  = time.Minute
	MaxApprovalWait  = time.Hour
	MaxToolNameLen   = 128 // имя инструмента MCP (спецификация MCP: до 128 символов)
	MaxServerSlugLen = 64
)

// DefaultApprovalTimeout — срок ожидания подтверждения по умолчанию (DM-22).
const DefaultApprovalTimeout = 10 * time.Minute

// FunctionServer — «сервер» вызовов функций в ответах модели (путь chat):
// инструмент function/<имя>. MCP-сервер с таким slug не регистрируется.
const FunctionServer = "function"

// ToolRisk — уровень риска инструмента (ADR-0023, раздел 1).
type ToolRisk string

// Уровни риска по возрастанию.
const (
	RiskLow      ToolRisk = "low"
	RiskMedium   ToolRisk = "medium"
	RiskHigh     ToolRisk = "high"
	RiskCritical ToolRisk = "critical"
)

var riskRank = map[ToolRisk]int{RiskLow: 1, RiskMedium: 2, RiskHigh: 3, RiskCritical: 4}

// ValidRisk — известный уровень риска.
func ValidRisk(r ToolRisk) bool { return riskRank[r] > 0 }

// RiskRank — место уровня риска по возрастанию; 0 — неизвестный.
func RiskRank(r ToolRisk) int { return riskRank[r] }

// Duration — длительность в YAML политики: запись вида 10m, 90s, 1h
// (целые секунды); выгружается в той же короткой записи.
type Duration time.Duration

// UnmarshalYAML разбирает строку длительности.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("строка %d: длительность — строка вида 10m", n.Line)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("строка %d: длительность %q, например 10m", n.Line, clipText(s))
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML выгружает длительность короткой записью.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// String — короткая запись: 1h, 10m, 90s.
func (d Duration) String() string {
	v := time.Duration(d)
	switch {
	case v == 0:
		return "0s"
	case v%time.Hour == 0:
		return strconv.FormatInt(int64(v/time.Hour), 10) + "h"
	case v%time.Minute == 0:
		return strconv.FormatInt(int64(v/time.Minute), 10) + "m"
	}
	return strconv.FormatInt(int64(v/time.Second), 10) + "s"
}

// ToolsSpec — раздел tools версии политики.
type ToolsSpec struct {
	// Unapproved — инструмент не одобрен (new, changed, suspicious, revoked,
	// нет в реестре): block или log.
	Unapproved Action `yaml:"unapproved"`
	// Default — инструмент одобрен, но ни одно правило не подошло (DM-20):
	// block или log.
	Default Action `yaml:"default"`
	// ApprovalTimeout — срок ожидания подтверждения (DM-22), 1m–60m;
	// 0 — DefaultApprovalTimeout.
	ApprovalTimeout Duration       `yaml:"approval_timeout,omitempty"`
	Limits          ToolLimits     `yaml:"limits,omitempty"`
	Rules           []ToolRuleSpec `yaml:"rules,omitempty"`
}

// ToolLimits — лимиты вызовов (DM-23); 0 — без предела.
type ToolLimits struct {
	// AgentPerMinute — вызовов агента приложения в минуту.
	AgentPerMinute int `yaml:"agent_per_minute,omitempty"`
	// SessionCalls — вызовов агента в одной сессии за 24 ч.
	SessionCalls int `yaml:"session_calls,omitempty"`
	// Repeat — одинаковых вызовов (инструмент и хеш аргументов) в сессии за
	// RepeatWindow: признак зацикливания.
	Repeat       int      `yaml:"repeat,omitempty"`
	RepeatWindow Duration `yaml:"repeat_window,omitempty"`
}

// ToolRuleSpec — правило политики вызовов.
type ToolRuleSpec struct {
	ID string `yaml:"id"`
	// Agents — slug агентов приложения; пусто — все агенты и вызовы без агента.
	Agents []string `yaml:"agents,omitempty,flow"`
	// Tool — «сервер/имя» (function/имя для вызовов функций в ответах
	// модели); «*» только в конце имени; пусто — любой инструмент.
	Tool string `yaml:"tool,omitempty"`
	// Risk — только инструменты этих уровней риска; пусто — любые.
	Risk   []ToolRisk `yaml:"risk,omitempty,flow"`
	Action Action     `yaml:"action"`
	// Args — ограничения аргументов: подмножество JSON Schema (argschema).
	Args     map[string]any `yaml:"args,omitempty"`
	Rate     *ToolRate      `yaml:"rate,omitempty"`
	Severity Severity       `yaml:"severity"`
	Message  string         `yaml:"message,omitempty"`
}

// ToolRate — лимиты частоты правила для агента (DM-23); 0 — без предела.
type ToolRate struct {
	PerMinute int `yaml:"per_minute,omitempty"`
	PerHour   int `yaml:"per_hour,omitempty"`
}

var (
	agentSlugRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	// toolRe — сервер/имя: slug MCP-сервера или function, имя инструмента
	// MCP (латиница, цифры, «_», «-», «.»), «*» только в конце.
	toolRe = regexp.MustCompile(`^[a-z0-9-]{1,64}/[A-Za-z0-9_.-]{0,128}\*?$`)
)

// ValidAgentSlug — slug агента (ADR-0023, раздел 1).
func ValidAgentSlug(s string) bool { return agentSlugRe.MatchString(s) }

// validate — ошибки раздела; patterns — выражений pattern в схемах (предел
// на политику).
func (t *ToolsSpec) validate() (errs []error) {
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf("tools: "+format, a...)) }
	if t.Unapproved != Block && t.Unapproved != Log {
		add("unapproved — block или log")
	}
	if t.Default != Block && t.Default != Log {
		add("default — block или log")
	}
	if w := time.Duration(t.ApprovalTimeout); w != 0 && (w < MinApprovalWait || w > MaxApprovalWait || w%time.Second != 0) {
		add("approval_timeout — от 1m до 60m целыми секундами")
	}
	l := t.Limits
	if l.AgentPerMinute < 0 || l.AgentPerMinute > MaxAgentPerMin {
		add("limits.agent_per_minute — от 0 до %d", MaxAgentPerMin)
	}
	if l.SessionCalls < 0 || l.SessionCalls > MaxSessionCalls {
		add("limits.session_calls — от 0 до %d", MaxSessionCalls)
	}
	if l.Repeat < 0 || l.Repeat > MaxRepeat {
		add("limits.repeat — от 0 до %d", MaxRepeat)
	}
	if w := time.Duration(l.RepeatWindow); w != 0 && (w < MinRepeatWindow || w > MaxRepeatWindow || w%time.Second != 0) ||
		l.Repeat > 0 && w == 0 {
		add("limits.repeat_window — от 1m до 24h целыми секундами, обязателен вместе с repeat")
	}
	if len(t.Rules) > MaxToolRules {
		add("не больше %d правил", MaxToolRules)
		return errs
	}
	seen := map[string]bool{}
	patterns := 0
	for i, r := range t.Rules {
		n, rerrs := r.validate()
		patterns += n
		for _, err := range rerrs {
			add("rules[%d] (%s): %v", i, clipText(r.ID), err)
		}
		if seen[r.ID] {
			add("rules[%d]: правило %s указано дважды", i, clipText(r.ID))
		}
		seen[r.ID] = true
	}
	if patterns > argschema.MaxPatternsPerPolicy {
		add("больше %d выражений pattern в ограничениях аргументов", argschema.MaxPatternsPerPolicy)
	}
	return errs
}

// validate — ошибки правила и число pattern в его схеме.
func (r *ToolRuleSpec) validate() (int, []error) {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !idRe.MatchString(r.ID) {
		add("id — строчные латинские буквы, цифры и дефис")
	}
	if len(r.Agents) > MaxToolAgents || !unique(r.Agents, agentSlugRe.MatchString) {
		add("agents — до %d slug агентов без повторов", MaxToolAgents)
	}
	if r.Tool != "" && !validToolPattern(r.Tool) {
		add("tool — сервер/имя инструмента, «*» только в конце имени")
	}
	if !unique(r.Risk, ValidRisk) {
		add("risk — low, medium, high, critical без повторов")
	}
	switch r.Action {
	case Allow, Log, RequireApproval, Block:
	default:
		add("action — allow, log, require_approval или block")
	}
	patterns := 0
	if r.Args != nil {
		s, err := argschema.CompileAny(r.Args)
		if err != nil {
			add("args: %v", err)
		} else {
			patterns = s.Patterns()
		}
	}
	if r.Rate != nil {
		if r.Rate.PerMinute < 0 || r.Rate.PerMinute > MaxRuleRateMin || r.Rate.PerHour < 0 || r.Rate.PerHour > MaxRuleRateHour {
			add("rate — per_minute от 0 до %d, per_hour от 0 до %d", MaxRuleRateMin, MaxRuleRateHour)
		}
	}
	if severityRank[r.Severity] == 0 {
		add("severity — info, low, medium, high или critical")
	}
	if r.Message != "" && checkText(r.Message, MaxMessageLen) != nil {
		add("message — до %d символов без управляющих символов", MaxMessageLen)
	}
	return patterns, errs
}

// validToolPattern — «сервер/имя»: имя не пустое, если нет «*».
func validToolPattern(s string) bool {
	if len(s) > MaxServerSlugLen+1+MaxToolNameLen+1 || !toolRe.MatchString(s) {
		return false
	}
	_, name, _ := strings.Cut(s, "/")
	return name != ""
}

// toolMatches — инструмент server/name подходит под шаблон правила.
func toolMatches(pattern, tool string) bool {
	if pattern == "" {
		return true
	}
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(tool, p)
	}
	return pattern == tool
}

// normalize — пустые списки как отсутствующие: импорт выгруженной политики
// даёт ту же политику.
func (t *ToolsSpec) normalize() {
	if len(t.Rules) == 0 {
		t.Rules = nil
	}
	for i := range t.Rules {
		r := &t.Rules[i]
		r.Agents, r.Risk = nilIfEmpty(r.Agents), nilIfEmpty(r.Risk)
		if r.Rate != nil && *r.Rate == (ToolRate{}) {
			r.Rate = nil
		}
	}
}

// CompatTools — раздел tools версии без него (ADR-0023, «Совместимость»):
// неодобренные инструменты только журналируются, остальное разрешено.
func CompatTools() ToolsSpec { return ToolsSpec{Unapproved: Log, Default: Allow} }

// ConsoleTools — раздел tools новой политики из консоли: неодобренное и
// не разрешённое правилом блокируется.
func ConsoleTools() *ToolsSpec { return &ToolsSpec{Unapproved: Block, Default: Block} }

// Clone — независимая копия раздела (схемы аргументов — тоже).
func (t *ToolsSpec) Clone() *ToolsSpec {
	if t == nil {
		return nil
	}
	c := *t
	c.Rules = slices.Clone(t.Rules)
	for i := range c.Rules {
		r := &c.Rules[i]
		r.Agents, r.Risk = slices.Clone(r.Agents), slices.Clone(r.Risk)
		if r.Args != nil {
			r.Args, _ = cloneTree(r.Args).(map[string]any)
		}
		if r.Rate != nil {
			rate := *r.Rate
			r.Rate = &rate
		}
	}
	return &c
}

func cloneTree(x any) any {
	switch v := x.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			out[k] = cloneTree(e)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = cloneTree(e)
		}
		return out
	}
	return x
}

// clipText укорачивает недоверенную строку для сообщения об ошибке.
func clipText(s string) string {
	if len(s) <= 64 {
		return s
	}
	cut := 64
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
