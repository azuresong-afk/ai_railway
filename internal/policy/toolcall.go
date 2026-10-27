package policy

import (
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

// Решение по вызову инструмента агентом (ADR-0023, раздел 2; DM-20–DM-25).
// Шаги зафиксированы тестом TestToolDecisionSteps:
//  1. Инструмент не в состоянии approved или его хеш не совпадает с
//     одобренным — действие unapproved (DM-25 для подмены, DM-24 для
//     отравленного описания, DM-20 для остального).
//  2. Иначе выбираются все правила, подходящие по агенту, инструменту и
//     риску. Ни одно не подошло — действие default (DM-20).
//  3. По каждому подходящему правилу проверяются args (нарушение — block,
//     DM-21) и rate, затем лимиты раздела (нарушение — block, DM-23).
//  4. Итог — самое сильное действие по таблице приоритетов ТЗ 5.3:
//     block > require_approval > log > allow.
// Режим monitor (ТЗ 5.3): block и require_approval только журналируются,
// вызов проходит; в решении видно, что было бы сделано в enforce.

// ToolStatus — состояние инструмента в реестре (ADR-0023, раздел 1).
type ToolStatus string

// Состояния инструмента. ToolUnknown — инструмента нет в реестре.
const (
	ToolUnknown    ToolStatus = ""
	ToolNew        ToolStatus = "new"
	ToolApproved   ToolStatus = "approved"
	ToolChanged    ToolStatus = "changed"
	ToolSuspicious ToolStatus = "suspicious"
	ToolRevoked    ToolStatus = "revoked"
)

// Угрозы матрицы 5.16 в решении по вызову.
const (
	ThreatToolNotAllowed = "DM-20"
	ThreatToolArgs       = "DM-21"
	ThreatToolApproval   = "DM-22"
	ThreatToolRate       = "DM-23"
	ThreatToolPoisoned   = "DM-24"
	ThreatToolChanged    = "DM-25"
)

// Причины шагов трассировки решения.
const (
	ToolReasonUnapproved = "unapproved"    // не одобрен (new, revoked, нет в реестре)
	ToolReasonChanged    = "changed"       // хеш описания не совпадает с одобренным
	ToolReasonSuspicious = "suspicious"    // отравленное описание
	ToolReasonNoRule     = "no_rule"       // одобрен, но ни одно правило не подошло
	ToolReasonRule       = "rule"          // действие правила
	ToolReasonArgs       = "args"          // аргументы вне ограничений правила
	ToolReasonArgsSyntax = "args_syntax"   // аргументы не проходят строгий разбор
	ToolReasonRate       = "rate"          // лимит частоты правила
	ToolReasonAgentRate  = "agent_rate"    // limits.agent_per_minute
	ToolReasonSession    = "session_calls" // limits.session_calls
	ToolReasonRepeat     = "repeat"        // limits.repeat — зацикливание
	ToolRuleUnapproved   = "tools.unapproved"
	ToolRuleDefault      = "tools.default"
	ToolRuleLimits       = "tools.limits"
)

// DefaultToolBlockMessage — сообщение агенту при отказе без сообщения правила.
const DefaultToolBlockMessage = "Вызов инструмента отклонён политикой безопасности."

// RateCounter — счётчики лимитов (toolrate.Counters): Hit учитывает вызов
// и сообщает, превышен ли limit в окне window.
type RateCounter interface {
	Hit(key string, window time.Duration, limit int, now time.Time) bool
}

// ToolCall — вызов инструмента для решения.
type ToolCall struct {
	// Mode — режим политики приложения; пусто — режим политики.
	Mode    Mode
	App     string
	Agent   string // пусто — вызов без агента (путь chat)
	Session string // пусто — сессия неизвестна
	// Server — slug MCP-сервера или FunctionServer; Name — имя инструмента.
	Server, Name string
	Status       ToolStatus
	// HashMatch — хеш описания, увиденный шлюзом, равен одобренному.
	HashMatch bool
	Risk      ToolRisk
	// Args — аргументы вызова (JSON); пусто — {}.
	Args []byte
	// ArgsHash — хеш аргументов для признака зацикливания (вычисляет
	// вызывающий через internal/crypto); пусто — repeat не считается.
	ArgsHash string
	Now      time.Time
}

// ToolStep — шаг трассировки решения: правило (или tools.*), действие,
// угроза и причина.
type ToolStep struct {
	Rule   string
	Action Action
	Threat string
	Reason string
}

// ToolDecision — решение по вызову инструмента.
type ToolDecision struct {
	PolicyID string
	Version  int
	Mode     Mode
	// Action — итог по таблице приоритетов: что было бы сделано в enforce.
	Action Action
	Rule   string
	// Block — вызов отклоняется; Approval — вызов ждёт подтверждения
	// человеком (только enforce).
	Block    bool
	Approval bool
	Severity Severity
	Message  string
	Threats  []string
	Trace    []ToolStep
	// ApprovalTimeout — срок ожидания подтверждения.
	ApprovalTimeout time.Duration
	// Args — разобранные аргументы (если разбор выполнялся): шлюз
	// передаёт серверу MCP ровно их (ADR-0023, раздел 6).
	Args *argschema.Value
}

// toolPolicy — скомпилированный раздел tools.
type toolPolicy struct {
	declared        bool
	unapproved, def Action
	approvalTimeout time.Duration
	limits          ToolLimits
	rules           []toolRule
}

type toolRule struct {
	id       string
	agents   []string
	tool     string
	risk     []ToolRisk
	action   Action
	args     *argschema.Schema
	rate     ToolRate
	severity Severity
	message  string
}

// compileTools — раздел tools проверен Validate; nil — совместимость.
func compileTools(t *ToolsSpec) (toolPolicy, error) {
	if t == nil {
		c := CompatTools()
		return toolPolicy{unapproved: c.Unapproved, def: c.Default, approvalTimeout: DefaultApprovalTimeout}, nil
	}
	tp := toolPolicy{declared: true, unapproved: t.Unapproved, def: t.Default, limits: t.Limits,
		approvalTimeout: time.Duration(t.ApprovalTimeout)}
	if tp.approvalTimeout == 0 {
		tp.approvalTimeout = DefaultApprovalTimeout
	}
	for _, r := range t.Rules {
		tr := toolRule{id: r.ID, agents: slices.Clone(r.Agents), tool: r.Tool, risk: slices.Clone(r.Risk), action: r.Action,
			severity: r.Severity, message: r.Message}
		if r.Rate != nil {
			tr.rate = *r.Rate
		}
		if r.Args != nil {
			s, err := argschema.CompileAny(r.Args)
			if err != nil {
				return toolPolicy{}, err
			}
			tr.args = s
		}
		tp.rules = append(tp.rules, tr)
	}
	return tp, nil
}

// ToolsDeclared — у версии есть раздел tools (иначе — умолчания
// совместимости).
func (p *Policy) ToolsDeclared() bool { return p.tools.declared }

// ToolsUnapproved — действие для неодобренных инструментов (MCP-прокси
// убирает их из tools/list в enforce, задача 4.11).
func (p *Policy) ToolsUnapproved() Action { return p.tools.unapproved }

func (r *toolRule) matches(c *ToolCall, tool string) bool {
	if len(r.agents) > 0 && !slices.Contains(r.agents, c.Agent) {
		return false
	}
	if len(r.risk) > 0 && !slices.Contains(r.risk, c.Risk) {
		return false
	}
	return toolMatches(r.tool, tool)
}

// keySep — разделитель частей ключа счётчика: в slug и ID его нет.
const keySep = "\x1f"

// maxKeyPart — байт одной части ключа: сессия и имя инструмента приходят
// извне, и без предела 100 000 ключей счётчиков не ограничивали бы память.
// Обрезка только сливает счётчики (строже), но не разделяет их.
const maxKeyPart = 256

func rateKey(parts ...string) string {
	for i, p := range parts {
		if len(p) > maxKeyPart {
			parts[i] = p[:maxKeyPart]
		}
	}
	return strings.Join(parts, keySep)
}

// ToolListed — инструмент показывается агенту в tools/list в режиме
// enforce (ADR-0023, раздел 6, tools/list, п. 4; задача 4.11): вызов не
// был бы заблокирован по состоянию в реестре и по правилам — шаги 1 и 2
// DecideTool. Подменённое описание (хеш не совпал с одобренным) не
// показывается никогда. Аргументы, частота и лимиты не учитываются: их
// проверяет tools/call. Находки встроенной проверки описаний (DM-24)
// учитывает вызывающий.
func (p *Policy) ToolListed(c ToolCall) bool {
	tp := &p.tools
	switch {
	case c.Status == ToolApproved && !c.HashMatch:
		return false
	case c.Status != ToolApproved:
		return tp.unapproved != Block
	}
	tool := c.Server + "/" + c.Name
	matched := false
	for i := range tp.rules {
		if !tp.rules[i].matches(&c, tool) {
			continue
		}
		if tp.rules[i].action == Block {
			return false
		}
		matched = true
	}
	return matched || tp.def != Block
}

// DecideTool вычисляет решение по вызову инструмента. rc — счётчики
// лимитов; nil — лимиты не считаются.
func (p *Policy) DecideTool(c ToolCall, rc RateCounter) ToolDecision {
	mode := c.Mode
	switch mode {
	case "":
		mode = p.Mode
	case Monitor, Enforce:
	default:
		mode = Enforce
	}
	now := c.Now
	if now.IsZero() {
		now = time.Now()
	}
	tp := &p.tools
	d := ToolDecision{PolicyID: p.ID, Version: p.Version, Mode: mode, Action: Allow, ApprovalTimeout: tp.approvalTimeout}
	best := -1 // порядок решающего шага
	step := func(s ToolStep, sev Severity, msg string) {
		d.Trace = append(d.Trace, s)
		if s.Threat != "" && !slices.Contains(d.Threats, s.Threat) {
			d.Threats = append(d.Threats, s.Threat)
		}
		if s.Action != Allow && severityRank[sev] > severityRank[d.Severity] {
			d.Severity = sev
		}
		if best < 0 || Stronger(s.Action, d.Action) {
			d.Action, d.Rule, d.Message, best = s.Action, s.Rule, msg, len(d.Trace)-1
		}
	}
	tool := c.Server + "/" + c.Name

	// Строгий разбор аргументов — до всех шагов и при любом состоянии
	// инструмента (в monitor и при unapproved: log вызов проходит, и
	// серверу MCP уходят ровно разобранные аргументы). Только при
	// объявленном разделе: версия без него ведёт себя как прежде.
	var args *argschema.Value
	argsErr := false
	if tp.declared {
		raw := c.Args
		if len(raw) == 0 {
			raw = []byte("{}")
		}
		v, err := argschema.ValidateArgs(nil, raw)
		if err != nil {
			argsErr = true
			step(ToolStep{Rule: ToolRuleLimits, Action: Block, Threat: ThreatToolArgs, Reason: ToolReasonArgsSyntax}, High, "")
		} else {
			args = &v
			d.Args = args
		}
	}

	// Шаг 1. Состояние в реестре.
	if c.Status != ToolApproved || !c.HashMatch {
		reason, threat, sev := ToolReasonUnapproved, ThreatToolNotAllowed, Medium
		switch c.Status {
		case ToolChanged, ToolApproved:
			reason, threat, sev = ToolReasonChanged, ThreatToolChanged, High
		case ToolSuspicious:
			reason, threat, sev = ToolReasonSuspicious, ThreatToolPoisoned, High
		}
		step(ToolStep{Rule: ToolRuleUnapproved, Action: tp.unapproved, Threat: threat, Reason: reason}, sev, "")
		return p.finishTool(d)
	}

	// Шаг 2. Подходящие правила.
	var matched []*toolRule
	for i := range tp.rules {
		if tp.rules[i].matches(&c, tool) {
			matched = append(matched, &tp.rules[i])
		}
	}
	if len(matched) == 0 {
		threat := ThreatToolNotAllowed
		if tp.def == Allow {
			threat = ""
		}
		step(ToolStep{Rule: ToolRuleDefault, Action: tp.def, Threat: threat, Reason: ToolReasonNoRule}, Medium, "")
	}

	// Шаг 3. Частота правил, лимиты раздела, аргументы по правилам.
	for _, r := range matched {
		threat := ""
		switch r.action {
		case Block:
			threat = ThreatToolNotAllowed
		case RequireApproval:
			threat = ThreatToolApproval
		}
		step(ToolStep{Rule: r.id, Action: r.action, Threat: threat, Reason: ToolReasonRule}, r.severity, r.message)
		if r.args != nil && args != nil && !argsErr {
			if err := r.args.Validate(*args); err != nil {
				step(ToolStep{Rule: r.id, Action: Block, Threat: ThreatToolArgs, Reason: ToolReasonArgs}, r.severity, r.message)
			}
		}
		if rc != nil {
			if rc.Hit(rateKey("rule", c.App, c.Agent, r.id, "m"), time.Minute, r.rate.PerMinute, now) ||
				rc.Hit(rateKey("rule", c.App, c.Agent, r.id, "h"), time.Hour, r.rate.PerHour, now) {
				step(ToolStep{Rule: r.id, Action: Block, Threat: ThreatToolRate, Reason: ToolReasonRate}, r.severity, r.message)
			}
		}
	}
	if rc != nil {
		l := tp.limits
		limit := func(reason string, exceeded bool) {
			if exceeded {
				step(ToolStep{Rule: ToolRuleLimits, Action: Block, Threat: ThreatToolRate, Reason: reason}, Medium, "")
			}
		}
		limit(ToolReasonAgentRate, rc.Hit(rateKey("agent", c.App, c.Agent), time.Minute, l.AgentPerMinute, now))
		if c.Session != "" {
			limit(ToolReasonSession, rc.Hit(rateKey("session", c.App, c.Agent, c.Session), 24*time.Hour, l.SessionCalls, now))
			if c.ArgsHash != "" {
				limit(ToolReasonRepeat, rc.Hit(rateKey("repeat", c.App, c.Agent, c.Session, tool, c.ArgsHash),
					time.Duration(l.RepeatWindow), l.Repeat, now))
			}
		}
	}
	return p.finishTool(d)
}

// finishTool — режим и сообщение итога.
func (p *Policy) finishTool(d ToolDecision) ToolDecision {
	d.Block = d.Mode == Enforce && d.Action == Block
	d.Approval = d.Mode == Enforce && d.Action == RequireApproval
	// Сообщение правила require_approval нужно для ответа агенту при
	// отказе дежурного.
	if !d.Block && !d.Approval {
		d.Message = ""
	} else if d.Block && d.Message == "" {
		d.Message = DefaultToolBlockMessage
	}
	return d
}
