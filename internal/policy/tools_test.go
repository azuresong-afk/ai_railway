package policy

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
	"github.com/azuresong-afk/ai_railway/internal/policy/toolrate"
)

// toolsYAML — политика с разделом tools по примеру ADR-0023, раздел 2.
const toolsYAML = `id: agents
name: Агенты
version: 1
mode: enforce
rules: []
tools:
  unapproved: block
  default: block
  approval_timeout: 10m
  limits:
    agent_per_minute: 120
    session_calls: 500
    repeat: 5
    repeat_window: 10m
  rules:
    - id: reports-read
      agents: [report-bot]
      tool: files/read_*
      action: allow
      args:
        type: object
        required: [path]
        properties:
          path: {type: string, maxLength: 512, x-aisec-path-prefix: ["/data/reports/"]}
      rate: {per_minute: 30, per_hour: 600}
      severity: medium
      message: Чтение разрешено только из каталога отчётов
    - id: mail-send
      tool: mail/send
      action: allow
      args:
        type: object
        additionalProperties: false
        required: [to, amount]
        properties:
          to: {type: string, x-aisec-domains: [example.ru]}
          amount: {type: integer, minimum: 1, maximum: 1000}
          kind: {enum: [invoice, notice]}
      severity: high
    - id: high-risk
      risk: [high, critical]
      action: require_approval
      severity: high
      message: Вызов подтверждает дежурный
    - id: deny-delete
      tool: files/delete*
      action: block
      severity: critical
`

func mustTools(t *testing.T, doc string) *Policy {
	t.Helper()
	s, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func approved(server, name string, risk ToolRisk, args string) ToolCall {
	return ToolCall{App: "app", Agent: "report-bot", Session: "s1", Server: server, Name: name, Status: ToolApproved,
		HashMatch: true, Risk: risk, Args: []byte(args), Now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
}

func TestToolsYAMLRoundTrip(t *testing.T) {
	s, err := Parse(strings.NewReader(toolsYAML))
	if err != nil {
		t.Fatal(err)
	}
	y, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Parse(strings.NewReader(string(y)))
	if err != nil {
		t.Fatalf("выгруженная политика не разбирается: %v\n%s", err, y)
	}
	y2, err := Marshal(s2)
	if err != nil || string(y) != string(y2) {
		t.Fatalf("выгрузка не устойчива:\n%s\n---\n%s", y, y2)
	}
	if !strings.Contains(string(y), "repeat_window: 10m") || !strings.Contains(string(y), "approval_timeout: 10m") {
		t.Errorf("длительности не в короткой записи:\n%s", y)
	}
}

func TestToolsValidation(t *testing.T) {
	base := "id: p\nname: P\nversion: 1\nmode: enforce\nrules: []\ntools:\n"
	bad := map[string]string{
		"нет unapproved":         "  default: block\n",
		"allow в unapproved":     "  unapproved: allow\n  default: block\n",
		"redact в default":       "  unapproved: block\n  default: redact\n",
		"таймаут мал":            "  unapproved: block\n  default: block\n  approval_timeout: 30s\n",
		"таймаут велик":          "  unapproved: block\n  default: block\n  approval_timeout: 2h\n",
		"repeat без окна":        "  unapproved: block\n  default: block\n  limits: {repeat: 5}\n",
		"лимит выше предела":     "  unapproved: block\n  default: block\n  limits: {agent_per_minute: 100001}\n",
		"отрицательный лимит":    "  unapproved: block\n  default: block\n  limits: {session_calls: -1}\n",
		"незнакомое поле":        "  unapproved: block\n  default: block\n  allow_all: true\n",
		"действие redact":        "  unapproved: block\n  default: block\n  rules:\n    - {id: a, action: redact, severity: low}\n",
		"звёздочка в середине":   "  unapproved: block\n  default: block\n  rules:\n    - {id: a, tool: 'fs/*read', action: allow, severity: low}\n",
		"сервер без имени":       "  unapproved: block\n  default: block\n  rules:\n    - {id: a, tool: 'fs/', action: allow, severity: low}\n",
		"плохой агент":           "  unapproved: block\n  default: block\n  rules:\n    - {id: a, agents: [Bot], action: allow, severity: low}\n",
		"плохой риск":            "  unapproved: block\n  default: block\n  rules:\n    - {id: a, risk: [extreme], action: allow, severity: low}\n",
		"повтор правила":         "  unapproved: block\n  default: block\n  rules:\n    - {id: a, action: allow, severity: low}\n    - {id: a, action: block, severity: low}\n",
		"незнакомое слово схемы": "  unapproved: block\n  default: block\n  rules:\n    - {id: a, action: allow, severity: low, args: {type: object, format: email}}\n",
		"ссылка в схеме":         "  unapproved: block\n  default: block\n  rules:\n    - {id: a, action: allow, severity: low, args: {$ref: '#/x'}}\n",
		"схема не объект":        "  unapproved: block\n  default: block\n  rules:\n    - {id: a, action: allow, severity: low, args: [1]}\n",
		"rate выше предела":      "  unapproved: block\n  default: block\n  rules:\n    - {id: a, action: allow, severity: low, rate: {per_hour: 1000001}}\n",
		"глубокая схема":         "  unapproved: block\n  default: block\n  rules:\n    - {id: a, action: allow, severity: low, args: {items: {items: {items: {items: {items: {items: {items: {items: {items: {}}}}}}}}}}}\n",
	}
	for name, tail := range bad {
		if _, err := Parse(strings.NewReader(base + tail)); err == nil {
			t.Errorf("%s: политика должна быть отвергнута", name)
		}
	}
	// Предел pattern на политику.
	var b strings.Builder
	b.WriteString(base + "  unapproved: block\n  default: block\n  rules:\n")
	for i := range argschema.MaxPatternsPerPolicy + 1 {
		b.WriteString("    - {id: r" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + itoa(i) +
			", action: allow, severity: low, args: {pattern: 'a+'}}\n")
	}
	if _, err := Parse(strings.NewReader(b.String())); err == nil || !strings.Contains(err.Error(), "pattern") {
		t.Errorf("больше 64 выражений pattern в политике: %v", err)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// Совместимость: версия без раздела tools — неодобренные только в журнал,
// остальное разрешено, аргументы не разбираются строго.
func TestToolsCompatWithoutSection(t *testing.T) {
	s, err := Parse(strings.NewReader("id: old\nname: Старая\nversion: 3\nmode: enforce\nrules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Tools != nil {
		t.Fatal("раздел tools появился сам")
	}
	p, err := Compile(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.ToolsDeclared() || p.ToolsUnapproved() != Log {
		t.Fatal("умолчания совместимости не те")
	}
	c := approved("fs", "read", RiskHigh, `{"a":1,"a":2}`)
	if d := p.DecideTool(c, toolrate.New(0)); d.Action != Allow || d.Block || len(d.Threats) != 0 {
		t.Errorf("одобренный инструмент в старой политике: %+v", d)
	}
	c.Status = ToolNew
	if d := p.DecideTool(c, nil); d.Action != Log || d.Block || !slices.Contains(d.Threats, ThreatToolNotAllowed) {
		t.Errorf("неодобренный инструмент в старой политике: %+v", d)
	}
	y, err := Marshal(s)
	if err != nil || strings.Contains(string(y), "tools") {
		t.Errorf("версия без раздела выгружается с разделом:\n%s", y)
	}
}

func TestDM20_ToolNotInAllowlistBlocked(t *testing.T) {
	p := mustTools(t, toolsYAML)
	// Одобренный инструмент без подходящего правила — default: block.
	d := p.DecideTool(approved("db", "query", RiskLow, `{}`), nil)
	if !d.Block || d.Rule != ToolRuleDefault || !slices.Contains(d.Threats, ThreatToolNotAllowed) || d.Message == "" {
		t.Fatalf("вызов вне allowlist: %+v", d)
	}
	// Правило для другого агента не подходит.
	c := approved("files", "read_report", RiskLow, `{"path":"/data/reports/a"}`)
	c.Agent = "other-bot"
	if d := p.DecideTool(c, nil); !d.Block || d.Rule != ToolRuleDefault {
		t.Fatalf("правило другого агента применилось: %+v", d)
	}
	// Запрещающее правило сильнее разрешающего.
	if d := p.DecideTool(approved("files", "delete_all", RiskLow, `{}`), nil); !d.Block || d.Rule != "deny-delete" {
		t.Fatalf("block-правило: %+v", d)
	}
	// Неодобренный, отозванный и неизвестный инструменты — unapproved.
	for _, st := range []ToolStatus{ToolNew, ToolRevoked, ToolUnknown} {
		c := approved("files", "read_report", RiskLow, `{"path":"/data/reports/a"}`)
		c.Status = st
		if d := p.DecideTool(c, nil); !d.Block || d.Rule != ToolRuleUnapproved || !slices.Contains(d.Threats, ThreatToolNotAllowed) {
			t.Errorf("состояние %q: %+v", st, d)
		}
	}
	// Разрешённый вызов.
	if d := p.DecideTool(approved("files", "read_report", RiskLow, `{"path":"/data/reports/a.csv"}`), nil); d.Block || d.Action != Allow {
		t.Fatalf("разрешённый вызов: %+v", d)
	}
}

func TestDM25_ChangedDescriptorBlockedByPolicy(t *testing.T) {
	p := mustTools(t, toolsYAML)
	c := approved("files", "read_report", RiskLow, `{"path":"/data/reports/a"}`)
	c.HashMatch = false // одобрен, но описание подменено после одобрения
	d := p.DecideTool(c, nil)
	if !d.Block || !slices.Contains(d.Threats, ThreatToolChanged) || d.Trace[0].Reason != ToolReasonChanged {
		t.Fatalf("подменённое описание: %+v", d)
	}
	c.Status, c.HashMatch = ToolSuspicious, true
	if d := p.DecideTool(c, nil); !d.Block || !slices.Contains(d.Threats, ThreatToolPoisoned) {
		t.Fatalf("отравленное описание: %+v", d)
	}
}

func TestDM21_ArgsOutsideConstraintsBlocked(t *testing.T) {
	p := mustTools(t, toolsYAML)
	read := func(path string) ToolDecision {
		return p.DecideTool(approved("files", "read_report", RiskLow, `{"path":"`+path+`"}`), nil)
	}
	for _, path := range []string{`/data/reports/../secret`, `/data/reports/%2e%2e/secret`, `/data/reports\\..\\x`,
		`/data/reports-old/a`, `data/reports/a`, `/etc/passwd`} {
		d := read(path)
		if !d.Block || !slices.Contains(d.Threats, ThreatToolArgs) || d.Message != "Чтение разрешено только из каталога отчётов" {
			t.Errorf("путь %q: %+v", path, d)
		}
	}
	if d := read(`/data/reports/2026/x.csv`); d.Block {
		t.Errorf("путь внутри каталога отклонён: %+v", d)
	}
	mail := func(args string) ToolDecision { return p.DecideTool(approved("mail", "send", RiskLow, args), nil) }
	for _, args := range []string{
		`{"to":"a@evil.com","amount":5}`, `{"to":"a@example.ru.evil.com","amount":5}`, // домены
		`{"to":"a@example.ru","amount":0}`, `{"to":"a@example.ru","amount":1001}`, // диапазоны
		`{"to":"a@example.ru","amount":5,"kind":"refund"}`,         // enum
		`{"to":"a@example.ru","amount":5,"cc":"x@evil.com"}`,       // лишнее свойство
		`{"to":"a@example.ru"}`,                                    // нет обязательного
		`{"to":"a@example.ru","amount":5,"amount":6}`,              // повтор ключа
		"{\"to\":\"a@example.ru\",\"amount\":5,\"kind\":\"\xff\"}", // неверный UTF-8
		`{"to":"a@example.ru","amount":5} {}`,                      // данные после JSON
	} {
		if d := mail(args); !d.Block || !slices.Contains(d.Threats, ThreatToolArgs) {
			t.Errorf("аргументы %s: %+v", args, d)
		}
	}
	if d := mail(`{"to":"buh@mail.example.ru","amount":1000,"kind":"invoice"}`); d.Block {
		t.Errorf("допустимые аргументы отклонены: %+v", d)
	}
}

func TestDM23_AgentRateLimit(t *testing.T) {
	p := mustTools(t, toolsYAML)
	rc := toolrate.New(0)
	c := approved("files", "read_report", RiskLow, `{"path":"/data/reports/a"}`)
	c.Session = "" // без сессии считаются лимиты агента и правила
	blocked := 0
	for i := range 40 {
		c.Args = []byte(`{"path":"/data/reports/` + itoa(i) + `"}`)
		d := p.DecideTool(c, rc)
		if d.Block {
			blocked++
			if !slices.Contains(d.Threats, ThreatToolRate) || d.Trace[len(d.Trace)-1].Reason != ToolReasonRate {
				t.Fatalf("причина отказа: %+v", d)
			}
		}
	}
	// rate правила — 30 в минуту.
	if blocked != 10 {
		t.Fatalf("заблокировано %d вызовов из 40 при rate 30/мин", blocked)
	}
	// Через две минуты окно свободно.
	c.Now = c.Now.Add(2 * time.Minute)
	if d := p.DecideTool(c, rc); d.Block {
		t.Fatalf("после окна вызов отклонён: %+v", d)
	}
	// limits.agent_per_minute — 120 на агента по всем правилам.
	rc = toolrate.New(0)
	m := approved("mail", "send", RiskLow, `{"to":"a@example.ru","amount":1}`)
	m.Session = ""
	for i := range 121 {
		d := p.DecideTool(m, rc)
		if (i < 120) == d.Block {
			t.Fatalf("вызов %d: %+v", i+1, d)
		}
		if i == 120 && d.Trace[len(d.Trace)-1].Reason != ToolReasonAgentRate {
			t.Fatalf("причина: %+v", d.Trace)
		}
	}
}

func TestDM23_RepeatedCallLoopBlocked(t *testing.T) {
	p := mustTools(t, toolsYAML)
	rc := toolrate.New(0)
	c := approved("mail", "send", RiskLow, `{"to":"a@example.ru","amount":1}`)
	c.ArgsHash = "h1"
	for i := range 6 {
		d := p.DecideTool(c, rc)
		if (i < 5) == d.Block {
			t.Fatalf("повтор %d: %+v", i+1, d)
		}
		if i == 5 && (d.Trace[len(d.Trace)-1].Reason != ToolReasonRepeat || !slices.Contains(d.Threats, ThreatToolRate)) {
			t.Fatalf("причина: %+v", d)
		}
	}
	// Другие аргументы — другой счётчик повторов; другая сессия — тоже.
	c.ArgsHash = "h2"
	if d := p.DecideTool(c, rc); d.Block {
		t.Fatalf("другие аргументы: %+v", d)
	}
	c.ArgsHash, c.Session = "h1", "s2"
	if d := p.DecideTool(c, rc); d.Block {
		t.Fatalf("другая сессия: %+v", d)
	}
	// session_calls — 500 вызовов агента в сессии за 24 ч.
	rc = toolrate.New(0)
	c.Session = "s3"
	for i := range 501 {
		c.ArgsHash = itoa(i)
		c.Now = c.Now.Add(time.Second) // agent_per_minute не мешает: 120 в минуту
		d := p.DecideTool(c, rc)
		if i < 500 && d.Block && d.Trace[len(d.Trace)-1].Reason != ToolReasonAgentRate {
			t.Fatalf("вызов %d: %+v", i+1, d)
		}
		if i == 500 && !slices.ContainsFunc(d.Trace, func(s ToolStep) bool { return s.Reason == ToolReasonSession }) {
			t.Fatalf("session_calls не сработал: %+v", d.Trace)
		}
	}
}

// TestToolDecisionSteps фиксирует шаги решения и таблицу приоритетов
// (ADR-0023, раздел 2, как TestPriorityTable для детекторов).
func TestToolDecisionSteps(t *testing.T) {
	p := mustTools(t, toolsYAML)
	// require_approval сильнее allow и log.
	c := approved("files", "read_report", RiskHigh, `{"path":"/data/reports/a"}`)
	d := p.DecideTool(c, nil)
	if d.Action != RequireApproval || !d.Approval || d.Block || d.Rule != "high-risk" || !slices.Contains(d.Threats, ThreatToolApproval) ||
		d.ApprovalTimeout != 10*time.Minute || d.Message != "Вызов подтверждает дежурный" {
		t.Fatalf("require_approval: %+v", d)
	}
	// block из-за аргументов сильнее require_approval.
	c.Args = []byte(`{"path":"/etc/passwd"}`)
	if d := p.DecideTool(c, nil); d.Action != Block || d.Approval || !slices.Contains(d.Threats, ThreatToolArgs) {
		t.Fatalf("block > require_approval: %+v", d)
	}
	// Шаг 1 прекращает решение: правила не применяются.
	c.Status = ToolNew
	if d := p.DecideTool(c, nil); len(d.Trace) != 1 || d.Trace[0].Rule != ToolRuleUnapproved {
		t.Fatalf("шаг 1: %+v", d.Trace)
	}
	// Порядок приоритетов действий политики вызовов.
	order := []Action{Allow, Log, RequireApproval, Block}
	for i := 1; i < len(order); i++ {
		if !Stronger(order[i], order[i-1]) {
			t.Errorf("%s должно быть сильнее %s", order[i], order[i-1])
		}
	}
	// Совпало несколько правил: итог — самое сильное, трассировка — все.
	m := approved("mail", "send", RiskCritical, `{"to":"a@example.ru","amount":1}`)
	d = p.DecideTool(m, nil)
	if d.Action != RequireApproval || len(d.Trace) != 2 {
		t.Fatalf("несколько правил: %+v", d)
	}
}

func TestToolMonitorOnlyLogs(t *testing.T) {
	p := mustTools(t, toolsYAML)
	c := approved("files", "read_report", RiskLow, `{"path":"/etc/passwd"}`)
	c.Mode = Monitor
	d := p.DecideTool(c, nil)
	if d.Action != Block || d.Block || d.Approval || d.Message != "" || !slices.Contains(d.Threats, ThreatToolArgs) {
		t.Fatalf("monitor: %+v", d)
	}
	c = approved("files", "read_report", RiskHigh, `{"path":"/data/reports/a"}`)
	c.Mode = Monitor
	if d := p.DecideTool(c, nil); d.Action != RequireApproval || d.Approval {
		t.Fatalf("monitor и require_approval: %+v", d)
	}
	c.HashMatch = false
	if d := p.DecideTool(c, nil); d.Block || !slices.Contains(d.Threats, ThreatToolChanged) {
		t.Fatalf("monitor и DM-25: %+v", d)
	}
	// Незнакомый режим — enforce: ошибка вызывающего не ослабляет защиту.
	c.Mode = "observe"
	if d := p.DecideTool(c, nil); !d.Block {
		t.Fatalf("незнакомый режим: %+v", d)
	}
	// Неодобренный инструмент в monitor: аргументы всё равно разбираются
	// строго, повтор ключа виден в решении, разобранных аргументов нет.
	c = approved("files", "read_report", RiskLow, `{"path":"/data/reports/a","path":"/etc/passwd"}`)
	c.Mode, c.Status = Monitor, ToolNew
	if d := p.DecideTool(c, nil); d.Block || d.Args != nil || !slices.Contains(d.Threats, ThreatToolArgs) {
		t.Fatalf("monitor, неодобренный, повтор ключа: %+v", d)
	}
}

// Части ключа счётчика ограничены: длинная сессия не раздувает память.
func TestRateKeyBounded(t *testing.T) {
	k := rateKey("session", "app", "bot", strings.Repeat("s", 1<<20))
	if len(k) > 4*maxKeyPart {
		t.Fatalf("длина ключа %d", len(k))
	}
}

func TestAgentBaseTemplate(t *testing.T) {
	s, ok := Template(TemplateAgentBase)
	if !ok || s.Tools == nil || s.Tools.Unapproved != Block || s.Tools.Default != Block || s.Mode != Enforce {
		t.Fatalf("шаблон: %+v", s)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	// Риск high — подтверждение, low — разрешено.
	ps, err := Compile(&Spec{ID: "a", Name: "A", Version: 1, Mode: Enforce, Tools: s.Tools}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := ps.DecideTool(approved("fs", "rm", RiskHigh, `{}`), nil); !d.Approval {
		t.Errorf("high: %+v", d)
	}
	if d := ps.DecideTool(approved("fs", "ls", RiskLow, `{}`), nil); d.Block || d.Approval {
		t.Errorf("low: %+v", d)
	}
	// Копия шаблона независима.
	s.Tools.Rules[0].Risk[0] = RiskLow
	s2, _ := Template(TemplateAgentBase)
	if s2.Tools.Rules[0].Risk[0] != RiskHigh {
		t.Error("изменение копии изменило шаблон")
	}
}

// DM-24, DM-25 (tools/list): в enforce агенту показываются только
// инструменты, вызов которых не был бы заблокирован по состоянию и
// правилам; подменённое описание — никогда.
func TestDM20_ToolListed(t *testing.T) {
	p := mustTools(t, toolsYAML)
	cases := []struct {
		c    ToolCall
		want bool
	}{
		{approved("files", "read_report", RiskLow, ""), true},
		{approved("files", "delete_all", RiskLow, ""), false}, // block-правило
		{approved("db", "query", RiskLow, ""), false},         // default: block
		{approved("db", "query", RiskHigh, ""), true},         // require_approval
	}
	for _, st := range []ToolStatus{ToolNew, ToolRevoked, ToolUnknown, ToolSuspicious, ToolChanged} {
		c := approved("files", "read_report", RiskLow, "")
		c.Status = st
		cases = append(cases, struct {
			c    ToolCall
			want bool
		}{c, false})
	}
	changed := approved("files", "read_report", RiskLow, "")
	changed.HashMatch = false
	cases = append(cases, struct {
		c    ToolCall
		want bool
	}{changed, false})
	for i, tc := range cases {
		if got := p.ToolListed(tc.c); got != tc.want {
			t.Errorf("случай %d (%s/%s, %q): %v", i, tc.c.Server, tc.c.Name, tc.c.Status, got)
		}
	}
	// Без раздела tools (совместимость: unapproved log, default allow) —
	// неодобренный показывается, подменённый — нет.
	compat := mustTools(t, "id: c\nname: C\nversion: 1\nmode: enforce\nrules: []\n")
	c := approved("files", "read_report", RiskLow, "")
	c.Status = ToolNew
	if !compat.ToolListed(c) {
		t.Error("совместимость: неодобренный скрыт")
	}
	c.Status, c.HashMatch = ToolApproved, false
	if compat.ToolListed(c) {
		t.Error("совместимость: подменённый показан")
	}
}
