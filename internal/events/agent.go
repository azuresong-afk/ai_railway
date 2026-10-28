package events

import (
	"errors"
	"fmt"
	"regexp"
)

// События агентов (ТЗ 5.5, 5.10; ADR-0023, раздел 7; задача 4.11 этапа
// 4). agent_tool_call — вызов инструмента: tools/call через MCP-прокси или
// tool_calls в ответе модели; agent_mcp — остальные методы MCP (tools/list,
// resources/*, prompts/*, server/discover, отклонённые методы и
// нарушения протокола). Решение по вызову и трассировка правил раздела
// tools — в Decision, находки по аргументам, результату и описаниям — в
// Findings; аргументы и результат — в Content по режиму хранения.
const (
	TypeAgentToolCall = "agent_tool_call"
	TypeAgentMCP      = "agent_mcp"
)

// Пути вызова инструмента.
const (
	AgentPathMCP  = "mcp"
	AgentPathChat = "chat"
)

// Итоги ожидания подтверждения (DM-22; совпадают с gateway.ApprovalState).
var approvalStates = map[string]bool{"approved": true, "denied": true, "timeout": true, "cancelled": true,
	"interrupted": true, "queue_full": true, "unavailable": true}

// Пределы раздела agent.
const (
	// MaxAgentNames — имён инструментов в списках hidden, poisoned, changed.
	MaxAgentNames = 256
	maxAgentName  = 128
)

var (
	agentSlugRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	toolNameRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	hashHexRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	protocolRe  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	violationRe = regexp.MustCompile(`^[a-z_]{1,64}$`)
	methodRe    = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,128}$`)
)

// Agent — подробности события агента. Строки здесь — служебные имена и
// хеши, без содержимого: имена инструментов проверены по правилу имени
// (tooldesc.ValidName), недоверенные имена в событие не попадают.
type Agent struct {
	// Path — mcp или chat (agent_tool_call); RequestEventID — событие
	// gateway_request для chat.
	Path           string `json:"path,omitempty"`
	RequestEventID string `json:"request_event_id,omitempty"`
	// Agent — slug агента; Server — slug MCP-сервера (function для пути
	// chat); Method — метод MCP; Protocol — ревизия MCP.
	Agent    string `json:"agent,omitempty"`
	Server   string `json:"server,omitempty"`
	Method   string `json:"method,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	// Tool — имя инструмента, ToolHash — хеш увиденного описания, Risk —
	// уровень риска из реестра, ToolStatus — состояние в реестре.
	Tool       string `json:"tool,omitempty"`
	ToolHash   string `json:"tool_hash,omitempty"`
	Risk       string `json:"risk,omitempty"`
	ToolStatus string `json:"tool_status,omitempty"`
	// Session — псевдоним сессии (32 hex): X-AISec-Session или
	// Mcp-Session-Id (2025-11-25) на ключе шлюза.
	Session string `json:"session,omitempty"`
	// Approval — подтверждение человеком (DM-22).
	Approval *Approval `json:"approval,omitempty"`
	// Upstream — HTTP-статус вышестоящего сервера (0 — не обращались),
	// ResultBytes — размер результата, IsError — результат с isError.
	Upstream    int  `json:"upstream_status,omitempty"`
	ResultBytes int  `json:"result_bytes,omitempty"`
	IsError     bool `json:"is_error,omitempty"`
	// ArgsUnmasked — по аргументам сработали redact или pseudonymize, но
	// аргументы не маскировались: маска сломала бы вызов (ADR-0023, раздел 6).
	ArgsUnmasked bool `json:"args_unmasked,omitempty"`
	// Items — элементов в списке от сервера; Hidden — инструменты,
	// убранные из tools/list; Poisoned — с находками встроенной проверки
	// описаний (DM-24); Changed — с хешем, отличным от одобренного (DM-25);
	// Invalid — исключённые разбором (неверное описание, повтор имени).
	Items    int      `json:"items,omitempty"`
	Hidden   []string `json:"hidden,omitempty"`
	Poisoned []string `json:"poisoned,omitempty"`
	Changed  []string `json:"changed,omitempty"`
	Invalid  int      `json:"invalid,omitempty"`
	// Stripped — вырезанные возможности клиента (sampling, roots и т. п.);
	// Dropped — сообщения сервера, не переданные клиенту (запросы к
	// клиенту, input_required, прочие уведомления).
	Stripped []string `json:"stripped,omitempty"`
	Dropped  int      `json:"dropped,omitempty"`
	// Violation — нарушение протокола, из-за которого шлюз отказал:
	// header_mismatch, unsupported_version, method_not_allowed, batch,
	// invalid_message, session_unknown, origin, input_required и т. п.
	Violation string `json:"violation,omitempty"`
}

// Approval — итог ожидания подтверждения вызова.
type Approval struct {
	ID        string `json:"id,omitempty"`
	State     string `json:"state"`
	DecidedBy string `json:"decided_by,omitempty"`
	WaitedMS  int64  `json:"waited_ms"`
	Comment   string `json:"comment,omitempty"`
}

// validateAgent — раздел agent событий агентов.
func (e *Event) validateAgent() []error {
	var errs []error
	a := e.Agent
	if e.App == "" || e.Decision == nil || e.Decision.Action == "" {
		errs = append(errs, fmt.Errorf("%s: нужны приложение и решение", e.Type))
	}
	if e.PolicyMode != ModeMonitor && e.PolicyMode != ModeEnforce {
		errs = append(errs, fmt.Errorf("%s: неизвестный режим политики %q", e.Type, e.PolicyMode))
	}
	if e.Session != nil {
		errs = append(errs, fmt.Errorf("%s: сессия агента — в agent.session", e.Type))
	}
	if a == nil {
		return append(errs, fmt.Errorf("%s: нет раздела agent", e.Type))
	}
	if e.Type == TypeAgentToolCall {
		switch a.Path {
		case AgentPathMCP, AgentPathChat:
		default:
			errs = append(errs, errors.New("agent.path — mcp или chat"))
		}
		if !toolNameRe.MatchString(a.Tool) {
			errs = append(errs, errors.New("agent.tool — имя инструмента"))
		}
	} else if a.Path != "" {
		errs = append(errs, errors.New("agent.path — только у agent_tool_call"))
	}
	check := func(field, v string, re *regexp.Regexp) {
		if v != "" && !re.MatchString(v) {
			errs = append(errs, fmt.Errorf("agent.%s: неверное значение", field))
		}
	}
	check("agent", a.Agent, agentSlugRe)
	check("server", a.Server, agentSlugRe)
	check("method", a.Method, methodRe)
	check("protocol", a.Protocol, protocolRe)
	check("tool", a.Tool, toolNameRe)
	check("tool_hash", a.ToolHash, hashHexRe)
	check("session", a.Session, sessionIDRe)
	check("violation", a.Violation, violationRe)
	check("request_event_id", a.RequestEventID, uuidRe)
	switch a.Risk {
	case "", "low", "medium", "high", "critical":
	default:
		errs = append(errs, errors.New("agent.risk — low, medium, high или critical"))
	}
	switch a.ToolStatus {
	case "", "new", "approved", "changed", "suspicious", "revoked", "unknown":
	default:
		errs = append(errs, errors.New("agent.tool_status — состояние реестра"))
	}
	for _, list := range [][]string{a.Hidden, a.Poisoned, a.Changed, a.Stripped} {
		if len(list) > MaxAgentNames {
			errs = append(errs, fmt.Errorf("agent: больше %d имён в списке", MaxAgentNames))
		}
		for _, n := range list {
			if len(n) > maxAgentName || !toolNameRe.MatchString(n) {
				errs = append(errs, errors.New("agent: неверное имя в списке"))
				break
			}
		}
	}
	if a.Upstream < 0 || a.Upstream > 999 || a.ResultBytes < 0 || a.Items < 0 || a.Invalid < 0 || a.Dropped < 0 {
		errs = append(errs, errors.New("agent: отрицательные или неверные счётчики"))
	}
	if ap := a.Approval; ap != nil {
		if e.Type != TypeAgentToolCall {
			errs = append(errs, errors.New("agent.approval — только у agent_tool_call"))
		}
		if !approvalStates[ap.State] || ap.WaitedMS < 0 || len(ap.Comment) > 1024 || len(ap.DecidedBy) > 256 {
			errs = append(errs, errors.New("agent.approval: неверный итог"))
		}
		check("approval.id", ap.ID, uuidRe)
	}
	return errs
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
