package gateway

import (
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Реестр агентов и инструментов в шлюзе (задача 4.8, ADR-0023, раздел 1):
// разделы agents и agent_tools пакета конфигурации. По нему шлюз
// определяет агента запроса и берёт для политики вызовов статус, риск и
// одобренный хеш инструмента (задачи 4.10, 4.11). Неизменяем после
// создания и безопасен для одновременного использования.

// HeaderAgent — агент запроса, если ключ приложения к агенту не привязан.
const HeaderAgent = "X-AISec-Agent"

// maxAgentHeader — предел X-AISec-Agent, байт.
const maxAgentHeader = 64

// Agent — агент приложения.
type Agent struct {
	ID string
	// App — ID (slug) приложения; Slug — slug агента в приложении.
	App, Slug string
	Active    bool
	// MCPServers — slug MCP-серверов, к которым агенту можно обращаться.
	MCPServers []string
}

// AllowsServer — агенту можно обращаться к MCP-серверу server.
func (a *Agent) AllowsServer(server string) bool {
	for _, s := range a.MCPServers {
		if s == server {
			return true
		}
	}
	return false
}

// AgentTool — инструмент реестра.
type AgentTool struct {
	// Server — slug MCP-сервера или policy.FunctionServer; Agent — ID
	// агента функции (только для function).
	Server, Agent, Name string
	// ApprovedHash — одобренный хеш описания (hex), HashAlg — алгоритм.
	ApprovedHash, HashAlg string
	Risk                  policy.ToolRisk
	Status                policy.ToolStatus
}

// AgentError — отказ в определении агента: ответ 403 с кодом.
type AgentError struct {
	Code    string
	Message string
}

func (e *AgentError) Error() string { return e.Message }

// Write отвечает клиенту ошибкой в формате OpenAI (403).
func (e *AgentError) Write(w http.ResponseWriter) {
	WriteError(w, http.StatusForbidden, e.Message, "invalid_request_error", e.Code)
}

// Отказы определения агента (ADR-0023, раздел 1).
var (
	ErrAgentRequired = &AgentError{Code: "agent_required",
		Message: "агент не определён: привяжите ключ приложения к агенту или передайте заголовок X-AISec-Agent"}
	ErrAgentMismatch = &AgentError{Code: "agent_mismatch",
		Message: "заголовок X-AISec-Agent не совпадает с агентом ключа или не называет агента приложения"}
	ErrAgentDisabled = &AgentError{Code: "agent_disabled", Message: "агент отключён"}
	errAgentHeader   = &AgentError{Code: "agent_mismatch",
		Message: "X-AISec-Agent — один заголовок до 64 байт: slug агента из латинских строчных букв, цифр и дефиса"}
)

// Agents — реестр агентов и инструментов шлюза.
type Agents struct {
	byID   map[string]*Agent
	bySlug map[string]*Agent // приложение \x00 slug
	keys   map[string]string // префикс ключа → ID агента
	tools  map[string]AgentTool
	// apps — приложения, у которых есть агенты.
	apps map[string]bool
}

func slugKey(app, slug string) string { return app + "\x00" + slug }

// toolKey — инструмент MCP-сервера по (server, name), функция агента по
// (function, agent, name).
func toolKey(server, agent, name string) string { return server + "\x00" + agent + "\x00" + name }

// NewAgents строит реестр по проверенному содержимому пакета (ссылки
// проверены bundle.Content.Validate). nil — реестр пуст.
func NewAgents(c *bundle.Content) *Agents {
	a := &Agents{byID: map[string]*Agent{}, bySlug: map[string]*Agent{}, keys: map[string]string{}, tools: map[string]AgentTool{},
		apps: map[string]bool{}}
	if c == nil {
		return a
	}
	for _, x := range c.Agents {
		ag := &Agent{ID: x.ID, App: x.App, Slug: x.Slug, Active: x.Status == "active", MCPServers: append([]string(nil), x.MCPServers...)}
		a.byID[x.ID], a.bySlug[slugKey(x.App, x.Slug)], a.apps[x.App] = ag, ag, true
	}
	for _, app := range c.Applications {
		for _, k := range app.Keys {
			if k.Agent != "" {
				a.keys[k.Prefix] = k.Agent
			}
		}
	}
	for _, t := range c.AgentTools {
		agent := ""
		if t.Server == policy.FunctionServer {
			agent = t.Agent
		}
		a.tools[toolKey(t.Server, agent, t.Name)] = AgentTool{Server: t.Server, Agent: agent, Name: t.Name,
			ApprovedHash: t.ApprovedHash, HashAlg: t.HashAlg, Risk: t.Risk, Status: t.Status}
	}
	return a
}

// HasAgents — у приложения есть агенты.
func (a *Agents) HasAgents(app string) bool { return a != nil && a.apps[app] }

// ByID — агент по ID.
func (a *Agents) ByID(id string) (*Agent, bool) {
	if a == nil {
		return nil, false
	}
	ag, ok := a.byID[id]
	return ag, ok
}

// Resolve — агент запроса приложения id.AppID с ключом id.KeyPrefix и
// значениями заголовка X-AISec-Agent header (ADR-0023, раздел 1): агент
// ключа; без привязки — по заголовку; заголовок, не совпадающий с агентом
// ключа или не называющий агента приложения, — ErrAgentMismatch. Без
// агента — nil без ошибки: путь chat работает без агента, MCP-прокси
// отвечает ErrAgentRequired. Отключённый агент — ErrAgentDisabled.
func (a *Agents) Resolve(id auth.Identity, header []string) (*Agent, *AgentError) {
	slug, err := parseAgentHeader(header)
	if err != nil {
		return nil, err
	}
	var ag *Agent
	if a != nil {
		if bound, ok := a.keys[id.KeyPrefix]; ok {
			ag = a.byID[bound]
			if ag == nil || ag.App != id.AppID || slug != "" && slug != ag.Slug {
				return nil, ErrAgentMismatch
			}
		} else if slug != "" {
			ag = a.bySlug[slugKey(id.AppID, slug)]
		}
	}
	switch {
	case ag == nil && slug != "":
		return nil, ErrAgentMismatch
	case ag == nil:
		return nil, nil
	case !ag.Active:
		return nil, ErrAgentDisabled
	}
	return ag, nil
}

// parseAgentHeader — значение X-AISec-Agent; пусто — заголовка нет.
func parseAgentHeader(vals []string) (string, *AgentError) {
	switch {
	case len(vals) == 0:
		return "", nil
	case len(vals) > 1 || len(vals[0]) > maxAgentHeader || !policy.ValidAgentSlug(vals[0]):
		return "", errAgentHeader
	}
	return vals[0], nil
}

// Tool — инструмент MCP-сервера server по имени.
func (a *Agents) Tool(server, name string) (AgentTool, bool) {
	if a == nil || server == policy.FunctionServer {
		return AgentTool{}, false
	}
	t, ok := a.tools[toolKey(server, "", name)]
	return t, ok
}

// Function — функция агента agentID по имени (путь chat).
func (a *Agents) Function(agentID, name string) (AgentTool, bool) {
	if a == nil {
		return AgentTool{}, false
	}
	t, ok := a.tools[toolKey(policy.FunctionServer, agentID, name)]
	return t, ok
}
