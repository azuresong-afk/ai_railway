package bundle

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/tooldesc"
)

// Пределы разделов агентов (задача 4.8, ADR-0023, раздел 1).
const (
	MaxAgents         = 256
	MaxMCPServers     = 64
	MaxAgentTools     = 2000
	MaxToolsPerServer = 256
	MaxAgentServers   = 64
	// MaxMCPCallTimeout — срок tools/call, секунды (ADR-0023, раздел 6).
	MaxMCPCallTimeout = 600
)

// Версии протокола MCP (ADR-0023, раздел 6).
var mcpVersions = []string{"2025-11-25", "2026-07-28"}

var (
	uuidRe      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	mcpSlugRe   = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	headerRe    = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	hashRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hashAlgRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,32}$`)
	agentStatus = []string{"active", "disabled"}
)

// Agent — агент приложения (раздел agents). Ключ приложения с полем agent
// привязан к агенту; без привязки шлюз берёт агента из X-AISec-Agent по
// slug в приложении App.
type Agent struct {
	ID     string `json:"id"`
	App    string `json:"app"`
	Slug   string `json:"slug"`
	Status string `json:"status"`
	// MCPServers — slug MCP-серверов, к которым агенту можно обращаться.
	MCPServers []string `json:"mcp_servers"`
}

// MCPServer — вышестоящий MCP-сервер (раздел mcp_servers). Учётные данные
// — в секретах пакета (HPKE). CredentialSetAt меняется при каждой установке
// учётных данных: новый секрет — новая версия пакета.
type MCPServer struct {
	ID              string     `json:"id"`
	URL             string     `json:"url"`
	CAPEM           string     `json:"ca_pem"`
	AuthHeader      string     `json:"auth_header,omitempty"`
	External        bool       `json:"external"`
	InsecureHTTP    bool       `json:"insecure_http,omitempty"`
	CallTimeout     int        `json:"call_timeout"`
	Versions        []string   `json:"versions"`
	CredentialSetAt *time.Time `json:"credential_set_at,omitempty"`
}

// AgentTool — инструмент реестра (раздел agent_tools): одобренный хеш
// описания, риск и состояние. Шлюз сам считает хеш увиденного описания и
// сверяет его с ApprovedHash (DM-25).
type AgentTool struct {
	// Server — slug MCP-сервера или policy.FunctionServer; для функций Agent
	// — ID агента.
	Server       string            `json:"server"`
	Agent        string            `json:"agent,omitempty"`
	Name         string            `json:"name"`
	ApprovedHash string            `json:"approved_hash,omitempty"`
	HashAlg      string            `json:"hash_alg"`
	Risk         policy.ToolRisk   `json:"risk"`
	Status       policy.ToolStatus `json:"status"`
}

// validateAgents — разделы agents, mcp_servers и agent_tools: пределы,
// форма полей и ссылки (агент — на приложение пакета и серверы раздела,
// ключ — на агента своего приложения, инструмент — на сервер или агента).
func (c *Content) validateAgents() []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if len(c.Agents) > MaxAgents || len(c.MCPServers) > MaxMCPServers || len(c.AgentTools) > MaxAgentTools {
		return []error{fmt.Errorf("агенты: больше %d агентов, %d MCP-серверов или %d инструментов", MaxAgents, MaxMCPServers, MaxAgentTools)}
	}
	servers := map[string]bool{}
	for i, m := range c.MCPServers {
		at := fmt.Sprintf("mcp_servers[%d] (%s)", i, short(m.ID))
		if !mcpSlugRe.MatchString(m.ID) || m.ID == policy.FunctionServer || servers[m.ID] {
			add("%s: неверный или повторный id", at)
		}
		servers[m.ID] = true
		if err := checkMCPURL(m.URL, m.InsecureHTTP); err != nil {
			add("%s: %w", at, err)
		}
		if m.CAPEM == "" || len(m.CAPEM) > MaxCAPEM {
			add("%s: ca_pem — от 1 байта до %d байт", at, MaxCAPEM)
		}
		if m.AuthHeader != "" && !headerRe.MatchString(m.AuthHeader) {
			add("%s: неверное имя заголовка auth_header", at)
		}
		if m.CallTimeout < 0 || m.CallTimeout > MaxMCPCallTimeout {
			add("%s: call_timeout — от 0 до %d секунд", at, MaxMCPCallTimeout)
		}
		if len(m.Versions) == 0 || len(m.Versions) > len(mcpVersions) || !slices.IsSorted(m.Versions) ||
			len(slices.Compact(slices.Clone(m.Versions))) != len(m.Versions) {
			add("%s: versions — упорядоченные версии MCP без повторов", at)
		}
		for _, v := range m.Versions {
			if !slices.Contains(mcpVersions, v) {
				add("%s: неизвестная версия MCP %q", at, short(v))
			}
		}
	}
	apps := map[string]bool{}
	for _, a := range c.Applications {
		apps[a.ID] = true
	}
	agents := map[string]string{} // ID → приложение
	slugs := map[string]bool{}
	for i, a := range c.Agents {
		at := fmt.Sprintf("agents[%d] (%s)", i, short(a.ID))
		if _, dup := agents[a.ID]; !uuidRe.MatchString(a.ID) || dup {
			add("%s: неверный или повторный id", at)
		}
		agents[a.ID] = a.App
		if !apps[a.App] {
			add("%s: приложение %q не описано в пакете", at, short(a.App))
		}
		if !policy.ValidAgentSlug(a.Slug) || slugs[a.App+"|"+a.Slug] {
			add("%s: неверный или повторный в приложении slug", at)
		}
		slugs[a.App+"|"+a.Slug] = true
		if !slices.Contains(agentStatus, a.Status) {
			add("%s: status — active или disabled", at)
		}
		if len(a.MCPServers) > MaxAgentServers {
			add("%s: больше %d MCP-серверов", at, MaxAgentServers)
		}
		for _, s := range a.MCPServers {
			if !servers[s] {
				add("%s: MCP-сервер %q не описан в пакете", at, short(s))
			}
		}
	}
	for i, a := range c.Applications {
		for j, k := range a.Keys {
			if k.Agent != "" && agents[k.Agent] != a.ID {
				add("applications[%d].keys[%d]: агент ключа не описан в приложении %s", i, j, short(a.ID))
			}
		}
	}
	for i, u := range c.Unavailable {
		for j, k := range u.Keys {
			if k.Agent != "" {
				add("unavailable[%d].keys[%d]: у исключённого приложения ключ без агента", i, j)
			}
		}
	}
	tools := map[string]bool{}
	perOwner := map[string]int{}
	for i, t := range c.AgentTools {
		at := fmt.Sprintf("agent_tools[%d] (%s)", i, short(t.Name))
		owner := t.Server
		switch {
		case t.Server == policy.FunctionServer:
			if _, ok := agents[t.Agent]; !ok {
				add("%s: агент функции не описан в пакете", at)
			}
			owner = "agent:" + t.Agent
		case t.Agent != "":
			add("%s: agent — только для server: function", at)
		case !servers[t.Server]:
			add("%s: MCP-сервер %q не описан в пакете", at, short(t.Server))
		}
		if !tooldesc.ValidName(t.Name) || tools[owner+"|"+t.Name] {
			add("%s: неверное или повторное имя", at)
		}
		tools[owner+"|"+t.Name] = true
		if perOwner[owner]++; perOwner[owner] == MaxToolsPerServer+1 {
			add("%s: больше %d инструментов у сервера или агента", at, MaxToolsPerServer)
		}
		if t.ApprovedHash != "" && !hashRe.MatchString(t.ApprovedHash) {
			add("%s: approved_hash — 64 шестнадцатеричные цифры", at)
		}
		if !hashAlgRe.MatchString(t.HashAlg) {
			add("%s: неверный hash_alg", at)
		}
		if !policy.ValidRisk(t.Risk) {
			add("%s: risk — low, medium, high или critical", at)
		}
		switch t.Status {
		case policy.ToolNew, policy.ToolChanged, policy.ToolSuspicious, policy.ToolRevoked:
		case policy.ToolApproved:
			if t.ApprovedHash == "" {
				add("%s: одобренный инструмент без approved_hash", at)
			}
		default:
			add("%s: неверный status", at)
		}
	}
	return errs
}

// checkMCPURL — адрес MCP-сервера: https:// (http:// — только с
// insecure_http), без имени пользователя, запроса и фрагмента. Правило
// адресов (loopback, метаданные) шлюз проверяет при каждом подключении
// после разрешения имени.
func checkMCPURL(raw string, insecure bool) error {
	if raw == "" || len(raw) > 2048 {
		return errors.New("url — от 1 до 2048 байт")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("url — адрес вида https://узел/путь без имени пользователя, запроса и фрагмента")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !insecure) {
		return errors.New("url — только https:// (http:// — с insecure_http)")
	}
	return nil
}

// mcpIDs — MCP-серверы пакета: для них в секретах могут быть учётные
// данные.
func (c *Content) mcpIDs() map[string]bool {
	out := make(map[string]bool, len(c.MCPServers))
	for _, m := range c.MCPServers {
		out[m.ID] = true
	}
	return out
}
