package agents

import (
	"bytes"
	"cmp"
	"context"
	"slices"
	"sync"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов без PostgreSQL. Повторяет правила
// PGStore и миграции 0054: slug уникален (агента — в приложении), сервер из
// списка агента не удаляется, агент с привязанным ключом не удаляется,
// инструменты удаляются вместе с сервером или агентом. Записи аудита
// копятся в Records.
type Memory struct {
	mu      sync.Mutex
	servers map[string]MCPServer
	agents  map[string]Agent
	tools   map[string]Tool
	// keys — число ключей приложения, привязанных к агенту.
	keys    map[string]int
	records []audit.Entry
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{servers: map[string]MCPServer{}, agents: map[string]Agent{}, tools: map[string]Tool{}, keys: map[string]int{}}
}

// Records — копия записей аудита.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

// BindKey отмечает ключ приложения, привязанный к агенту (в PostgreSQL —
// app_keys.agent_id).
func (m *Memory) BindKey(agentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[agentID]++
}

func cloneServer(s MCPServer) MCPServer {
	s.Versions = slices.Clone(s.Versions)
	if s.Credential != nil {
		c := *s.Credential
		c.Data = bytes.Clone(c.Data)
		s.Credential = &c
	}
	return s
}

func cloneAgent(a Agent) Agent {
	a.Servers = slices.Clone(a.Servers)
	return a
}

func cloneTool(t Tool) Tool {
	t.Descriptor, t.Hash = bytes.Clone(t.Descriptor), bytes.Clone(t.Hash)
	t.ApprovedDescriptor, t.ApprovedHash = bytes.Clone(t.ApprovedDescriptor), bytes.Clone(t.ApprovedHash)
	return t
}

// CreateServer — см. Store.
func (m *Memory) CreateServer(_ context.Context, s MCPServer, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, o := range m.servers {
		if o.OrgID != s.OrgID {
			continue
		}
		if o.Slug == s.Slug {
			return ErrSlugTaken
		}
		n++
	}
	if n >= MaxServers {
		return ErrTooMany
	}
	m.servers[s.ID] = cloneServer(s)
	m.records = append(m.records, rec)
	return nil
}

// UpdateServer — см. Store.
func (m *Memory) UpdateServer(_ context.Context, orgID, id string, fn func(*MCPServer, []Tool) (ServerUpdate, error)) (MCPServer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.servers[id]
	if !ok || s.OrgID != orgID {
		return MCPServer{}, ErrNotFound
	}
	s = cloneServer(s)
	var tools []Tool
	for _, t := range m.tools {
		if t.OrgID == orgID && t.ServerID == id {
			tools = append(tools, cloneTool(t))
		}
	}
	slices.SortFunc(tools, func(a, b Tool) int { return cmp.Compare(a.Name, b.Name) })
	upd, err := fn(&s, tools)
	if err != nil {
		return MCPServer{}, err
	}
	m.servers[id] = cloneServer(s)
	for _, t := range upd.Tools {
		m.tools[t.ID] = cloneTool(t)
	}
	m.records = append(m.records, upd.Entry)
	m.records = append(m.records, upd.ToolEntries...)
	return s, nil
}

// DeleteServer — см. Store.
func (m *Memory) DeleteServer(_ context.Context, orgID, id string, fn func(MCPServer) (audit.Entry, error)) (MCPServer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.servers[id]
	if !ok || s.OrgID != orgID {
		return MCPServer{}, ErrNotFound
	}
	for _, a := range m.agents {
		if slices.Contains(a.Servers, id) {
			return MCPServer{}, ErrInUse
		}
	}
	rec, err := fn(cloneServer(s))
	if err != nil {
		return MCPServer{}, err
	}
	delete(m.servers, id)
	for tid, t := range m.tools {
		if t.ServerID == id {
			delete(m.tools, tid)
		}
	}
	m.records = append(m.records, rec)
	return s, nil
}

// Server — см. Store.
func (m *Memory) Server(_ context.Context, orgID, id string) (MCPServer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.servers[id]
	if !ok || s.OrgID != orgID {
		return MCPServer{}, ErrNotFound
	}
	return cloneServer(s), nil
}

// ServerBySlug — см. Store.
func (m *Memory) ServerBySlug(_ context.Context, orgID, slug string) (MCPServer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.servers {
		if s.OrgID == orgID && s.Slug == slug {
			return cloneServer(s), nil
		}
	}
	return MCPServer{}, ErrNotFound
}

// Servers — см. Store.
func (m *Memory) Servers(_ context.Context, orgID string) ([]MCPServer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []MCPServer
	for _, s := range m.servers {
		if s.OrgID == orgID {
			out = append(out, cloneServer(s))
		}
	}
	slices.SortFunc(out, func(a, b MCPServer) int { return cmp.Compare(a.Slug, b.Slug) })
	return out, nil
}

func (m *Memory) checkServers(orgID string, ids []string) error {
	for _, id := range ids {
		if s, ok := m.servers[id]; !ok || s.OrgID != orgID {
			return invalidf("mcp_servers — MCP-сервер %s не найден", id)
		}
	}
	return nil
}

// CreateAgent — см. Store.
func (m *Memory) CreateAgent(_ context.Context, a Agent, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, o := range m.agents {
		if o.OrgID != a.OrgID {
			continue
		}
		if o.AppID == a.AppID && o.Slug == a.Slug {
			return ErrSlugTaken
		}
		n++
	}
	if n >= MaxAgents {
		return ErrTooMany
	}
	if err := m.checkServers(a.OrgID, a.Servers); err != nil {
		return err
	}
	m.agents[a.ID] = cloneAgent(a)
	m.records = append(m.records, rec)
	return nil
}

// UpdateAgent — см. Store.
func (m *Memory) UpdateAgent(_ context.Context, orgID, id string, fn func(*Agent) (audit.Entry, error)) (Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	if !ok || a.OrgID != orgID {
		return Agent{}, ErrNotFound
	}
	a = cloneAgent(a)
	rec, err := fn(&a)
	if err != nil {
		return Agent{}, err
	}
	if err := m.checkServers(orgID, a.Servers); err != nil {
		return Agent{}, err
	}
	m.agents[id] = cloneAgent(a)
	m.records = append(m.records, rec)
	return a, nil
}

// DeleteAgent — см. Store.
func (m *Memory) DeleteAgent(_ context.Context, orgID, id string, fn func(Agent) (audit.Entry, error)) (Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	if !ok || a.OrgID != orgID {
		return Agent{}, ErrNotFound
	}
	if m.keys[id] > 0 {
		return Agent{}, ErrInUse
	}
	rec, err := fn(cloneAgent(a))
	if err != nil {
		return Agent{}, err
	}
	delete(m.agents, id)
	for tid, t := range m.tools {
		if t.AgentID == id {
			delete(m.tools, tid)
		}
	}
	m.records = append(m.records, rec)
	return a, nil
}

// Agent — см. Store.
func (m *Memory) Agent(_ context.Context, orgID, id string) (Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	if !ok || a.OrgID != orgID {
		return Agent{}, ErrNotFound
	}
	return cloneAgent(a), nil
}

// AgentBySlug — см. Store.
func (m *Memory) AgentBySlug(_ context.Context, orgID, appID, slug string) (Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.agents {
		if a.OrgID == orgID && a.AppID == appID && a.Slug == slug {
			return cloneAgent(a), nil
		}
	}
	return Agent{}, ErrNotFound
}

// Agents — см. Store.
func (m *Memory) Agents(_ context.Context, orgID string, appIDs []string) ([]Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Agent
	for _, a := range m.agents {
		if a.OrgID == orgID && (appIDs == nil || slices.Contains(appIDs, a.AppID)) {
			out = append(out, cloneAgent(a))
		}
	}
	slices.SortFunc(out, func(a, b Agent) int { return cmp.Or(cmp.Compare(a.AppID, b.AppID), cmp.Compare(a.Slug, b.Slug)) })
	return out, nil
}

// Observe — см. Store.
func (m *Memory) Observe(_ context.Context, orgID, serverID, agentID string, names []string,
	fn func(known map[string]Tool, total, owned int) ([]Tool, []audit.Entry, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	known := map[string]Tool{}
	total, owned := 0, 0
	for _, t := range m.tools {
		if t.OrgID != orgID {
			continue
		}
		total++
		if t.ServerID == serverID && t.AgentID == agentID {
			owned++
			if slices.Contains(names, t.Name) {
				known[t.Name] = cloneTool(t)
			}
		}
	}
	ts, recs, err := fn(known, total, owned)
	if err != nil {
		return err
	}
	for _, t := range ts {
		m.tools[t.ID] = cloneTool(t)
	}
	m.records = append(m.records, recs...)
	return nil
}

// UpdateTool — см. Store.
func (m *Memory) UpdateTool(_ context.Context, orgID, id string, fn func(*Tool) (audit.Entry, error)) (Tool, error) {
	m.mu.Lock()
	t, ok := m.tools[id]
	m.mu.Unlock()
	if !ok || t.OrgID != orgID {
		return Tool{}, ErrNotFound
	}
	// fn читает имя сервера или агента через хранилище: без блокировки.
	t = cloneTool(t)
	rec, err := fn(&t)
	if err != nil {
		return Tool{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tools[id] = cloneTool(t)
	m.records = append(m.records, rec)
	return t, nil
}

// Tool — см. Store.
func (m *Memory) Tool(_ context.Context, orgID, id string) (Tool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tools[id]
	if !ok || t.OrgID != orgID {
		return Tool{}, ErrNotFound
	}
	return cloneTool(t), nil
}

// Tools — см. Store.
func (m *Memory) Tools(_ context.Context, orgID string, f ToolFilter) ([]Tool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Tool
	for _, t := range m.tools {
		if t.OrgID != orgID || f.ServerID != "" && t.ServerID != f.ServerID || f.AgentID != "" && t.AgentID != f.AgentID ||
			f.Status != "" && t.Status != f.Status {
			continue
		}
		out = append(out, cloneTool(t))
	}
	slices.SortFunc(out, func(a, b Tool) int {
		return cmp.Or(cmp.Compare(a.ServerID, b.ServerID), cmp.Compare(a.AgentID, b.AgentID), cmp.Compare(a.Name, b.Name))
	})
	return out, nil
}
