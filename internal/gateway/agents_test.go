package gateway_test

import (
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

const (
	agentBot  = "01900000-0000-7000-8000-0000000000e1"
	agentOff  = "01900000-0000-7000-8000-0000000000e2"
	agentHR   = "01900000-0000-7000-8000-0000000000e3"
	keyBound  = "aisec_bound"
	keyFree   = "aisec_free"
	keyHRBind = "aisec_hrbnd"
)

func agentsContent() *bundle.Content {
	return &bundle.Content{
		Applications: []bundle.Application{
			{ID: "crm", Keys: []bundle.Key{{Prefix: keyBound, Agent: agentBot}, {Prefix: keyFree}}},
			{ID: "hr", Keys: []bundle.Key{{Prefix: keyHRBind, Agent: agentHR}}},
		},
		Agents: []bundle.Agent{
			{ID: agentBot, App: "crm", Slug: "support-bot", Status: "active", MCPServers: []string{"files"}},
			{ID: agentOff, App: "crm", Slug: "old-bot", Status: "disabled"},
			{ID: agentHR, App: "hr", Slug: "support-bot", Status: "active"},
		},
		AgentTools: []bundle.AgentTool{
			{Server: "files", Name: "read_file", Risk: policy.RiskLow, Status: policy.ToolApproved, HashAlg: "sha-256"},
			{Server: policy.FunctionServer, Agent: agentBot, Name: "send_mail", Risk: policy.RiskHigh, Status: policy.ToolNew, HashAlg: "sha-256"},
		},
	}
}

// Определение агента запроса (ADR-0023, раздел 1): агент ключа, заголовок
// X-AISec-Agent без привязки, несовпадение — agent_mismatch.
func TestAgentsResolve(t *testing.T) {
	a := gateway.NewAgents(agentsContent())
	id := func(app, key string) auth.Identity { return auth.Identity{AppID: app, KeyPrefix: key} }
	for name, c := range map[string]struct {
		id     auth.Identity
		header []string
		agent  string
		err    *gateway.AgentError
	}{
		"ключ привязан":                {id("crm", keyBound), nil, agentBot, nil},
		"ключ и тот же заголовок":      {id("crm", keyBound), []string{"support-bot"}, agentBot, nil},
		"ключ и другой заголовок":      {id("crm", keyBound), []string{"old-bot"}, "", gateway.ErrAgentMismatch},
		"заголовок без привязки":       {id("crm", keyFree), []string{"support-bot"}, agentBot, nil},
		"агент другого приложения":     {id("crm", keyFree), []string{"nobody"}, "", gateway.ErrAgentMismatch},
		"slug из другого приложения":   {id("hr", keyHRBind), []string{"support-bot"}, agentHR, nil},
		"без агента":                   {id("crm", keyFree), nil, "", nil},
		"отключён":                     {id("crm", keyFree), []string{"old-bot"}, "", gateway.ErrAgentDisabled},
		"два заголовка":                {id("crm", keyFree), []string{"support-bot", "support-bot"}, "", nil},
		"неверный заголовок":           {id("crm", keyFree), []string{"Support Bot"}, "", nil},
		"привязка к чужому приложению": {id("crm", keyHRBind), nil, "", gateway.ErrAgentMismatch},
	} {
		ag, err := a.Resolve(c.id, c.header)
		switch {
		case name == "два заголовка" || name == "неверный заголовок":
			if err == nil || err.Code != "agent_mismatch" {
				t.Errorf("%s: %v", name, err)
			}
		case err != c.err:
			t.Errorf("%s: ошибка %v, ожидалась %v", name, err, c.err)
		case c.agent == "" && ag != nil, c.agent != "" && (ag == nil || ag.ID != c.agent):
			t.Errorf("%s: агент %+v", name, ag)
		}
	}
	if ag, _ := a.ByID(agentBot); !ag.AllowsServer("files") || ag.AllowsServer("db") {
		t.Fatal("серверы агента")
	}
	if !a.HasAgents("crm") || a.HasAgents("billing") {
		t.Fatal("приложения с агентами")
	}
	// Пустой реестр: агента нет, заголовок называет неизвестного агента.
	var empty *gateway.Agents
	if ag, err := empty.Resolve(id("crm", keyFree), nil); ag != nil || err != nil {
		t.Fatal("пустой реестр без заголовка")
	}
	if _, err := empty.Resolve(id("crm", keyFree), []string{"support-bot"}); err != gateway.ErrAgentMismatch {
		t.Fatalf("пустой реестр с заголовком: %v", err)
	}
}

func TestAgentsTools(t *testing.T) {
	a := gateway.NewAgents(agentsContent())
	if tl, ok := a.Tool("files", "read_file"); !ok || tl.Status != policy.ToolApproved || tl.Risk != policy.RiskLow {
		t.Fatalf("инструмент: %+v %v", tl, ok)
	}
	if _, ok := a.Tool("files", "write_file"); ok {
		t.Fatal("неизвестный инструмент найден")
	}
	if _, ok := a.Tool(policy.FunctionServer, "send_mail"); ok {
		t.Fatal("функция найдена как инструмент MCP-сервера")
	}
	if tl, ok := a.Function(agentBot, "send_mail"); !ok || tl.Risk != policy.RiskHigh || tl.Agent != agentBot {
		t.Fatalf("функция: %+v %v", tl, ok)
	}
	if _, ok := a.Function(agentHR, "send_mail"); ok {
		t.Fatal("функция чужого агента")
	}
}
