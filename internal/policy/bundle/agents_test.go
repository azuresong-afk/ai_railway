package bundle_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

const (
	agentID   = "0198f0a2-1c3e-7d4a-9b2e-3f4a5b6c7d8e"
	toolHash  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mcpSecret = "mcp-synthetic-token-1"
)

// withAgents — содержимое с разделами agents, mcp_servers и agent_tools.
func withAgents(t testing.TB, f *bundletest.Fixture) *bundle.Content {
	c := f.Content(t)
	set := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	c.MCPServers = []bundle.MCPServer{{ID: "files", URL: "https://mcp.example.ru/mcp", CAPEM: bundletest.CAPEM, External: true,
		CallTimeout: 120, Versions: []string{"2025-11-25", "2026-07-28"}, CredentialSetAt: &set}}
	c.Agents = []bundle.Agent{{ID: agentID, App: "crm", Slug: "helper", Status: "active", MCPServers: []string{"files"}}}
	c.AgentTools = []bundle.AgentTool{
		{Server: "files", Name: "read_file", ApprovedHash: toolHash, HashAlg: "SHA-256", Risk: policy.RiskMedium, Status: policy.ToolApproved},
		{Server: policy.FunctionServer, Agent: agentID, Name: "lookup", HashAlg: "SHA-256", Risk: policy.RiskHigh, Status: policy.ToolNew},
	}
	c.Applications[0].Keys[0].Agent = agentID
	return c
}

// Разделы агентов (задача 4.8, ADR-0023, раздел 1): шлюз получает реестр
// с одобренными хешами описаний и учётные данные MCP-серверов в
// зашифрованной части; пакет без агентов не меняется. Покрывает: DM-25.
func TestDM25_BundleAgentsSections(t *testing.T) {
	f := bundletest.New(t)
	o := f.Opener(t)
	plain, err := f.Content(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("agent")) || bytes.Contains(plain, []byte("mcp")) {
		t.Fatalf("без агентов в пакете появились новые поля: %s", plain)
	}
	c := withAgents(t, f)
	raw, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(mcpSecret)) {
		t.Fatal("учётные данные MCP-сервера в открытом содержимом")
	}
	data, err := f.Sealer.Seal(bundle.SealInput{Version: 1, IssuedAt: time.Now(), GatewayID: bundletest.GatewayID, Content: raw,
		Secrets: bundle.Secrets{"llm": bundletest.Credential}, MCPSecrets: bundle.Secrets{"files": mcpSecret},
		RecipientKey: f.Recipient.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := o.Open(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.MCPSecrets["files"] != mcpSecret || b.Secrets["llm"] != bundletest.Credential || len(b.Content.AgentTools) != 2 ||
		b.Content.AgentTools[0].ApprovedHash != toolHash || b.Content.Applications[0].Keys[0].Agent != agentID {
		t.Fatalf("разделы агентов потеряны: %+v %v", b.Content, b.MCPSecrets)
	}
	// Секрет MCP-сервера, которого нет в пакете, — отказ.
	bad, err := f.Sealer.Seal(bundle.SealInput{Version: 1, IssuedAt: time.Now(), GatewayID: bundletest.GatewayID, Content: raw,
		Secrets: bundle.Secrets{"llm": bundletest.Credential}, MCPSecrets: bundle.Secrets{"other": mcpSecret},
		RecipientKey: f.Recipient.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Open(bad, 0); bundle.Reason(err) != bundle.ReasonInvalidContent {
		t.Fatalf("секрет чужого MCP-сервера принят: %v", err)
	}
}

// Неверные разделы агентов отклоняются целиком: шлюз не применяет реестр,
// в котором одобренный инструмент без хеша, ключ привязан к чужому агенту
// или сервер разрешён по http:// без insecure_http. Покрывает: DM-25.
func TestDM25_BundleAgentsValidate(t *testing.T) {
	f := bundletest.New(t)
	if err := withAgents(t, f).Validate(); err != nil {
		t.Fatalf("верные разделы: %v", err)
	}
	cases := map[string]struct {
		mod  func(c *bundle.Content)
		want string
	}{
		"http без признака": {func(c *bundle.Content) { c.MCPServers[0].URL = "http://mcp.example.ru/mcp" }, "только https"},
		"адрес с паролем": {func(c *bundle.Content) { c.MCPServers[0].URL = "https://u:p@mcp.example.ru/" },
			"без имени пользователя"},
		"сервер function":         {func(c *bundle.Content) { c.MCPServers[0].ID = "function" }, "неверный или повторный id"},
		"неизвестная версия":      {func(c *bundle.Content) { c.MCPServers[0].Versions = []string{"2024-11-05"} }, "неизвестная версия"},
		"длинный таймаут":         {func(c *bundle.Content) { c.MCPServers[0].CallTimeout = 601 }, "call_timeout"},
		"заголовок с пробелом":    {func(c *bundle.Content) { c.MCPServers[0].AuthHeader = "X Key" }, "auth_header"},
		"агент чужого приложения": {func(c *bundle.Content) { c.Agents[0].App = "other" }, "не описано в пакете"},
		"агент с чужим сервером": {func(c *bundle.Content) { c.Agents[0].MCPServers = []string{"nope"} },
			"MCP-сервер \"nope\" не описан"},
		"повторный slug": {func(c *bundle.Content) {
			a := c.Agents[0]
			a.ID = "0198f0a2-1c3e-7d4a-9b2e-3f4a5b6c7d8f"
			c.Agents = append(c.Agents, a)
		}, "повторный в приложении slug"},
		"ключ чужого агента": {func(c *bundle.Content) {
			c.Applications[0].Keys[0].Agent = "0198f0a2-1c3e-7d4a-9b2e-3f4a5b6c7d8f"
		}, "агент ключа не описан"},
		"одобрен без хеша": {func(c *bundle.Content) { c.AgentTools[0].ApprovedHash = "" }, "без approved_hash"},
		"короткий хеш":     {func(c *bundle.Content) { c.AgentTools[0].ApprovedHash = "abc" }, "approved_hash"},
		"неверный статус":  {func(c *bundle.Content) { c.AgentTools[0].Status = "ok" }, "неверный status"},
		"неверный риск":    {func(c *bundle.Content) { c.AgentTools[0].Risk = "none" }, "risk"},
		"повтор инструмента": {func(c *bundle.Content) { c.AgentTools = append(c.AgentTools, c.AgentTools[0]) },
			"повторное имя"},
		"функция без агента": {func(c *bundle.Content) { c.AgentTools[1].Agent = "" }, "агент функции"},
		"агент у сервера":    {func(c *bundle.Content) { c.AgentTools[0].Agent = agentID }, "только для server: function"},
		"имя с косой":        {func(c *bundle.Content) { c.AgentTools[0].Name = "a/b" }, "неверное"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := withAgents(t, f)
			tc.mod(c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ожидалась ошибка %q: %v", tc.want, err)
			}
		})
	}
	// Пределы: 257 инструментов одного сервера.
	c := withAgents(t, f)
	c.AgentTools = c.AgentTools[:0]
	for i := range bundle.MaxToolsPerServer + 1 {
		c.AgentTools = append(c.AgentTools, bundle.AgentTool{Server: "files", Name: "t" + strings.Repeat("x", i%100) + string(rune('a'+i%26)) +
			string(rune('a'+i/26%26)), HashAlg: "SHA-256", Risk: policy.RiskLow, Status: policy.ToolNew})
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "больше 256 инструментов") {
		t.Fatalf("предел инструментов сервера: %v", err)
	}
}
