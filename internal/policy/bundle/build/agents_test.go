package build_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/agents"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

const mcpCredential = "mcp-synthetic-token-1" //nolint:gosec // G101: синтетические учётные данные MCP-сервера для теста, нигде не выданы

// Разделы агентов в пакете (задача 4.8): агент приложения пакета, только
// нужные ему MCP-серверы, инструменты сервера и функции агента без
// описаний, привязка ключа; учётные данные — только в секретах HPKE;
// исключённое приложение — без агентов и без привязки ключей; учётные
// данные, заменённые после сборки версии, не выдаются с ней.
func TestBuildAgentsSections(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.now = time.Now().UTC().Truncate(time.Second)
	mem := agents.NewMemory()
	asvc, err := agents.New(agents.Options{Store: mem, Provider: e.fx.Provider, Box: e.box, Apps: agents.AppsOf(e.apps), Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	var rev int64 = 1
	svc, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: e.store, Audit: e.audit, Agents: asvc,
		Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock,
		Revision: func(context.Context) (int64, error) { return rev, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("AISec test MCP CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	by := agents.By{Actor: audit.Actor{Type: audit.ActorUser, ID: owner, Name: "admin"}, Security: true,
		Confirm: func(context.Context) error { return nil }}
	server := func(slug string) agents.MCPServer {
		t.Helper()
		m, err := asvc.CreateServer(ctx, by, agents.ServerInput{Slug: slug, Name: slug, URL: "https://" + slug + ".example.ru/mcp",
			CAPEM: string(ca.CertPEM()), Versions: []string{agents.MCP20260728}})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	files, _ := server("files"), server("unused")
	if _, err := asvc.SetServerCredential(ctx, by, files.ID, []byte(mcpCredential)); err != nil {
		t.Fatal(err)
	}
	ag, err := asvc.CreateAgent(ctx, by, agents.AgentInput{AppID: e.app.ID, Slug: "support", Name: "Поддержка", Servers: []string{files.ID}})
	if err != nil {
		t.Fatal(err)
	}
	e.appsMem.BindAgent(ag.ID, e.app.ID)
	k, _, err := e.apps.IssueKey(ctx, e.appsBy, e.app.ID, "", apps.KeyInput{Name: "agent", AgentID: ag.ID})
	if err != nil {
		t.Fatal(err)
	}
	gw := agents.By{Actor: audit.Actor{Type: audit.ActorGateway, ID: bundletest.GatewayID}}
	for _, in := range []agents.ObserveInput{
		{Server: "files", Tools: []agents.ObservedRaw{{Descriptor: []byte(`{"name":"read_file","description":"Читает файл."}`)}}},
		{Server: policy.FunctionServer, AgentID: ag.ID, Tools: []agents.ObservedRaw{{Descriptor: []byte(`{"name":"lookup"}`)}}},
	} {
		if _, err := asvc.Observe(ctx, gw, in); err != nil {
			t.Fatal(err)
		}
	}
	rev++
	if _, err := svc.Current(ctx); err != nil {
		h, herr := svc.Health(ctx)
		t.Fatalf("сборка: %v %+v %v", err, h, herr)
	}
	d, err := svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, e.fx.Recipient.PublicKey(), "", -1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(d.Body, []byte(mcpCredential)) {
		t.Fatal("учётные данные MCP-сервера в пакете открытым текстом")
	}
	b, err := e.fx.Opener(t).Open(d.Body, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := b.Content
	if len(c.Agents) != 1 || c.Agents[0].ID != ag.ID || c.Agents[0].App != "crm" || len(c.Agents[0].MCPServers) != 1 ||
		len(c.MCPServers) != 1 || c.MCPServers[0].ID != "files" || c.MCPServers[0].CredentialSetAt == nil {
		t.Fatalf("агенты и серверы: %+v %+v", c.Agents, c.MCPServers)
	}
	if len(c.AgentTools) != 2 || b.MCPSecrets["files"] != mcpCredential || len(b.MCPSecrets) != 1 {
		t.Fatalf("инструменты и секреты: %+v, секретов %d", c.AgentTools, len(b.MCPSecrets))
	}
	for _, tl := range c.AgentTools {
		mcp := tl.Server == "files"
		fn := tl.Server == policy.FunctionServer && tl.Agent == ag.ID
		if tl.Status != policy.ToolNew || tl.ApprovedHash != "" || !mcp && !fn {
			t.Fatalf("инструмент: %+v", tl)
		}
	}
	bound := false
	for _, a := range c.Applications {
		for _, key := range a.Keys {
			bound = bound || key.Prefix == k.Prefix && key.Agent == ag.ID
		}
	}
	if !bound {
		t.Fatal("ключ не привязан к агенту в пакете")
	}

	// Учётные данные заменены без новой сборки: выдача этой версии другому
	// шлюзу отказывает.
	e.now = e.now.Add(time.Second)
	if _, err := asvc.SetServerCredential(ctx, by, files.ID, []byte("mcp-synthetic-token-2")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Deliver(ctx, build.Gateway{ID: "другой"}, e.fx.Recipient.PublicKey(), "", -1); err == nil ||
		!strings.Contains(err.Error(), "заменены после сборки") {
		t.Fatalf("выдача версии с заменёнными учётными данными: %v", err)
	}

	// Приложение исключено из пакета: агентов и серверов нет, ключи — без
	// привязки.
	if _, err := e.apps.SetProtection(ctx, e.appsBy, e.app.ID, apps.ProtectionInput{Lists: &[]apps.List{}}); err != nil {
		t.Fatal(err)
	}
	rev++
	r, err := svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := bundle.ParseContent(r.Content)
	if err != nil {
		t.Fatal(err)
	}
	if len(c2.Agents) != 0 || len(c2.MCPServers) != 0 || len(c2.AgentTools) != 0 || len(c2.Unavailable) != 1 {
		t.Fatalf("исключённое приложение: %+v", c2)
	}
	for _, key := range c2.Unavailable[0].Keys {
		if key.Agent != "" {
			t.Fatalf("ключ исключённого приложения с агентом: %+v", key)
		}
	}
}
