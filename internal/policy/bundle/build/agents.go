package build

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/agents"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// addAgents добавляет разделы agents, mcp_servers и agent_tools (задача
// 4.8, ADR-0023): агенты приложений пакета, MCP-серверы, к которым они
// обращаются, и инструменты этих серверов и функций этих агентов. appSlugs
// — ID приложения пакета по ID приложения. Агентов нет — разделов нет.
func (s *Service) addAgents(ctx context.Context, c *bundle.Content, appSlugs map[string]string) error {
	if s.agents == nil {
		return nil
	}
	list, err := s.agents.Agents(ctx, "", "")
	if err != nil {
		return fmt.Errorf("пакеты: агенты: %w", err)
	}
	servers, err := s.agents.Servers(ctx)
	if err != nil {
		return fmt.Errorf("пакеты: MCP-серверы: %w", err)
	}
	slugByID := make(map[string]string, len(servers))
	for _, m := range servers {
		slugByID[m.ID] = m.Slug
	}
	used := map[string]bool{}
	inBundle := map[string]bool{}
	for _, a := range list {
		app, ok := appSlugs[a.AppID]
		if !ok {
			continue // приложение в архиве или исключено из пакета
		}
		ba := bundle.Agent{ID: a.ID, App: app, Slug: a.Slug, Status: a.Status, MCPServers: []string{}}
		for _, id := range a.Servers {
			if slug, ok := slugByID[id]; ok {
				ba.MCPServers = append(ba.MCPServers, slug)
				used[id] = true
			}
		}
		slices.Sort(ba.MCPServers)
		c.Agents = append(c.Agents, ba)
		inBundle[a.ID] = true
	}
	for _, m := range servers {
		if used[m.ID] {
			c.MCPServers = append(c.MCPServers, mcpServer(m))
		}
	}
	tools, err := s.agents.Tools(ctx, agents.ToolFilter{}, "")
	if err != nil {
		return fmt.Errorf("пакеты: инструменты агентов: %w", err)
	}
	for _, t := range tools {
		bt := bundle.AgentTool{Name: t.Name, HashAlg: t.HashAlg, Risk: t.Risk, Status: t.Status}
		switch {
		case t.ServerID != "" && used[t.ServerID]:
			bt.Server = slugByID[t.ServerID]
		case t.ServerID == "" && inBundle[t.AgentID]:
			bt.Server, bt.Agent = policy.FunctionServer, t.AgentID
		default:
			continue
		}
		if len(t.ApprovedHash) > 0 {
			bt.ApprovedHash = hex.EncodeToString(t.ApprovedHash)
		}
		c.AgentTools = append(c.AgentTools, bt)
	}
	slices.SortFunc(c.Agents, func(a, b bundle.Agent) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.MCPServers, func(a, b bundle.MCPServer) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.AgentTools, func(a, b bundle.AgentTool) int {
		return strings.Compare(a.Server+"\x00"+a.Agent+"\x00"+a.Name, b.Server+"\x00"+b.Agent+"\x00"+b.Name)
	})
	return nil
}

func mcpServer(m agents.MCPServer) bundle.MCPServer {
	bm := bundle.MCPServer{ID: m.Slug, URL: m.URL, CAPEM: m.CAPEM, AuthHeader: m.AuthHeader, External: m.External,
		InsecureHTTP: m.InsecureHTTP, CallTimeout: m.CallTimeout, Versions: slices.Clone(m.Versions)}
	if bm.CallTimeout == 0 {
		bm.CallTimeout = agents.DefaultCallTimeout
	}
	if m.Credential != nil {
		t := m.Credential.SetAt.UTC()
		bm.CredentialSetAt = &t
	}
	return bm
}

// withoutAgent — ключи исключённого приложения без привязки к агентам:
// агентов такого приложения в пакете нет, шлюз отвечает на его ключи 503.
func withoutAgent(keys []bundle.Key) []bundle.Key {
	out := slices.Clone(keys)
	for i := range out {
		out[i].Agent = ""
	}
	return out
}

// mcpSecrets расшифровывает учётные данные MCP-серверов пакета (ключ
// данных, keyring.Box). Сервер без учётных данных или удалённый — без
// секрета.
func (s *Service) mcpSecrets(ctx context.Context, c *bundle.Content) (bundle.Secrets, error) {
	out := bundle.Secrets{}
	if s.agents == nil || len(c.MCPServers) == 0 {
		return out, nil
	}
	servers, err := s.agents.Servers(ctx)
	if err != nil {
		return out, err
	}
	bySlug := make(map[string]agents.MCPServer, len(servers))
	for _, m := range servers {
		bySlug[m.Slug] = m
	}
	for _, bm := range c.MCPServers {
		m, ok := bySlug[bm.ID]
		if !ok || m.Credential == nil || bm.CredentialSetAt == nil {
			continue
		}
		if !m.Credential.SetAt.UTC().Equal(*bm.CredentialSetAt) {
			return out, errors.New("пакеты: учётные данные MCP-сервера заменены после сборки версии — повторите запрос")
		}
		cred, err := s.agents.OpenServerCredential(ctx, m)
		if err != nil {
			return out, fmt.Errorf("пакеты: учётные данные MCP-сервера %s: %w", bm.ID, err)
		}
		out[bm.ID] = string(cred)
		clear(cred)
	}
	return out, nil
}
