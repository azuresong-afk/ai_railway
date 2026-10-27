package agents

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Переходы состояний инструмента (ADR-0023, раздел 1):
//
//	(нет) ──observe──▶ new | suspicious
//	approved ──observe, хеш ≠ одобренному──▶ changed (DM-25, agents.tool_changed)
//	changed ──observe, хеш = одобренному──▶ approved (описание вернулось)
//	new | approved | changed ──observe, находка DM-24──▶ suspicious
//	любое, кроме revoked ──revoke──▶ revoked
//	любое ──approve (повторная проверка)──▶ approved; из changed и
//	suspicious — ослабление (DM-40)
//
// revoked и suspicious наблюдение не снимает: только решение администратора.

// SuggestedRisk — предлагаемый уровень риска по описанию: подсказки сервера
// недоверенные и только поднимают уровень (destructiveHint → high).
func SuggestedRisk(d Descriptor) policy.ToolRisk {
	if d.Destructive {
		return policy.RiskHigh
	}
	return policy.RiskMedium
}

// ObservedRaw — описание из tools/list в сообщении шлюза.
type ObservedRaw struct {
	Descriptor []byte
	// Suspicious — детекторы шлюза нашли в описании внедрённые инструкции
	// (DM-24).
	Suspicious bool
}

// ObserveInput — сообщение шлюза об увиденных инструментах
// (POST /internal/v1/agents/tools:observe).
type ObserveInput struct {
	// Server — slug MCP-сервера или policy.FunctionServer для функций
	// агента AgentID (путь chat).
	Server  string
	AgentID string
	Tools   []ObservedRaw
}

// ObserveResult — итог приёма.
type ObserveResult struct {
	New, Changed, Restored, Suspicious, Unchanged int
	// Skipped — новые инструменты сверх пределов реестра: остаются
	// неизвестными, вызовы по ним получают действие unapproved.
	Skipped int
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// toolDetails — сведения об инструменте для аудита: без описания.
func toolDetails(t Tool, owner string) map[string]any {
	d := map[string]any{"name": t.Name, "status": string(t.Status), "risk": string(t.Risk), "hash": hexOf(t.Hash),
		"hash_alg": t.HashAlg}
	if t.ServerID != "" {
		d["mcp_server"] = owner
	} else {
		d["agent"] = owner
	}
	if len(t.ApprovedHash) > 0 {
		d["approved_hash"] = hexOf(t.ApprovedHash)
	}
	return d
}

// Observe принимает описания инструментов, увиденные шлюзом. Новые
// инструменты попадают в реестр в состоянии new (оповещение
// agents.tool_new), изменённые после одобрения — в changed (DM-25,
// оповещение agents.tool_changed). Не чаще ObserveInterval на MCP-сервер.
func (s *Service) Observe(ctx context.Context, by By, in ObserveInput) (_ ObserveResult, err error) {
	if len(in.Tools) == 0 || len(in.Tools) > MaxObserve {
		return ObserveResult{}, invalidf("tools — от 1 до %d описаний", MaxObserve)
	}
	var serverID, agentID, owner, key string
	if in.Server == policy.FunctionServer {
		if _, err := ids.Parse(in.AgentID); err != nil {
			return ObserveResult{}, invalidf("agent_id — UUID агента")
		}
		a, err := s.store.Agent(ctx, s.orgID, in.AgentID)
		if err != nil {
			return ObserveResult{}, err
		}
		agentID, owner, key = a.ID, a.Slug, "agent:"+a.ID
	} else {
		if in.AgentID != "" {
			return ObserveResult{}, invalidf("agent_id — только для server: function")
		}
		m, err := s.store.ServerBySlug(ctx, s.orgID, in.Server)
		if err != nil {
			return ObserveResult{}, err
		}
		serverID, owner, key = m.ID, m.Slug, "server:"+m.ID
	}
	items := make([]Observed, 0, len(in.Tools))
	names := make([]string, 0, len(in.Tools))
	var errs []error
	for i, raw := range in.Tools {
		d, err := ParseDescriptor(raw.Descriptor)
		if err != nil {
			errs = append(errs, fmt.Errorf("tools[%d].descriptor — %w", i, err))
			continue
		}
		h := s.Hash(d)
		if slices.Contains(names, d.Name) || slices.ContainsFunc(items, func(o Observed) bool { return bytes.Equal(o.Hash, h) }) {
			errs = append(errs, fmt.Errorf("tools[%d] — повтор имени или описания", i))
			continue
		}
		names = append(names, d.Name)
		items = append(items, Observed{Desc: d, Hash: h, Suspicious: raw.Suspicious})
	}
	if len(errs) > 0 {
		return ObserveResult{}, invalid(errs...)
	}
	// Предел частоты — на пару (шлюз, сервер или агент): шлюзы кластера
	// сообщают независимо. Отметка снимается, если запись не удалась
	// (4Н3 ревью 4.r1).
	key = by.Actor.ID + "|" + key
	now := s.now()
	s.mu.Lock()
	last, seen := s.observed[key]
	if seen && now.Sub(last) < ObserveInterval && !now.Before(last) {
		s.mu.Unlock()
		return ObserveResult{}, ErrTooSoon
	}
	s.observed[key] = now
	s.mu.Unlock()
	defer func() {
		if err != nil {
			s.mu.Lock()
			if seen {
				s.observed[key] = last
			} else {
				delete(s.observed, key)
			}
			s.mu.Unlock()
		}
	}()

	var res ObserveResult
	err = s.store.Observe(ctx, s.orgID, serverID, agentID, names,
		func(known map[string]Tool, total, owned int) ([]Tool, []audit.Entry, error) {
			res = ObserveResult{}
			var out []Tool
			var recs []audit.Entry
			for _, o := range items {
				t, ok := known[o.Desc.Name]
				if !ok {
					if total >= MaxTools || owned >= MaxToolsPerOwner {
						res.Skipped++
						continue
					}
					id, err := s.newID()
					if err != nil {
						return nil, nil, err
					}
					t = Tool{ID: id, OrgID: s.orgID, ServerID: serverID, AgentID: agentID, Name: o.Desc.Name,
						Descriptor: o.Desc.Canonical, Hash: o.Hash, HashAlg: s.HashAlg(), Risk: SuggestedRisk(o.Desc),
						Status: policy.ToolNew, FirstSeen: now, LastSeen: now, UpdatedAt: now}
					if o.Suspicious {
						t.Status = policy.ToolSuspicious
					}
					total, owned = total+1, owned+1
					res.New++
					out = append(out, t)
					recs = append(recs, by.entry("agent_tool.discovered", "agent_tool", id, toolDetails(t, owner)))
					continue
				}
				action := ""
				prev := t.Status
				t.Descriptor, t.Hash, t.HashAlg, t.LastSeen, t.UpdatedAt = o.Desc.Canonical, o.Hash, s.HashAlg(), now, now
				match := bytes.Equal(t.Hash, t.ApprovedHash)
				// Подмена одобренного описания — всегда changed и оповещение
				// DM-25, даже если детекторы нашли в нём инструкции (4В1 ревью
				// 4.r1). Описание, одобренное после проверки находки, снова
				// подозрительным не становится (4Н1).
				switch {
				case t.Status == policy.ToolApproved && !match:
					t.Status, action = policy.ToolChanged, "agent_tool.changed"
					res.Changed++
					if o.Suspicious {
						res.Suspicious++
					}
				case o.Suspicious && !match && t.Status != policy.ToolRevoked && t.Status != policy.ToolSuspicious:
					t.Status, action = policy.ToolSuspicious, "agent_tool.suspicious"
					res.Suspicious++
				case t.Status == policy.ToolChanged && match:
					t.Status, action = policy.ToolApproved, "agent_tool.restored"
					res.Restored++
				default:
					res.Unchanged++
				}
				out = append(out, t)
				if action != "" {
					d := toolDetails(t, owner)
					d["previous_status"], d["suspicious"] = string(prev), o.Suspicious
					recs = append(recs, by.entry(action, "agent_tool", t.ID, d))
				}
			}
			return out, recs, nil
		})
	return res, err
}

// ApproveInput — одобрение инструмента.
type ApproveInput struct {
	Risk policy.ToolRisk
	// Hash — хеш описания, которое видел администратор (hex): описание,
	// изменившееся после показа, не одобряется (ErrStale).
	Hash    string
	Comment string
}

func checkComment(c string) error {
	if errs := text("comment", c, 0, maxComment); len(errs) > 0 {
		return invalid(errs...)
	}
	return nil
}

// Approve одобряет текущее описание инструмента с уровнем риска. Каждое
// одобрение — с повторной проверкой субъекта; одобрение changed и
// suspicious и понижение риска — ослабление защиты (DM-40).
func (s *Service) Approve(ctx context.Context, by By, id string, in ApproveInput) (Tool, error) {
	if !by.Security {
		return Tool{}, ErrSecurityRequired
	}
	if !policy.ValidRisk(in.Risk) {
		return Tool{}, invalidf("risk — low, medium, high или critical")
	}
	if err := checkComment(in.Comment); err != nil {
		return Tool{}, err
	}
	t, err := s.store.UpdateTool(ctx, s.orgID, id, func(t *Tool) (audit.Entry, error) {
		if !strings.EqualFold(in.Hash, hexOf(t.Hash)) {
			return audit.Entry{}, ErrStale
		}
		if t.Status == policy.ToolApproved && bytes.Equal(t.Hash, t.ApprovedHash) && t.Risk == in.Risk {
			return audit.Entry{}, errUnchanged
		}
		if err := by.confirm(ctx); err != nil {
			return audit.Entry{}, err
		}
		var reasons []string
		switch t.Status {
		case policy.ToolChanged:
			reasons = append(reasons, "tool_changed_approved")
		case policy.ToolSuspicious:
			reasons = append(reasons, "tool_suspicious_approved")
		case policy.ToolRevoked:
			reasons = append(reasons, "tool_revoked_approved")
		}
		if len(t.ApprovedHash) > 0 && policy.RiskRank(in.Risk) < policy.RiskRank(t.Risk) {
			reasons = append(reasons, "tool_risk_lowered")
		}
		prev, prevRisk := t.Status, t.Risk
		now := s.now()
		t.ApprovedHash, t.ApprovedDescriptor = slices.Clone(t.Hash), slices.Clone(t.Descriptor)
		t.Status, t.Risk, t.Comment = policy.ToolApproved, in.Risk, in.Comment
		t.DecidedBy, t.DecidedAt, t.UpdatedAt = by.ref(), now, now
		d := toolDetails(*t, s.ownerName(ctx, *t))
		d["previous_status"], d["previous_risk"], d["comment"] = string(prev), string(prevRisk), in.Comment
		d["weakening"], d["weakening_reasons"] = len(reasons) > 0, reasons
		return by.entry("agent_tool.approve", "agent_tool", t.ID, d), nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.Tool(ctx, s.orgID, id)
	}
	return t, err
}

// Revoke снимает одобрение: вызовы инструмента получают действие
// unapproved. Повторной проверки не требует — это усиление защиты.
func (s *Service) Revoke(ctx context.Context, by By, id, comment string) (Tool, error) {
	if err := checkComment(comment); err != nil {
		return Tool{}, err
	}
	t, err := s.store.UpdateTool(ctx, s.orgID, id, func(t *Tool) (audit.Entry, error) {
		if t.Status == policy.ToolRevoked {
			return audit.Entry{}, errUnchanged
		}
		prev := t.Status
		now := s.now()
		t.Status, t.Comment, t.DecidedBy, t.DecidedAt, t.UpdatedAt = policy.ToolRevoked, comment, by.ref(), now, now
		d := toolDetails(*t, s.ownerName(ctx, *t))
		d["previous_status"], d["comment"] = string(prev), comment
		return by.entry("agent_tool.revoke", "agent_tool", t.ID, d), nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.Tool(ctx, s.orgID, id)
	}
	return t, err
}

// SetRisk меняет уровень риска. Понижение — ослабление защиты (правила
// политики по риску, например require_approval для high): только с
// повторной проверкой.
func (s *Service) SetRisk(ctx context.Context, by By, id string, risk policy.ToolRisk, comment string) (Tool, error) {
	if !by.Security {
		return Tool{}, ErrSecurityRequired
	}
	if !policy.ValidRisk(risk) {
		return Tool{}, invalidf("risk — low, medium, high или critical")
	}
	if err := checkComment(comment); err != nil {
		return Tool{}, err
	}
	t, err := s.store.UpdateTool(ctx, s.orgID, id, func(t *Tool) (audit.Entry, error) {
		if t.Risk == risk {
			return audit.Entry{}, errUnchanged
		}
		lowered := policy.RiskRank(risk) < policy.RiskRank(t.Risk)
		if lowered {
			if err := by.confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		prev := t.Risk
		now := s.now()
		t.Risk, t.Comment, t.DecidedBy, t.DecidedAt, t.UpdatedAt = risk, comment, by.ref(), now, now
		d := toolDetails(*t, s.ownerName(ctx, *t))
		d["previous_risk"], d["comment"], d["weakening"] = string(prev), comment, lowered
		if lowered {
			d["weakening_reasons"] = []string{"tool_risk_lowered"}
		}
		return by.entry("agent_tool.risk", "agent_tool", t.ID, d), nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.Tool(ctx, s.orgID, id)
	}
	return t, err
}

// ownerName — slug сервера или агента инструмента для аудита; пусто при
// ошибке чтения (аудит не теряет запись из-за подписи).
func (s *Service) ownerName(ctx context.Context, t Tool) string {
	if t.ServerID != "" {
		if m, err := s.store.Server(ctx, s.orgID, t.ServerID); err == nil {
			return m.Slug
		}
		return ""
	}
	if a, err := s.store.Agent(ctx, s.orgID, t.AgentID); err == nil {
		return a.Slug
	}
	return ""
}

// Tool — инструмент по ID; ownerID не пуст — только видимый владельцу
// приложения (Tools).
func (s *Service) Tool(ctx context.Context, id, ownerID string) (Tool, error) {
	t, err := s.store.Tool(ctx, s.orgID, id)
	if err != nil {
		return Tool{}, err
	}
	if ownerID != "" {
		vis, err := s.visibleTo(ctx, ownerID)
		if err != nil {
			return Tool{}, err
		}
		if !vis.tool(t) {
			return Tool{}, ErrNotFound
		}
	}
	return t, nil
}

// Tools — инструменты по отбору; ownerID не пуст — только функции агентов
// своих приложений и инструменты MCP-серверов этих агентов.
func (s *Service) Tools(ctx context.Context, f ToolFilter, ownerID string) ([]Tool, error) {
	ts, err := s.store.Tools(ctx, s.orgID, f)
	if err != nil || ownerID == "" {
		return ts, err
	}
	vis, err := s.visibleTo(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(ts, func(t Tool) bool { return !vis.tool(t) }), nil
}

// visibility — что видит владелец приложения.
type visibility struct{ agents, servers []string }

func (v visibility) tool(t Tool) bool {
	if t.ServerID != "" {
		return slices.Contains(v.servers, t.ServerID)
	}
	return slices.Contains(v.agents, t.AgentID)
}

// server — MCP-сервер в списке агента своих приложений.
func (v visibility) server(id string) bool { return slices.Contains(v.servers, id) }

func (s *Service) visibleTo(ctx context.Context, ownerID string) (visibility, error) {
	as, err := s.Agents(ctx, "", ownerID)
	if err != nil {
		return visibility{}, err
	}
	var v visibility
	for _, a := range as {
		v.agents = append(v.agents, a.ID)
		v.servers = append(v.servers, a.Servers...)
	}
	return v, nil
}

// ServersFor — MCP-серверы; ownerID не пуст — только серверы агентов своих
// приложений.
func (s *Service) ServersFor(ctx context.Context, ownerID string) ([]MCPServer, error) {
	ms, err := s.store.Servers(ctx, s.orgID)
	if err != nil || ownerID == "" {
		return ms, err
	}
	vis, err := s.visibleTo(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(ms, func(m MCPServer) bool { return !vis.server(m.ID) }), nil
}

// ServerFor — MCP-сервер по ID с той же видимостью, что ServersFor.
func (s *Service) ServerFor(ctx context.Context, id, ownerID string) (MCPServer, error) {
	m, err := s.store.Server(ctx, s.orgID, id)
	if err != nil || ownerID == "" {
		return m, err
	}
	vis, err := s.visibleTo(ctx, ownerID)
	if err != nil {
		return MCPServer{}, err
	}
	if !vis.server(m.ID) {
		return MCPServer{}, ErrNotFound
	}
	return m, nil
}
