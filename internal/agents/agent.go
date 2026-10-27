package agents

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// AgentInput — создание и изменение агента.
type AgentInput struct {
	AppID       string // только при создании
	Slug        string // только при создании
	Name        string
	Description string
	Owner       string
	// Servers — ID MCP-серверов агента.
	Servers []string
	// Status — active или disabled; пусто — active.
	Status string
}

func (in *AgentInput) check() error {
	errs := text("name", in.Name, 1, maxName)
	if err := textLen("description", in.Description, 0, maxDescription); err != nil {
		errs = append(errs, err)
	}
	// В описании допустимы переводы строк и табуляция.
	if strings.IndexFunc(in.Description, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0 {
		errs = append(errs, errors.New("description — без управляющих символов, кроме перевода строки и табуляции"))
	}
	errs = append(errs, text("owner", in.Owner, 0, maxOwner)...)
	if in.Status == "" {
		in.Status = AgentActive
	}
	if in.Status != AgentActive && in.Status != AgentDisabled {
		errs = append(errs, errors.New("status — active или disabled"))
	}
	if len(in.Servers) > MaxAgentServers {
		errs = append(errs, errors.New("mcp_servers — не больше 64 серверов"))
	}
	in.Servers = slices.Compact(slices.Sorted(slices.Values(in.Servers)))
	if len(errs) > 0 {
		return invalid(errs...)
	}
	return nil
}

func agentDetails(a Agent, app string) map[string]any {
	return map[string]any{"application": app, "slug": a.Slug, "name": a.Name, "owner": a.Owner, "status": a.Status,
		"mcp_servers": a.Servers}
}

// app — приложение агента: действующее и видимое субъекту (ownerID не
// пуст — только своё).
func (s *Service) app(ctx context.Context, id, ownerID string) (AppInfo, error) {
	a, err := s.apps.App(ctx, id)
	if errors.Is(err, ErrNoApp) {
		return AppInfo{}, ErrNoApp
	}
	if err != nil {
		return AppInfo{}, err
	}
	if ownerID != "" && a.OwnerID != ownerID {
		return AppInfo{}, ErrNoApp
	}
	return a, nil
}

// CreateAgent создаёт агента приложения.
func (s *Service) CreateAgent(ctx context.Context, by By, in AgentInput) (Agent, error) {
	var errs []error
	if !slugRe.MatchString(in.Slug) {
		errs = append(errs, errors.New("slug — строчные латинские буквы, цифры и дефис, до 64 символов"))
	}
	if err := in.check(); err != nil {
		var ie *InputError
		if errors.As(err, &ie) {
			errs = append(errs, ie.Errs...)
		}
	}
	if len(errs) > 0 {
		return Agent{}, invalid(errs...)
	}
	app, err := s.app(ctx, in.AppID, "")
	if err != nil {
		return Agent{}, err
	}
	if app.Archived {
		return Agent{}, ErrArchivedApp
	}
	id, err := s.newID()
	if err != nil {
		return Agent{}, err
	}
	now := s.now()
	a := Agent{ID: id, OrgID: s.orgID, AppID: app.ID, Slug: in.Slug, Name: in.Name, Description: in.Description,
		Owner: in.Owner, Servers: in.Servers, Status: in.Status, CreatedAt: now, CreatedBy: by.ref(), UpdatedAt: now, UpdatedBy: by.ref()}
	d := agentDetails(a, app.Slug)
	// Новый агент с MCP-серверами сразу получает их одобренные инструменты:
	// это то же расширение списка, что и в UpdateAgent (4В2 ревью 4.r1).
	if len(a.Servers) > 0 {
		if err := by.confirm(ctx); err != nil {
			return Agent{}, err
		}
		d["weakening"], d["weakening_reasons"], d["servers_added"] = true, []string{"agent_servers_widened"}, slices.Clone(a.Servers)
	}
	if err := s.store.CreateAgent(ctx, a, by.entry("agent.create", "agent", id, d)); err != nil {
		return Agent{}, err
	}
	return a, nil
}

// UpdateAgent меняет агента. Расширение списка MCP-серверов — ослабление
// защиты (ADR-0023, раздел 1; DM-40): только с повторной проверкой.
func (s *Service) UpdateAgent(ctx context.Context, by By, id string, in AgentInput) (Agent, error) {
	if err := in.check(); err != nil {
		return Agent{}, err
	}
	cur, err := s.store.Agent(ctx, s.orgID, id)
	if err != nil {
		return Agent{}, err
	}
	app, err := s.app(ctx, cur.AppID, "")
	if err != nil {
		return Agent{}, err
	}
	if app.Archived {
		return Agent{}, ErrArchivedApp
	}
	return s.store.UpdateAgent(ctx, s.orgID, id, func(a *Agent) (audit.Entry, error) {
		before := agentDetails(*a, app.Slug)
		var added []string
		for _, sv := range in.Servers {
			if !slices.Contains(a.Servers, sv) {
				added = append(added, sv)
			}
		}
		a.Name, a.Description, a.Owner, a.Servers, a.Status = in.Name, in.Description, in.Owner, in.Servers, in.Status
		d := map[string]any{"before": before, "after": agentDetails(*a, app.Slug)}
		if len(added) > 0 {
			if err := by.confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
			d["weakening"], d["weakening_reasons"], d["servers_added"] = true, []string{"agent_servers_widened"}, added
		}
		a.UpdatedAt, a.UpdatedBy = s.now(), by.ref()
		return by.entry("agent.update", "agent", id, d), nil
	})
}

// DeleteAgent удаляет агента без привязанных ключей приложения вместе с его
// функциями в реестре инструментов.
func (s *Service) DeleteAgent(ctx context.Context, by By, id string) (Agent, error) {
	return s.store.DeleteAgent(ctx, s.orgID, id, func(a Agent) (audit.Entry, error) {
		slug := ""
		if app, err := s.app(ctx, a.AppID, ""); err == nil {
			slug = app.Slug
		}
		return by.entry("agent.delete", "agent", id, agentDetails(a, slug)), nil
	})
}

// Agent — агент по ID; ownerID не пуст — только агент своего приложения.
func (s *Service) Agent(ctx context.Context, id, ownerID string) (Agent, error) {
	a, err := s.store.Agent(ctx, s.orgID, id)
	if err != nil {
		return Agent{}, err
	}
	if ownerID != "" {
		if _, err := s.app(ctx, a.AppID, ownerID); err != nil {
			return Agent{}, ErrNotFound
		}
	}
	return a, nil
}

// Agents — агенты организации; appID не пуст — одного приложения; ownerID
// не пуст — только приложений владельца.
func (s *Service) Agents(ctx context.Context, appID, ownerID string) ([]Agent, error) {
	var ids []string
	switch {
	case ownerID != "":
		owned, err := s.apps.Owned(ctx, ownerID)
		if err != nil {
			return nil, err
		}
		ids = owned
		if appID != "" {
			ids = nil
			if slices.Contains(owned, appID) {
				ids = []string{appID}
			}
		}
		if ids == nil {
			ids = []string{}
		}
	case appID != "":
		ids = []string{appID}
	}
	return s.store.Agents(ctx, s.orgID, ids)
}
