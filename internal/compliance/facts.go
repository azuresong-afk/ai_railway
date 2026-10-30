package compliance

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/notify"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
)

// Источники сведений снимка. Каждый — сервис сервера (*apps.Service и т. д.);
// интерфейсы узкие, чтобы тесты подставляли свои. Читаются только
// настройки и состояние: событий, запросов и их содержимого здесь нет.
type (
	// AppSource — приложения и провайдеры.
	AppSource interface {
		Applications(ctx context.Context, ownerID string, after *apps.Cursor, limit int) ([]apps.Application, error)
		Providers(ctx context.Context) ([]apps.Provider, error)
	}
	// PolicySource — политики (шаблоны и версии).
	PolicySource interface {
		Get(ctx context.Context, slug string, n int) (versions.Doc, error)
	}
	// RoleSource — роли и настройки входа.
	RoleSource interface {
		Roles(ctx context.Context) ([]auth.RoleSummary, error)
		Policy(ctx context.Context) (auth.Policy, error)
	}
	// StatusSource — состояние системы.
	StatusSource interface {
		Status(ctx context.Context) sysstatus.Status
	}
	// AlertRuleSource — правила оповещений.
	AlertRuleSource interface {
		Rules(ctx context.Context) ([]alerting.Rule, error)
	}
	// ChannelSource — каналы уведомлений.
	ChannelSource interface {
		Channels(ctx context.Context) ([]notify.Channel, error)
	}
	// DetectorSource — реестр детекторов (направления по умолчанию).
	DetectorSource interface {
		Get(id string) (detect.Detector, bool)
	}
)

// SystemFacts собирает Snapshot из сервисов сервера. Недоступный источник
// не обрывает сбор: его группа помечается недоступной.
type SystemFacts struct {
	Apps      AppSource
	Policies  PolicySource
	Roles     RoleSource
	Status    StatusSource
	Alerts    AlertRuleSource
	Channels  ChannelSource
	Detectors DetectorSource
	Logger    *slog.Logger
	Now       func() time.Time
}

const appsPage = 500

// Snapshot — см. Facts.
func (f *SystemFacts) Snapshot(ctx context.Context) (*Snapshot, error) {
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	log := f.Logger
	if log == nil {
		log = slog.Default()
	}
	s := &Snapshot{Now: now().UTC(), Unavailable: map[string]bool{}}
	fail := func(group string, err error) {
		s.Unavailable[group] = true
		log.Warn("соответствие: источник сведений недоступен", "class", "compliance", "group", group, "error", err)
	}
	if err := f.collectApps(ctx, s); err != nil {
		s.Apps = nil
		fail(GroupApps, err)
	}
	if err := f.collectRoles(ctx, s); err != nil {
		fail(GroupRoles, err)
	}
	f.collectStatus(ctx, s)
	if f.Alerts == nil {
		fail(GroupAlerts, errNoSource)
	} else if rules, err := f.Alerts.Rules(ctx); err != nil {
		fail(GroupAlerts, err)
	} else {
		for _, r := range rules {
			if r.Enabled {
				s.AlertRulesEnabled++
			}
		}
	}
	if f.Channels == nil {
		fail(GroupChannels, errNoSource)
	} else if chs, err := f.Channels.Channels(ctx); err != nil {
		fail(GroupChannels, err)
	} else {
		for _, c := range chs {
			if c.Enabled {
				s.ChannelsEnabled++
			}
		}
	}
	return s, nil
}

type sourceError string

func (e sourceError) Error() string { return string(e) }

const errNoSource = sourceError("источник не подключён")

func (f *SystemFacts) collectApps(ctx context.Context, s *Snapshot) error {
	if f.Apps == nil || f.Policies == nil {
		return errNoSource
	}
	provs, err := f.Apps.Providers(ctx)
	if err != nil {
		return err
	}
	external := map[string]bool{}
	for _, p := range provs {
		external[p.ID] = p.External
	}
	specs := map[string]*policy.Spec{}
	// spec — действующая версия политики; «не найдена» — приложение без
	// политики, другой сбой — группа недоступна (4В35), а не «не выполнено».
	spec := func(slug string) (*policy.Spec, error) {
		if sp, ok := specs[slug]; ok {
			return sp, nil
		}
		var sp *policy.Spec
		doc, err := f.Policies.Get(ctx, slug, 0)
		switch {
		case err == nil:
			sp = doc.Spec
		case !errors.Is(err, versions.ErrNotFound):
			return nil, err
		}
		specs[slug] = sp
		return sp, nil
	}
	var after *apps.Cursor
	for {
		page, err := f.Apps.Applications(ctx, "", after, appsPage)
		if err != nil {
			return err
		}
		for _, a := range page {
			if a.Archived() {
				continue
			}
			sp, err := spec(a.Policy)
			if err != nil {
				return err
			}
			s.Apps = append(s.Apps, f.appFact(a, external[a.ProviderID], sp))
		}
		if len(page) < appsPage {
			return nil
		}
		last := page[len(page)-1]
		after = &apps.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
}

func (f *SystemFacts) appFact(a apps.Application, external bool, sp *policy.Spec) AppFact {
	q := a.Quotas
	fact := AppFact{Slug: a.Slug, Env: a.Env, ExternalProvider: external, Storage: a.Storage, Models: len(a.Models),
		Quotas: map[string]int{"requests_per_minute": q.RequestsPerMinute, "requests_per_minute_per_user": q.RequestsPerMinutePerUser,
			"requests_per_minute_per_key": q.RequestsPerMinutePerKey, "tokens_per_minute": q.TokensPerMinute, "tokens_per_day": q.TokensPerDay,
			"max_messages": q.MaxMessages, "max_tokens": q.MaxTokens, "max_input_bytes": q.MaxInputBytes}}
	if sp == nil {
		return fact
	}
	fact.PolicyMode = string(sp.Mode)
	if a.PolicyMode != "" {
		fact.PolicyMode = a.PolicyMode
	}
	enforce := fact.PolicyMode == string(policy.Enforce)
	fact.ToolsBlockUnapproved = sp.Tools != nil && sp.Tools.Unapproved == policy.Block
	for _, r := range sp.Rules {
		if !changesOutcome(r.Action) {
			continue
		}
		for _, dir := range f.directions(r) {
			switch dir {
			case detect.Input:
				fact.InputRules++
				// В режиме monitor действуют только redact и pseudonymize (ТЗ 5.3).
				if r.Detector == "pii.ru" && (enforce || r.Action == policy.Redact || r.Action == policy.Pseudonymize) {
					fact.PIIRules++
				}
			case detect.Output:
				fact.OutputRules++
			}
		}
	}
	return fact
}

func changesOutcome(a policy.Action) bool {
	switch a {
	case policy.Block, policy.RequireApproval, policy.Redact, policy.Pseudonymize:
		return true
	}
	return false
}

// directions — направления правила: заданные явно или все направления
// детектора.
func (f *SystemFacts) directions(r policy.RuleSpec) []detect.Direction {
	if len(r.Directions) > 0 {
		return r.Directions
	}
	if f.Detectors != nil {
		if d, ok := f.Detectors.Get(r.Detector); ok {
			return d.Directions()
		}
	}
	return nil
}

func (f *SystemFacts) collectRoles(ctx context.Context, s *Snapshot) error {
	if f.Roles == nil {
		return errNoSource
	}
	pol, err := f.Roles.Policy(ctx)
	if err != nil {
		return err
	}
	roles, err := f.Roles.Roles(ctx)
	if err != nil {
		return err
	}
	security := map[string]bool{}
	for _, p := range auth.Permissions() {
		if p.Security {
			security[p.Name] = true
		}
	}
	s.MFARequiredAll = pol.MFARequiredAll
	for _, r := range roles {
		priv := false
		for p := range r.Grants {
			if security[p] {
				priv = true
				break
			}
		}
		if priv {
			s.PrivilegedRoles = append(s.PrivilegedRoles, RoleFact{ID: string(r.ID), MFA: r.MFARequired, Users: r.Users})
		}
	}
	return nil
}

func (f *SystemFacts) collectStatus(ctx context.Context, s *Snapshot) {
	if f.Status == nil {
		s.Unavailable[GroupAuditChain], s.Unavailable[GroupIntegrity] = true, true
		return
	}
	st := f.Status.Status(ctx)
	gone := map[string]bool{}
	for _, g := range st.Unavailable {
		gone[g] = true
	}
	if gone["audit_chain"] {
		s.Unavailable[GroupAuditChain] = true
	} else if c := st.AuditChain; c != nil {
		s.AuditChain = &ChainFact{OK: c.OK, CheckedAt: c.CheckedAt}
	}
	if gone["server"] || gone["gateways"] || gone["integrity"] {
		s.Unavailable[GroupIntegrity] = true
		return
	}
	fact := &IntegrityFact{ServerOK: st.Server.Selftest != nil && st.Server.Selftest.OK && !st.Server.Selftest.Stale && len(st.Server.Integrity) > 0}
	for _, i := range st.Server.Integrity {
		if !i.OK {
			fact.ServerOK = false
		}
		if i.CheckedAt.After(fact.CheckedAt) {
			fact.CheckedAt = i.CheckedAt
		}
	}
	for _, g := range st.Gateways {
		if g.State == sysstatus.GatewayPending || g.State == sysstatus.GatewayRevoked {
			continue
		}
		fact.Gateways++
		if g.Selftest != nil && g.Selftest.OK && g.Integrity != nil && g.Integrity.OK {
			fact.GatewaysOK++
		}
	}
	s.Integrity = fact
}
