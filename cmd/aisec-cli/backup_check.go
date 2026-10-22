package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/backup"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

// setupLockKey — блокировка первичной настройки (Н40 ревью 2.r4).
const setupLockKey = auth.SetupLockKey

// maxInvalidListed — сколько отклонённых объектов перечисляется в ошибке.
const maxInvalidListed = 20

// invalidObjectsError — объекты копии, которые сервис этого выпуска не
// принял бы (В22 ревью 2.r4).
type invalidObjectsError struct{ items []string }

func (e *invalidObjectsError) Error() string {
	items := e.items
	more := ""
	if len(items) > maxInvalidListed {
		more = fmt.Sprintf("; и ещё %d", len(items)-maxInvalidListed)
		items = items[:maxInvalidListed]
	}
	return fmt.Sprintf("объекты копии не проходят проверки этого выпуска (%d): %s%s", len(e.items), strings.Join(items, "; "), more)
}

// checkSnapshot проверяет объекты копии правилами сервиса текущего
// выпуска до записи в БД: политики — по каталогу детекторов, приложения —
// по правилам API и так, как их проверит шлюз (словари, политики),
// свои роли и токены API — по каталогу разрешений и правилу 2.10. Копия
// от другого выпуска иначе прошла бы восстановление, а сломалась при
// сборке пакета для шлюзов (В22 ревью 2.r4).
func checkSnapshot(s *backup.Snapshot) error {
	reg, err := detect.NewRegistry(builtin.All()...)
	if err != nil {
		return err
	}
	var bad []string
	add := func(what string, err error) {
		bad = append(bad, what+": "+shortReason(err))
	}
	for _, r := range s.Roles {
		perms := make([]auth.GrantInput, 0, len(r.Permissions))
		for _, p := range r.Permissions {
			perms = append(perms, auth.GrantInput{Permission: p.Permission, Scope: p.Scope})
		}
		if err := auth.CheckStoredRole(r.DisplayName, r.Description, r.MFARequired, perms); err != nil {
			add("роль "+r.ID, err)
		}
	}
	for _, t := range s.APITokens {
		if err := auth.CheckStoredTokenGrants(t.Permissions); err != nil {
			add("токен API "+t.Prefix, err)
		}
	}
	specs := make([]policy.Spec, 0, len(s.Policies))
	for _, p := range s.Policies {
		spec, err := currentSpec(p)
		if err == nil {
			err = versions.Check(spec, reg)
		}
		if err != nil {
			// Ошибки разбора и компиляции политики уже называют её.
			if what := "политика " + p.Slug; strings.HasPrefix(err.Error(), what) {
				bad = append(bad, shortReason(err))
			} else {
				add(what, err)
			}
			continue
		}
		specs = append(specs, *spec)
	}
	providers := make(map[string]string, len(s.Providers))
	for _, p := range s.Providers {
		providers[p.ID] = p.Slug
	}
	var gw []config.Application
	for _, a := range s.Applications {
		ga, err := gatewayApplication(a, providers[a.ProviderID])
		if err != nil {
			add("приложение "+a.Slug, err)
			continue
		}
		if a.ArchivedAt == nil {
			gw = append(gw, ga)
		}
	}
	// Ошибки CheckApplications уже называют приложение.
	if len(bad) == 0 {
		if err := gateway.CheckApplications(gw, specs); err != nil {
			for _, e := range unjoin(err) {
				bad = append(bad, shortReason(e))
			}
		}
	}
	if len(bad) > 0 {
		return &invalidObjectsError{items: bad}
	}
	return nil
}

// currentSpec — текущая версия политики, разобранная строгой схемой.
func currentSpec(p backup.Policy) (*policy.Spec, error) {
	for _, v := range p.Versions {
		if v.Version != p.CurrentVersion {
			continue
		}
		spec, err := policy.Parse(strings.NewReader(v.SpecYAML))
		if err != nil {
			return nil, err
		}
		if spec.ID != p.Slug {
			return nil, fmt.Errorf("id %q не совпадает с политикой", spec.ID)
		}
		return spec, nil
	}
	return nil, fmt.Errorf("нет текущей версии %d", p.CurrentVersion)
}

// gatewayApplication разбирает поля приложения строгой схемой сервиса,
// проверяет их правилами API и собирает приложение шлюза.
func gatewayApplication(a backup.Application, provider string) (config.Application, error) {
	var aliases map[string]string
	var quotas apps.Quotas
	var ls []apps.List
	for _, f := range []struct {
		name string
		raw  json.RawMessage
		dst  any
	}{{"aliases", a.Aliases, &aliases}, {"quotas", a.Quotas, &quotas}, {"lists", a.Lists, &ls}} {
		if err := strictJSON(f.raw, f.dst); err != nil {
			return config.Application{}, fmt.Errorf("%s: %w", f.name, err)
		}
	}
	specs := make([]lists.Spec, 0, len(ls))
	for _, l := range ls {
		specs = append(specs, lists.Spec(l))
	}
	p := config.AppParams{Env: a.Env, FailMode: a.FailMode, Storage: a.Storage, UserFrom: a.UserFrom, Models: a.Models,
		Aliases: aliases, Quotas: config.Quotas(quotas), Lists: specs, ExfilAllowDomains: a.ExfilAllowDomains}
	if errs := p.Check(); len(errs) > 0 {
		return config.Application{}, errors.Join(errs...)
	}
	pol := a.Policy
	if pol == "" {
		pol = policy.DefaultTemplate
	}
	if len(aliases) == 0 {
		aliases = nil
	}
	return config.Application{ID: a.Slug, Env: a.Env, Provider: provider, Models: a.Models, Aliases: aliases,
		Policy: pol, PolicyMode: a.PolicyMode, FailMode: a.FailMode, Storage: a.Storage, UserFrom: a.UserFrom,
		Quotas: p.Quotas, Lists: specs, ExfilAllowDomains: a.ExfilAllowDomains}, nil
}

// strictJSON — разбор без неизвестных полей и данных после значения.
func strictJSON(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("данные после значения")
	}
	return nil
}

// unjoin — составляющие ошибки errors.Join.
func unjoin(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}
