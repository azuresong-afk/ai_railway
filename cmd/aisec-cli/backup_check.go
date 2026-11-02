package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/agents"
	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
	"github.com/azuresong-afk/ai_railway/internal/backup"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/inventory"
	"github.com/azuresong-afk/ai_railway/internal/license"
	"github.com/azuresong-afk/ai_railway/internal/notify"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
	"github.com/azuresong-afk/ai_railway/internal/servicedb/kinds"
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
// сборке пакета для шлюзов (В22 ревью 2.r4). Токены проверяются только
// те, что останутся действующими (keepTokens): отозванный токен прав не
// даёт, а неизвестное новому выпуску право в нём не повод отклонять копию.
// Файлы лицензий проверяются подписью ключа производителя, как загруженная
// лицензия при запуске сервера (ADR-0026, п. 2; задача 5.8): лицензию,
// которую сервер не принял бы, копия не переносит, а без неё установка
// вернулась бы в режим пилота — поэтому отказ, а не пропуск. Настройки,
// которые переносятся только в пустую установку (встроенные правила
// оповещений, сертификат шлюза, OIDC, LDAP, лицензии), проверяются только
// при settings: в непустую установку Restore их не пишет, и отклонять из-за
// них копию незачем (5Н1 ревью 5.r1 этапа 5).
func checkSnapshot(p aisecCrypto.Provider, arch *backup.Archive, keepTokens, settings bool) error {
	s := arch.Snapshot
	reg, err := detect.NewRegistry(builtin.Catalog()...)
	if err != nil {
		return err
	}
	tlsp, err := p.TLS()
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
		if !keepTokens || t.RevokedAt != nil {
			continue
		}
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
		if a.UserAccess != nil {
			if err := checkUserAccess(a); err != nil {
				add("доступ по группам приложения "+a.Slug, err)
			}
		}
		ga, err := gatewayApplication(a, providers[a.ProviderID])
		if err != nil {
			add("приложение "+a.Slug, err)
			continue
		}
		if a.ArchivedAt == nil {
			gw = append(gw, ga)
		}
	}
	// Разделы версии 2 (задача 5.8) — проверками модулей (вынесены в
	// остатках волны A этапа 5): каналы уведомлений — как при сохранении
	// через API, с расшифрованными секретами; правила оповещений — свои как
	// правило из API, встроенные — по ключу этого выпуска; MCP-серверы —
	// адрес, признак insecure_http и корневые сертификаты; сертификат шлюза
	// — пара ключу и цепочка; издатель OIDC и настройки каталога LDAP — как
	// при сохранении в консоли.
	for _, c := range s.Channels {
		if err := checkChannel(tlsp, arch, c); err != nil {
			add("канал «"+c.Name+"»", err)
		}
	}
	for _, r := range s.AlertRules {
		if r.BuiltinKey != nil && !settings {
			continue
		}
		// Снятое в этом выпуске встроенное правило восстановление пропускает
		// строкой отчёта (5В1 ревью 5.r1).
		if err := checkAlertRule(r); err != nil && !errors.Is(err, alerting.ErrUnknownBuiltin) {
			add("правило оповещений «"+r.Name+"»", err)
		}
	}
	for _, m := range s.MCPServers {
		header := ""
		if m.AuthHeader != nil {
			header = *m.AuthHeader
		}
		in := agents.ServerInput{Name: m.Name, URL: m.URL, CAPEM: m.CAPEM, AuthHeader: header, CallTimeout: m.CallTimeoutS,
			Versions: m.Versions}
		if err := agents.CheckStoredServer(tlsp, nil, m.Slug, in, m.InsecureHTTP); err != nil {
			add("MCP-сервер "+m.Slug, err)
		}
	}
	if t := s.GatewayTLS; t != nil && settings {
		key, err := arch.GatewayTLSKey()
		if err == nil {
			err = apps.CheckStoredGatewayTLS(t.Host, []byte(t.ChainPEM), key, t.Fingerprint, t.NotAfter)
			clear(key)
		}
		if err != nil {
			add("сертификат шлюза", err)
		}
	}
	if o := s.OIDC; o != nil && settings {
		if err := oidc.ValidateIssuer(o.Issuer); err != nil {
			add("вход через OIDC", err)
		}
	}
	if l := s.LDAP; l != nil && settings {
		if err := ldap.ValidateConfig(ldap.Config{URL: l.URL, BindDN: l.BindDN, UserBaseDN: l.UserBaseDN, UserFilter: l.UserFilter,
			IDAttribute: l.IDAttribute, DisplayAttribute: l.DisplayAttribute, GroupMode: l.GroupMode, GroupBaseDN: l.GroupBaseDN}); err != nil {
			add("вход через LDAP", err)
		}
	}
	if len(s.Licenses) > 0 && settings {
		vendor, err := license.VendorVerifier(p)
		if err != nil {
			return err
		}
		for _, l := range s.Licenses {
			sg, err := license.Verify(p, vendor, l.File, time.Time{})
			if err == nil && sg.License.Number != uint64(l.Number) { //nolint:gosec // G115: номер > 0 (CHECK в схеме), сравнение
				err = fmt.Errorf("номер в файле %d", sg.License.Number)
			}
			if err != nil {
				add(fmt.Sprintf("лицензия № %d", l.Number), err)
			}
		}
	}
	// Модели реестра ИИ — правилами ручной записи (остаток 5.17 этапа 5).
	for _, m := range s.InventoryModels {
		files := make([]inventory.File, 0, len(m.Files))
		for _, f := range m.Files {
			files = append(files, inventory.File{Path: f.Path, Size: f.Size, Role: f.Role, HashAlg: f.HashAlg, Hash: f.Hash})
		}
		if err := inventory.CheckStoredModel(inventory.StoredModel{Kind: m.Kind, Provider: m.Provider, Name: m.Name, Version: m.Version,
			Title: m.Title, Description: m.Description, Owner: m.Owner, Origin: m.Origin, Status: m.Status, Files: files}); err != nil {
			add("модель реестра ИИ "+m.ID, err)
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

// serviceDBVerifier — проверка файла служебной базы копии по правилам
// ADR-0028 для сохранённой версии, как при запуске сервера: подпись файла
// и заверения встроенным ключом производителя, отзыв, дата выпуска внутри
// срока заверения, разбор содержимого видом этого выпуска; срок заверения
// на текущее время не проверяется. Вид, неизвестный выпуску, — ошибка.
func serviceDBVerifier(p aisecCrypto.Provider) (func(kind string, file []byte) (backup.ServiceDBMeta, error), error) {
	vendor, err := servicedb.EmbeddedVendor(p)
	if err != nil {
		return nil, err
	}
	all := kinds.All()
	return func(kind string, file []byte) (backup.ServiceDBMeta, error) {
		k, err := servicedb.KindByName(all, kind)
		if err != nil {
			return backup.ServiceDBMeta{}, errors.New(inspectReasonText(servicedb.ReasonKind))
		}
		v, err := servicedb.Verify(p, vendor, k, file, time.Time{})
		if err != nil {
			return backup.ServiceDBMeta{}, errors.New(inspectReasonText(servicedb.Reason(err)))
		}
		return backup.ServiceDBMeta{Version: v.Content.Version, Date: v.Content.Date, Records: v.Content.Records,
			SubkeySerial: v.Endorsement.Serial, Fingerprint: v.Fingerprint}, nil
	}, nil
}

// checkChannel проверяет канал уведомлений копии правилами сохранения
// через API (notify.CheckStoredChannel); секреты расшифровываются ключом
// копии только на время проверки.
func checkChannel(tlsp aisecCrypto.TLSProvider, arch *backup.Archive, c backup.NotifyChannel) error {
	sec, err := arch.ChannelSecrets(c)
	if err != nil {
		return err
	}
	defer clear(sec)
	return notify.CheckStoredChannel(tlsp, notify.StoredChannel{Name: c.Name, Type: c.Type, Enabled: c.Enabled,
		MinSeverity: c.MinSeverity, Settings: c.Settings, SecretFields: c.SecretFields, Secrets: sec, AuditStream: c.AuditStream})
}

// checkUserAccess проверяет доступ к моделям по группам правилами API для
// моделей и псевдонимов приложения (apps.CheckStoredUserAccess).
func checkUserAccess(a backup.Application) error {
	u := a.UserAccess
	var aliases map[string]string
	if err := strictJSON(a.Aliases, &aliases); err != nil {
		return fmt.Errorf("aliases: %w", err)
	}
	var groups map[string][]string
	if err := strictJSON(u.ModelGroups, &groups); err != nil {
		return fmt.Errorf("model_groups: %w", err)
	}
	return apps.CheckStoredUserAccess(a.Models, aliases, apps.UserAccess{Mode: u.Mode, Issuer: u.Issuer, Audience: u.Audience,
		GroupsClaim: u.GroupsClaim, Leeway: u.LeewaySeconds, ModelGroups: groups})
}

// checkAlertRule проверяет правило оповещений копии правилами API этого
// выпуска (alerting.CheckStoredRule): своё — условие, группировка,
// важность, окно подавления и получатели; встроенное — ключ, вид и то, что
// у него меняется через API.
func checkAlertRule(r backup.AlertRule) error {
	var c alerting.Condition
	var rc alerting.Recipients
	if err := strictJSON(r.Condition, &c); err != nil {
		return fmt.Errorf("condition: %w", err)
	}
	if err := strictJSON(r.Recipients, &rc); err != nil {
		return fmt.Errorf("recipients: %w", err)
	}
	enabled, suppress := r.Enabled, r.SuppressMinutes
	key := ""
	if r.BuiltinKey != nil {
		key = *r.BuiltinKey
	}
	return alerting.CheckStoredRule(key, alerting.RuleInput{Kind: r.Kind, Name: r.Name, Description: r.Description, Enabled: &enabled,
		Severity: r.Severity, Condition: c, GroupBy: r.GroupBy, SuppressMinutes: &suppress, Recipients: rc})
}

// builtinAlertRule — встроенное правило оповещений этого выпуска для
// восстановления (backup.RestoreOptions.BuiltinAlertRule, 5В1 ревью 5.r1).
func builtinAlertRule(key string) (backup.BuiltinAlertRule, bool) {
	r, ok := alerting.StoredBuiltin(key)
	if !ok {
		return backup.BuiltinAlertRule{}, false
	}
	cond, err := json.Marshal(r.Condition)
	if err != nil {
		return backup.BuiltinAlertRule{}, false
	}
	group := r.GroupBy
	if group == nil {
		group = []string{}
	}
	return backup.BuiltinAlertRule{Locked: alerting.Locked(r.Kind), Rule: backup.AlertRule{Kind: r.Kind, Name: r.Name,
		Description: r.Description, Enabled: r.Enabled, Severity: r.Severity, Condition: cond, GroupBy: group,
		SuppressMinutes: r.SuppressMinutes, GroupMinutes: r.GroupMinutes}}, true
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
