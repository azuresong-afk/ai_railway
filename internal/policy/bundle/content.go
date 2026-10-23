package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Пределы содержимого пакета. Сервер не собирает пакет, который шлюз
// отверг бы, поэтому пределы общие.
const (
	MaxProviders    = 1000
	MaxApplications = 2000
	MaxPolicies     = 1000
	// MaxKeysPerApp — ключей приложения в пакете: только действующие на
	// момент сборки (не больше 20) с запасом на перекрытие при ротации.
	MaxKeysPerApp = 64
	MaxCIDRs      = 64
	MaxModels     = 100
	MaxCAPEM      = 256 << 10
	// MaxCredential — учётные данные одного провайдера.
	MaxCredential = 16 << 10
	// MaxTimeoutSeconds — таймаут провайдера.
	MaxTimeoutSeconds = 600
)

var (
	prefixRe = regexp.MustCompile(`^aisec_[a-z0-9]{8}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Content — открытая часть пакета (решение Р7): провайдеры без учётных
// данных, приложения с хешами ключей и словарями, политики организации.
// Шаблоны политик не передаются: они в коде шлюза.
type Content struct {
	Providers    []Provider    `json:"providers"`
	Applications []Application `json:"applications"`
	Policies     []Policy      `json:"policies"`
	// Unavailable — приложения, не прошедшие проверку при сборке (В16 ревью
	// 2.r3b): шлюз принимает их действующие ключи и отвечает 503, остальные
	// приложения пакета работают.
	Unavailable []Unavailable `json:"unavailable,omitempty"`
	// Budgets — цены моделей и жёсткие бюджеты (задача 3.18 этапа 3); нет
	// раздела — ни цен, ни бюджетов не задано, шлюз расход не считает.
	Budgets *Budgets `json:"budgets,omitempty"`
	// GatewayTLS — сертификат заказчика для адреса шлюза (задача 3.27 этапа
	// 3); ключ — в секретах. Нет раздела — шлюз на своём сертификате.
	GatewayTLS *GatewayTLS `json:"gateway_tls,omitempty"`
}

// Unavailable — приложение, исключённое из пакета: только ID, контур и
// действующие ключи (отозванный ключ в пакет не попадает и на шлюзе — 401).
type Unavailable struct {
	ID   string `json:"id"`
	Env  string `json:"env"`
	Keys []Key  `json:"keys"`
}

// Provider — провайдер модели без учётных данных. CredentialSetAt меняется
// при каждой установке учётных данных: новый секрет — новая версия пакета.
type Provider struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	BaseURL  string `json:"base_url"`
	CAPEM    string `json:"ca_pem"`
	AuthURL  string `json:"auth_url,omitempty"`
	Scope    string `json:"scope,omitempty"`
	FolderID string `json:"folder_id,omitempty"`
	// Таймауты, секунды; 0 — по умолчанию шлюза.
	ConnectTimeout    int        `json:"connect_timeout"`
	HeaderTimeout     int        `json:"header_timeout"`
	ResponseTimeout   int        `json:"response_timeout"`
	StreamIdleTimeout int        `json:"stream_idle_timeout"`
	External          bool       `json:"external"`
	CredentialSetAt   *time.Time `json:"credential_set_at,omitempty"`
}

// Application — действующее приложение (ТЗ 5.4).
type Application struct {
	ID                string            `json:"id"`
	Env               string            `json:"env"`
	Provider          string            `json:"provider"`
	Models            []string          `json:"models"`
	Aliases           map[string]string `json:"aliases,omitempty"`
	Policy            string            `json:"policy"`
	PolicyMode        string            `json:"policy_mode"`
	FailMode          string            `json:"fail_mode"`
	Storage           string            `json:"storage"`
	UserFrom          string            `json:"user_from"`
	Quotas            Quotas            `json:"quotas"`
	Lists             []List            `json:"lists,omitempty"`
	ExfilAllowDomains []string          `json:"exfil_allow_domains,omitempty"`
	Keys              []Key             `json:"keys"`
}

// Quotas — лимиты приложения; 0 — без лимита.
type Quotas struct {
	RequestsPerMinute        int `json:"requests_per_minute"`
	RequestsPerMinutePerUser int `json:"requests_per_minute_per_user"`
	RequestsPerMinutePerKey  int `json:"requests_per_minute_per_key"`
	TokensPerMinute          int `json:"tokens_per_minute"`
	TokensPerDay             int `json:"tokens_per_day"`
	MaxMessages              int `json:"max_messages"`
	MaxTokens                int `json:"max_tokens"`
	MaxInputBytes            int `json:"max_input_bytes"`
}

// List — словарь или выражения заказчика для детектора lists (ТЗ 5.2).
type List struct {
	ID            string   `json:"id"`
	Category      string   `json:"category"`
	Threat        string   `json:"threat,omitempty"`
	Score         float64  `json:"score,omitempty"`
	Direction     string   `json:"direction,omitempty"`
	Words         []string `json:"words,omitempty"`
	Regex         []string `json:"regex,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
}

// Key — ключ приложения: префикс и SHA-256 профиля (ИАФ.8), без секрета.
type Key struct {
	Prefix       string    `json:"prefix"`
	SHA256       string    `json:"sha256"`
	ExpiresAt    time.Time `json:"expires_at"`
	AllowedCIDRs []string  `json:"allowed_cidrs,omitempty"`
}

// Policy — текущая версия политики организации: каноничный YAML (ADR-0016).
type Policy struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	YAML    string `json:"yaml"`
}

// Marshal кодирует содержимое. Порядок полей задают типы, ключи словарей
// encoding/json сортирует, списки упорядочивает сборщик: одинаковые данные
// дают одинаковые байты и одинаковый хеш.
func (c *Content) Marshal() ([]byte, error) { return json.Marshal(c) }

// ParseContent строго разбирает содержимое: один объект JSON, неизвестные
// поля — отказ, затем Validate.
func ParseContent(data []byte) (*Content, error) {
	var c Content
	if err := decodeStrict(data, &c); err != nil {
		return nil, fmt.Errorf("содержимое: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// decodeStrict — один объект JSON без неизвестных полей и данных после него.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("данные после объекта JSON")
	}
	return nil
}

// Validate — те же проверки, что у файла шлюза этапа 1 (config), плюс
// пределы пакета и ссылки между частями.
func (c *Content) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if len(c.Providers) > MaxProviders || len(c.Applications)+len(c.Unavailable) > MaxApplications || len(c.Policies) > MaxPolicies {
		return fmt.Errorf("содержимое: больше %d провайдеров, %d приложений или %d политик", MaxProviders, MaxApplications, MaxPolicies)
	}
	providers := map[string]bool{}
	for i, p := range c.Providers {
		at := fmt.Sprintf("providers[%d] (%s)", i, short(p.ID))
		if !config.ValidID(p.ID) || providers[p.ID] {
			add("%s: неверный или повторный id", at)
		}
		providers[p.ID] = true
		errs = append(errs, prefixed(at, p.params().Check())...)
		for _, t := range []int{p.ConnectTimeout, p.HeaderTimeout, p.ResponseTimeout, p.StreamIdleTimeout} {
			if t < 0 || t > MaxTimeoutSeconds {
				add("%s: таймаут — от 0 до %d секунд", at, MaxTimeoutSeconds)
				break
			}
		}
		if p.CAPEM == "" || len(p.CAPEM) > MaxCAPEM {
			add("%s: ca_pem — от 1 байта до %d байт", at, MaxCAPEM)
		}
	}
	policies := map[string]bool{}
	for i, p := range c.Policies {
		at := fmt.Sprintf("policies[%d] (%s)", i, short(p.ID))
		if !config.ValidID(p.ID) || policy.IsTemplate(p.ID) || policies[p.ID] {
			add("%s: неверный, повторный или совпадающий с шаблоном id", at)
		}
		policies[p.ID] = true
		if p.Version < 1 {
			add("%s: version — от 1", at)
		}
		s, err := policy.Parse(strings.NewReader(p.YAML))
		switch {
		case err != nil:
			add("%s: %w", at, err)
		case s.ID != p.ID:
			add("%s: id в YAML не совпадает", at)
		}
	}
	apps := map[string]bool{}
	prefixes := map[string]bool{}
	for i, a := range c.Applications {
		at := fmt.Sprintf("applications[%d] (%s)", i, short(a.ID))
		if !config.ValidID(a.ID) || apps[a.ID] {
			add("%s: неверный или повторный id", at)
		}
		apps[a.ID] = true
		if !providers[a.Provider] {
			add("%s: провайдер %q не описан в пакете", at, short(a.Provider))
		}
		if !policies[a.Policy] && !policy.IsTemplate(a.Policy) {
			add("%s: политика %q не описана в пакете и не является шаблоном", at, short(a.Policy))
		}
		if a.PolicyMode == "" {
			// В сервере режим политики приложения всегда явный (решение 1.19).
			add("%s: policy_mode обязателен", at)
		}
		if len(a.Models) > MaxModels {
			add("%s: больше %d моделей", at, MaxModels)
		}
		errs = append(errs, prefixed(at, a.params().Check())...)
		errs = append(errs, checkKeys(at, a.Keys, prefixes)...)
	}
	for i, u := range c.Unavailable {
		at := fmt.Sprintf("unavailable[%d] (%s)", i, short(u.ID))
		if !config.ValidID(u.ID) || apps[u.ID] {
			add("%s: неверный или повторный id", at)
		}
		apps[u.ID] = true
		if u.Env != "prod" && u.Env != "test" {
			add("%s: env — prod или test", at)
		}
		errs = append(errs, checkKeys(at, u.Keys, prefixes)...)
	}
	provIDs, appIDs := c.budgetIDs()
	errs = append(errs, c.Budgets.validate(provIDs, appIDs)...)
	errs = append(errs, c.GatewayTLS.validate()...)
	return errors.Join(errs...)
}

// checkKeys проверяет ключи приложения; prefixes — уже встреченные префиксы.
func checkKeys(at string, keys []Key, prefixes map[string]bool) []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if len(keys) > MaxKeysPerApp {
		add("%s: больше %d ключей", at, MaxKeysPerApp)
	}
	for j, k := range keys {
		kat := fmt.Sprintf("%s.keys[%d]", at, j)
		if !prefixRe.MatchString(k.Prefix) || prefixes[k.Prefix] {
			add("%s: неверный или повторный prefix", kat)
		}
		prefixes[k.Prefix] = true
		if !sha256Re.MatchString(k.SHA256) {
			add("%s: sha256 — 64 шестнадцатеричные цифры", kat)
		}
		if k.ExpiresAt.IsZero() {
			add("%s: expires_at обязателен", kat)
		}
		if len(k.AllowedCIDRs) > MaxCIDRs {
			add("%s: больше %d подсетей", kat, MaxCIDRs)
		}
		errs = append(errs, prefixed(kat, config.CheckCIDRs(k.AllowedCIDRs))...)
	}
	return errs
}

func (p Provider) params() config.ProviderParams {
	return config.ProviderParams{Type: p.Type, BaseURL: p.BaseURL, AuthURL: p.AuthURL, Scope: p.Scope, FolderID: p.FolderID,
		ConnectTimeout: seconds(p.ConnectTimeout), HeaderTimeout: seconds(p.HeaderTimeout),
		ResponseTimeout: seconds(p.ResponseTimeout), StreamIdleTimeout: seconds(p.StreamIdleTimeout)}
}

func (a Application) params() config.AppParams {
	return config.AppParams{Env: a.Env, PolicyMode: a.PolicyMode, FailMode: a.FailMode, Storage: a.Storage,
		UserFrom: a.UserFrom, Models: a.Models, Aliases: a.Aliases, Quotas: config.Quotas(a.Quotas),
		Lists: a.listSpecs(), ExfilAllowDomains: a.ExfilAllowDomains}
}

func (a Application) listSpecs() []lists.Spec {
	if len(a.Lists) == 0 {
		return nil
	}
	out := make([]lists.Spec, 0, len(a.Lists))
	for _, l := range a.Lists {
		out = append(out, lists.Spec(l))
	}
	return out
}

func seconds(n int) time.Duration { return time.Duration(n) * time.Second }

// GatewayProviders — провайдеры в виде файла шлюза этапа 1: без путей,
// корневые сертификаты и учётные данные передаются отдельно (CAPEM и секреты).
func (c *Content) GatewayProviders() []config.Provider {
	out := make([]config.Provider, 0, len(c.Providers))
	for _, p := range c.Providers {
		ext := p.External
		out = append(out, config.Provider{ID: p.ID, Type: p.Type, BaseURL: p.BaseURL, External: &ext,
			ConnectTimeout: config.Duration(seconds(p.ConnectTimeout)), HeaderTimeout: config.Duration(seconds(p.HeaderTimeout)),
			ResponseTimeout: config.Duration(seconds(p.ResponseTimeout)), StreamIdleTimeout: config.Duration(seconds(p.StreamIdleTimeout)),
			AuthURL: p.AuthURL, Scope: p.Scope, FolderID: p.FolderID})
	}
	return out
}

// GatewayApplications — приложения в виде файла шлюза этапа 1 без ключей:
// ключи с точным сроком даёт KeyRecords.
func (c *Content) GatewayApplications() []config.Application {
	out := make([]config.Application, 0, len(c.Applications))
	for _, a := range c.Applications {
		out = append(out, config.Application{ID: a.ID, Env: a.Env, Provider: a.Provider, Models: a.Models,
			Aliases: a.Aliases, Policy: a.Policy, PolicyMode: a.PolicyMode, FailMode: a.FailMode, Storage: a.Storage,
			UserFrom: a.UserFrom, Quotas: config.Quotas(a.Quotas), Lists: a.listSpecs(), ExfilAllowDomains: a.ExfilAllowDomains})
	}
	return out
}

// Specs — политики организации; содержимое уже проверено Validate.
func (c *Content) Specs() ([]policy.Spec, error) {
	out := make([]policy.Spec, 0, len(c.Policies))
	for _, p := range c.Policies {
		s, err := policy.Parse(strings.NewReader(p.YAML))
		if err != nil {
			return nil, fmt.Errorf("политика %s: %w", p.ID, err)
		}
		out = append(out, *s)
	}
	return out, nil
}

// UnavailableIDs — ID приложений, исключённых из пакета.
func (c *Content) UnavailableIDs() []string {
	out := make([]string, 0, len(c.Unavailable))
	for _, u := range c.Unavailable {
		out = append(out, u.ID)
	}
	return out
}

// KeyRecords — ключи приложений для аутентификации на шлюзе, в том числе
// исключённых из пакета (их запросы шлюз отклоняет с 503).
func (c *Content) KeyRecords() ([]auth.KeyRecord, error) {
	type owner struct {
		id, env string
		keys    []Key
	}
	all := make([]owner, 0, len(c.Applications)+len(c.Unavailable))
	for _, a := range c.Applications {
		all = append(all, owner{a.ID, a.Env, a.Keys})
	}
	for _, u := range c.Unavailable {
		all = append(all, owner{u.ID, u.Env, u.Keys})
	}
	var out []auth.KeyRecord
	for _, a := range all {
		for _, k := range a.keys {
			rec := auth.KeyRecord{AppID: a.id, Env: a.env, Prefix: k.Prefix, SHA256: k.SHA256, Expires: k.ExpiresAt}
			for _, s := range k.AllowedCIDRs {
				p, err := netip.ParsePrefix(s)
				if err != nil {
					return nil, fmt.Errorf("ключ %s: allowed_cidrs: %w", k.Prefix, err)
				}
				rec.AllowedCIDRs = append(rec.AllowedCIDRs, p.Masked())
			}
			out = append(out, rec)
		}
	}
	return out, nil
}

// short укорачивает недоверенную строку для сообщения об ошибке.
func short(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

func prefixed(at string, errs []error) []error {
	out := make([]error, 0, len(errs))
	for _, e := range errs {
		out = append(out, fmt.Errorf("%s: %w", at, e))
	}
	return out
}
