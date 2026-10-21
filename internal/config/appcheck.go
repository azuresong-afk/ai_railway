package config

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect/exfil"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
)

// Проверки приложений и провайдеров, общие для файла шлюза и сервера
// управления (задача 2.11 этапа 2): одни и те же значения принимаются в
// обоих местах, а пакет для шлюза (2.13) не содержит того, что шлюз
// отверг бы. Ошибки — без префикса места, его добавляет вызывающий.

// ValidID — допустимый ID приложения, провайдера или политики: строчные
// латинские буквы, цифры и дефис, до 63 символов.
func ValidID(s string) bool { return idRe.MatchString(s) }

// ValidModel — допустимое имя модели или псевдонима.
func ValidModel(s string) bool { return modelRe.MatchString(s) }

// ProviderParams — параметры провайдера без путей к файлам.
type ProviderParams struct {
	Type    string
	BaseURL string
	// AuthURL, Scope — GigaChat; FolderID — YandexGPT. Обязательность
	// проверяет вызывающий: в файле шлюза она идёт вместе с key_file.
	AuthURL  string
	Scope    string
	FolderID string
	// Таймауты; ноль — значение по умолчанию.
	ConnectTimeout    time.Duration
	HeaderTimeout     time.Duration
	ResponseTimeout   time.Duration
	StreamIdleTimeout time.Duration
}

// Check проверяет параметры провайдера.
func (p ProviderParams) Check() []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !provTypes[p.Type] {
		add("type — openai, gigachat или yandexgpt")
	}
	if _, err := ParseUpstreamURL(p.BaseURL); err != nil {
		add("base_url: %v", err)
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"connect_timeout", p.ConnectTimeout}, {"header_timeout", p.HeaderTimeout},
		{"response_timeout", p.ResponseTimeout}, {"stream_idle_timeout", p.StreamIdleTimeout}} {
		if d.v < 0 || d.v > MaxUpstreamTimeout {
			add("%s — от 0 до %s (0 — по умолчанию)", d.name, MaxUpstreamTimeout)
		}
	}
	if p.Scope != "" && !gigaChatScopes[p.Scope] {
		add("scope — GIGACHAT_API_PERS, GIGACHAT_API_B2B или GIGACHAT_API_CORP")
	}
	if p.AuthURL != "" {
		if _, err := ParseUpstreamURL(p.AuthURL); err != nil {
			add("auth_url: %v", err)
		}
	}
	if p.FolderID != "" && !folderRe.MatchString(p.FolderID) {
		add("folder_id — строчные латинские буквы и цифры")
	}
	return errs
}

// AppParams — параметры приложения, общие для файла шлюза и сервера.
type AppParams struct {
	Env        string
	PolicyMode string // пусто — режим политики (только файл шлюза)
	FailMode   string
	Storage    string
	UserFrom   string
	Models     []string
	Aliases    map[string]string
	Quotas     Quotas
	Lists      []lists.Spec
	// ExfilAllowDomains — домены для output.exfil (DM-11).
	ExfilAllowDomains []string
}

// MaxQuota — верхняя граница значений квот.
const MaxQuota = 1_000_000_000

// Check проверяет параметры приложения.
func (a AppParams) Check() []error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if len(a.Models) == 0 {
		add("нужен хотя бы один разрешённый model (DM-33)")
	}
	allowed := map[string]bool{}
	for _, m := range a.Models {
		if !modelRe.MatchString(m) {
			add("недопустимое имя модели %q", m)
		}
		allowed[m] = true
	}
	for alias, m := range a.Aliases {
		if !modelRe.MatchString(alias) || !allowed[m] {
			add("псевдоним %q должен указывать на разрешённую модель", alias)
		}
	}
	check := func(field, v string, set map[string]bool) {
		if !set[v] {
			add("недопустимое значение %s %q", field, v)
		}
	}
	check("env", a.Env, envs)
	if a.PolicyMode != "" {
		check("policy_mode", a.PolicyMode, modes)
	}
	check("fail_mode", a.FailMode, failModes)
	check("storage", a.Storage, storages)
	check("user_from", a.UserFrom, userFrom)
	q := a.Quotas
	for _, f := range []struct {
		name string
		v    int
	}{{"requests_per_minute", q.RequestsPerMinute}, {"requests_per_minute_per_user", q.RequestsPerMinutePerUser},
		{"requests_per_minute_per_key", q.RequestsPerMinutePerKey}, {"max_input_bytes", q.MaxInputBytes},
		{"tokens_per_minute", q.TokensPerMinute}, {"tokens_per_day", q.TokensPerDay},
		{"max_messages", q.MaxMessages}, {"max_tokens", q.MaxTokens}} {
		if f.v < 0 || f.v > MaxQuota {
			add("quotas.%s — от 0 до 10^9", f.name)
		}
	}
	if err := lists.Validate(lists.WithDefaults(a.Lists)); err != nil {
		errs = append(errs, err)
	}
	if _, err := exfil.NewWithConfig(exfil.Config{AllowDomains: a.ExfilAllowDomains}); err != nil {
		add("exfil_allow_domains: %v", err)
	}
	return errs
}

// CheckCIDRs проверяет подсети привязки ключа к адресам (ИАФ.8):
// канонический вид, без записи IPv4-in-IPv6.
func CheckCIDRs(cidrs []string) []error {
	var errs []error
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("allowed_cidrs: %q — подсеть вида 10.0.0.0/8", c))
		case p.Addr().Is4In6():
			// Адрес клиента IPv4 сравнивается в обычной записи; подсеть
			// ::ffff:a.b.c.d/n ему никогда не соответствовала бы.
			errs = append(errs, fmt.Errorf("allowed_cidrs: %q — укажите подсеть IPv4 в обычной записи", c))
		case p.Masked() != p:
			errs = append(errs, fmt.Errorf("allowed_cidrs: %q — адрес подсети с ненулевыми битами узла, имелось в виду %s?", c, p.Masked()))
		}
	}
	return errs
}

// prefixed добавляет к каждой ошибке место в конфигурации.
func prefixed(at string, errs []error) error {
	out := make([]error, 0, len(errs))
	for _, e := range errs {
		out = append(out, fmt.Errorf("%s: %w", at, e))
	}
	return errors.Join(out...)
}
