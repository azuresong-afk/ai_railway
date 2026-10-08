package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"
)

// Файл конфигурации шлюза этапа 1 (план этапа 1, Р2): приложения, ключи,
// провайдеры и модели. С этапа 2 эти данные приходят с сервера управления
// подписанным пакетом. Секретов в файле нет: ключи провайдеров — путями к
// файлам, ключи приложений — только SHA-256.

// MaxGatewayFile — предел размера файла конфигурации.
const MaxGatewayFile = 4 << 20

// Типы провайдеров.
const (
	ProviderOpenAI    = "openai"
	ProviderGigaChat  = "gigachat"
	ProviderYandexGPT = "yandexgpt"
)

// Duration — длительность в YAML строкой («30s», «1m»).
type Duration time.Duration

// UnmarshalYAML разбирает строку длительности.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("строка %d: длительность %q, например 30s", n.Line, s)
	}
	*d = Duration(v)
	return nil
}

// GatewayFile — содержимое файла конфигурации.
type GatewayFile struct {
	SchemaVersion int            `yaml:"schema_version"`
	Gateway       GatewaySection `yaml:"gateway"`
	Providers     []Provider     `yaml:"providers"`
	Applications  []Application  `yaml:"applications"`
}

// GatewaySection — общие параметры шлюза.
type GatewaySection struct {
	// EventsFile — приёмник-заглушка событий JSONL (этап 1, 5.5).
	EventsFile string `yaml:"events_file"`
	// UserHMACKeyFile — ключ HMAC для псевдонимов пользователей в событиях
	// (5.5), не короче 32 байт, права 0600.
	UserHMACKeyFile string `yaml:"user_hmac_key_file"`
}

// Provider — провайдер модели.
type Provider struct {
	ID      string `yaml:"id"`
	Type    string `yaml:"type"`
	BaseURL string `yaml:"base_url"`
	// CAFile — корневые сертификаты, которым шлюз доверяет для этого
	// провайдера (например, НУЦ Минцифры). Доверие системному хранилищу —
	// только явно: путём к его файлу (/etc/ssl/certs/ca-certificates.crt).
	CAFile string `yaml:"ca_file"`
	// SystemRoots — зарезервировано; на этапе 1 не поддерживается.
	SystemRoots bool `yaml:"system_roots"`
	// KeyFile — учётные данные провайдера (ключ API или авторизационные данные
	// GigaChat), права 0600.
	KeyFile string `yaml:"key_file"`
	// External — провайдер вне контура заказчика. По умолчанию true (5.4).
	External       *bool    `yaml:"external"`
	ConnectTimeout Duration `yaml:"connect_timeout"`
	HeaderTimeout  Duration `yaml:"header_timeout"`
	// ResponseTimeout — общий срок ответа (по умолчанию 10 мин),
	// StreamIdleTimeout — пауза между событиями потока (по умолчанию 60 с).
	ResponseTimeout   Duration `yaml:"response_timeout"`
	StreamIdleTimeout Duration `yaml:"stream_idle_timeout"`
	// Параметры GigaChat: адрес выдачи токена и область доступа.
	AuthURL string `yaml:"auth_url"`
	Scope   string `yaml:"scope"`
	// Параметр YandexGPT: идентификатор каталога облака.
	FolderID string `yaml:"folder_id"`
}

// IsExternal — признак внешнего провайдера с учётом значения по умолчанию.
func (p Provider) IsExternal() bool { return p.External == nil || *p.External }

// Application — зарегистрированное приложение (5.4).
type Application struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Env      string `yaml:"env"`
	Provider string `yaml:"provider"`
	// Models — разрешённые модели провайдера; Aliases — имя для приложения → модель.
	Models     []string          `yaml:"models"`
	Aliases    map[string]string `yaml:"aliases"`
	Policy     string            `yaml:"policy"`
	PolicyMode string            `yaml:"policy_mode"`
	FailMode   string            `yaml:"fail_mode"`
	Storage    string            `yaml:"storage"`
	// UserFrom — откуда брать идентификатор конечного пользователя: header
	// (X-AISec-User), field (поле user запроса) или none.
	UserFrom string   `yaml:"user_from"`
	Quotas   Quotas   `yaml:"quotas"`
	Keys     []AppKey `yaml:"keys"`
}

// Quotas — лимиты приложения (5.2, quota). Ноль — без лимита.
type Quotas struct {
	RequestsPerMinute        int `yaml:"requests_per_minute"`
	RequestsPerMinutePerUser int `yaml:"requests_per_minute_per_user"`
	TokensPerMinute          int `yaml:"tokens_per_minute"`
	TokensPerDay             int `yaml:"tokens_per_day"`
	MaxMessages              int `yaml:"max_messages"`
	MaxTokens                int `yaml:"max_tokens"`
}

// AppKey — ключ приложения: только префикс и SHA-256 (ИАФ.8).
type AppKey struct {
	Prefix       string   `yaml:"prefix"`
	SHA256       string   `yaml:"sha256"`
	Expires      string   `yaml:"expires"`
	Revoked      bool     `yaml:"revoked"`
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
}

// Значения перечислимых полей.
var (
	envs           = map[string]bool{"prod": true, "test": true}
	modes          = map[string]bool{"monitor": true, "enforce": true}
	failModes      = map[string]bool{"fail_open": true, "fail_closed": true}
	storages       = map[string]bool{"none": true, "masked": true}
	userFrom       = map[string]bool{"header": true, "field": true, "none": true}
	provTypes      = map[string]bool{ProviderOpenAI: true, ProviderGigaChat: true, ProviderYandexGPT: true}
	gigaChatScopes = map[string]bool{"GIGACHAT_API_PERS": true, "GIGACHAT_API_B2B": true, "GIGACHAT_API_CORP": true}
	idRe           = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	prefixRe       = regexp.MustCompile(`^aisec_[a-z0-9]{8}$`)
	sha256Re       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	modelRe        = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
)

// ParseGatewayFile разбирает и проверяет файл конфигурации.
func ParseGatewayFile(r io.Reader) (*GatewayFile, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxGatewayFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxGatewayFile {
		return nil, fmt.Errorf("файл конфигурации больше %d байт", MaxGatewayFile)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f GatewayFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("разбор конфигурации: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("разбор конфигурации: ожидается один YAML-документ")
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// LoadGatewayFile читает файл конфигурации. Секретов в нём нет, но по нему
// принимаются решения о доступе, поэтому файл, который могут изменить
// группа или остальные пользователи, не принимается.
func LoadGatewayFile(path string) (*GatewayFile, error) {
	f, err := os.Open(path) //nolint:gosec // G304: путь задаёт администратор флагом -config
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // файл только читается; ошибка закрытия не важна
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: не обычный файл", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s: файл конфигурации доступен на запись группе или остальным (права %o)", path, info.Mode().Perm())
	}
	// Каталог, в который могут писать другие, позволил бы подменить файл
	// переименованием. Владелец файла не проверяется: для этого нужен
	// syscall, запрещённый в серверных компонентах (ADR-0004); он задаётся
	// при установке (этапы 3 и 6).
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if dir.Mode().Perm()&0o022 != 0 && dir.Mode()&os.ModeSticky == 0 {
		return nil, fmt.Errorf("%s: каталог файла конфигурации доступен на запись группе или остальным (права %o)", filepath.Dir(path), dir.Mode().Perm())
	}
	return ParseGatewayFile(f)
}

func (f *GatewayFile) validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if f.SchemaVersion != 1 {
		add("schema_version: ожидается 1")
	}
	// На этапе 1 файл JSONL — единственный приёмник событий, без него
	// неудачные попытки входа (DM-38) нигде не были бы видны.
	if f.Gateway.EventsFile == "" {
		add("gateway.events_file: обязательный параметр")
	}
	providers := map[string]Provider{}
	for i, p := range f.Providers {
		at := fmt.Sprintf("providers[%d] (%s)", i, p.ID)
		if !idRe.MatchString(p.ID) {
			add("%s: id — строчные латинские буквы, цифры и дефис", at)
		}
		if _, dup := providers[p.ID]; dup {
			add("%s: провайдер указан дважды", at)
		}
		providers[p.ID] = p
		if !provTypes[p.Type] {
			add("%s: type — openai, gigachat или yandexgpt", at)
		}
		if _, err := ParseUpstreamURL(p.BaseURL); err != nil {
			add("%s: base_url: %v", at, err)
		}
		if p.CAFile == "" {
			add("%s: нужен ca_file — корневые сертификаты провайдера", at)
		}
		if p.SystemRoots {
			add("%s: system_roots не поддерживается; укажите файл системного хранилища в ca_file явно", at)
		}
		for _, d := range []struct {
			name string
			v    Duration
		}{{"connect_timeout", p.ConnectTimeout}, {"header_timeout", p.HeaderTimeout},
			{"response_timeout", p.ResponseTimeout}, {"stream_idle_timeout", p.StreamIdleTimeout}} {
			if d.v < 0 || time.Duration(d.v) > MaxUpstreamTimeout {
				add("%s: %s — от 0 до %s (0 — по умолчанию)", at, d.name, MaxUpstreamTimeout)
			}
		}
		switch p.Type {
		case ProviderGigaChat:
			if p.KeyFile == "" || p.Scope == "" {
				add("%s: для GigaChat нужны key_file (ключ авторизации) и scope", at)
			} else if !gigaChatScopes[p.Scope] {
				add("%s: scope — GIGACHAT_API_PERS, GIGACHAT_API_B2B или GIGACHAT_API_CORP", at)
			}
			if p.AuthURL != "" {
				if _, err := ParseUpstreamURL(p.AuthURL); err != nil {
					add("%s: auth_url: %v", at, err)
				}
			}
		case ProviderYandexGPT:
			if p.KeyFile == "" || p.FolderID == "" {
				add("%s: для YandexGPT нужны key_file и folder_id", at)
			}
		}
	}
	appIDs := map[string]bool{}
	prefixes := map[string]string{}
	for i, a := range f.Applications {
		at := fmt.Sprintf("applications[%d] (%s)", i, a.ID)
		if !idRe.MatchString(a.ID) {
			add("%s: id — строчные латинские буквы, цифры и дефис", at)
		}
		if appIDs[a.ID] {
			add("%s: приложение указано дважды", at)
		}
		appIDs[a.ID] = true
		if _, ok := providers[a.Provider]; !ok {
			add("%s: провайдер %q не описан в providers", at, a.Provider)
		}
		if len(a.Models) == 0 {
			add("%s: нужен хотя бы один разрешённый model (DM-33)", at)
		}
		allowed := map[string]bool{}
		for _, m := range a.Models {
			if !modelRe.MatchString(m) {
				add("%s: недопустимое имя модели %q", at, m)
			}
			allowed[m] = true
		}
		for alias, m := range a.Aliases {
			if !modelRe.MatchString(alias) || !allowed[m] {
				add("%s: псевдоним %q должен указывать на разрешённую модель", at, alias)
			}
		}
		if !idRe.MatchString(a.Policy) {
			add("%s: нужна политика (policy)", at)
		}
		check := func(field, v string, set map[string]bool) {
			if !set[v] {
				add("%s: недопустимое значение %s %q", at, field, v)
			}
		}
		check("env", a.Env, envs)
		check("policy_mode", a.PolicyMode, modes)
		check("fail_mode", a.FailMode, failModes)
		if a.Storage == "full" {
			add("%s: storage full недоступен до шифрования при хранении (этап 2, ЗИ.1)", at)
		} else {
			check("storage", a.Storage, storages)
		}
		check("user_from", a.UserFrom, userFrom)
		q := a.Quotas
		for name, v := range map[string]int{"requests_per_minute": q.RequestsPerMinute, "requests_per_minute_per_user": q.RequestsPerMinutePerUser,
			"tokens_per_minute": q.TokensPerMinute, "tokens_per_day": q.TokensPerDay, "max_messages": q.MaxMessages, "max_tokens": q.MaxTokens} {
			if v < 0 || v > 1_000_000_000 {
				add("%s: quotas.%s — от 0 до 10^9", at, name)
			}
		}
		if len(a.Keys) == 0 {
			add("%s: нужен хотя бы один ключ приложения", at)
		}
		for j, k := range a.Keys {
			kat := fmt.Sprintf("%s.keys[%d]", at, j)
			if !prefixRe.MatchString(k.Prefix) {
				add("%s: prefix — aisec_ и 8 символов [a-z0-9]", kat)
			}
			if owner, dup := prefixes[k.Prefix]; dup {
				add("%s: префикс %s уже используется (%s)", kat, k.Prefix, owner)
			}
			prefixes[k.Prefix] = a.ID
			if !sha256Re.MatchString(k.SHA256) {
				add("%s: sha256 — 64 шестнадцатеричные цифры (выдаёт aisec-cli app-key)", kat)
			}
			if k.Expires != "" {
				if _, err := time.Parse(time.DateOnly, k.Expires); err != nil {
					add("%s: expires — ГГГГ-ММ-ДД", kat)
				}
			}
			for _, c := range k.AllowedCIDRs {
				p, err := netip.ParsePrefix(c)
				switch {
				case err != nil:
					add("%s: allowed_cidrs: %q — подсеть вида 10.0.0.0/8", kat, c)
				case p.Addr().Is4In6():
					// Адрес клиента IPv4 сравнивается в обычной записи; подсеть
					// ::ffff:a.b.c.d/n ему никогда не соответствовала бы.
					add("%s: allowed_cidrs: %q — укажите подсеть IPv4 в обычной записи", kat, c)
				case p.Masked() != p:
					add("%s: allowed_cidrs: %q — адрес подсети с ненулевыми битами узла, имелось в виду %s?", kat, c, p.Masked())
				}
			}
		}
	}
	if len(f.Applications) == 0 {
		add("нет ни одного приложения")
	}
	return errors.Join(errs...)
}
