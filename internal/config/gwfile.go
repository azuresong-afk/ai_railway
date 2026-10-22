package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Файл конфигурации шлюза этапа 1 (план этапа 1, Р2): приложения, ключи,
// провайдеры, модели и политики. С этапа 2 эти данные приходят с сервера
// управления подписанным пакетом. Секретов в файле нет: ключи провайдеров — путями к
// файлам, ключи приложений — только SHA-256.

// MaxGatewayFile — предел размера файла конфигурации.
const MaxGatewayFile = 4 << 20

// MaxPolicies — предел числа политик в файле конфигурации.
const MaxPolicies = 64

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
	// Policies — политики заказчика (ТЗ, 5.3). Приложение ссылается на
	// политику отсюда или на шаблон (policy.TemplateIDs). Наличие детекторов
	// проверяет policy.Resolve при запуске конвейера.
	Policies []policy.Spec `yaml:"policies"`
}

// GatewaySection — общие параметры шлюза.
type GatewaySection struct {
	// EventsFile — приёмник-заглушка событий JSONL (этап 1, 5.5): только
	// без сервера управления; с -server события уходят на сервер.
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

// Params — параметры провайдера для общих проверок.
func (p Provider) Params() ProviderParams {
	return ProviderParams{Type: p.Type, BaseURL: p.BaseURL, AuthURL: p.AuthURL, Scope: p.Scope, FolderID: p.FolderID,
		ConnectTimeout: time.Duration(p.ConnectTimeout), HeaderTimeout: time.Duration(p.HeaderTimeout),
		ResponseTimeout: time.Duration(p.ResponseTimeout), StreamIdleTimeout: time.Duration(p.StreamIdleTimeout)}
}

// Application — зарегистрированное приложение (5.4). Policy — ID политики
// из policies или шаблона, пусто — «Базовая защита» (base, решение Р7);
// PolicyMode — режим политики для приложения, пусто — режим самой политики
// (у base — monitor).
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
	UserFrom string `yaml:"user_from"`
	Quotas   Quotas `yaml:"quotas"`
	// Lists — словари и выражения заказчика для детектора lists (5.2);
	// дополняют встроенный список грифов.
	Lists []lists.Spec `yaml:"lists"`
	// ExfilAllowDomains — домены, на которые в ответе модели разрешены
	// изображения и ссылки (детектор output.exfil, DM-11): example.com — сам
	// домен, *.example.com — его поддомены. Пусто — ни на какие.
	ExfilAllowDomains []string `yaml:"exfil_allow_domains"`
	Keys              []AppKey `yaml:"keys"`
}

// Params — параметры приложения для общих проверок.
func (a Application) Params() AppParams {
	return AppParams{Env: a.Env, PolicyMode: a.PolicyMode, FailMode: a.FailMode, Storage: a.Storage, UserFrom: a.UserFrom,
		Models: a.Models, Aliases: a.Aliases, Quotas: a.Quotas, Lists: a.Lists, ExfilAllowDomains: a.ExfilAllowDomains}
}

// Quotas — лимиты приложения (5.2, quota). Ноль — без лимита.
type Quotas struct {
	RequestsPerMinute        int `yaml:"requests_per_minute"`
	RequestsPerMinutePerUser int `yaml:"requests_per_minute_per_user"`
	RequestsPerMinutePerKey  int `yaml:"requests_per_minute_per_key"`
	TokensPerMinute          int `yaml:"tokens_per_minute"`
	TokensPerDay             int `yaml:"tokens_per_day"`
	MaxMessages              int `yaml:"max_messages"`
	MaxTokens                int `yaml:"max_tokens"`
	// MaxInputBytes — суммарный размер текста сообщений запроса, байт.
	MaxInputBytes int `yaml:"max_input_bytes"`
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
	storages       = map[string]bool{"none": true, "masked": true, "full": true}
	userFrom       = map[string]bool{"header": true, "field": true, "none": true}
	provTypes      = map[string]bool{ProviderOpenAI: true, ProviderGigaChat: true, ProviderYandexGPT: true}
	folderRe       = regexp.MustCompile(`^[a-z0-9]{1,50}$`)
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
	f, _, err := ReadGatewayFile(path)
	return f, err
}

// ReadGatewayFile — как LoadGatewayFile, но возвращает и прочитанные байты:
// эталон контроля целостности файла — их хеш (Н37 ревью 2.r4).
func ReadGatewayFile(path string) (*GatewayFile, []byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: путь задаёт администратор флагом -config
	if err != nil {
		return nil, nil, err
	}
	defer f.Close() //nolint:errcheck // файл только читается; ошибка закрытия не важна
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: не обычный файл", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, nil, fmt.Errorf("%s: файл конфигурации доступен на запись группе или остальным (права %o)", path, info.Mode().Perm())
	}
	// Каталог, в который могут писать другие, позволил бы подменить файл
	// переименованием. Владелец файла не проверяется: для этого нужен
	// syscall, запрещённый в серверных компонентах (ADR-0004); он задаётся
	// при установке (этапы 3 и 6).
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, nil, err
	}
	if dir.Mode().Perm()&0o022 != 0 && dir.Mode()&os.ModeSticky == 0 {
		return nil, nil, fmt.Errorf("%s: каталог файла конфигурации доступен на запись группе или остальным (права %o)", filepath.Dir(path), dir.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxGatewayFile+1))
	if err != nil {
		return nil, nil, err
	}
	gf, err := ParseGatewayFile(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	return gf, data, nil
}

// Warnings — допустимые, но опасные настройки, о которых шлюз предупреждает
// при запуске (конфигурация принимается). Сейчас — «Только мониторинг» у
// приложения с внешним провайдером: ПДн и секреты уходят провайдеру как есть
// (ревью 1.17–1.21, п. 15).
func (f *GatewayFile) Warnings() []string {
	external := map[string]bool{}
	for _, p := range f.Providers {
		external[p.ID] = p.IsExternal()
	}
	var out []string
	for _, a := range f.Applications {
		if a.Policy == policy.TemplateMonitorOnly && external[a.Provider] {
			out = append(out, fmt.Sprintf("приложение %s: политика %s с внешним провайдером %s — ПДн и секреты передаются провайдеру без маскирования; для внешнего провайдера выберите %s или %s",
				a.ID, policy.TemplateMonitorOnly, a.Provider, policy.TemplateBase, policy.TemplateExternalPII))
		}
	}
	return out
}

// CheckEventsSink проверяет приёмник событий. С сервером управления
// (withServer) события уходят на сервер по mTLS. Без сервера нужен файл
// JSONL этапа 1 — иначе неудачные попытки входа (DM-38) нигде не были бы
// видны, — а режим full недоступен: полное содержимое хранится только на
// сервере и только зашифрованным (ЗИ.1).
func (f *GatewayFile) CheckEventsSink(withServer bool) error {
	if withServer {
		return nil
	}
	var errs []error
	if f.Gateway.EventsFile == "" {
		errs = append(errs, errors.New("gateway.events_file: обязателен, если сервер управления не задан (-server)"))
	}
	for _, a := range f.Applications {
		if a.Storage == "full" {
			errs = append(errs, fmt.Errorf("приложение %s: storage full — только с сервером управления (-server): содержимое хранится на сервере зашифрованным (ЗИ.1), в файл событий оно не пишется", a.ID))
		}
	}
	return errors.Join(errs...)
}

func (f *GatewayFile) validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if f.SchemaVersion != 1 {
		add("schema_version: ожидается 1")
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
		if err := prefixed(at, p.Params().Check()); err != nil {
			errs = append(errs, err)
		}
		if p.CAFile == "" {
			add("%s: нужен ca_file — корневые сертификаты провайдера", at)
		}
		if p.SystemRoots {
			add("%s: system_roots не поддерживается; укажите файл системного хранилища в ca_file явно", at)
		}
		switch p.Type {
		case ProviderGigaChat:
			if p.KeyFile == "" || p.Scope == "" {
				add("%s: для GigaChat нужны key_file (ключ авторизации) и scope", at)
			}
		case ProviderYandexGPT:
			if p.KeyFile == "" || p.FolderID == "" {
				add("%s: для YandexGPT нужны key_file (API-ключ сервисного аккаунта) и folder_id", at)
			}
		}
	}
	policies := map[string]bool{}
	if len(f.Policies) > MaxPolicies {
		add("policies: не больше %d политик", MaxPolicies)
	}
	for i := range f.Policies {
		p := &f.Policies[i]
		at := fmt.Sprintf("policies[%d] (%s)", i, p.ID)
		if err := p.Validate(); err != nil {
			add("%s: %w", at, err)
		}
		if policy.IsTemplate(p.ID) {
			add("%s: id совпадает с шаблоном политики; выберите другое", at)
		}
		if policies[p.ID] {
			add("%s: политика указана дважды", at)
		}
		policies[p.ID] = true
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
		if a.Policy != "" && !policies[a.Policy] && !policy.IsTemplate(a.Policy) {
			add("%s: политика %q не описана в policies и не является шаблоном", at, a.Policy)
		}
		if err := prefixed(at, a.Params().Check()); err != nil {
			errs = append(errs, err)
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
			if err := prefixed(kat, CheckCIDRs(k.AllowedCIDRs)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(f.Applications) == 0 {
		add("нет ни одного приложения")
	}
	return errors.Join(errs...)
}
