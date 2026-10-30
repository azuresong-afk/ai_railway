package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Разделы формата версии 2 (задача 5.8 этапа 5, дополнение ADR-0017):
// настройки этапов 3 и 4. Этап 3 — каналы уведомлений, правила оповещений,
// расписания отчётов, цены моделей и бюджеты приложений, инструкции
// реагирования, сертификат заказчика для адреса шлюза. Этап 4 — вход через
// OIDC и LDAP с сопоставлением групп, эталоны системных промптов, доступ к
// моделям по группам, MCP-серверы, агенты, инструменты с одобрениями,
// привязка ключей к агентам, исключения теневого ИИ, лицензия, ручные
// отметки соответствия, сроки хранения и режим квот. Данные (события,
// инциденты, журнал аудита, очереди), служебные базы и ключи установки в
// копию не входят. Секреты — шифротексты ключа секретов копии.

// NotifyChannel — канал уведомлений; Secret — шифротекст ключа секретов
// копии (пароль SMTP, адрес и ключ подписи webhook одним JSON).
type NotifyChannel struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Type         string          `json:"type"`
	Enabled      bool            `json:"enabled"`
	MinSeverity  string          `json:"min_severity"`
	Settings     json.RawMessage `json:"settings"`
	SecretFields []string        `json:"secret_fields"`
	Secret       []byte          `json:"secret"`
	AuditStream  bool            `json:"audit_stream"`
	Version      int             `json:"version"`
	CreatedAt    time.Time       `json:"created_at"`
	CreatedBy    string          `json:"created_by"`
	UpdatedAt    time.Time       `json:"updated_at"`
	UpdatedBy    string          `json:"updated_by"`
}

// AlertRule — правило оповещений. Встроенное (BuiltinKey) создаёт сервер:
// из копии переносятся его настройки, и только в пустую установку.
type AlertRule struct {
	ID              string          `json:"id"`
	BuiltinKey      *string         `json:"builtin_key"`
	Kind            string          `json:"kind"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Enabled         bool            `json:"enabled"`
	Severity        string          `json:"severity"`
	Condition       json.RawMessage `json:"condition"`
	GroupBy         []string        `json:"group_by"`
	SuppressMinutes int             `json:"suppress_minutes"`
	GroupMinutes    int             `json:"group_minutes"`
	Recipients      json.RawMessage `json:"recipients"`
	Version         int             `json:"version"`
	CreatedAt       time.Time       `json:"created_at"`
	CreatedBy       string          `json:"created_by"`
	UpdatedAt       time.Time       `json:"updated_at"`
	UpdatedBy       string          `json:"updated_by"`
}

// ReportSchedule — расписание рассылки отчётов.
type ReportSchedule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Report           string     `json:"report"`
	Frequency        string     `json:"frequency"`
	Weekday          *int16     `json:"weekday"`
	Day              *int16     `json:"day"`
	AtTime           string     `json:"at_time"`
	Format           string     `json:"format"`
	ChannelID        string     `json:"channel_id"`
	Enabled          bool       `json:"enabled"`
	NextRunAt        time.Time  `json:"next_run_at"`
	LastRunAt        *time.Time `json:"last_run_at"`
	ScopeIncidents   bool       `json:"scope_incidents"`
	ScopeAlerts      bool       `json:"scope_alerts"`
	ScopeBudgets     bool       `json:"scope_budgets"`
	ScopeCompliance  bool       `json:"scope_compliance"`
	RecipientUserIDs []string   `json:"recipient_user_ids"`
	Version          int        `json:"version"`
	CreatedAt        time.Time  `json:"created_at"`
	CreatedBy        string     `json:"created_by"`
	UpdatedAt        time.Time  `json:"updated_at"`
	UpdatedBy        string     `json:"updated_by"`
}

// ModelPrice — цена модели провайдера.
type ModelPrice struct {
	ID          string    `json:"id"`
	ProviderID  string    `json:"provider_id"`
	Model       string    `json:"model"`
	InputPrice  int64     `json:"input_price"`
	OutputPrice int64     `json:"output_price"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by"`
}

// AppBudget — месячный бюджет приложения.
type AppBudget struct {
	Mode         string    `json:"mode"`
	MonthlyLimit int64     `json:"monthly_limit"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
	UpdatedAt    time.Time `json:"updated_at"`
	UpdatedBy    string    `json:"updated_by"`
}

// PromptBaseline — эталон системного промпта приложения; Text —
// шифротекст ключа секретов копии.
type PromptBaseline struct {
	Mode      string    `json:"mode"`
	Hash      string    `json:"hash"`
	TextBytes int       `json:"text_bytes"`
	Text      []byte    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// AppUserAccess — доступ к моделям приложения по группам пользователей.
type AppUserAccess struct {
	Mode          string          `json:"mode"`
	Issuer        string          `json:"issuer"`
	Audience      string          `json:"audience"`
	GroupsClaim   string          `json:"groups_claim"`
	LeewaySeconds int             `json:"leeway_seconds"`
	ModelGroups   json.RawMessage `json:"model_groups"`
	UpdatedAt     time.Time       `json:"updated_at"`
	UpdatedBy     string          `json:"updated_by"`
}

// IncidentInstruction — версия инструкции реагирования категории.
type IncidentInstruction struct {
	Category  string    `json:"category"`
	Version   int       `json:"version"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// GatewayTLS — сертификат заказчика для адреса шлюза; Key — шифротекст
// закрытого ключа ключом секретов копии.
type GatewayTLS struct {
	Host        string    `json:"host"`
	ChainPEM    string    `json:"chain_pem"`
	ChainLen    int       `json:"chain_len"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DNSNames    []string  `json:"dns_names"`
	IPAddresses []string  `json:"ip_addresses"`
	CertKeyAlg  string    `json:"cert_key_alg"`
	Key         []byte    `json:"key"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by"`
}

// GroupRole — сопоставление группы IdP или каталога роли.
type GroupRole struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

// OIDCSettings — вход через OIDC; ClientSecret — шифротекст ключа
// секретов копии.
type OIDCSettings struct {
	Enabled      bool        `json:"enabled"`
	DisplayName  string      `json:"display_name"`
	Issuer       string      `json:"issuer"`
	ClientID     string      `json:"client_id"`
	ClientSecret []byte      `json:"client_secret"`
	ConsoleURL   string      `json:"console_url"`
	CAPEM        string      `json:"ca_pem"`
	Scopes       []string    `json:"scopes"`
	GroupsClaim  string      `json:"groups_claim"`
	RequiredACR  []string    `json:"required_acr"`
	RequiredAMR  []string    `json:"required_amr"`
	Version      int         `json:"version"`
	UpdatedAt    time.Time   `json:"updated_at"`
	UpdatedBy    string      `json:"updated_by"`
	GroupRoles   []GroupRole `json:"group_roles"`
}

// LDAPSettings — вход через каталог LDAP; BindPassword — шифротекст
// пароля сервисной записи ключом секретов копии.
type LDAPSettings struct {
	Enabled          bool        `json:"enabled"`
	URL              string      `json:"url"`
	CAPEM            string      `json:"ca_pem"`
	BindDN           string      `json:"bind_dn"`
	BindPassword     []byte      `json:"bind_password"`
	UserBaseDN       string      `json:"user_base_dn"`
	UserFilter       string      `json:"user_filter"`
	IDAttribute      string      `json:"id_attribute"`
	DisplayAttribute string      `json:"display_attribute"`
	GroupMode        string      `json:"group_mode"`
	GroupBaseDN      string      `json:"group_base_dn"`
	Version          int         `json:"version"`
	UpdatedAt        time.Time   `json:"updated_at"`
	UpdatedBy        string      `json:"updated_by"`
	GroupRoles       []GroupRole `json:"group_roles"`
}

// MCPServer — MCP-сервер; Credential — шифротекст ключа секретов копии.
type MCPServer struct {
	ID              string     `json:"id"`
	Slug            string     `json:"slug"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	CAPEM           string     `json:"ca_pem"`
	AuthHeader      *string    `json:"auth_header"`
	Credential      []byte     `json:"credential"`
	CredentialSetAt *time.Time `json:"credential_set_at"`
	External        bool       `json:"external"`
	InsecureHTTP    bool       `json:"insecure_http"`
	CallTimeoutS    int        `json:"call_timeout_s"`
	Versions        []string   `json:"versions"`
	CreatedAt       time.Time  `json:"created_at"`
	CreatedBy       string     `json:"created_by"`
	UpdatedAt       time.Time  `json:"updated_at"`
	UpdatedBy       string     `json:"updated_by"`
}

// Agent — агент ИИ приложения со списком MCP-серверов.
type Agent struct {
	ID          string    `json:"id"`
	AppID       string    `json:"app_id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Owner       string    `json:"owner"`
	Status      string    `json:"status"`
	ServerIDs   []string  `json:"server_ids"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by"`
}

// AgentTool — инструмент MCP-сервера или функция агента с одобренным
// описанием.
type AgentTool struct {
	ID                 string     `json:"id"`
	ServerID           *string    `json:"server_id"`
	AgentID            *string    `json:"agent_id"`
	Name               string     `json:"name"`
	Descriptor         string     `json:"descriptor"`
	DescriptorHash     []byte     `json:"descriptor_hash"`
	ApprovedDescriptor *string    `json:"approved_descriptor"`
	ApprovedHash       []byte     `json:"approved_hash"`
	HashAlg            string     `json:"hash_alg"`
	Risk               string     `json:"risk"`
	Status             string     `json:"status"`
	FirstSeen          time.Time  `json:"first_seen"`
	LastSeen           time.Time  `json:"last_seen"`
	DecidedBy          *string    `json:"decided_by"`
	DecidedAt          *time.Time `json:"decided_at"`
	Comment            string     `json:"comment"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// ShadowAIExclusion — исключение теневого ИИ (сервис или псевдоним
// пользователя).
type ShadowAIExclusion struct {
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// License — загруженный файл лицензии. Подпись проверяется при
// восстановлении так же, как при загрузке (ADR-0026).
type License struct {
	Number   int64     `json:"number"`
	File     []byte    `json:"file"`
	LoadedAt time.Time `json:"loaded_at"`
	LoadedBy string    `json:"loaded_by"`
}

// ServiceDB — сохранённая служебная база (ADR-0028): подписанный файл
// текущей или предыдущей версии вида и сведения о загрузке. Раздел
// необязательный (остатки волны A этапа 5): копия выпуска до него
// восстанавливается без баз. Сведения о версии при восстановлении берутся
// из проверенного файла, а не из этих полей.
type ServiceDB struct {
	Kind       string    `json:"kind"`
	Slot       string    `json:"slot"`
	Version    uint64    `json:"version"`
	File       []byte    `json:"file"`
	UploadedAt time.Time `json:"uploaded_at"`
	UploadedBy string    `json:"uploaded_by"`
}

// ComplianceMark — ручная отметка соответствия требованию.
type ComplianceMark struct {
	RequirementID string     `json:"requirement_id"`
	Status        string     `json:"status"`
	Comment       string     `json:"comment"`
	Document      string     `json:"document"`
	ReviewBy      *time.Time `json:"review_by"`
	SetAt         time.Time  `json:"set_at"`
	SetBy         string     `json:"set_by"`
}

// Пределы разделов версии 2: с запасом выше разумной установки.
const (
	maxChannels     = 1000
	maxAlertRules   = 10_000
	maxSchedules    = 1000
	maxPrices       = 100_000
	maxInstructions = 10_000
	maxGroupRoles   = 1000
	maxMCPServers   = 1000
	maxAgents       = 10_000
	maxAgentServers = 1000
	maxTools        = 100_000
	maxExclusions   = 100_000
	maxLicenses     = 1000
	// maxServiceDBs — видов служебных баз по две версии; maxServiceDBFile —
	// предел файла (CHECK миграции 0068).
	maxServiceDBs    = 64
	maxServiceDBFile = 4 << 20
	// maxServiceDBVersion — предел номера версии (CHECK миграции 0068).
	maxServiceDBVersion = 1<<53 - 1
	maxLicenseFile      = 16 << 10
	maxMarks            = 10_000
	maxBaseline         = 160 << 10
)

// Виды секретов разделов версии 2 (входят в AAD шифротекста копии).
const (
	secretChannel    = "notify_channels.secret"
	secretBaseline   = "prompt_baselines.text"
	secretMCP        = "mcp_servers.credential"      //nolint:gosec // G101: вид секрета для AAD, а не секрет
	secretGatewayTLS = "gateway_tls.key"             //nolint:gosec // G101: вид секрета для AAD, а не секрет
	secretOIDC       = "oidc_settings.client_secret" //nolint:gosec // G101: вид секрета для AAD, а не секрет
	secretLDAP       = "ldap_settings.bind_password" //nolint:gosec // G101: вид секрета для AAD, а не секрет
)

// hasV2 — в содержимом есть разделы версии 2.
func (s *Snapshot) hasV2() bool {
	if len(s.Channels)+len(s.AlertRules)+len(s.ReportSchedules)+len(s.ModelPrices)+len(s.Instructions)+
		len(s.MCPServers)+len(s.Agents)+len(s.AgentTools)+len(s.ShadowAIExclusions)+len(s.Licenses)+len(s.ComplianceMarks)+
		len(s.ServiceDBs) > 0 ||
		s.GatewayTLS != nil || s.OIDC != nil || s.LDAP != nil || s.LicenseClock != nil {
		return true
	}
	if i := s.Settings.Install; i != nil && (i.AlertRetentionDays != nil || i.IncidentRetentionDays != nil ||
		i.ShadowAIRetentionDays != nil || i.QuotaMode != nil) {
		return true
	}
	for _, u := range s.Users {
		if u.Email != "" {
			return true
		}
	}
	for _, a := range s.Applications {
		if a.Budget != nil || a.Baseline != nil || a.UserAccess != nil {
			return true
		}
		for _, k := range a.Keys {
			if k.AgentID != nil {
				return true
			}
		}
	}
	return false
}

// validateV2 — строгая проверка разделов версии 2: ID, повторы, пределы и
// согласованность секретов. Ссылки на объекты, которых нет в копии, —
// не ошибка формата: такие объекты пропускаются при восстановлении
// (resolve) со строкой в отчёте.
func (s *Snapshot) validateV2() error {
	switch {
	case len(s.Channels) > maxChannels, len(s.AlertRules) > maxAlertRules, len(s.ReportSchedules) > maxSchedules,
		len(s.ModelPrices) > maxPrices, len(s.Instructions) > maxInstructions, len(s.MCPServers) > maxMCPServers,
		len(s.Agents) > maxAgents, len(s.AgentTools) > maxTools, len(s.ShadowAIExclusions) > maxExclusions,
		len(s.Licenses) > maxLicenses, len(s.ComplianceMarks) > maxMarks, len(s.ServiceDBs) > maxServiceDBs:
		return errors.New("объектов больше предела")
	}
	channels, cnames := ids{}, ids{}
	for _, c := range s.Channels {
		if err := checkUUID("канал", c.ID); err != nil {
			return err
		}
		if err := channels.add("канал", c.ID); err != nil {
			return err
		}
		if err := cnames.add("имя канала", c.Name); err != nil {
			return err
		}
		if (c.Secret == nil) != (len(c.SecretFields) == 0) || len(c.Secret) > maxSecret {
			return fmt.Errorf("канал %s: секрет не согласован со списком полей", c.Name)
		}
	}
	rules, builtins := ids{}, ids{}
	for _, r := range s.AlertRules {
		if err := checkUUID("правило оповещений", r.ID); err != nil {
			return err
		}
		if err := rules.add("правило оповещений", r.ID); err != nil {
			return err
		}
		if r.BuiltinKey != nil {
			if err := builtins.add("встроенное правило", *r.BuiltinKey); err != nil {
				return err
			}
		}
	}
	schedules, snames := ids{}, ids{}
	for _, r := range s.ReportSchedules {
		if err := checkUUID("расписание отчёта", r.ID); err != nil {
			return err
		}
		if err := schedules.add("расписание отчёта", r.ID); err != nil {
			return err
		}
		if err := snames.add("имя расписания", r.Name); err != nil {
			return err
		}
	}
	prices, pmodels := ids{}, ids{}
	for _, p := range s.ModelPrices {
		if err := checkUUID("цена модели", p.ID); err != nil {
			return err
		}
		if err := prices.add("цена модели", p.ID); err != nil {
			return err
		}
		if err := pmodels.add("цена модели провайдера", p.ProviderID+"|"+p.Model); err != nil {
			return err
		}
	}
	instr := ids{}
	for _, i := range s.Instructions {
		if err := instr.add("инструкция реагирования", fmt.Sprintf("%s|%d", i.Category, i.Version)); err != nil {
			return err
		}
	}
	if t := s.GatewayTLS; t != nil && (len(t.Key) == 0 || len(t.Key) > maxSecret) {
		return errors.New("сертификат шлюза: нет закрытого ключа")
	}
	if o := s.OIDC; o != nil {
		if len(o.ClientSecret) == 0 || len(o.ClientSecret) > maxSecret {
			return errors.New("OIDC: нет секрета клиента")
		}
		if err := checkGroupRoles("OIDC", o.GroupRoles); err != nil {
			return err
		}
	}
	if l := s.LDAP; l != nil {
		if len(l.BindPassword) == 0 || len(l.BindPassword) > maxSecret {
			return errors.New("LDAP: нет пароля сервисной записи")
		}
		if err := checkGroupRoles("LDAP", l.GroupRoles); err != nil {
			return err
		}
	}
	servers, sslugs := ids{}, ids{}
	for _, m := range s.MCPServers {
		if err := checkUUID("MCP-сервер", m.ID); err != nil {
			return err
		}
		if err := servers.add("MCP-сервер", m.ID); err != nil {
			return err
		}
		if err := sslugs.add("slug MCP-сервера", m.Slug); err != nil {
			return err
		}
		if (m.Credential == nil) != (m.CredentialSetAt == nil) || len(m.Credential) > maxSecret {
			return fmt.Errorf("MCP-сервер %s: учётные данные без отметки времени или наоборот", m.Slug)
		}
	}
	agents, aslugs := ids{}, ids{}
	for _, a := range s.Agents {
		if err := checkUUID("агент", a.ID); err != nil {
			return err
		}
		if err := agents.add("агент", a.ID); err != nil {
			return err
		}
		if err := aslugs.add("slug агента приложения", a.AppID+"|"+a.Slug); err != nil {
			return err
		}
		if len(a.ServerIDs) > maxAgentServers {
			return fmt.Errorf("агент %s: MCP-серверов больше предела", a.Slug)
		}
		links := ids{}
		for _, id := range a.ServerIDs {
			if err := links.add("MCP-сервер агента "+a.Slug, id); err != nil {
				return err
			}
		}
	}
	tools, tnames := ids{}, ids{}
	for _, t := range s.AgentTools {
		if err := checkUUID("инструмент", t.ID); err != nil {
			return err
		}
		if err := tools.add("инструмент", t.ID); err != nil {
			return err
		}
		if (t.ServerID == nil) == (t.AgentID == nil) {
			return fmt.Errorf("инструмент %s: владелец — ровно один из сервера и агента", t.Name)
		}
		owner := ""
		if t.ServerID != nil {
			owner = "s|" + *t.ServerID
		} else {
			owner = "a|" + *t.AgentID
		}
		if err := tnames.add("имя инструмента", owner+"|"+t.Name); err != nil {
			return err
		}
	}
	excl := ids{}
	for _, e := range s.ShadowAIExclusions {
		if err := excl.add("исключение теневого ИИ", e.Kind+"|"+e.Value); err != nil {
			return err
		}
	}
	lics := ids{}
	for _, l := range s.Licenses {
		if err := lics.add("лицензия", fmt.Sprint(l.Number)); err != nil {
			return err
		}
		if len(l.File) == 0 || len(l.File) > maxLicenseFile {
			return fmt.Errorf("лицензия %d: неверная длина файла", l.Number)
		}
	}
	if err := s.validateServiceDBs(); err != nil {
		return err
	}
	marks := ids{}
	for _, m := range s.ComplianceMarks {
		if err := marks.add("отметка соответствия", m.RequirementID); err != nil {
			return err
		}
	}
	appIDs := ids{}
	for _, a := range s.Applications {
		appIDs[a.ID] = struct{}{}
		if b := a.Baseline; b != nil && (len(b.Text) == 0 || len(b.Text) > maxBaseline) {
			return fmt.Errorf("приложение %s: неверная длина эталона промпта", a.Slug)
		}
		for _, k := range a.Keys {
			if k.AgentID != nil {
				if !k.AgentBound {
					return fmt.Errorf("ключ %s: привязка к агенту без отметки", k.Prefix)
				}
				if err := checkUUID("агент ключа", *k.AgentID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkGroupRoles(what string, gr []GroupRole) error {
	if len(gr) > maxGroupRoles {
		return fmt.Errorf("%s: сопоставлений групп больше предела", what)
	}
	seen := ids{}
	for _, g := range gr {
		if err := seen.add(what+": группа", g.Group); err != nil {
			return err
		}
	}
	return nil
}

// recipients — получатели правила оповещений (internal/alerting.Recipients).
type recipients struct {
	Roles []string `json:"roles"`
	Users []string `json:"users"`
}

// resolve отбирает объекты разделов версии 2, которые можно восстановить:
// объект со ссылкой на объект, которого нет в копии (или который сам
// пропущен), пропускается со строкой отчёта, восстановление из-за него не
// падает. Исходный снимок не меняется.
func (s *Snapshot) resolve() (*Snapshot, []string) {
	r := *s
	var lines []string
	skip := func(format string, a ...any) { lines = append(lines, fmt.Sprintf(format, a...)) }
	users, roles, apps, providers := ids{}, ids{}, map[string]string{}, ids{}
	for _, u := range s.Users {
		users[u.ID] = struct{}{}
	}
	for _, x := range s.Roles {
		roles[x.ID] = struct{}{}
	}
	roleKnown := func(id string) bool {
		_, ok := roles[id]
		return ok || auth.Role(id).Builtin()
	}
	for _, a := range s.Applications {
		apps[a.ID] = a.Slug
	}
	for _, p := range s.Providers {
		providers[p.ID] = struct{}{}
	}
	channels := ids{}
	for _, c := range s.Channels {
		channels[c.ID] = struct{}{}
	}

	r.AlertRules = nil
	for _, a := range s.AlertRules {
		var rc recipients
		if err := strictJSON(a.Recipients, &rc); err != nil {
			skip("правило оповещений «%s»: получатели не разбираются", a.Name)
			continue
		}
		if i := slices.IndexFunc(rc.Users, func(id string) bool { _, ok := users[id]; return !ok }); i >= 0 {
			skip("правило оповещений «%s»: получателя-пользователя %s нет в копии", a.Name, truncate(rc.Users[i]))
			continue
		}
		if i := slices.IndexFunc(rc.Roles, func(id string) bool { return !roleKnown(id) }); i >= 0 {
			skip("правило оповещений «%s»: роли-получателя %q нет", a.Name, truncate(rc.Roles[i]))
			continue
		}
		r.AlertRules = append(r.AlertRules, a)
	}
	r.ReportSchedules = nil
	for _, x := range s.ReportSchedules {
		if _, ok := channels[x.ChannelID]; !ok {
			skip("расписание отчёта «%s»: канала %s нет в копии", x.Name, x.ChannelID)
			continue
		}
		if i := slices.IndexFunc(x.RecipientUserIDs, func(id string) bool { _, ok := users[id]; return !ok }); i >= 0 {
			skip("расписание отчёта «%s»: получателя %s нет в копии", x.Name, truncate(x.RecipientUserIDs[i]))
			continue
		}
		r.ReportSchedules = append(r.ReportSchedules, x)
	}
	r.ModelPrices = nil
	for _, p := range s.ModelPrices {
		if _, ok := providers[p.ProviderID]; !ok {
			skip("цена модели %s: провайдера %s нет в копии", p.Model, p.ProviderID)
			continue
		}
		r.ModelPrices = append(r.ModelPrices, p)
	}
	servers := ids{}
	for _, m := range s.MCPServers {
		servers[m.ID] = struct{}{}
	}
	r.Agents = nil
	agents := ids{}
	for _, a := range s.Agents {
		if _, ok := apps[a.AppID]; !ok {
			skip("агент %s: приложения %s нет в копии", a.Slug, a.AppID)
			continue
		}
		var keep []string
		for _, id := range a.ServerIDs {
			if _, ok := servers[id]; ok {
				keep = append(keep, id)
			} else {
				skip("агент %s: MCP-сервера %s нет в копии — сервер не привязан", a.Slug, id)
			}
		}
		a.ServerIDs = keep
		agents[a.ID] = struct{}{}
		r.Agents = append(r.Agents, a)
	}
	r.AgentTools = nil
	for _, t := range s.AgentTools {
		switch {
		case t.ServerID != nil:
			if _, ok := servers[*t.ServerID]; !ok {
				skip("инструмент %s: MCP-сервера %s нет в копии", t.Name, *t.ServerID)
				continue
			}
		default:
			if _, ok := agents[*t.AgentID]; !ok {
				skip("инструмент %s: агента %s нет в копии", t.Name, *t.AgentID)
				continue
			}
		}
		r.AgentTools = append(r.AgentTools, t)
	}
	groups := func(what string, in []GroupRole) []GroupRole {
		var out []GroupRole
		for _, g := range in {
			if !roleKnown(g.Role) {
				skip("%s: группа «%s» — роли %q нет", what, truncate(g.Group), truncate(g.Role))
				continue
			}
			out = append(out, g)
		}
		return out
	}
	// Исключение по пользователю — псевдоним ключа HMAC: без ключа в копии
	// оно ни с кем не совпадёт (ErrNoUserKey модуля теневого ИИ).
	r.ShadowAIExclusions = nil
	for _, e := range s.ShadowAIExclusions {
		if e.Kind == "user" && s.UserHMACKey == nil {
			skip("исключение теневого ИИ по пользователю: в копии нет ключа псевдонимов")
			continue
		}
		r.ShadowAIExclusions = append(r.ShadowAIExclusions, e)
	}
	if o := s.OIDC; o != nil {
		if _, ok := users[o.UpdatedBy]; !ok {
			skip("вход через OIDC: изменившего настройки пользователя %s нет в копии", o.UpdatedBy)
			r.OIDC = nil
		} else {
			x := *o
			x.GroupRoles = groups("вход через OIDC", o.GroupRoles)
			r.OIDC = &x
		}
	}
	if l := s.LDAP; l != nil {
		if _, ok := users[l.UpdatedBy]; !ok {
			skip("вход через LDAP: изменившего настройки пользователя %s нет в копии", l.UpdatedBy)
			r.LDAP = nil
		} else {
			x := *l
			x.GroupRoles = groups("вход через LDAP", l.GroupRoles)
			r.LDAP = &x
		}
	}
	return &r, lines
}

// withoutSettings — копия без настроек версии 2, которые переносятся только
// в пустую установку: в непустую они не пишутся, и строк о пропуске по ним
// в отчёте быть не должно.
func (s *Snapshot) withoutSettings() *Snapshot {
	r := *s
	r.Instructions, r.GatewayTLS, r.OIDC, r.LDAP = nil, nil, nil, nil
	r.ShadowAIExclusions, r.Licenses, r.LicenseClock, r.ComplianceMarks = nil, nil, nil, nil
	r.AlertRules = nil
	for _, a := range s.AlertRules {
		if a.BuiltinKey == nil {
			r.AlertRules = append(r.AlertRules, a)
		}
	}
	return &r
}

// secretRef — секрет копии: вид, ID строки и место хранения в БД (AAD
// ключа данных, ADR-0007).
type secretRef struct {
	sealed        []byte
	kind, id      string
	table, column string
	what          string
}

// secrets — все секреты копии, которые при восстановлении перешифровываются
// ключом данных новой установки.
func (s *Snapshot) secrets() []secretRef {
	var out []secretRef
	for _, p := range s.Providers {
		if p.Credential != nil {
			out = append(out, secretRef{p.Credential, secretProviderCredential, p.ID, providersTable, credentialColumn, "провайдер " + p.Slug})
		}
	}
	for _, u := range s.Users {
		if u.MFA != nil {
			out = append(out, secretRef{u.MFA.Secret, secretMFA, u.ID, mfaTable, mfaColumn, "второй фактор " + u.Login})
		}
	}
	for _, c := range s.Channels {
		if c.Secret != nil {
			out = append(out, secretRef{c.Secret, secretChannel, c.ID, channelsTable, channelsColumn, "канал " + c.Name})
		}
	}
	for _, a := range s.Applications {
		if a.Baseline != nil {
			out = append(out, secretRef{a.Baseline.Text, secretBaseline, a.ID, baselineTable, baselineColumn, "эталон промпта " + a.Slug})
		}
	}
	for _, m := range s.MCPServers {
		if m.Credential != nil {
			out = append(out, secretRef{m.Credential, secretMCP, m.ID, mcpTable, mcpColumn, "MCP-сервер " + m.Slug})
		}
	}
	if t := s.GatewayTLS; t != nil {
		out = append(out, secretRef{t.Key, secretGatewayTLS, s.OrgID, gatewayTLSTable, gatewayTLSColumn, "сертификат шлюза"})
	}
	if o := s.OIDC; o != nil {
		out = append(out, secretRef{o.ClientSecret, secretOIDC, s.OrgID, oidcTable, oidcColumn, "вход через OIDC"})
	}
	if l := s.LDAP; l != nil {
		out = append(out, secretRef{l.BindPassword, secretLDAP, s.OrgID, ldapTable, ldapColumn, "вход через LDAP"})
	}
	return out
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

// serviceDBKindRe — вид служебной базы (CHECK миграции 0068).
var serviceDBKindRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// validateServiceDBs — вид и слот без повторов, у вида с предыдущей
// версией есть текущая и она старше, длина файла и отметки загрузки в
// пределах схемы.
func (s *Snapshot) validateServiceDBs() error {
	slots := ids{}
	cur := map[string]uint64{}
	for _, b := range s.ServiceDBs {
		if !serviceDBKindRe.MatchString(b.Kind) {
			return fmt.Errorf("служебная база: неверный вид %q", truncate(b.Kind))
		}
		if b.Slot != "current" && b.Slot != "previous" {
			return fmt.Errorf("служебная база %s: неверный слот %q", b.Kind, truncate(b.Slot))
		}
		if err := slots.add("служебная база", b.Kind+"|"+b.Slot); err != nil {
			return err
		}
		if b.Version == 0 || b.Version > maxServiceDBVersion || len(b.File) == 0 || len(b.File) > maxServiceDBFile ||
			b.UploadedBy == "" || len(b.UploadedBy) > 128 || b.UploadedAt.IsZero() {
			return fmt.Errorf("служебная база %s (%s): неверная версия, файл или отметка загрузки", b.Kind, b.Slot)
		}
		if b.Slot == "current" {
			cur[b.Kind] = b.Version
		}
	}
	for _, b := range s.ServiceDBs {
		if b.Slot == "previous" && (cur[b.Kind] == 0 || cur[b.Kind] <= b.Version) {
			return fmt.Errorf("служебная база %s: предыдущая версия %d без текущей или не старше её", b.Kind, b.Version)
		}
	}
	return nil
}
