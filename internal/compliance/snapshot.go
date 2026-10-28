package compliance

import "time"

// Группы сведений снимка. Группа, которую не удалось прочитать, попадает в
// Snapshot.Unavailable: проверки, которым она нужна, не считаются
// выполненными (нет данных — нет доказательства).
const (
	GroupApps       = "apps"
	GroupRoles      = "roles"
	GroupAuditChain = "audit_chain"
	GroupIntegrity  = "integrity"
	GroupAlerts     = "alerts"
	GroupChannels   = "channels"
)

// AppFact — приложение в снимке: только настройки, без содержимого запросов.
type AppFact struct {
	Slug string
	// Env — prod или test.
	Env string
	// PolicyMode — enforce или monitor; пусто — политики нет или она не найдена.
	PolicyMode string
	// InputRules и OutputRules — правила политики, меняющие исход проверки
	// (block, redact, pseudonymize, require_approval), на входе и на выходе.
	InputRules, OutputRules int
	// PIIRules — такие правила детектора pii.ru на входе.
	PIIRules int
	// ToolsBlockUnapproved — политика приложения блокирует неодобренные
	// инструменты агентов.
	ToolsBlockUnapproved bool
	// ExternalProvider — приложение работает через внешнего провайдера.
	ExternalProvider bool
	// Storage — режим хранения содержимого: none, masked или full.
	Storage string
	// Models — число разрешённых моделей; 0 — ограничения нет.
	Models int
	// Quotas — заданные лимиты по именам полей (ТЗ 5.2, quota); 0 — не задан.
	Quotas map[string]int
}

// RoleFact — роль, дающая функции безопасности, в снимке.
type RoleFact struct {
	ID string
	// MFA — второй фактор для роли обязателен.
	MFA   bool
	Users int
}

// ChainFact — последняя проверка цепочки журнала аудита.
type ChainFact struct {
	OK        bool
	CheckedAt time.Time
}

// IntegrityFact — самотест и контроль целостности сервера и шлюзов.
type IntegrityFact struct {
	// ServerOK — последние самотест и контроль целостности сервера успешны.
	ServerOK  bool
	CheckedAt time.Time
	// Gateways и GatewaysOK — активные шлюзы и те из них, чьи проверки успешны.
	Gateways, GatewaysOK int
}

// Snapshot — сведения о конфигурации и состоянии, по которым вычисляются
// статусы. Собирается из сервисов (SystemFacts) и подставляется в тестах.
type Snapshot struct {
	Now time.Time
	// Unavailable — группы, которые не удалось прочитать.
	Unavailable map[string]bool

	Apps []AppFact
	// MFARequiredAll — второй фактор обязателен для всех ролей.
	MFARequiredAll bool
	// PrivilegedRoles — роли с правами функций безопасности.
	PrivilegedRoles []RoleFact
	AuditChain      *ChainFact
	Integrity       *IntegrityFact
	// AlertRulesEnabled — включённые правила оповещений.
	AlertRulesEnabled int
	// ChannelsEnabled — включённые каналы уведомлений.
	ChannelsEnabled int
}

func (s *Snapshot) has(group string) bool { return !s.Unavailable[group] }
