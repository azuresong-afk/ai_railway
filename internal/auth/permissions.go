package auth

import (
	"maps"
	"slices"
	"strings"
)

// Разрешения эндпоинтов консоли (УПД.1, 3). Новое разрешение добавляется
// константой, строкой в permissionCatalog и, если нужно, в права
// предустановленных ролей (builtinRoles); в api/openapi.yaml эндпоинт
// ссылается на него через x-permission.
const (
	// PermSession — любая сессия, в том числе до второго фактора: свои
	// данные, выход и второй фактор (ИАФ.5). Состояние сессии проверяет
	// обработчик. В роль не назначается: его даёт SessionGrants.
	PermSession = "session"
	// PermSelf — смена своего пароля: есть у любой роли, но не до второго
	// фактора. В роль не назначается: его даёт SessionGrants.
	PermSelf       = "self"
	PermSystemRead = "system.read"
	// PermIntegrityVerify — проверка целостности по команде (ОЦЛ.2, задача
	// 2.17): при -integrity-action stop нарушение останавливает сервер.
	PermIntegrityVerify = "integrity.verify"
	// PermSettingsManage — настройки установки: часовой пояс показа и режим
	// хранения по умолчанию (ВРМ.2, ТЗ 5.5; В26 ревью 2.r5). Режим хранения
	// — функция безопасности (DM-40).
	PermSettingsManage   = "settings.manage"
	PermUsersRead        = "users.read"
	PermUsersManage      = "users.manage"
	PermSessionsRead     = "sessions.read"
	PermSessionsManage   = "sessions.manage"
	PermAuthPolicyRead   = "auth_policy.read"
	PermAuthPolicyManage = "auth_policy.manage"
	PermAuthIdPRead      = "auth_idp.read"
	PermAuthIdPManage    = "auth_idp.manage"
	PermRolesRead        = "roles.read"
	PermRolesManage      = "roles.manage"
	// PermAPITokensRead и PermAPITokensManage — токены API (ИАФ.9, задача
	// 2.10). Со ScopeOwn — только свои токены (УПД.8). Самому токену не
	// выдаются (TokenGrantable).
	PermAPITokensRead   = "api_tokens.read"
	PermAPITokensManage = "api_tokens.manage"
	// События (ТЗ 5.5, задача 2.16). Содержимое запросов и ответов —
	// отдельное разрешение с указанием причины (УПД.7).
	PermEventsRead            = "events.read"
	PermEventsExport          = "events.export"
	PermEventsContentRead     = "events.content.read"
	PermEventsRetentionManage = "events.retention.manage"
	// PermEventsMark — отметки «ложное срабатывание» и «подтверждено» (ТЗ
	// 5.5, задача 3.22 этапа 3): работа аналитика; исключение по отметке
	// создаёт только администратор безопасности (policies.manage).
	PermEventsMark = "events.mark"
	// Приложения, ключи и провайдеры (ТЗ 5.4, ИАФ.8; задача 2.11). Поля
	// защиты приложения (политика, режим, режим хранения) и снятие
	// признака «внешний» у провайдера, эталон системного промпта (DM-26) —
	// функции безопасности (УПД.2, DM-40).
	PermApplicationsRead   = "applications.read"
	PermApplicationsManage = "applications.manage"
	PermApplicationsPolicy = "applications.policy"
	PermAppKeysManage      = "app_keys.manage"
	PermProvidersRead      = "providers.read"
	PermProvidersManage    = "providers.manage"
	PermProvidersExternal  = "providers.external"
	// Политики (ТЗ 5.3, задача 2.12): изменение — функция безопасности
	// (УПД.2, DM-40); песочница ничего не меняет и выдаётся отдельно.
	PermPoliciesRead   = "policies.read"
	PermPoliciesManage = "policies.manage"
	PermPoliciesTest   = "policies.test"
	// Журнал аудита (ТЗ 6.3 п. 11, РСБ.4; задача 2.4a): просмотр и проверка
	// цепочки по команде. Проверка ничего не меняет, кроме записи своего
	// итога, поэтому есть у аудитора (ТЗ 1.3).
	PermAuditRead   = "audit.read"
	PermAuditVerify = "audit.verify"
	// Оповещения (ТЗ 5.6, задача 3.10 этапа 3, ADR-0020): разбор
	// оповещений — работа аналитика, доступна и токену (SOAR); правила —
	// функция безопасности (ослабление — DM-40).
	PermAlertsRead       = "alerts.read"
	PermAlertsManage     = "alerts.manage"
	PermAlertRulesRead   = "alert_rules.read"
	PermAlertRulesManage = "alert_rules.manage"
	// Каналы уведомлений (ТЗ 5.6, Р4; задача 3.13 этапа 3): изменение и
	// тестовая отправка — функция безопасности (отключение и смена адреса —
	// ослабление, DM-40); секреты каналов в ответах не показываются.
	PermNotifyChannelsRead   = "notify_channels.read"
	PermNotifyChannelsManage = "notify_channels.manage"
	// Цены моделей и бюджеты приложений (ТЗ 5.8, задача 3.18 этапа 3).
	// Снятие или повышение жёсткого бюджета — не ослабление защиты (не
	// DM-40): права не относятся к безопасности, изменения пишутся в аудит.
	PermModelPricesRead   = "model_prices.read"
	PermModelPricesManage = "model_prices.manage"
	PermBudgetsRead       = "budgets.read"
	PermBudgetsManage     = "budgets.manage"
	// Режим квот при нескольких шлюзах (ADR-0021, задача 4.29): local или
	// leased. Переход на local при нескольких шлюзах на связи — ослабление
	// (DM-40) с повторной проверкой; право не относится к безопасности, как
	// и бюджеты, чтение — по budgets.read.
	PermQuotaModeManage = "quota_mode.manage"
	// Дашборды (ТЗ 5.8, задача 3.19 этапа 3): агрегаты без содержимого
	// запросов. Со ScopeOwn (владелец приложения) — только дашборд «Приложение»
	// своих приложений (УПД.8); остальные дашборды видят роли со ScopeAll.
	PermDashboardsRead = "dashboards.read"
	// Отчёты (ТЗ 5.8, задача 3.24 этапа 3): сводный, по инцидентам, «Итоги
	// пилота» в HTML, CSV и XLSX из агрегатов, без содержимого запросов.
	// Каждая выгрузка пишет data.export (DM-41). Со ScopeOwn (владелец
	// приложения) — только сводный отчёт по своему приложению (УПД.8).
	// Расписания рассылки на почту (задача 3.25) ведут администраторы.
	PermReportsRead           = "reports.read"
	PermReportSchedulesRead   = "reports.schedules.read"
	PermReportSchedulesManage = "reports.schedules.manage"
	// Инциденты (ТЗ 5.7, задача 3.16 этапа 3): разбор — работа аналитика,
	// доступна и токену (SOAR, IRP); выгрузка карточки — отдельное право
	// (data.export, DM-41); инструкции реагирования — функция безопасности.
	PermIncidentsRead            = "incidents.read"
	PermIncidentsManage          = "incidents.manage"
	PermIncidentsExport          = "incidents.export"
	PermIncidentCategoriesManage = "incident_categories.manage"
	// Сертификат заказчика для адреса шлюза (S1, ТЗ 5.4; задача 3.27 этапа
	// 3): загрузка цепочки и закрытого ключа — у администраторов системы и
	// безопасности (ТЗ 7: интеграции и TLS). Ключ в ответах не показывается.
	PermGatewayTLSRead   = "gateway_tls.read"
	PermGatewayTLSManage = "gateway_tls.manage"
	// Агенты, MCP-серверы и инструменты (ТЗ 5.10; задача 4.8 этапа 4,
	// ADR-0023, раздел 9). Со ScopeOwn (владелец приложения) — только агенты
	// своих приложений и их MCP-серверы и инструменты (УПД.8). Одобрение,
	// снятие одобрения и риск инструмента, признаки external и insecure_http
	// MCP-сервера — функция безопасности (DM-25, DM-40).
	PermAgentsRead         = "agents.read"
	PermAgentsManage       = "agents.manage"
	PermAgentsToolsApprove = "agents.tools.approve"
	// Очередь подтверждений вызовов (задача 4.10, ADR-0023, раздел 9).
	PermApprovalsRead   = "approvals.read"
	PermApprovalsDecide = "approvals.decide"
	// Теневой ИИ (ТЗ 5.11, DM-37; задача 4.22, ADR-0027, п. 7): сводки по
	// журналам прокси — пользователи только псевдонимами; управление —
	// импорт журналов, загрузка подписанного каталога, срок хранения.
	PermShadowAIRead   = "shadow_ai.read"
	PermShadowAIManage = "shadow_ai.manage"
	// Исключения из учёта теневого ИИ (задача 4.23; 4В26): исключение
	// пользователя необратимо удаляет его сводки — право безопасности, только
	// у security_admin, токенам API не выдаётся (УПД.2).
	PermShadowAIExclusionsManage = "shadow_ai.exclusions.manage"
	// Лицензия (ТЗ 5.15; задача 4.27, ADR-0026, п. 6): просмотр сведений и
	// использования пределов; загрузка и замена — действие администратора
	// системы с повторной проверкой паролем или кодом (у токена её нет).
	PermLicenseRead   = "license.read"
	PermLicenseManage = "license.manage"
	// Соответствие требованиям (ТЗ 5.9, Р10; задача 4.24): чтение статусов и
	// отчёта; ручные отметки — решение администратора безопасности, они
	// меняют картину соответствия в отчёте для проверяющих (Security, не
	// входит в «.read» аудитора и не выдаётся токенам); загрузка обновлённой
	// подписанной базы требований — администратор системы.
	PermComplianceRead     = "compliance.read"
	PermComplianceMark     = "compliance.mark"
	PermComplianceBaseLoad = "compliance.base.load"
)

// Permission — разрешение из каталога.
type Permission struct {
	Name  string
	Title string // описание для консоли
	Group string // раздел консоли
	// Security — управление функциями безопасности (учётные записи, роли,
	// вход). Администратору системы такие разрешения не выдаются (УПД.2).
	Security bool
	// Ownable — разрешение может выдаваться только на свои объекты
	// (ScopeOwn, УПД.8). Эндпоинт с таким разрешением сам отбирает объекты.
	Ownable bool
}

// ReadOnly — разрешение только на чтение (имя оканчивается на «.read»).
func (p Permission) ReadOnly() bool { return strings.HasSuffix(p.Name, ".read") }

// TokenGrantable — разрешение можно выдать токену API (решение владельца
// по задаче 2.10): кроме функций безопасности и самих токенов. Управление
// доступом остаётся за человеком с паролем и вторым фактором; токен не
// выпускает и не продлевает токены. Загрузка лицензии требует повторной
// проверки в сессии (ADR-0026, п. 6) — токену тоже не выдаётся.
func TokenGrantable(perm string) bool {
	p, ok := LookupPermission(perm)
	return ok && !p.Security && !strings.HasPrefix(p.Name, "api_tokens.") && p.Name != PermLicenseManage
}

var permissionCatalog = []Permission{
	{Name: PermSystemRead, Title: "Просмотр состояния и версии системы", Group: "Система"},
	{Name: PermIntegrityVerify, Title: "Запуск проверки целостности", Group: "Система", Security: true},
	{Name: PermSettingsManage, Title: "Изменение часового пояса и режима хранения по умолчанию", Group: "Система", Security: true},
	{Name: PermUsersRead, Title: "Просмотр учётных записей", Group: "Пользователи"},
	{Name: PermUsersManage, Title: "Создание, деактивация и сброс пароля учётных записей", Group: "Пользователи", Security: true},
	{Name: PermSessionsRead, Title: "Просмотр сессий пользователей", Group: "Пользователи"},
	{Name: PermSessionsManage, Title: "Принудительное завершение сессий", Group: "Пользователи", Security: true},
	{Name: PermAuthPolicyRead, Title: "Просмотр парольной политики и настроек входа", Group: "Вход"},
	{Name: PermAuthPolicyManage, Title: "Изменение парольной политики и настроек входа", Group: "Вход", Security: true},
	{Name: PermAuthIdPRead, Title: "Просмотр настроек входа через внешний IdP", Group: "Вход"},
	{Name: PermAuthIdPManage, Title: "Изменение и отключение входа через внешний IdP", Group: "Вход", Security: true},
	{Name: PermRolesRead, Title: "Просмотр ролей и разрешений", Group: "Роли"},
	{Name: PermRolesManage, Title: "Создание, изменение и удаление ролей, назначение ролей", Group: "Роли", Security: true},
	{Name: PermAPITokensRead, Title: "Просмотр токенов API", Group: "Токены API", Ownable: true},
	{Name: PermAPITokensManage, Title: "Выпуск и отзыв токенов API", Group: "Токены API", Ownable: true},
	{Name: PermEventsRead, Title: "Просмотр событий без содержимого, сохранённые фильтры, агрегаты", Group: "События"},
	{Name: PermEventsExport, Title: "Выгрузка событий в CSV и JSON (без содержимого)", Group: "События"},
	{Name: PermEventsContentRead, Title: "Просмотр содержимого запросов и ответов с указанием причины", Group: "События", Security: true},
	{Name: PermEventsRetentionManage, Title: "Изменение сроков хранения событий", Group: "События", Security: true},
	{Name: PermEventsMark, Title: "Отметки «ложное срабатывание» и «подтверждено» в событиях", Group: "События"},
	{Name: PermApplicationsRead, Title: "Просмотр приложений и их ключей (без секретов)", Group: "Приложения", Ownable: true},
	{Name: PermApplicationsManage, Title: "Создание, изменение и архивация приложений", Group: "Приложения"},
	{Name: PermApplicationsPolicy, Title: "Политика, режим политики, режим хранения, эталон системного промпта, JWT пользователя и доступ к моделям по группам", Group: "Приложения", Security: true},
	{Name: PermAppKeysManage, Title: "Выпуск, ротация и отзыв ключей приложений", Group: "Приложения", Ownable: true},
	{Name: PermProvidersRead, Title: "Просмотр провайдеров (без учётных данных)", Group: "Провайдеры"},
	{Name: PermProvidersManage, Title: "Создание, изменение и удаление провайдеров, учётные данные", Group: "Провайдеры"},
	{Name: PermProvidersExternal, Title: "Снятие и установка признака «внешний» у провайдера", Group: "Провайдеры", Security: true},
	{Name: PermPoliciesRead, Title: "Просмотр политик, их версий и выгрузка в YAML", Group: "Политики"},
	{Name: PermPoliciesManage, Title: "Создание, изменение, откат и загрузка политик", Group: "Политики", Security: true},
	{Name: PermPoliciesTest, Title: "Проверка текста в песочнице политик", Group: "Политики"},
	{Name: PermAuditRead, Title: "Просмотр журнала аудита", Group: "Журнал аудита"},
	{Name: PermAuditVerify, Title: "Проверка цепочки журнала аудита по команде", Group: "Журнал аудита"},
	{Name: PermAlertsRead, Title: "Просмотр оповещений и ссылок на события", Group: "Оповещения"},
	{Name: PermAlertsManage, Title: "Принятие оповещений в работу и закрытие", Group: "Оповещения"},
	{Name: PermAlertRulesRead, Title: "Просмотр правил оповещений и получателей", Group: "Оповещения"},
	{Name: PermAlertRulesManage, Title: "Создание и изменение правил оповещений и получателей", Group: "Оповещения", Security: true},
	{Name: PermNotifyChannelsRead, Title: "Просмотр каналов уведомлений (без секретов) и журнала доставки", Group: "Оповещения"},
	{Name: PermNotifyChannelsManage, Title: "Создание, изменение и тестовая отправка каналов уведомлений", Group: "Оповещения",
		Security: true},
	{Name: PermDashboardsRead, Title: "Просмотр дашбордов: агрегаты без содержимого запросов", Group: "Дашборды", Ownable: true},
	{Name: PermModelPricesRead, Title: "Просмотр цен моделей", Group: "Потребление"},
	{Name: PermModelPricesManage, Title: "Задание, изменение и удаление цен моделей", Group: "Потребление"},
	{Name: PermBudgetsRead, Title: "Просмотр бюджетов и расхода приложений", Group: "Потребление"},
	{Name: PermBudgetsManage, Title: "Задание, изменение и снятие бюджетов приложений", Group: "Потребление"},
	{Name: PermQuotaModeManage, Title: "Изменение режима учёта квот и бюджетов при нескольких шлюзах (local или leased)", Group: "Потребление"},
	{Name: PermReportsRead, Title: "Построение и выгрузка отчётов: сводный, по инцидентам, «Итоги пилота»", Group: "Отчёты", Ownable: true},
	{Name: PermReportSchedulesRead, Title: "Просмотр расписаний рассылки отчётов и журнала рассылки", Group: "Отчёты"},
	{Name: PermReportSchedulesManage, Title: "Создание, изменение и удаление расписаний рассылки отчётов", Group: "Отчёты"},
	{Name: PermIncidentsRead, Title: "Просмотр инцидентов, хронологии, комментариев и инструкций реагирования", Group: "Инциденты"},
	{Name: PermIncidentsManage, Title: "Создание инцидентов, смена статуса, назначение, комментарии, этапы реагирования", Group: "Инциденты"},
	{Name: PermIncidentsExport, Title: "Выгрузка карточки инцидента в JSON (без содержимого событий)", Group: "Инциденты"},
	{Name: PermIncidentCategoriesManage, Title: "Изменение инструкций реагирования по категориям инцидентов и срока хранения закрытых инцидентов", Group: "Инциденты", Security: true},
	{Name: PermGatewayTLSRead, Title: "Просмотр сертификата заказчика для адреса шлюза (без ключа)", Group: "Шлюзы"},
	{Name: PermGatewayTLSManage, Title: "Загрузка, замена и удаление сертификата заказчика для адреса шлюза", Group: "Шлюзы"},
	{Name: PermAgentsRead, Title: "Просмотр агентов, MCP-серверов (без учётных данных) и инструментов", Group: "Агенты", Ownable: true},
	{Name: PermAgentsManage, Title: "Создание, изменение и удаление агентов и MCP-серверов, привязка ключей к агентам", Group: "Агенты"},
	{Name: PermAgentsToolsApprove, Title: "Одобрение и снятие одобрения инструментов, уровень риска, признаки «внешний» и http:// у MCP-сервера",
		Group: "Агенты", Security: true},
	{Name: PermApprovalsRead, Title: "Просмотр очереди подтверждений вызовов инструментов агентов", Group: "Агенты"},
	// Безопасность: не выдаётся администратору системы и токенам API, не
	// входит в чтение аудитора — подтверждает вызов человек (ADR-0023, раздел 9).
	{Name: PermApprovalsDecide, Title: "Одобрение и отклонение вызовов инструментов агентов из очереди подтверждений",
		Group: "Агенты", Security: true},
	{Name: PermShadowAIRead, Title: "Просмотр сводок теневого ИИ (пользователи — псевдонимами), каталога сервисов и журнала импорта", Group: "Теневой ИИ"},
	{Name: PermShadowAIManage, Title: "Импорт журналов прокси, загрузка подписанного каталога ИИ-сервисов и возврат его предыдущей версии, срок хранения сводок", Group: "Теневой ИИ"},
	// Безопасность: исключение пользователя удаляет его сводки (4В26).
	{Name: PermShadowAIExclusionsManage, Title: "Исключение пользователей и сервисов из учёта теневого ИИ (сводки исключённого пользователя удаляются) и снятие исключений",
		Group: "Теневой ИИ", Security: true},
	{Name: PermLicenseRead, Title: "Просмотр лицензии: владелец, срок, пределы и их использование, модули", Group: "Система"},
	{Name: PermLicenseManage, Title: "Загрузка и замена лицензии (с повторной проверкой паролем или кодом)", Group: "Система"},
	{Name: PermComplianceRead, Title: "Просмотр соответствия требованиям: пункты, статусы, доказательства, ручные отметки и база требований", Group: "Соответствие"},
	// Безопасность: ручная отметка меняет статус пункта в отчёте для проверяющих.
	{Name: PermComplianceMark, Title: "Ручные отметки по пунктам соответствия (организационные меры) с комментарием и сроком пересмотра",
		Group: "Соответствие", Security: true},
	{Name: PermComplianceBaseLoad, Title: "Загрузка обновлённой подписанной базы требований и возврат её предыдущей версии", Group: "Соответствие"},
}

// auditorExtra — разрешения аудитора сверх чтения: они ничего не меняют,
// кроме записи своего итога в журнал аудита (УПД.2 «аудитор только читает»).
var auditorExtra = []string{PermAuditVerify}

var permissionIndex = func() map[string]Permission {
	m := make(map[string]Permission, len(permissionCatalog))
	for _, p := range permissionCatalog {
		if _, dup := m[p.Name]; dup || p.Name == PermSelf || p.Name == PermSession || !validPermissionName(p.Name) {
			panic("auth: неверное или повторное разрешение в каталоге: " + p.Name)
		}
		m[p.Name] = p
	}
	return m
}()

// Permissions — каталог разрешений в порядке объявления.
func Permissions() []Permission { return slices.Clone(permissionCatalog) }

// LookupPermission — разрешение каталога по имени.
func LookupPermission(name string) (Permission, bool) {
	p, ok := permissionIndex[name]
	return p, ok
}

// permissionNameByte — допустимый символ части имени разрешения.
func permissionNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c == '_' || c >= '0' && c <= '9'
}

// validPermissionName — «раздел.действие» или «раздел.объект.действие»
// (events.content.read из ТЗ 5.5): части из латиницы в нижнем регистре,
// цифр и «_», часть не начинается с цифры.
func validPermissionName(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || p[0] >= '0' && p[0] <= '9' {
			return false
		}
		for i := 0; i < len(p); i++ {
			if !permissionNameByte(p[i]) {
				return false
			}
		}
	}
	return true
}

// Scope — область действия разрешения (УПД.8).
type Scope uint8

// Области. Нулевое значение — разрешения нет.
const (
	ScopeNone Scope = iota
	// ScopeOwn — только свои объекты (например, приложения владельца).
	ScopeOwn
	// ScopeAll — все объекты организации.
	ScopeAll
)

// String — имя области в API и БД.
func (s Scope) String() string {
	switch s {
	case ScopeOwn:
		return "own"
	case ScopeAll:
		return "all"
	}
	return "none"
}

// ParseScope разбирает имя области; ok = false — неизвестное имя.
func ParseScope(s string) (Scope, bool) {
	switch s {
	case "own":
		return ScopeOwn, true
	case "all":
		return ScopeAll, true
	}
	return ScopeNone, false
}

// Grants — права: разрешение → область. В правах роли только разрешения
// каталога; PermSelf и PermSession добавляет SessionGrants по состоянию сессии.
type Grants map[string]Scope

// Scope — область разрешения perm; ScopeNone — разрешения нет.
func (g Grants) Scope(perm string) Scope { return g[perm] }

// Allows — есть ли разрешение perm с любой областью.
func (g Grants) Allows(perm string) bool { return g.Scope(perm) != ScopeNone }

// Full — есть ли разрешение perm на все объекты.
func (g Grants) Full(perm string) bool { return g.Scope(perm) == ScopeAll }

// Covers — каждое разрешение o есть в g с той же или более широкой
// областью: обладатель g не повышает свои права, выдавая o (УПД.2).
func (g Grants) Covers(o Grants) bool {
	for p, s := range o {
		if s != ScopeNone && g.Scope(p) < s {
			return false
		}
	}
	return true
}

// Names — имена разрешений по алфавиту.
func (g Grants) Names() []string {
	out := []string{}
	for p, s := range g {
		if s != ScopeNone {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// Clone — независимая копия.
func (g Grants) Clone() Grants { return maps.Clone(g) }

func grantAll(perms ...string) Grants {
	g := make(Grants, len(perms))
	for _, p := range perms {
		g[p] = ScopeAll
	}
	return g
}

// allPermissions — все разрешения каталога на все объекты.
func allPermissions() Grants {
	g := make(Grants, len(permissionCatalog))
	for _, p := range permissionCatalog {
		g[p.Name] = ScopeAll
	}
	return g
}

// readPermissions — все разрешения каталога только на чтение, кроме
// разрешений безопасности: чтение содержимого событий (УПД.7) аудитору
// не выдаётся (ТЗ 1.3).
func readPermissions() Grants {
	g := Grants{}
	for _, p := range permissionCatalog {
		if p.ReadOnly() && !p.Security {
			g[p.Name] = ScopeAll
		}
	}
	return g
}

// auditorPermissions — права аудитора: чтение и auditorExtra.
func auditorPermissions() Grants {
	g := readPermissions()
	for _, p := range auditorExtra {
		g[p] = ScopeAll
	}
	return g
}

// AuditorExtra — разрешения аудитора не на чтение (для тестов УПД.2).
func AuditorExtra() []string { return slices.Clone(auditorExtra) }

// builtinRoles — права предустановленных ролей задаются кодом и
// обновляются вместе с продуктом; изменить их из консоли нельзя (УПД.1).
// Администратор безопасности управляет пользователями, ролями и входом;
// администратор системы не меняет политики безопасности и выпускает
// только свои токены API; аудитор только читает (УПД.2). Разрешения следующих задач (приложения, политики,
// события) добавляются сюда вместе с эндпоинтами.
var builtinRoles = []RoleDef{
	{ID: RoleSecurityAdmin, DisplayName: "Администратор безопасности", Builtin: true, MFARequired: true,
		Description: "Политики, правила оповещений, доступ к содержимому событий, пользователи и роли",
		Grants:      allPermissions()},
	{ID: RoleSystemAdmin, DisplayName: "Администратор системы", Builtin: true, MFARequired: true,
		Description: "Приложения, провайдеры, интеграции, обновления, резервное копирование. Политики безопасности не меняет",
		Grants: Grants{PermSystemRead: ScopeAll, PermAPITokensRead: ScopeOwn, PermAPITokensManage: ScopeOwn,
			PermApplicationsRead: ScopeAll, PermApplicationsManage: ScopeAll, PermAppKeysManage: ScopeAll,
			PermProvidersRead: ScopeAll, PermProvidersManage: ScopeAll, PermPoliciesRead: ScopeAll, PermPoliciesTest: ScopeAll,
			PermModelPricesRead: ScopeAll, PermModelPricesManage: ScopeAll, PermBudgetsRead: ScopeAll, PermBudgetsManage: ScopeAll,
			PermQuotaModeManage: ScopeAll, PermDashboardsRead: ScopeAll, PermGatewayTLSRead: ScopeAll, PermGatewayTLSManage: ScopeAll,
			PermReportsRead: ScopeAll, PermReportSchedulesRead: ScopeAll, PermReportSchedulesManage: ScopeAll,
			PermAgentsRead: ScopeAll, PermAgentsManage: ScopeAll, PermShadowAIRead: ScopeAll, PermShadowAIManage: ScopeAll,
			PermLicenseRead: ScopeAll, PermLicenseManage: ScopeAll,
			PermComplianceRead: ScopeAll, PermComplianceBaseLoad: ScopeAll}},
	{ID: RoleAnalyst, DisplayName: "Аналитик", Builtin: true,
		Description: "Разбор оповещений и инцидентов, поиск по событиям",
		Grants: grantAll(PermSystemRead, PermEventsRead, PermEventsExport, PermEventsMark, PermApplicationsRead, PermProvidersRead,
			PermPoliciesRead, PermPoliciesTest, PermAlertsRead, PermAlertsManage, PermAlertRulesRead, PermModelPricesRead, PermBudgetsRead,
			PermDashboardsRead, PermIncidentsRead, PermIncidentsManage, PermIncidentsExport, PermReportsRead, PermAgentsRead,
			PermApprovalsRead, PermApprovalsDecide, PermShadowAIRead)},
	{ID: RoleAuditor, DisplayName: "Аудитор", Builtin: true,
		Description: "Только просмотр: журнал аудита, отчёты, состояние соответствия. Ничего не меняет",
		Grants:      auditorPermissions()},
	{ID: RoleAppOwner, DisplayName: "Владелец приложения", Builtin: true,
		Description: "Статистика и события только своих приложений, без доступа к содержимому",
		Grants: Grants{PermApplicationsRead: ScopeOwn, PermDashboardsRead: ScopeOwn, PermReportsRead: ScopeOwn,
			PermAgentsRead: ScopeOwn}},
}

var builtinIndex = func() map[Role]RoleDef {
	m := make(map[Role]RoleDef, len(builtinRoles))
	for _, r := range builtinRoles {
		m[r.ID] = r
	}
	return m
}()

// BuiltinRoles — предустановленные роли (копии).
func BuiltinRoles() []RoleDef {
	out := make([]RoleDef, len(builtinRoles))
	for i, r := range builtinRoles {
		out[i] = r.clone()
	}
	return out
}

// Builtin — роль из числа предустановленных.
func (r Role) Builtin() bool {
	_, ok := builtinIndex[r]
	return ok
}
