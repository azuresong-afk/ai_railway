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
	// признака «внешний» у провайдера — функции безопасности (УПД.2, DM-40).
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
	// Инциденты (ТЗ 5.7, задача 3.16 этапа 3): разбор — работа аналитика,
	// доступна и токену (SOAR, IRP); выгрузка карточки — отдельное право
	// (data.export, DM-41); инструкции реагирования — функция безопасности.
	PermIncidentsRead            = "incidents.read"
	PermIncidentsManage          = "incidents.manage"
	PermIncidentsExport          = "incidents.export"
	PermIncidentCategoriesManage = "incident_categories.manage"
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
// выпускает и не продлевает токены.
func TokenGrantable(perm string) bool {
	p, ok := LookupPermission(perm)
	return ok && !p.Security && !strings.HasPrefix(p.Name, "api_tokens.")
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
	{Name: PermApplicationsPolicy, Title: "Политика, режим политики и режим хранения приложения", Group: "Приложения", Security: true},
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
	{Name: PermModelPricesRead, Title: "Просмотр цен моделей", Group: "Потребление"},
	{Name: PermModelPricesManage, Title: "Задание, изменение и удаление цен моделей", Group: "Потребление"},
	{Name: PermBudgetsRead, Title: "Просмотр бюджетов и расхода приложений", Group: "Потребление"},
	{Name: PermBudgetsManage, Title: "Задание, изменение и снятие бюджетов приложений", Group: "Потребление"},
	{Name: PermIncidentsRead, Title: "Просмотр инцидентов, хронологии, комментариев и инструкций реагирования", Group: "Инциденты"},
	{Name: PermIncidentsManage, Title: "Создание инцидентов, смена статуса, назначение, комментарии, этапы реагирования", Group: "Инциденты"},
	{Name: PermIncidentsExport, Title: "Выгрузка карточки инцидента в JSON (без содержимого событий)", Group: "Инциденты"},
	{Name: PermIncidentCategoriesManage, Title: "Изменение инструкций реагирования по категориям инцидентов", Group: "Инциденты", Security: true},
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
			PermModelPricesRead: ScopeAll, PermModelPricesManage: ScopeAll, PermBudgetsRead: ScopeAll, PermBudgetsManage: ScopeAll}},
	{ID: RoleAnalyst, DisplayName: "Аналитик", Builtin: true,
		Description: "Разбор оповещений и инцидентов, поиск по событиям",
		Grants: grantAll(PermSystemRead, PermEventsRead, PermEventsExport, PermEventsMark, PermApplicationsRead, PermProvidersRead,
			PermPoliciesRead, PermPoliciesTest, PermAlertsRead, PermAlertsManage, PermAlertRulesRead, PermModelPricesRead, PermBudgetsRead,
			PermIncidentsRead, PermIncidentsManage, PermIncidentsExport)},
	{ID: RoleAuditor, DisplayName: "Аудитор", Builtin: true,
		Description: "Только просмотр: журнал аудита, отчёты, состояние соответствия. Ничего не меняет",
		Grants:      auditorPermissions()},
	{ID: RoleAppOwner, DisplayName: "Владелец приложения", Builtin: true,
		Description: "Статистика и события только своих приложений, без доступа к содержимому",
		Grants:      Grants{PermApplicationsRead: ScopeOwn}},
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
