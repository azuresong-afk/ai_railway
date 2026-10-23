// Пакет sysstatus собирает «Состояние системы» (ТЗ 6.2 п. 12, задача 2.20):
// компоненты и версии, шлюзы, итоги контроля целостности и самотестирования,
// синхронизацию времени (ВРМ.1–2), отброшенные события, заполнение хранилища
// журнала аудита (РСБ.5) и уведомления раздела 7 (ИАФ.4, УПД.6, РСБ.5, ОЦЛ.5,
// ВРМ.1). На этапе 2 уведомление — запись в журнал аудита при смене
// состояния и поле в ответе; доставка по каналам — этап 3.
package sysstatus

import "time"

// Status — «Состояние системы».
type Status struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Server      ServerStatus    `json:"server"`
	Gateways    []GatewayStatus `json:"gateways"`
	Events      EventsStatus    `json:"events"`
	Time        TimeStatus      `json:"time"`
	Storage     StorageStatus   `json:"storage"`
	// AuditChain — последняя проверка цепочки журнала аудита (РСБ.4); nil —
	// проверок ещё не было.
	AuditChain *AuditChainStatus `json:"audit_chain"`
	// Bundle — сборка пакета конфигурации шлюзов (В16, Н28 ревью 2.r3b);
	// nil — сервер без внутреннего порта для шлюзов.
	Bundle *BundleStatus `json:"bundle"`
	// Notifications — по одной записи на каждое условие раздела 7.
	Notifications []Notification `json:"notifications"`
	// Unavailable — разделы, которые не удалось собрать (сбой БД и т. п.);
	// остальные разделы при этом корректны.
	Unavailable []string `json:"unavailable"`
}

// Report — итог проверки (самотест или контроль целостности).
type Report struct {
	OK        bool      `json:"ok"`
	CheckedAt time.Time `json:"checked_at"`
	// Reason — причина итога целостности; у самотеста пусто.
	Reason string `json:"reason,omitempty"`
	Failed int    `json:"failed"`
	// Stale — итог старше двух периодов проверки: «нет данных» (Н29), в
	// уведомлениях — условие reports_stale (DM-44).
	Stale bool `json:"stale,omitempty"`
}

// ServerStatus — сервер управления.
type ServerStatus struct {
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
	// Selftest — итог самотеста сервера при запуске; nil — нет данных.
	Selftest *Report `json:"selftest"`
	// Integrity — последние проверки целостности компонентов сервера.
	Integrity []IntegrityStatus `json:"integrity"`
}

// IntegrityStatus — последняя проверка целостности компонента.
type IntegrityStatus struct {
	Component       string    `json:"component"`
	Trigger         string    `json:"trigger"`
	CheckedAt       time.Time `json:"checked_at"`
	OK              bool      `json:"ok"`
	Reason          string    `json:"reason"`
	ManifestVersion string    `json:"manifest_version"`
	TestSigned      bool      `json:"test_signed"`
	Failed          int       `json:"failed"`
}

// Состояния шлюза в ответе.
const (
	GatewayOnline  = "online"  // контакт был не позднее трёх периодов heartbeat назад
	GatewayOffline = "offline" // контакта нет дольше трёх периодов или не было вовсе
	GatewayPending = "pending" // токен выпущен, шлюз не зарегистрирован
	GatewayRevoked = "revoked"
)

// GatewayStatus — шлюз.
type GatewayStatus struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	State        string     `json:"state"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	Version      string     `json:"version"`
	BundleETag   string     `json:"bundle_etag"`
	CertNotAfter *time.Time `json:"cert_not_after"`
	// Selftest и Integrity — последние итоги, присланные шлюзом в heartbeat;
	// nil — шлюз их не присылал.
	Selftest  *Report `json:"selftest"`
	Integrity *Report `json:"integrity"`
	// Events — счётчики отправителя событий шлюза; nil — шлюз событий не слал.
	Events *GatewayEvents `json:"events"`
}

// GatewayEvents — счётчики отправителя событий шлюза с его последнего запуска.
type GatewayEvents struct {
	Dropped    uint64    `json:"dropped"`
	Rejected   uint64    `json:"rejected"`
	StartedAt  time.Time `json:"started_at"`
	ReportedAt time.Time `json:"reported_at"`
}

// EventsStatus — суммы счётчиков по шлюзам (с последнего запуска каждого).
type EventsStatus struct {
	Dropped  uint64 `json:"dropped"`
	Rejected uint64 `json:"rejected"`
}

// TimeStatus — время (ВРМ.1–2).
type TimeStatus struct {
	// ServerTime — время сервера в UTC (хранение везде в UTC).
	ServerTime time.Time `json:"server_time"`
	// Timezone — часовой пояс для показа (настройка, ВРМ.2).
	Timezone string `json:"timezone"`
	// Sync — synchronized, unsynchronized или unknown (нет данных ОС).
	Sync string `json:"sync"`
	// ErrorMicros — оценка ошибки времени, мкс; nil — нет оценки.
	ErrorMicros *int64 `json:"error_micros"`
}

// StorageStatus — заполнение хранилища журнала аудита (РСБ.5).
type StorageStatus struct {
	// Available — размер удалось определить.
	Available    bool  `json:"available"`
	AuditBytes   int64 `json:"audit_bytes"`
	LimitBytes   int64 `json:"limit_bytes"`
	UsedPercent  int   `json:"used_percent"`
	WarnPercent  int   `json:"warn_percent"`
	WarnExceeded bool  `json:"warn_exceeded"`
}

// AuditChainStatus — итог последней проверки цепочки журнала аудита:
// фоновой проверки сервера или ручной aisec-cli audit verify.
type AuditChainStatus struct {
	CheckedAt time.Time `json:"checked_at"`
	OK        bool      `json:"ok"`
	// Checked — проверено записей; LastSeq — последняя проверенная запись.
	Checked int64 `json:"checked"`
	LastSeq int64 `json:"last_seq"`
	// Reason — ok или причина нарушения (rewritten, tail_truncated и т. п.).
	Reason string `json:"reason"`
	// BrokenSeq — номер записи, на которой цепочка нарушена; nil — цела.
	BrokenSeq *int64 `json:"broken_seq"`
}

// BundleHealth — итог сборки пакета конфигурации (build.Service.Health).
type BundleHealth struct {
	Version int64
	ETag    string
	BuiltAt time.Time
	// Failed — содержимое не собрано целиком (размер): шлюзы на прежней версии.
	Failed   bool
	Reason   string
	Excluded []ExcludedApp
}

// ExcludedApp — приложение, исключённое из пакета, и причина.
type ExcludedApp struct {
	Application string `json:"application"`
	Reason      string `json:"reason"`
}

// BundleStatus — пакет конфигурации шлюзов.
type BundleStatus struct {
	// Version и ETag — текущая корректная версия; 0 — её нет.
	Version int64      `json:"version"`
	ETag    string     `json:"etag"`
	BuiltAt *time.Time `json:"built_at"`
	// Complete — в версии все действующие приложения и данные собраны.
	Complete bool `json:"complete"`
	// Reason — почему не собрано содержимое целиком; пусто — собрано.
	Reason   string        `json:"reason,omitempty"`
	Excluded []ExcludedApp `json:"excluded"`
	// Lagging — действующие шлюзы, которые дольше BundleLagAfter работают на
	// другой версии (Н28 ревью 2.r3b).
	Lagging []string `json:"lagging"`
}

// BundleLagAfter — через сколько после сборки версии шлюз на прежней
// версии считается отставшим (опрос — раз в 30 с).
const BundleLagAfter = 10 * time.Minute

// Условия уведомлений раздела 7.
const (
	ConditionAccount   = "account_lockout" // ИАФ.4: блокировки учётных записей
	ConditionDenied    = "access_denied"   // УПД.6: отказы в доступе к управлению
	ConditionStorage   = "audit_storage"   // РСБ.5: журнал близок к пределу
	ConditionIntegrity = "integrity"       // ОЦЛ.5: нарушение целостности или провал самотеста
	ConditionTime      = "time_sync"       // ВРМ.1: рассинхронизация времени
	ConditionAuditLog  = "audit_chain"     // РСБ.4: нарушена цепочка журнала аудита
	// ConditionBundle — ОЦЛ.3: пакет конфигурации собран не полностью (В16).
	ConditionBundle = "config_bundle"
	// ConditionBundleLag — ОЦЛ.3: шлюз работает на устаревшем пакете (Н28).
	ConditionBundleLag = "config_bundle_lag"
	// ConditionTestBuild — ОЦЛ.1: компонент собран с тестовым ключом
	// манифеста, сборка не для поставки (Н34 ревью 2.r4).
	ConditionTestBuild = "test_build"
	// Условия DM-44 по шлюзу (задача 3.11 этапа 3): «ослепление»
	// мониторинга. Код — семейство и ID шлюза.
	ConditionEventsDropped = "events_dropped"  // шлюз отбрасывает события
	ConditionOffline       = "gateway_offline" // шлюз не выходит на связь
	ConditionCertExpiry    = "cert_expiry"     // сертификат шлюза скоро истекает
	ConditionReportsStale  = "reports_stale"   // итог целостности шлюза устарел (Н29)
	// ConditionCAExpiry — ИАФ.10: действующему корню внутреннего УЦ осталось
	// CAExpiryWarn и меньше; нужна ротация (aisec-cli keys rotate-ca). За
	// CAExpiryCritical пишется ещё одно system.alert (код ca_expiry:critical).
	// Сертификаты шлюзов после этого не продлеваются: их срок обрезан сроком
	// корня (3В5 ревью 3.r1).
	ConditionCAExpiry = "ca_expiry"
	// ConditionCustomerCertExpiry — ЗИ.4: сертификату заказчика для адреса
	// шлюза (задача 3.27) осталось CustomerCertExpiryWarn и меньше; за
	// CustomerCertExpiryCritical пишется ещё одно system.alert (код
	// customer_cert_expiry:critical). Отдельное семейство, а не
	// cert_expiry:<ID>: те коды относятся к шлюзам реестра.
	ConditionCustomerCertExpiry = "customer_cert_expiry"
)

// Пороги условий DM-44 (обоснование — ADR-0020).
const (
	// CertExpiryWarn — за сколько до истечения сертификата шлюза условие
	// активно. Сервер перевыпускает сертификат за 30 суток
	// (gwregistry.ReissueBefore): 14 суток без перевыпуска — сбой ротации.
	CertExpiryWarn = 14 * 24 * time.Hour
	// GatewayIntegrityPeriod — период контроля целостности шлюза по
	// умолчанию (config.DefaultIntegrityInterval). Шлюз свой период не
	// сообщает: итог старше двух периодов по умолчанию — «нет данных» (Н29).
	GatewayIntegrityPeriod = time.Hour
	// StaleAfter — возраст итога, после которого он устарел.
	StaleAfter = 2 * GatewayIntegrityPeriod
	// DroppedWindow — сколько условие отброшенных событий остаётся активным
	// после последнего роста счётчика.
	DroppedWindow = 15 * time.Minute
)

// Пороги условия ca_expiry (3В5 ревью 3.r1): за 60 суток — время на
// ротацию с перекрытием 30 суток по умолчанию, за 7 — последнее
// предупреждение.
const (
	CAExpiryWarn     = 60 * 24 * time.Hour
	CAExpiryCritical = 7 * 24 * time.Hour
	caExpiryCritical = ConditionCAExpiry + ":critical"
)

// Пороги условия customer_cert_expiry (задача 3.27): за 30 суток — время
// заказать сертификат у УЦ заказчика, за 7 — последнее предупреждение.
const (
	CustomerCertExpiryWarn     = 30 * 24 * time.Hour
	CustomerCertExpiryCritical = 7 * 24 * time.Hour
	customerCertCritical       = ConditionCustomerCertExpiry + ":critical"
)

// Коды условий по компоненту (В18 ревью 2.r3b): ОЦЛ.5 и отставание пакета
// ведутся отдельно для сервера и каждого шлюза, чтобы второе нарушение
// тоже попало в журнал. В ответе — одна строка со списком компонентов.
const (
	integrityServer  = ConditionIntegrity + ":server"
	integrityGateway = ConditionIntegrity + ":gateway:"
	bundleLagGateway = ConditionBundleLag + ":"
	componentServer  = "server"
	componentGateway = "gateway:"
)

// gatewayFamilies — семейства условий с кодом «семейство:ID шлюза».
var gatewayFamilies = []string{ConditionBundleLag, ConditionEventsDropped, ConditionOffline, ConditionCertExpiry,
	ConditionReportsStale}

// Notification — условие уведомления на этапе 2.
type Notification struct {
	Condition   string `json:"condition"`
	Requirement string `json:"requirement"` // ИАФ.4, УПД.6, РСБ.4, РСБ.5, ОЦЛ.5, ВРМ.1
	Title       string `json:"title"`
	Active      bool   `json:"active"`
	// Since — когда условие возникло; nil — неактивно или момент не известен.
	Since *time.Time `json:"since"`
	// Count — число событий за сутки для ИАФ.4 и УПД.6; nil — не считается.
	Count *int `json:"count"`
	// Components — компоненты с активным условием (ОЦЛ.5: server или
	// gateway:<ID>; отставание пакета — gateway:<ID>).
	Components []string `json:"components,omitempty"`
}
