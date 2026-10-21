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

// Условия уведомлений раздела 7.
const (
	ConditionAccount   = "account_lockout" // ИАФ.4: блокировки учётных записей
	ConditionDenied    = "access_denied"   // УПД.6: отказы в доступе к управлению
	ConditionStorage   = "audit_storage"   // РСБ.5: журнал близок к пределу
	ConditionIntegrity = "integrity"       // ОЦЛ.5: нарушение целостности или провал самотеста
	ConditionTime      = "time_sync"       // ВРМ.1: рассинхронизация времени
)

// Notification — условие уведомления на этапе 2.
type Notification struct {
	Condition   string `json:"condition"`
	Requirement string `json:"requirement"` // ИАФ.4, УПД.6, РСБ.5, ОЦЛ.5, ВРМ.1
	Title       string `json:"title"`
	Active      bool   `json:"active"`
	// Since — когда условие возникло; nil — неактивно или момент не известен.
	Since *time.Time `json:"since"`
	// Count — число событий за сутки для ИАФ.4 и УПД.6; nil — не считается.
	Count *int `json:"count"`
}
