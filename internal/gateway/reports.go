package gateway

import (
	"sync"
	"time"
)

// CheckReport — итог самотеста или контроля целостности шлюза для heartbeat
// (задача 2.20): результат, время и число провалов. Пути файлов, имена
// детекторов и тексты эталонов на сервер не передаются.
type CheckReport struct {
	OK        bool      `json:"ok"`
	CheckedAt time.Time `json:"checked_at"`
	// Reason — причина итога целостности (перечень миграции 0008_integrity);
	// у самотеста пусто.
	Reason string `json:"reason,omitempty"`
	Failed int    `json:"failed"`
	// Только у целостности (В20, Н34 ревью 2.r4): версия и время сборки
	// манифеста — сервер по ним обнаруживает откат выпуска — и тестовый ключ.
	ManifestVersion string     `json:"manifest_version,omitempty"`
	ManifestCreated *time.Time `json:"manifest_created,omitempty"`
	TestSigned      bool       `json:"test_signed,omitempty"`
}

// Manifest — манифест проверки целостности шлюза для heartbeat. Нулевое
// время — манифест не прочитан (нет файла, неверная подпись).
type Manifest struct {
	Version    string
	Created    time.Time
	TestSigned bool
}

// maxReportFailed — предел числа провалов в heartbeat (как на сервере).
const maxReportFailed = 1000

// Reports хранит последние итоги проверок шлюза, которые heartbeat сообщает
// серверу управления. Безопасен для параллельного использования.
type Reports struct {
	mu        sync.Mutex
	selftest  *CheckReport
	integrity *CheckReport
	// bundleKeys — KeyID ключей проверки пакетов (-bundle-pub, В19).
	bundleKeys []string
}

// SetBundleKeys запоминает KeyID ключей проверки пакетов: сервер сверяет
// их со своим ключом подписи (В19 ревью 2.r4).
func (r *Reports) SetBundleKeys(ids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bundleKeys = append([]string(nil), ids...)
}

// SetSelftest запоминает итог самотеста: failed — число провалов.
func (r *Reports) SetSelftest(ok bool, at time.Time, failed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selftest = &CheckReport{OK: ok, CheckedAt: at.UTC(), Failed: min(max(failed, 0), maxReportFailed)}
}

// SetIntegrity запоминает итог контроля целостности: reason — причина из
// перечня, failed — число нарушений (с учётом не вошедших в список), m —
// манифест проверки.
func (r *Reports) SetIntegrity(ok bool, at time.Time, reason string, failed int, m Manifest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rep := &CheckReport{OK: ok, CheckedAt: at.UTC(), Reason: reason, Failed: min(max(failed, 0), maxReportFailed),
		TestSigned: m.TestSigned}
	if !m.Created.IsZero() && m.Version != "" {
		c := m.Created.UTC()
		rep.ManifestVersion, rep.ManifestCreated = m.Version, &c
	}
	r.integrity = rep
}

// snapshot возвращает копии итогов; nil — итога ещё нет.
func (r *Reports) snapshot() (selftest, integrity *CheckReport, bundleKeys []string) {
	if r == nil {
		return nil, nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	bundleKeys = append([]string(nil), r.bundleKeys...)
	if r.selftest != nil {
		c := *r.selftest
		selftest = &c
	}
	if r.integrity != nil {
		c := *r.integrity
		integrity = &c
	}
	return selftest, integrity, bundleKeys
}

// heartbeatBody — тело POST /internal/v1/heartbeat.
type heartbeatBody struct {
	Version    string       `json:"version"`
	BundleETag string       `json:"bundle_etag"`
	Selftest   *CheckReport `json:"selftest,omitempty"`
	Integrity  *CheckReport `json:"integrity,omitempty"`
	BundleKeys []string     `json:"bundle_keys,omitempty"`
}
