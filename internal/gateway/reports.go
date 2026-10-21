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
}

// maxReportFailed — предел числа провалов в heartbeat (как на сервере).
const maxReportFailed = 1000

// Reports хранит последние итоги проверок шлюза, которые heartbeat сообщает
// серверу управления. Безопасен для параллельного использования.
type Reports struct {
	mu        sync.Mutex
	selftest  *CheckReport
	integrity *CheckReport
}

// SetSelftest запоминает итог самотеста: failed — число провалов.
func (r *Reports) SetSelftest(ok bool, at time.Time, failed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selftest = &CheckReport{OK: ok, CheckedAt: at.UTC(), Failed: min(max(failed, 0), maxReportFailed)}
}

// SetIntegrity запоминает итог контроля целостности: reason — причина из
// перечня, failed — число нарушений (с учётом не вошедших в список).
func (r *Reports) SetIntegrity(ok bool, at time.Time, reason string, failed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.integrity = &CheckReport{OK: ok, CheckedAt: at.UTC(), Reason: reason, Failed: min(max(failed, 0), maxReportFailed)}
}

// snapshot возвращает копии итогов; nil — итога ещё нет.
func (r *Reports) snapshot() (selftest, integrity *CheckReport) {
	if r == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.selftest != nil {
		c := *r.selftest
		selftest = &c
	}
	if r.integrity != nil {
		c := *r.integrity
		integrity = &c
	}
	return selftest, integrity
}

// heartbeatBody — тело POST /internal/v1/heartbeat.
type heartbeatBody struct {
	Version    string       `json:"version"`
	BundleETag string       `json:"bundle_etag"`
	Selftest   *CheckReport `json:"selftest,omitempty"`
	Integrity  *CheckReport `json:"integrity,omitempty"`
}
