// Пакет quotalease — распределённые квоты и бюджеты при нескольких шлюзах
// (ADR-0021, задача 4.29 этапа 4). В режиме leased счётчики ведёт сервер
// управления, а шлюз берёт у него аренду — долю квоты на короткий срок —
// запросом POST /internal/v1/quota-leases по mTLS. Внутри аренды шлюз
// считает сам и к серверу на каждый запрос не обращается. Выданная единица
// учитывается сразу при выдаче, поэтому сумма выданного в окне не больше
// лимита при любом числе шлюзов. Режим local (по умолчанию) — счётчики в
// памяти каждого шлюза, как на этапе 3.
//
// Аренда не содержит секретов и содержимого запросов: только ID
// приложений, имена квот и числа.
package quotalease

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// Квоты, которые распределяются (ADR-0021, п. 1). Ограничения одного
// запроса и квоты на пользователя и ключ остаются локальными.
const (
	QuotaRPM    = "requests_per_minute"
	QuotaTPM    = "tokens_per_minute"
	QuotaTPD    = "tokens_per_day"
	QuotaBudget = "budget"
)

// Quotas — распределяемые квоты в порядке блокировки строк.
var Quotas = []string{QuotaBudget, QuotaRPM, QuotaTPD, QuotaTPM}

// Режимы установки (install_settings.quota_mode).
const (
	ModeLocal  = "local"
	ModeLeased = "leased"
)

// Пределы запроса аренды (ADR-0021, п. 6).
const (
	// MaxBody — тело запроса.
	MaxBody = 64 << 10
	// MaxApps — приложений в запросе (bundle.MaxApplications).
	MaxApps = 2000
	// MaxReports — отчётов об аренде в одной квоте: шлюз держит текущую
	// и следующую аренду, остальное — запас на отложенные отчёты.
	MaxReports = 8
	// MaxUnits — предел числа в запросе и ответе.
	MaxUnits = 1 << 62
	// MaxResponse — ответ на запрос предельного размера.
	MaxResponse = 512 << 10
)

// Сроки аренды (ADR-0021, п. 3).
const (
	// MinuteTTL — аренда минутных квот.
	MinuteTTL = 10 * time.Second
	// LongTTL — аренда суточной квоты и бюджета.
	LongTTL = 5 * time.Minute
	// MinuteWindow — окно минутных квот: выдача учитывается, пока не
	// прошла минута после её срока (расход внутри аренды — не позже срока).
	MinuteWindow = time.Minute
)

var (
	appRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Request — тело POST /internal/v1/quota-leases: приложения, которым нужна
// доля или по которым есть отчёт.
type Request struct {
	Apps []AppRequest `json:"apps"`
}

// AppRequest — квоты одного приложения.
type AppRequest struct {
	App    string         `json:"app"`
	Quotas []QuotaRequest `json:"quotas"`
}

// QuotaRequest — квота приложения: сколько единиц нужно (0 — только
// отчёт), отчёты о прошлых арендах и расход на автономной доле с прошлого
// успешного запроса. RequestID — UUID запроса шлюза: повтор с тем же ID
// возвращает ту же выдачу и не учитывает автономный расход ещё раз.
type QuotaRequest struct {
	Quota     string        `json:"quota"`
	RequestID string        `json:"request_id"`
	Want      int64         `json:"want"`
	Reports   []LeaseReport `json:"reports,omitempty"`
	Offline   int64         `json:"offline,omitempty"`
}

// LeaseReport — израсходовано из аренды Lease. После отчёта шлюз аренду не
// использует, неизрасходованный остаток возвращается в окно.
type LeaseReport struct {
	Lease string `json:"lease"`
	Used  int64  `json:"used"`
}

// Response — ответ: время сервера, число шлюзов на связи (для автономной
// доли) и выдачи по квотам с Want > 0.
type Response struct {
	ServerTime time.Time     `json:"server_time"`
	Gateways   int           `json:"gateways"`
	Apps       []AppResponse `json:"apps"`
}

// AppResponse — выдачи по квотам приложения.
type AppResponse struct {
	App    string  `json:"app"`
	Quotas []Grant `json:"quotas"`
}

// Grant — выдача. Granted = 0 — свободного остатка нет (RetryAfterMS —
// когда освободится); Unlimited — у приложения на сервере нет этого
// лимита; Unknown — приложения нет среди действующих.
type Grant struct {
	Quota        string `json:"quota"`
	RequestID    string `json:"request_id"`
	Lease        string `json:"lease,omitempty"`
	Granted      int64  `json:"granted"`
	TTLMS        int64  `json:"ttl_ms"`
	Remaining    int64  `json:"remaining"`
	Limit        int64  `json:"limit"`
	RetryAfterMS int64  `json:"retry_after_ms,omitempty"`
	Unlimited    bool   `json:"unlimited,omitempty"`
	Unknown      bool   `json:"unknown,omitempty"`
}

// ErrInvalid — запрос не прошёл проверку формата и пределов.
var ErrInvalid = errors.New("аренда квот: неверный запрос")

// Parse разбирает тело запроса строго (неизвестные поля и данные после
// JSON — ошибка) и проверяет пределы. Тело больше MaxBody не принимается.
func Parse(data []byte) (Request, error) {
	if len(data) > MaxBody {
		return Request{}, fmt.Errorf("%w: тело больше %d байт", ErrInvalid, MaxBody)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Request
	if err := dec.Decode(&r); err != nil {
		return Request{}, fmt.Errorf("%w: не JSON или неизвестные поля", ErrInvalid)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Request{}, fmt.Errorf("%w: данные после JSON", ErrInvalid)
	}
	if err := r.Validate(); err != nil {
		return Request{}, err
	}
	return r, nil
}

// Validate проверяет пределы: до MaxApps приложений без повторов, у
// приложения — до четырёх разных квот, у квоты — UUID запроса без повторов
// в запросе, числа 0–MaxUnits, до MaxReports отчётов о разных арендах.
func (r Request) Validate() error {
	if len(r.Apps) == 0 || len(r.Apps) > MaxApps {
		return fmt.Errorf("%w: apps — от 1 до %d", ErrInvalid, MaxApps)
	}
	apps := make(map[string]bool, len(r.Apps))
	ids := map[string]bool{}
	leases := map[string]bool{}
	for i, a := range r.Apps {
		if !appRe.MatchString(a.App) || apps[a.App] {
			return fmt.Errorf("%w: apps[%d].app — ID приложения без повторов", ErrInvalid, i)
		}
		apps[a.App] = true
		if len(a.Quotas) == 0 || len(a.Quotas) > len(Quotas) {
			return fmt.Errorf("%w: apps[%d].quotas — от 1 до %d", ErrInvalid, i, len(Quotas))
		}
		seen := map[string]bool{}
		for j, q := range a.Quotas {
			at := fmt.Sprintf("apps[%d].quotas[%d]", i, j)
			if !validQuota(q.Quota) || seen[q.Quota] {
				return fmt.Errorf("%w: %s.quota — одна из распределяемых квот без повторов", ErrInvalid, at)
			}
			seen[q.Quota] = true
			if !uuidRe.MatchString(q.RequestID) || ids[q.RequestID] {
				return fmt.Errorf("%w: %s.request_id — UUID без повторов", ErrInvalid, at)
			}
			ids[q.RequestID] = true
			if q.Want < 0 || q.Want > MaxUnits || q.Offline < 0 || q.Offline > MaxUnits {
				return fmt.Errorf("%w: %s: want и offline — от 0 до 2^62", ErrInvalid, at)
			}
			if len(q.Reports) > MaxReports {
				return fmt.Errorf("%w: %s.reports — не больше %d", ErrInvalid, at, MaxReports)
			}
			for k, rep := range q.Reports {
				if !uuidRe.MatchString(rep.Lease) || leases[rep.Lease] || rep.Used < 0 || rep.Used > MaxUnits {
					return fmt.Errorf("%w: %s.reports[%d] — UUID аренды без повторов и used от 0 до 2^62", ErrInvalid, at, k)
				}
				leases[rep.Lease] = true
			}
		}
	}
	return nil
}

func validQuota(q string) bool {
	for _, x := range Quotas {
		if q == x {
			return true
		}
	}
	return false
}

// ValidMode — режим установки.
func ValidMode(m string) bool { return m == ModeLocal || m == ModeLeased }
