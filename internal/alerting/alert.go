package alerting

import (
	"encoding/json"
	"maps"
	"strings"
	"time"
	"unicode/utf8"
)

// Статусы оповещения: новое → принято в работу → закрыто (ТЗ 5.6).
const (
	StatusNew        = "new"
	StatusInProgress = "in_progress"
	StatusClosed     = "closed"
)

// transitionAllowed — допустимый переход статуса. Закрытое не открывается:
// повтор после окна подавления — новое оповещение (ADR-0020, п. 5).
func transitionAllowed(from, to string) bool {
	switch from {
	case StatusNew:
		return to == StatusInProgress || to == StatusClosed
	case StatusInProgress:
		return to == StatusClosed
	}
	return false
}

// EventRef — ссылка на событие: ID и ключ секции (время из UUIDv7).
type EventRef struct {
	ID string
	TS time.Time
}

// Alert — оповещение.
type Alert struct {
	ID       string
	OrgID    string
	RuleID   string
	RuleName string
	Kind     string
	Severity string
	Title    string
	Status   string
	DedupKey string
	// Open — оповещение принимает новые срабатывания (open_key задан).
	Open   bool
	Values map[string]string
	// Count — срабатываний, вошедших в оповещение; Suppressed — срабатываний
	// в окне подавления после закрытия.
	Count      int64
	Suppressed int64
	// Время первого и последнего события по часам шлюза; нулевое — не по событиям.
	FirstEventAt    time.Time
	LastEventAt     time.Time
	CreatedAt       time.Time
	LastTriggeredAt time.Time
	UpdatedAt       time.Time
	AssigneeID      string
	ClosedAt        time.Time
	ClosedBy        string
	IncidentID      string
	// Details — подробности без содержимого запросов (список изменений DM-40).
	Details map[string]any
}

func (a *Alert) clone() Alert {
	c := *a
	c.Values = maps.Clone(a.Values)
	c.Details = cloneDetails(a.Details)
	return c
}

func cloneDetails(d map[string]any) map[string]any {
	out := maps.Clone(d)
	if items, ok := out["items"].([]any); ok {
		out["items"] = append([]any(nil), items...)
	}
	if out == nil {
		out = map[string]any{}
	}
	return out
}

// History — переход статуса оповещения.
type History struct {
	ID      string
	AlertID string
	At      time.Time
	Actor   string
	From    string
	To      string
	Comment string
}

// Trigger — срабатывание правила по одному ключу дедупликации.
type Trigger struct {
	Key    string
	Values map[string]string
	Count  int64
	// FirstEvent и LastEvent — время событий по часам шлюза; нулевое —
	// срабатывание не по событиям.
	FirstEvent time.Time
	LastEvent  time.Time
	// Events — ссылки на события, не больше MaxAlertEvents.
	Events []EventRef
	// Details — подробности; список details["items"] дополняется при
	// группировке (не больше MaxDetailItems элементов).
	Details map[string]any
}

// add учитывает событие в срабатывании.
func (t *Trigger) add(ref EventRef, at time.Time) {
	t.Count++
	if t.FirstEvent.IsZero() || at.Before(t.FirstEvent) {
		t.FirstEvent = at
	}
	if at.After(t.LastEvent) {
		t.LastEvent = at
	}
	if len(t.Events) < MaxAlertEvents {
		t.Events = append(t.Events, ref)
	}
}

// mergeDetails дополняет подробности открытого оповещения подробностями
// нового срабатывания: список items склеивается до MaxDetailItems и
// MaxDetailsBytes, прочие поля берутся из нового срабатывания. Элемент
// сверх предела не добавляется, ставится items_truncated: вставка не
// нарушает предел столбца, и действие с записью аудита не откатывается
// (3В16 ревью 3.r2).
func mergeDetails(cur, add map[string]any) map[string]any {
	out := cloneDetails(cur)
	for k, v := range add {
		if k != "items" {
			out[k] = v
		}
	}
	newItems, _ := add["items"].([]any)
	if len(newItems) == 0 {
		return out
	}
	items, _ := out["items"].([]any)
	size := detailsSize(out)
	for _, it := range newItems {
		n := detailsSize(it) + 1
		if len(items) >= MaxDetailItems || size+n > MaxDetailsBytes {
			out["items_truncated"] = true
			break
		}
		items = append(items, it)
		size += n
	}
	out["items"] = items
	return out
}

// detailsSize — размер значения в JSON; неразборное — сверх предела.
func detailsSize(v any) int {
	raw, err := json.Marshal(v)
	if err != nil {
		return MaxDetailsBytes + 1
	}
	return len(raw)
}

// title — заголовок оповещения: название правила и значения группировки.
func title(r *Rule, values map[string]string) string {
	var parts []string
	for _, f := range r.GroupBy {
		if v := values[f]; v != "" {
			parts = append(parts, v)
		}
	}
	s := r.Name
	if len(parts) > 0 {
		s += " — " + strings.Join(parts, ", ")
	}
	if utf8.RuneCountInString(s) > MaxTitle {
		rs := []rune(s)
		s = string(rs[:MaxTitle-1]) + "…"
	}
	return s
}

// AlertQuery — выборка оповещений от новых к старым.
type AlertQuery struct {
	Status   string
	Severity string
	RuleID   string
	// From и To — период по времени последнего срабатывания: [From, To);
	// нулевое время — без границы.
	From, To time.Time
	// After — последняя выданная запись предыдущей страницы.
	After *Position
	Limit int
}

// Position — место в выборке: (время создания, ID).
type Position struct {
	CreatedAt time.Time
	ID        string
}

func (a *Alert) before(p *Position) bool {
	return a.CreatedAt.Before(p.CreatedAt) || a.CreatedAt.Equal(p.CreatedAt) && a.ID < p.ID
}

func (q *AlertQuery) match(a *Alert) bool {
	return (q.Status == "" || a.Status == q.Status) && (q.Severity == "" || a.Severity == q.Severity) &&
		(q.RuleID == "" || a.RuleID == q.RuleID) && (q.After == nil || a.before(q.After)) &&
		(q.From.IsZero() || !a.LastTriggeredAt.Before(q.From)) && (q.To.IsZero() || a.LastTriggeredAt.Before(q.To))
}
