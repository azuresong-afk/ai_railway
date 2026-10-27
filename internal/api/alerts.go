package api

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// alertRoutes — оповещения и правила (ТЗ 5.6; задача 3.10 этапа 3,
// ADR-0020). Смена статуса доступна токену (SOAR); правила — функция
// безопасности (alert_rules.manage): ослабление требует повторной
// проверки паролем или кодом (DM-40).
func alertRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/alerts", Permission: auth.PermAlertsRead, Handler: needAlerts(d, d.listAlerts)},
		{Method: http.MethodGet, Path: "/api/v1/alerts/{id}", Permission: auth.PermAlertsRead, Handler: needAlerts(d, d.getAlert)},
		{Method: http.MethodPost, Path: "/api/v1/alerts/{id}/status", Permission: auth.PermAlertsManage, MaxBody: smallMaxBody,
			Handler: needAlerts(d, d.setAlertStatus)},
		{Method: http.MethodGet, Path: "/api/v1/alert-rules", Permission: auth.PermAlertRulesRead, Handler: needAlerts(d, d.listAlertRules)},
		{Method: http.MethodPost, Path: "/api/v1/alert-rules", Permission: auth.PermAlertRulesManage, Idempotent: true,
			MaxBody: alerting.MaxRuleBody, Handler: needAlerts(d, d.createAlertRule)},
		{Method: http.MethodGet, Path: "/api/v1/alert-rules/{id}", Permission: auth.PermAlertRulesRead, Handler: needAlerts(d, d.getAlertRule)},
		{Method: http.MethodPut, Path: "/api/v1/alert-rules/{id}", Permission: auth.PermAlertRulesManage,
			MaxBody: alerting.MaxRuleBody, Handler: needAlerts(d, d.updateAlertRule)},
		{Method: http.MethodGet, Path: "/api/v1/alert-rules/{id}/state", Permission: auth.PermAlertRulesRead,
			Handler: needAlerts(d, d.getAlertRuleState)},
	}
}

func needAlerts(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Alerts == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Оповещения не подключены на сервере."))
			return
		}
		h(w, r)
	}
}

const (
	alertNotFound = "Оповещение не найдено."
	ruleNotFound  = "Правило оповещения не найдено."
)

// alertsProblem переводит ошибки сервиса оповещений в ответы API.
func alertsProblem(logger *slog.Logger, err error, notFound string) *Problem {
	var ie *alerting.InputError
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Errs))
		for _, e := range ie.Errs {
			f := ""
			if m := fieldRe.FindStringSubmatch(e.Error()); m != nil {
				f = m[1]
			}
			fields = append(fields, FieldError{Field: f, Detail: e.Error()})
		}
		return Invalid("Проверьте введённые данные.", fields...)
	case errors.Is(err, alerting.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, notFound)
	case errors.Is(err, alerting.ErrVersionConflict):
		return NewProblem(http.StatusConflict, CodeConflict, "Правило изменил другой пользователь: обновите страницу и повторите изменение.")
	case errors.Is(err, alerting.ErrTransition):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Статус уже изменён: принять в работу можно новое оповещение, закрыть — новое или принятое в работу.")
	case errors.Is(err, alerting.ErrSelfReview):
		return NewProblem(http.StatusConflict, CodeSelfReview,
			"Оповещение безопасности о ваших собственных действиях закрывает другой пользователь с правом разбора оповещений.")
	case errors.Is(err, alerting.ErrTokenClose):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Системное оповещение и оповещение безопасности закрывает пользователь в консоли, а не токен API. Принять в работу токеном можно.")
	case errors.Is(err, alerting.ErrLocked):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Системное правило и правило безопасности не отключаются и не меняются: можно изменить только получателей.")
	case errors.Is(err, alerting.ErrTooMany):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Достигнут предел в 200 правил: выключите или измените неиспользуемые.")
	case errors.Is(err, alerting.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Изменение ослабляет оповещения: выполните его в консоли с вводом текущего пароля или кода.")
	}
	logger.Error("оповещения: ошибка обработки запроса", "error", err)
	return errInternal()
}

// alertsBy — субъект запроса: для токена исполнитель — его владелец.
func (d Deps) alertsBy(r *http.Request) (alerting.By, bool) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		return alerting.By{}, false
	}
	c := p.Caller
	by := alerting.By{Actor: audit.Actor{Type: audit.ActorUser, ID: c.User.ID, Name: c.User.Login}, IP: clientAddr(r), UserID: c.User.ID}
	if c.Token != nil {
		by.Actor = audit.Actor{Type: audit.ActorAPIToken, ID: c.Token.ID, Name: c.User.Login + " (" + c.Token.Prefix + ")"}
	}
	// 3Н48 ревью 3.r4: владелец не закрывает оповещение о действиях своего
	// токена. Ошибка поиска (кроме «нет токена») — как владение: закрыть нельзя.
	ctx, userID := r.Context(), c.User.ID
	by.OwnsToken = func(tokenID string) bool {
		if d.Auth == nil {
			return true
		}
		owner, err := d.Auth.APITokenOwner(ctx, tokenID)
		if errors.Is(err, auth.ErrAPITokenNotFound) {
			return false
		}
		return err != nil || owner == userID
	}
	return by, true
}

// AlertView — оповещение в списке. Содержимого запросов нет: только
// метаданные группировки и ссылки на события в карточке.
type AlertView struct {
	ID              string            `json:"id"`
	RuleID          string            `json:"rule_id"`
	RuleName        string            `json:"rule_name"`
	Kind            string            `json:"kind"`
	Severity        string            `json:"severity"`
	Title           string            `json:"title"`
	Status          string            `json:"status"`
	Group           map[string]string `json:"group"`
	Count           int64             `json:"count"`
	Suppressed      int64             `json:"suppressed"`
	FirstEventAt    *time.Time        `json:"first_event_at,omitempty"`
	LastEventAt     *time.Time        `json:"last_event_at,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	LastTriggeredAt time.Time         `json:"last_triggered_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	AssigneeID      string            `json:"assignee_id,omitempty"`
	ClosedAt        *time.Time        `json:"closed_at,omitempty"`
	ClosedBy        string            `json:"closed_by,omitempty"`
	IncidentID      string            `json:"incident_id,omitempty"`
}

func alertView(a alerting.Alert) AlertView {
	g := a.Values
	if g == nil {
		g = map[string]string{}
	}
	return AlertView{ID: a.ID, RuleID: a.RuleID, RuleName: a.RuleName, Kind: a.Kind, Severity: a.Severity, Title: a.Title,
		Status: a.Status, Group: g, Count: a.Count, Suppressed: a.Suppressed, FirstEventAt: optTime(a.FirstEventAt),
		LastEventAt: optTime(a.LastEventAt), CreatedAt: a.CreatedAt.UTC(), LastTriggeredAt: a.LastTriggeredAt.UTC(),
		UpdatedAt: a.UpdatedAt.UTC(), AssigneeID: a.AssigneeID, ClosedAt: optTime(a.ClosedAt), ClosedBy: a.ClosedBy,
		IncidentID: a.IncidentID}
}

// AlertEventView — ссылка на событие; карточку события открывает
// GET /api/v1/events/{id} с правом events.read.
type AlertEventView struct {
	ID string    `json:"id"`
	TS time.Time `json:"ts"`
}

// AlertHistoryView — переход статуса.
type AlertHistoryView struct {
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	From    string    `json:"from"`
	To      string    `json:"to"`
	Comment string    `json:"comment"`
}

// AlertCardView — карточка оповещения.
type AlertCardView struct {
	AlertView
	Events []AlertEventView `json:"events"`
	// EventsTruncated — срабатываний больше, чем ссылок (хранятся первые 100).
	EventsTruncated bool               `json:"events_truncated"`
	History         []AlertHistoryView `json:"history"`
	Details         map[string]any     `json:"details"`
}

// alertQuery — фильтры списка оповещений: каждый параметр не больше одного раза.
func alertQuery(r *http.Request) (alerting.AlertQuery, *Problem) {
	q := r.URL.Query()
	var out alerting.AlertQuery
	var bad []FieldError
	one := func(name string, valid func(string) bool, detail string) string {
		vs, ok := q[name]
		if !ok {
			return ""
		}
		if len(vs) != 1 || !valid(vs[0]) {
			bad = append(bad, FieldError{name, detail})
			return ""
		}
		return vs[0]
	}
	out.Status = one("status", func(s string) bool {
		return s == alerting.StatusNew || s == alerting.StatusInProgress || s == alerting.StatusClosed
	}, "Одно из значений: new, in_progress, closed.")
	out.Severity = one("severity", func(s string) bool { return slices.Contains(alerting.Severities(), s) },
		"Одно из значений: info, low, medium, high, critical.")
	out.RuleID = one("rule_id", func(s string) bool { _, err := store.ParseUUID(s); return err == nil }, "Укажите ID правила (UUID).")
	timeParam := func(name string) time.Time {
		vs, ok := q[name]
		if !ok {
			return time.Time{}
		}
		t, err := time.Parse(time.RFC3339Nano, first(vs))
		if len(vs) != 1 || err != nil {
			bad = append(bad, FieldError{name, "Укажите время в формате RFC 3339, например 2026-10-21T15:00:00Z."})
			return time.Time{}
		}
		return t.UTC()
	}
	out.From, out.To = timeParam("from"), timeParam("to")
	if !out.From.IsZero() && !out.To.IsZero() && !out.From.Before(out.To) {
		bad = append(bad, FieldError{"from", "Начало периода должно быть раньше конца (to)."})
	}
	if len(bad) > 0 {
		return alerting.AlertQuery{}, Invalid("Параметры выборки заданы неверно.", bad...)
	}
	return out, nil
}

func (d Deps) listAlerts(w http.ResponseWriter, r *http.Request) {
	page, p := ParsePage(r)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	q, p := alertQuery(r)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	if page.Cursor != nil {
		if _, err := store.ParseUUID(page.Cursor.ID); err != nil {
			WriteProblem(w, Invalid("Параметры страницы заданы неверно.", FieldError{"cursor", "Курсор неверен или устарел: начните выборку сначала."}))
			return
		}
		q.After = &alerting.Position{CreatedAt: time.UnixMicro(page.Cursor.TimeMicro).UTC(), ID: page.Cursor.ID}
	}
	q.Limit = page.Limit + 1
	list, err := d.Alerts.Alerts(r.Context(), q)
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, alertNotFound))
		return
	}
	resp := PageResponse[AlertView]{Items: make([]AlertView, 0, min(len(list), page.Limit))}
	for i, a := range list {
		if i == page.Limit {
			last := list[i-1]
			resp.NextCursor = Cursor{TimeMicro: last.CreatedAt.UnixMicro(), ID: last.ID}.Encode()
			break
		}
		resp.Items = append(resp.Items, alertView(a))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) getAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, alertNotFound)
	if !ok {
		return
	}
	c, err := d.Alerts.Alert(r.Context(), id)
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, alertNotFound))
		return
	}
	v := AlertCardView{AlertView: alertView(c.Alert), Events: make([]AlertEventView, 0, len(c.Events)),
		EventsTruncated: c.Alert.Count > int64(len(c.Events)), History: make([]AlertHistoryView, 0, len(c.History)),
		Details: c.Alert.Details}
	for _, e := range c.Events {
		v.Events = append(v.Events, AlertEventView{ID: e.ID, TS: e.TS.UTC()})
	}
	for _, h := range c.History {
		v.History = append(v.History, AlertHistoryView{At: h.At.UTC(), Actor: h.Actor, From: h.From, To: h.To, Comment: h.Comment})
	}
	if v.Details == nil {
		v.Details = map[string]any{}
	}
	WriteJSON(w, http.StatusOK, v)
}

type alertStatusRequest struct {
	Status  string `json:"status"`
	Comment string `json:"comment"`
}

func (d Deps) setAlertStatus(w http.ResponseWriter, r *http.Request) {
	by, ok := d.alertsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, alertNotFound)
	if !ok {
		return
	}
	var req alertStatusRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	a, err := d.Alerts.SetStatus(r.Context(), by, id, req.Status, req.Comment)
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, alertNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, alertView(a))
}

// AlertRuleView — правило в ответах.
type AlertRuleView struct {
	ID          string `json:"id"`
	Builtin     string `json:"builtin,omitempty"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	// Locked — правило не отключается, меняются только получатели (ТЗ 5.6).
	Locked          bool                `json:"locked"`
	Severity        string              `json:"severity"`
	Condition       alerting.Condition  `json:"condition"`
	GroupBy         []string            `json:"group_by"`
	SuppressMinutes int                 `json:"suppress_minutes"`
	GroupMinutes    int                 `json:"group_minutes"`
	Recipients      alerting.Recipients `json:"recipients"`
	// EffectiveRoles — роли-получатели вместе с обязательными.
	EffectiveRoles []string  `json:"effective_roles"`
	Version        int       `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
	UpdatedAt      time.Time `json:"updated_at"`
	UpdatedBy      string    `json:"updated_by"`
}

func alertRuleView(r alerting.Rule) AlertRuleView {
	g := r.GroupBy
	if g == nil {
		g = []string{}
	}
	rc := r.Recipients
	if rc.Roles == nil {
		rc.Roles = []string{}
	}
	if rc.Users == nil {
		rc.Users = []string{}
	}
	return AlertRuleView{ID: r.ID, Builtin: r.BuiltinKey, Kind: r.Kind, Name: r.Name, Description: r.Description,
		Enabled: r.Enabled, Locked: alerting.Locked(r.Kind), Severity: r.Severity, Condition: r.Condition, GroupBy: g,
		SuppressMinutes: r.SuppressMinutes, GroupMinutes: r.GroupMinutes, Recipients: rc, EffectiveRoles: rc.EffectiveRoles(),
		Version: r.Version, CreatedAt: r.CreatedAt.UTC(), CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt.UTC(), UpdatedBy: r.UpdatedBy}
}

// AlertRuleList — все правила организации (не больше 200 своих и встроенные).
type AlertRuleList struct {
	Items []AlertRuleView `json:"items"`
}

func (d Deps) listAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := d.Alerts.Rules(r.Context())
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, ruleNotFound))
		return
	}
	out := AlertRuleList{Items: make([]AlertRuleView, 0, len(rules))}
	for _, x := range rules {
		out.Items = append(out.Items, alertRuleView(x))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) getAlertRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, ruleNotFound)
	if !ok {
		return
	}
	x, err := d.Alerts.Rule(r.Context(), id)
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, ruleNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, alertRuleView(x))
}

type alertRuleRequest struct {
	alerting.RuleInput
	reauthFields
}

func (d Deps) createAlertRule(w http.ResponseWriter, r *http.Request) {
	by, ok := d.alertsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req alerting.RuleInput
	if p := DecodeJSON(w, r, &req, alerting.MaxRuleBody); p != nil {
		WriteProblem(w, p)
		return
	}
	x, err := d.Alerts.CreateRule(r.Context(), by, req)
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, ruleNotFound))
		return
	}
	w.Header().Set("Location", "/api/v1/alert-rules/"+x.ID)
	WriteJSON(w, http.StatusCreated, alertRuleView(x))
}

func (d Deps) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	by, ok := d.alertsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, ruleNotFound)
	if !ok {
		return
	}
	var req alertRuleRequest
	if p := DecodeJSON(w, r, &req, alerting.MaxRuleBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by.Confirm = d.confirmFunc(r, req.reauthFields, "alert_rule.update", alerting.ErrConfirmRequired)
	x, err := d.Alerts.UpdateRule(r.Context(), by, id, req.RuleInput)
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, ruleNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, alertRuleView(x))
}

// AlertRuleStateView — состояние правила «частота», «аномалия» или
// «бюджет», вычисленное фоновой задачей (задача 3.12): когда считалось, идёт
// ли обучение базовой линии и по каким ключам. Значения — объёмы и
// проценты из агрегатов, без содержимого событий.
type AlertRuleStateView struct {
	RuleID string `json:"rule_id"`
	Kind   string `json:"kind"`
	// Evaluated — фоновая задача уже считала правило; у «порога», «нового»,
	// системных правил и правил безопасности — всегда false.
	Evaluated   bool       `json:"evaluated"`
	EvaluatedAt *time.Time `json:"evaluated_at,omitempty"`
	// Learning — правило «аномалия» на обучении и пока молчит.
	Learning      bool                `json:"learning"`
	LearningUntil *time.Time          `json:"learning_until,omitempty"`
	Month         string              `json:"month,omitempty"`
	Keys          []alerting.KeyState `json:"keys"`
	KeysTotal     int                 `json:"keys_total"`
	// KeysHidden — ключи скрыты: объёмы «аномалии» видны с правом
	// events.read, расход «бюджета» — с budgets.read (3Н13 ревью 3.12).
	KeysHidden bool `json:"keys_hidden"`
	// Warning — предупреждение последнего прохода (evaluation_failed,
	// timezone_invalid); пусто — нет (3В17, 3Н36 ревью 3.r2).
	Warning string `json:"warning,omitempty"`
}

// stateKeysPermission — право, без которого ключи состояния правила вида
// kind не показываются: те же данные закрыты им в других разделах.
func stateKeysPermission(kind string) string {
	switch kind {
	case alerting.KindAnomaly:
		return auth.PermEventsRead
	case alerting.KindBudget:
		return auth.PermBudgetsRead
	}
	return ""
}

func (d Deps) getAlertRuleState(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, ruleNotFound)
	if !ok {
		return
	}
	rule, st, evaluated, err := d.Alerts.RuleState(r.Context(), id)
	if err != nil {
		WriteProblem(w, alertsProblem(d.Logger, err, ruleNotFound))
		return
	}
	v := AlertRuleStateView{RuleID: rule.ID, Kind: rule.Kind, Evaluated: evaluated, Learning: st.Learning,
		LearningUntil: st.LearningUntil, Month: st.Month, Keys: st.Keys, KeysTotal: st.KeysTotal, Warning: st.Warning}
	if evaluated {
		v.EvaluatedAt = optTime(st.EvaluatedAt)
	}
	if perm := stateKeysPermission(rule.Kind); perm != "" {
		if pr, ok := PrincipalFrom(r.Context()); !ok || !pr.Grants.Allows(perm) {
			v.Keys, v.KeysTotal, v.KeysHidden = nil, 0, true
		}
	}
	if v.Keys == nil {
		v.Keys = []alerting.KeyState{}
	}
	for i := range v.Keys {
		if v.Keys[i].Group == nil {
			v.Keys[i].Group = map[string]string{}
		}
	}
	WriteJSON(w, http.StatusOK, v)
}
