package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Журнал аудита в консоли (задача 2.4a): просмотр записей с фильтрами
// (ТЗ 6.3 п. 11) и проверка цепочки по команде (РСБ.4, DM-43). Через API журнал
// только читается (УПД.2); секреты в записях замаскированы при записи.

// AuditJournal — журнал аудита для консоли (*audit.Log).
type AuditJournal interface {
	AuditRecorder
	List(ctx context.Context, q audit.Query) ([]audit.Record, error)
}

// AuditChainVerifier — проверка цепочки, общая с фоновой (*audit.Verifier):
// проверки не идут параллельно, занятая — audit.ErrVerifyBusy.
type AuditChainVerifier interface {
	TryVerifyBy(ctx context.Context, by audit.Actor, ip netip.Addr) (audit.Verification, error)
}

// Пределы эндпоинтов журнала аудита.
const (
	// DefaultAuditRange — период по умолчанию, если from не задан.
	DefaultAuditRange = 7 * 24 * time.Hour
	// auditQueryMax — предел строки запроса списка.
	auditQueryMax    = 8 << 10
	auditReadTimeout = 10 * time.Second
	// auditVerifyTimeout — предел проверки по команде: вся хранимая цепочка.
	auditVerifyTimeout = 5 * time.Minute
	// auditVerifyRetry — через сколько секунд повторить, если проверка занята.
	auditVerifyRetry = 30
	auditVerifyBody  = 1 << 10
)

func auditLogRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/audit", Permission: auth.PermAuditRead, Handler: d.listAudit},
		{Method: http.MethodPost, Path: "/api/v1/audit/verify", Permission: auth.PermAuditVerify,
			MaxBody: auditVerifyBody, Handler: d.verifyAudit},
	}
}

// AuditActorView — субъект записи.
type AuditActorView struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AuditObjectView — объект записи.
type AuditObjectView struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// AuditRecordView — запись журнала в ответе GET /api/v1/audit.
type AuditRecordView struct {
	Seq int64  `json:"seq"`
	ID  string `json:"id"`
	// TS — null, если время записи в БД не читается (подмена в обход CHECK).
	TS          *time.Time      `json:"ts"`
	Actor       AuditActorView  `json:"actor"`
	SourceIP    *string         `json:"source_ip"`
	Action      string          `json:"action"`
	ActionTitle string          `json:"action_title"`
	Object      AuditObjectView `json:"object"`
	Result      string          `json:"result"`
	Details     json.RawMessage `json:"details"`
	Hash        string          `json:"hash"`
}

func auditRecordView(r *audit.Record) AuditRecordView {
	v := AuditRecordView{
		Seq: r.Seq, ID: r.ID, Action: r.Action, Result: string(r.Result),
		Actor:   AuditActorView{Type: string(r.Actor.Type), ID: r.Actor.ID, Name: r.Actor.Name},
		Object:  AuditObjectView{Type: r.Object.Type, ID: r.Object.ID},
		Details: json.RawMessage("null"), Hash: hex.EncodeToString(r.Hash),
	}
	if !r.TS.IsZero() {
		ts := r.TS.UTC()
		v.TS = &ts
	}
	if r.SourceIP.IsValid() {
		s := r.SourceIP.String()
		v.SourceIP = &s
	}
	if ev, ok := audit.Lookup(r.Action); ok {
		v.ActionTitle = ev.Title
	}
	// Тип столбца json гарантирует корректный JSON; проверка — на случай
	// подмены в обход продукта, чтобы ответ не ломался.
	if len(r.Details) > 0 && json.Valid(r.Details) {
		v.Details = r.Details
	}
	return v
}

// auditListParams — разобранные параметры GET /api/v1/audit.
type auditListParams struct {
	query audit.Query
	page  Page
}

// auditSingle — параметры, которые задаются не больше одного раза.
var auditSingle = map[string]int{"actor_type": 0, "actor": 256, "object_type": 64, "object_id": 256, "result": 0}

// parseAuditList разбирает параметры списка по белому списку: from, to,
// action (повторяется), actor_type, actor, object_type, object_id, result,
// limit, cursor.
func parseAuditList(r *http.Request, now time.Time) (auditListParams, *Problem) {
	if len(r.URL.RawQuery) > auditQueryMax {
		return auditListParams{}, Invalid("Строка запроса слишком длинная.")
	}
	q := r.URL.Query()
	var bad []FieldError
	for k := range q {
		switch k {
		case "from", "to", "action", "limit", "cursor":
		default:
			if _, ok := auditSingle[k]; !ok {
				return auditListParams{}, Invalid("Неизвестный параметр запроса.", FieldError{k,
					"Допустимы from, to, action, actor_type, actor, object_type, object_id, result, limit, cursor."})
			}
		}
	}
	page, p := ParsePage(r)
	if p != nil {
		return auditListParams{}, p
	}
	from, to, rangeBad := parseRange(q, now, DefaultAuditRange)
	bad = append(bad, rangeBad...)
	if len(rangeBad) == 0 && (!from.Before(to) || to.Sub(from) > audit.MaxQueryRange) {
		bad = append(bad, FieldError{"from", "Период: from раньше to, не длиннее " +
			strconv.Itoa(int(audit.MaxQueryRange.Hours()/24)) + " суток."})
	}
	out := auditListParams{page: page, query: audit.Query{From: from, To: to, Limit: page.Limit + 1}}
	if c := page.Cursor; c != nil {
		seq, err := strconv.ParseInt(c.ID, 10, 64)
		if err != nil || seq < 1 || !validDecimal(c.ID) {
			bad = append(bad, FieldError{"cursor", "Курсор неверен или устарел: начните выборку сначала."})
		}
		out.query.BeforeSeq = seq
	}
	if vs := q["action"]; len(vs) > audit.MaxQueryActions {
		bad = append(bad, FieldError{"action", "Не больше " + strconv.Itoa(audit.MaxQueryActions) + " кодов событий."})
	} else {
		for _, a := range vs {
			if g, ok := strings.CutSuffix(a, ".*"); ok && audit.ValidActionGroup(g) {
				out.query.Groups = append(out.query.Groups, g)
			} else if audit.ValidAction(a) {
				out.query.Actions = append(out.query.Actions, a)
			} else {
				bad = append(bad, FieldError{"action", "Укажите код события (auth.login) или группу (auth.*)."})
				break
			}
		}
	}
	for k, maxLen := range auditSingle {
		vs, ok := q[k]
		if !ok {
			continue
		}
		v := first(vs)
		if len(vs) != 1 || v == "" || !utf8.ValidString(v) || maxLen > 0 && utf8.RuneCountInString(v) > maxLen {
			bad = append(bad, FieldError{k, "Укажите одно непустое значение."})
			continue
		}
		switch k {
		case "actor_type":
			switch t := audit.ActorType(v); t {
			case audit.ActorUser, audit.ActorAPIToken, audit.ActorSystem, audit.ActorGateway, audit.ActorCLI:
				out.query.ActorType = t
			default:
				bad = append(bad, FieldError{k, "Допустимы user, api_token, system, gateway, cli."})
			}
		case "actor":
			out.query.Actor = v
		case "object_type":
			out.query.ObjectType = v
		case "object_id":
			out.query.ObjectID = v
		case "result":
			switch res := audit.Result(v); res {
			case audit.ResultSuccess, audit.ResultFailure, audit.ResultDenied:
				out.query.Result = res
			default:
				bad = append(bad, FieldError{k, "Допустимы success, failure, denied."})
			}
		}
	}
	if len(bad) > 0 {
		slices.SortFunc(bad, func(a, b FieldError) int { return strings.Compare(a.Field, b.Field) })
		return auditListParams{}, Invalid("Параметры выборки заданы неверно.", bad...)
	}
	// Повторная проверка теми же правилами, что в internal/audit: расхождение
	// разбора и выборки — ошибка программиста, а не запроса.
	if err := out.query.Validate(); err != nil {
		return auditListParams{}, Invalid("Параметры выборки заданы неверно.")
	}
	return out, nil
}

func (d Deps) listAudit(w http.ResponseWriter, r *http.Request) {
	if d.AuditLog == nil {
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Журнал аудита не подключён к серверу."))
		return
	}
	p, _ := PrincipalFrom(r.Context())
	lp, prob := parseAuditList(r, time.Now().UTC())
	if prob != nil {
		WriteProblem(w, prob)
		return
	}
	ctx, cancel := contextTimeout(r, auditReadTimeout)
	defer cancel()
	list, err := d.AuditLog.List(ctx, lp.query)
	if errors.Is(err, context.DeadlineExceeded) {
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Запрос выполнялся слишком долго: сузьте период или фильтр."))
		return
	}
	if err != nil {
		d.Logger.Error("журнал аудита не прочитан", "error", err)
		WriteProblem(w, errInternal())
		return
	}
	resp := PageResponse[AuditRecordView]{Items: make([]AuditRecordView, 0, min(len(list), lp.page.Limit))}
	for i := range list {
		if i == lp.page.Limit {
			last := list[i-1]
			resp.NextCursor = Cursor{TimeMicro: max(last.TS.UnixMicro(), 0), ID: strconv.FormatInt(last.Seq, 10)}.Encode()
			break
		}
		resp.Items = append(resp.Items, auditRecordView(&list[i]))
	}
	// Просмотр — необязательное событие audit.list (РСБ.1). Пишется после
	// чтения: в текущую страницу не попадает, рекурсии нет. Сбой записи не
	// мешает ответу, но попадает в технический журнал.
	q := lp.query
	details := map[string]any{"from": q.From, "to": q.To, "count": len(resp.Items), "next_page": lp.page.Cursor != nil}
	for k, v := range map[string]string{"actor_type": string(q.ActorType), "actor": q.Actor,
		"object_type": q.ObjectType, "object_id": q.ObjectID, "result": string(q.Result)} {
		if v != "" {
			details[k] = v
		}
	}
	if len(q.Actions) > 0 {
		details["actions"] = q.Actions
	}
	if len(q.Groups) > 0 {
		details["groups"] = q.Groups
	}
	actx, acancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer acancel()
	if err := d.AuditLog.Record(actx, audit.Entry{
		Actor: eventsActor(p), SourceIP: clientAddr(r), Action: "audit.list", Object: audit.Object{Type: "audit_log"},
		Result: audit.ResultSuccess, Details: details,
	}); err != nil {
		d.Logger.Error("просмотр журнала аудита не записан в журнал аудита", "error", err)
	}
	WriteJSON(w, http.StatusOK, resp)
}

// AuditVerifyView — итог проверки цепочки (ответ POST /api/v1/audit/verify).
type AuditVerifyView struct {
	CheckedAt time.Time `json:"checked_at"`
	OK        bool      `json:"ok"`
	Checked   int64     `json:"checked"`
	LastSeq   int64     `json:"last_seq"`
	// Reason — ok или причина нарушения (как audit_chain «Состояния системы»).
	Reason    string `json:"reason"`
	BrokenSeq *int64 `json:"broken_seq"`
}

func auditVerifyView(res audit.Verification) AuditVerifyView {
	v := AuditVerifyView{CheckedAt: res.At.UTC(), OK: res.OK(), Checked: res.Checked, LastSeq: res.Head.Seq, Reason: "ok"}
	if b := res.Break; b != nil {
		seq := b.Seq
		v.Reason, v.BrokenSeq = string(b.Reason), &seq
	}
	return v
}

func (d Deps) verifyAudit(w http.ResponseWriter, r *http.Request) {
	if d.AuditVerifier == nil {
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Проверка цепочки журнала аудита не подключена к серверу."))
		return
	}
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	// Обрыв соединения не прерывает проверку: начатая по команде проверка
	// доходит до конца, итог — в журнале аудита и «Состоянии системы».
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditVerifyTimeout)
	defer cancel()
	res, err := d.AuditVerifier.TryVerifyBy(ctx, eventsActor(p), clientAddr(r))
	switch {
	case errors.Is(err, audit.ErrVerifyBusy):
		w.Header().Set("Retry-After", strconv.Itoa(auditVerifyRetry))
		WriteProblem(w, NewProblem(http.StatusConflict, CodeConflict,
			"Проверка цепочки уже выполняется. Повторите через "+strconv.Itoa(auditVerifyRetry)+" секунд."))
		return
	case errors.Is(err, context.DeadlineExceeded):
		d.Logger.Error("проверка цепочки журнала аудита по команде не уложилась в срок", "class", "db", "timeout", auditVerifyTimeout.String())
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Проверка не уложилась в отведённое время: повторите позже."))
		return
	case err != nil:
		d.Logger.Error("проверка цепочки журнала аудита по команде не выполнена", "error", err)
		WriteProblem(w, errInternal())
		return
	}
	WriteJSON(w, http.StatusOK, auditVerifyView(res))
}
