package api

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/approvals"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// approvalRoutes — очередь подтверждений вызовов инструментов агентов
// (ТЗ 5.10, DM-22; задача 4.10, ADR-0023, разделы 5 и 9). Решает человек:
// approvals.decide — право безопасности (администратор безопасности,
// аналитик), токенам API и администратору системы не выдаётся. Аргументы
// вызова (маскированные шлюзом) видит только тот, кто решает; одобрение
// вызова с риском critical — с повторной проверкой пароля или кода.
func approvalRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/approvals", Permission: auth.PermApprovalsRead,
			Handler: needApprovals(d, d.listApprovals)},
		{Method: http.MethodGet, Path: "/api/v1/approvals/{id}", Permission: auth.PermApprovalsRead,
			Handler: needApprovals(d, d.getApproval)},
		{Method: http.MethodPost, Path: "/api/v1/approvals/{id}/approve", Permission: auth.PermApprovalsDecide,
			MaxBody: smallMaxBody, Handler: needApprovals(d, d.approveApproval)},
		{Method: http.MethodPost, Path: "/api/v1/approvals/{id}/deny", Permission: auth.PermApprovalsDecide,
			MaxBody: smallMaxBody, Handler: needApprovals(d, d.denyApproval)},
	}
}

func needApprovals(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Approvals == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Очередь подтверждений не подключена на сервере."))
			return
		}
		h(w, r)
	}
}

const approvalNotFound = "Запрос подтверждения не найден."

// approvalsProblem переводит ошибки очереди в ответы API.
func approvalsProblem(logger *slog.Logger, err error) *Problem {
	var ie *approvals.InputError
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Errs))
		for _, e := range ie.Errs {
			fields = append(fields, FieldError{Field: "comment", Detail: e.Error()})
		}
		return Invalid("Проверьте введённые данные.", fields...)
	case errors.Is(err, approvals.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, approvalNotFound)
	case errors.Is(err, approvals.ErrExpired):
		return NewProblem(http.StatusConflict, CodeConflict, "Срок подтверждения истёк: вызов уже отклонён шлюзом.")
	case errors.Is(err, approvals.ErrClosed):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Запрос уже закрыт: его решил другой пользователь, отменил агент или прервал перезапуск шлюза.")
	case errors.Is(err, approvals.ErrStale):
		return NewProblem(http.StatusConflict, CodeConflict, "Аргументы вызова не совпадают с показанными: обновите страницу и проверьте их.")
	case errors.Is(err, approvals.ErrHumanRequired):
		return errForbidden()
	case errors.Is(err, approvals.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Вызов с риском «критический» подтверждается с вводом текущего пароля или кода.")
	case errors.Is(err, approvals.ErrNoDataKey):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Ключ данных не подключён: аргументы вызова недоступны. Выполните aisec-cli init и перезапустите сервер.")
	}
	logger.Error("подтверждения: ошибка обработки запроса", "error", err)
	return errInternal()
}

// ApprovalView — запрос подтверждения в ответах. Args — маскированные
// аргументы; только у пользователя с approvals.decide и пока не удалены
// по сроку (30 суток после закрытия).
type ApprovalView struct {
	ID            string          `json:"id"`
	State         approvals.State `json:"state"`
	Path          string          `json:"path"`
	ApplicationID string          `json:"application"`
	Agent         string          `json:"agent,omitempty"`
	User          string          `json:"user,omitempty"`
	Session       string          `json:"session,omitempty"`
	Server        string          `json:"server"`
	Tool          string          `json:"tool"`
	ApprovedHash  string          `json:"approved_hash,omitempty"`
	Risk          policy.ToolRisk `json:"risk"`
	Rule          string          `json:"rule"`
	Message       string          `json:"message,omitempty"`
	Severity      policy.Severity `json:"severity"`
	ArgsHash      string          `json:"args_hash"`
	Args          *string         `json:"args,omitempty"`
	GatewayID     string          `json:"gateway_id"`
	EventID       string          `json:"request_event_id,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	Deadline      time.Time       `json:"deadline"`
	ClosedAt      *time.Time      `json:"closed_at,omitempty"`
	DecidedBy     string          `json:"decided_by,omitempty"`
	Comment       string          `json:"comment,omitempty"`
	WaitedMS      int64           `json:"waited_ms"`
	ArgsDeleted   bool            `json:"args_deleted,omitempty"`
}

// approvalView — карточка запроса. Хеш аргументов и комментарий решения
// нужны только тем, кто решает (approvals.decide): аудитору они не
// выдаются (ревью 4.r1, 4В9, 4Н8).
func approvalView(r approvals.Request, now time.Time, decide bool) ApprovalView {
	v := ApprovalView{ID: r.ID, State: r.State, Path: r.Path, ApplicationID: r.App, Agent: r.Agent, User: r.User, Session: r.Session,
		Server: r.Server, Tool: r.Tool, ApprovedHash: r.ApprovedHash, Risk: r.Risk, Rule: r.Rule, Message: r.Message,
		Severity: r.Severity, GatewayID: r.GatewayID, EventID: r.RequestEventID,
		CreatedAt: r.CreatedAt.UTC(), Deadline: r.Deadline.UTC(), DecidedBy: r.DecidedByName,
		WaitedMS: r.Waited(now).Milliseconds(), ArgsDeleted: r.Args == nil}
	if decide {
		v.ArgsHash, v.Comment = r.ArgsHash, r.Comment
	}
	if !r.ClosedAt.IsZero() {
		at := r.ClosedAt.UTC()
		v.ClosedAt = &at
	}
	return v
}

var approvalSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func (d Deps) listApprovals(w http.ResponseWriter, r *http.Request) {
	page, p := ParsePage(r)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	q := r.URL.Query()
	f := approvals.Filter{Limit: page.Limit + 1}
	var bad []FieldError
	if vs, ok := q["state"]; ok {
		f.State = approvals.State(first(vs))
		if len(vs) != 1 || !approvals.ValidState(f.State) {
			bad = append(bad, FieldError{"state", "Одно из: pending, approved, denied, timeout, cancelled, interrupted."})
		}
	}
	for _, x := range []struct {
		name string
		dst  *string
	}{{"application", &f.App}, {"agent", &f.Agent}} {
		if vs, ok := q[x.name]; ok {
			*x.dst = first(vs)
			if len(vs) != 1 || !approvalSlugRe.MatchString(*x.dst) {
				bad = append(bad, FieldError{x.name, "Укажите один ID (slug)."})
			}
		}
	}
	if len(bad) > 0 {
		WriteProblem(w, Invalid("Параметры выборки заданы неверно.", bad...))
		return
	}
	if page.Cursor != nil {
		f.AfterTime, f.AfterID = time.UnixMicro(page.Cursor.TimeMicro).UTC(), page.Cursor.ID
		if !approvals.ValidID(f.AfterID) {
			WriteProblem(w, Invalid("Параметры страницы заданы неверно.", FieldError{"cursor", "Курсор неверен или устарел: начните выборку сначала."}))
			return
		}
	}
	list, err := d.Approvals.List(r.Context(), f)
	if err != nil {
		WriteProblem(w, approvalsProblem(d.Logger, err))
		return
	}
	now := time.Now()
	decide := canDecide(r)
	resp := PageResponse[ApprovalView]{Items: make([]ApprovalView, 0, min(len(list), page.Limit))}
	for i, a := range list {
		if i == page.Limit {
			last := list[i-1]
			resp.NextCursor = Cursor{TimeMicro: last.CreatedAt.UnixMicro(), ID: last.ID}.Encode()
			break
		}
		resp.Items = append(resp.Items, approvalView(a, now, decide))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) getApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, approvalNotFound)
	if !ok {
		return
	}
	a, err := d.Approvals.Get(r.Context(), id)
	if err != nil {
		WriteProblem(w, approvalsProblem(d.Logger, err))
		return
	}
	decide := canDecide(r)
	v := approvalView(a, time.Now(), decide)
	// Аргументы нужны дежурному для решения (ТЗ 5.10); аудитор видит запрос
	// без них, как события без содержимого.
	if decide && a.Args != nil {
		args, err := d.Approvals.Args(r.Context(), a)
		if err != nil {
			WriteProblem(w, approvalsProblem(d.Logger, err))
			return
		}
		s := string(args)
		v.Args = &s
	}
	WriteJSON(w, http.StatusOK, v)
}

type decideApprovalRequest struct {
	// ArgsHash — хеш аргументов показанного запроса (одобрение).
	ArgsHash string `json:"args_hash"`
	Comment  string `json:"comment"`
	reauthFields
}

// approvalsBy — субъект решения: только пользователь в сессии консоли.
func (d Deps) approvalsBy(r *http.Request, re reauthFields, action string) (approvals.By, bool) {
	c, ok := callerFrom(r)
	if !ok || c.Token != nil {
		return approvals.By{}, false
	}
	return approvals.By{Actor: audit.Actor{Type: audit.ActorUser, ID: c.User.ID, Name: c.User.Login}, IP: clientAddr(r),
		Confirm: d.confirmFunc(r, re, action, approvals.ErrConfirmRequired)}, true
}

func (d Deps) decideApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	id, ok := pathID(w, r, approvalNotFound)
	if !ok {
		return
	}
	var req decideApprovalRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	action := "agent.approval.deny"
	if approve {
		action = "agent.approval.approve"
	}
	by, ok := d.approvalsBy(r, req.reauthFields, action)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	a, err := d.Approvals.Decide(r.Context(), by, id, approvals.DecideInput{Approve: approve, Comment: req.Comment, ArgsHash: req.ArgsHash})
	if err != nil {
		WriteProblem(w, approvalsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, approvalView(a, time.Now(), true))
}

// canDecide — у субъекта есть право решать (approvals.decide).
func canDecide(r *http.Request) bool {
	p, ok := PrincipalFrom(r.Context())
	return ok && p.Grants.Allows(auth.PermApprovalsDecide)
}

func (d Deps) approveApproval(w http.ResponseWriter, r *http.Request) { d.decideApproval(w, r, true) }

func (d Deps) denyApproval(w http.ResponseWriter, r *http.Request) { d.decideApproval(w, r, false) }
