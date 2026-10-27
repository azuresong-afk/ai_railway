package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/approvals"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// approvalCreateMaxBody — аргументы до 16 КиБ; символы вне ASCII в JSON
// экранируются до 6 байт.
const approvalCreateMaxBody = 6*approvals.MaxArgs + 8<<10

// ApprovalsInternalRoutes — очередь подтверждений для шлюзов (DM-22; задача
// 4.10, ADR-0023, раздел 5): шлюз создаёт запрос, ждёт решения долгим
// опросом (wait до 25 с) и отменяет запрос, когда клиент закрыл поток.
// Шлюз видит только свои запросы: чужой ID — 404.
func ApprovalsInternalRoutes(svc *approvals.Service, logger *slog.Logger) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/internal/v1/approvals", Permission: PermGatewayInternal,
			MaxBody: approvalCreateMaxBody, Handler: createApproval(svc, logger)},
		{Method: http.MethodGet, Path: "/internal/v1/approvals/{id}", Permission: PermGatewayInternal,
			Handler: waitApproval(svc, logger)},
		{Method: http.MethodPost, Path: "/internal/v1/approvals/{id}/cancel", Permission: PermGatewayInternal,
			MaxBody: smallMaxBody, Handler: cancelApproval(svc, logger)},
	}
}

// CreateApprovalRequest — тело POST /internal/v1/approvals.
type CreateApprovalRequest struct {
	Path    string `json:"path"`
	App     string `json:"app"`
	Agent   string `json:"agent,omitempty"`
	User    string `json:"user,omitempty"`
	Session string `json:"session,omitempty"`
	Server  string `json:"server"`
	Tool    string `json:"tool"`
	// ApprovedHash — хеш одобренного описания инструмента (hex).
	ApprovedHash string          `json:"approved_hash,omitempty"`
	Risk         policy.ToolRisk `json:"risk"`
	Rule         string          `json:"rule"`
	Message      string          `json:"message,omitempty"`
	Severity     policy.Severity `json:"severity"`
	// ArgsHash — хеш аргументов, которые шлюз передаст после одобрения.
	ArgsHash string `json:"args_hash"`
	// Args — маскированные аргументы для дежурного.
	Args           string `json:"args"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	RequestEventID string `json:"request_event_id,omitempty"`
}

// ApprovalStatus — состояние запроса для шлюза: решение связано с ID,
// хешем аргументов и одобренным хешем описания.
type ApprovalStatus struct {
	ID           string          `json:"id"`
	State        approvals.State `json:"state"`
	ArgsHash     string          `json:"args_hash"`
	ApprovedHash string          `json:"approved_hash"`
	Deadline     time.Time       `json:"deadline"`
	ClosedAt     *time.Time      `json:"closed_at,omitempty"`
	// DecidedBy — логин пользователя консоли (approved, denied).
	DecidedBy string `json:"decided_by,omitempty"`
	Comment   string `json:"comment,omitempty"`
	WaitedMS  int64  `json:"waited_ms"`
}

func approvalStatus(r approvals.Request, now time.Time) ApprovalStatus {
	st := ApprovalStatus{ID: r.ID, State: r.State, ArgsHash: r.ArgsHash, ApprovedHash: r.ApprovedHash, Deadline: r.Deadline.UTC(),
		DecidedBy: r.DecidedByName, Comment: r.Comment, WaitedMS: r.Waited(now).Milliseconds()}
	if !r.ClosedAt.IsZero() {
		at := r.ClosedAt.UTC()
		st.ClosedAt = &at
	}
	return st
}

// internalApprovalProblem — ошибки очереди для шлюза.
func internalApprovalProblem(logger *slog.Logger, err error, gatewayID string) *Problem {
	var ie *approvals.InputError
	switch {
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Errs))
		for _, e := range ie.Errs {
			f, _, _ := strings.Cut(e.Error(), " ")
			fields = append(fields, FieldError{Field: f, Detail: e.Error()})
		}
		return Invalid("Неверный запрос подтверждения.", fields...)
	case errors.Is(err, approvals.ErrQueueFull):
		return NewProblem(http.StatusTooManyRequests, CodeApprovalQueueFull,
			"Очередь подтверждений переполнена: 256 ожидающих запросов на шлюз или 16 на агента.")
	case errors.Is(err, approvals.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Запрос подтверждения не найден.")
	case errors.Is(err, approvals.ErrNoDataKey):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Ключ данных не подключён: очередь подтверждений недоступна.")
	}
	logger.Error("подтверждения: ошибка обработки запроса шлюза", "error", err, "gateway_id", gatewayID)
	return errInternal()
}

func createApproval(svc *approvals.Service, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		var req CreateApprovalRequest
		if prob := DecodeJSON(w, r, &req, approvalCreateMaxBody); prob != nil {
			WriteProblem(w, prob)
			return
		}
		if req.TimeoutSeconds < 0 || req.TimeoutSeconds > int(approvals.MaxTimeout/time.Second) {
			WriteProblem(w, Invalid("Неверный запрос подтверждения.", FieldError{Field: "timeout_seconds", Detail: "от 60 до 3600"}))
			return
		}
		ctx, cancel := contextTimeout(r, 5*time.Second)
		defer cancel()
		res, err := svc.Create(ctx, p.ID, approvals.CreateInput{Path: req.Path, App: req.App, Agent: req.Agent, User: req.User,
			Session: req.Session, Server: req.Server, Tool: req.Tool, ApprovedHash: req.ApprovedHash, Risk: req.Risk, Rule: req.Rule,
			Message: req.Message, Severity: req.Severity, ArgsHash: req.ArgsHash, Args: req.Args,
			Timeout: time.Duration(req.TimeoutSeconds) * time.Second, RequestEventID: req.RequestEventID})
		if err != nil {
			WriteProblem(w, internalApprovalProblem(logger, err, p.ID))
			return
		}
		WriteJSON(w, http.StatusCreated, approvalStatus(res, res.CreatedAt))
	}
}

// ParseWait разбирает параметр wait долгого опроса: целые секунды с
// суффиксом «s», от 0 до 25. Пусто — без ожидания.
func ParseWait(s string) (time.Duration, bool) {
	if s == "" {
		return 0, true
	}
	n, ok := strings.CutSuffix(s, "s")
	if !ok || n == "" || len(n) > 2 || strings.TrimLeft(n, "0123456789") != "" {
		return 0, false
	}
	v, err := strconv.Atoi(n)
	if err != nil || time.Duration(v)*time.Second > approvals.MaxWait {
		return 0, false
	}
	return time.Duration(v) * time.Second, true
}

func waitApproval(svc *approvals.Service, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		q := r.URL.Query()
		for k, v := range q {
			if k != "wait" || len(v) > 1 {
				WriteProblem(w, Invalid("Неверные параметры: допускается один параметр wait.", FieldError{Field: "wait", Detail: "один параметр"}))
				return
			}
		}
		wait, ok := ParseWait(q.Get("wait"))
		if !ok {
			WriteProblem(w, Invalid("Неверный параметр wait: целые секунды от 0s до 25s.", FieldError{Field: "wait", Detail: "0s–25s"}))
			return
		}
		// Опрос держит соединение до wait; запрос к БД внутри — со своим сроком.
		ctx, cancel := contextTimeout(r, wait+5*time.Second)
		defer cancel()
		res, err := svc.Wait(ctx, p.ID, r.PathValue("id"), wait)
		if err != nil && r.Context().Err() != nil {
			return // шлюз ушёл
		}
		if err != nil {
			WriteProblem(w, internalApprovalProblem(logger, err, p.ID))
			return
		}
		WriteJSON(w, http.StatusOK, approvalStatus(res, time.Now()))
	}
}

func cancelApproval(svc *approvals.Service, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		ctx, cancel := contextTimeout(r, 5*time.Second)
		defer cancel()
		res, err := svc.Cancel(ctx, p.ID, r.PathValue("id"))
		if err != nil {
			WriteProblem(w, internalApprovalProblem(logger, err, p.ID))
			return
		}
		WriteJSON(w, http.StatusOK, approvalStatus(res, time.Now()))
	}
}
