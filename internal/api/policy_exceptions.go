package api

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

// Исключения в политиках (ТЗ 5.3; решение Р8 этапа 3, задача 3.22).
// Исключение — часть версии политики (ADR-0016): добавление, продление и
// удаление создают новую версию поверх base_version. Добавление и
// продление — ослабление защиты: пароль или код TOTP в теле и правило
// DM-40. Управление — policies.manage (только администратор безопасности).

// exceptionMaxBody — тело запроса на исключение с паролем и комментарием.
const exceptionMaxBody = versions.MaxExceptionInput + 2<<10

func policyExceptionRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/policies/{id}/exceptions", Permission: auth.PermPoliciesRead,
			Handler: needPolicies(d, d.listPolicyExceptions)},
		{Method: http.MethodPost, Path: "/api/v1/policies/{id}/exceptions", Permission: auth.PermPoliciesManage,
			MaxBody: exceptionMaxBody, Handler: needPolicies(d, d.addPolicyException)},
		{Method: http.MethodPost, Path: "/api/v1/policies/{id}/exceptions/{exc}/extend", Permission: auth.PermPoliciesManage,
			MaxBody: exceptionMaxBody, Handler: needPolicies(d, d.extendPolicyException)},
		{Method: http.MethodDelete, Path: "/api/v1/policies/{id}/exceptions/{exc}", Permission: auth.PermPoliciesManage,
			Handler: needPolicies(d, d.deletePolicyException)},
	}
}

// exceptionIDRe — ID исключения в пути; неверный — 404.
var exceptionIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func pathExceptionID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("exc")
	if !exceptionIDRe.MatchString(id) {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Исключение не найдено в текущей версии политики."))
		return "", false
	}
	return id, true
}

// ExceptionView — исключение и его состояние: истёкшее шлюз не применяет,
// но оно остаётся в версии, пока его не удалят.
type ExceptionView struct {
	PolicyExceptionJSON
	Status string `json:"status"` // active или expired
}

func exceptionView(e versions.ExceptionStatus) ExceptionView {
	st := "active"
	if e.Expired {
		st = "expired"
	}
	return ExceptionView{PolicyExceptionJSON: exceptionJSON(e.ExceptionSpec), Status: st}
}

// PolicyExceptionsView — исключения версии политики.
type PolicyExceptionsView struct {
	Policy  string          `json:"policy"`
	Version int             `json:"version"`
	Items   []ExceptionView `json:"items"`
}

func (d Deps) listPolicyExceptions(w http.ResponseWriter, r *http.Request) {
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	n, p := queryInt(r, "version", maxVersion)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	doc, list, err := d.Policies.Exceptions(r.Context(), slug, n)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	resp := PolicyExceptionsView{Policy: slug, Version: doc.Version.Version, Items: make([]ExceptionView, 0, len(list))}
	for _, e := range list {
		resp.Items = append(resp.Items, exceptionView(e))
	}
	WriteJSON(w, http.StatusOK, resp)
}

type addExceptionRequest struct {
	BaseVersion int    `json:"base_version"`
	Comment     string `json:"comment"`
	versions.ExceptionInput
	reauthFields
}

// ExceptionChangeResult — новая версия политики и изменённое исключение.
type ExceptionChangeResult struct {
	Policy    PolicyView     `json:"policy"`
	Exception *ExceptionView `json:"exception,omitempty"`
}

// exceptionPrefixRe — «exceptions[N] (id): » в начале ошибки поля.
var exceptionPrefixRe = regexp.MustCompile(`^exceptions\[\d+\](?: \([^)]*\))?: `)

// exceptionProblem — ошибки условия исключения без префикса exceptions[N]:
// в запросе одно исключение, поля — его собственные.
func exceptionProblem(d Deps, err error) *Problem {
	var ie *versions.InputError
	if !errors.As(err, &ie) {
		return policiesProblem(d.Logger, err)
	}
	fields := make([]FieldError, 0, len(ie.Errs))
	for _, e := range ie.Errs {
		f, msg := policyField(e.Error())
		if strings.HasPrefix(f, "exceptions[") {
			_, f, _ = strings.Cut(f, "].")
			msg = exceptionPrefixRe.ReplaceAllString(msg, "")
		}
		fields = append(fields, FieldError{Field: f, Detail: msg})
	}
	return Invalid("Исключение не прошло проверку.", fields...)
}

func (d Deps) addPolicyException(w http.ResponseWriter, r *http.Request) {
	by, ok := policyActor(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	var req addExceptionRequest
	if p := DecodeJSON(w, r, &req, exceptionMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if err := req.Check(); err != nil {
		WriteProblem(w, exceptionProblem(d, err))
		return
	}
	by = d.withPolicyConfirm(r, by, req.reauthFields, versions.ActionExceptionAdd)
	doc, e, err := d.Policies.AddException(r.Context(), by, slug, req.BaseVersion, req.ExceptionInput, req.Comment)
	if err != nil {
		WriteProblem(w, exceptionProblem(d, err))
		return
	}
	v := exceptionView(versions.ExceptionStatus{ExceptionSpec: e})
	w.Header().Set("Location", "/api/v1/policies/"+slug+"/exceptions")
	WriteJSON(w, http.StatusCreated, ExceptionChangeResult{Policy: policyView(doc), Exception: &v})
}

type extendExceptionRequest struct {
	BaseVersion   int        `json:"base_version"`
	ExpiresInDays int        `json:"expires_in_days"`
	ExpiresAt     *time.Time `json:"expires_at"`
	Reason        string     `json:"reason"`
	Comment       string     `json:"comment"`
	reauthFields
}

func (d Deps) extendPolicyException(w http.ResponseWriter, r *http.Request) {
	by, ok := policyActor(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	id, ok := pathExceptionID(w, r)
	if !ok {
		return
	}
	var req extendExceptionRequest
	if p := DecodeJSON(w, r, &req, exceptionMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if req.ExpiresInDays == 0 && req.ExpiresAt == nil {
		WriteProblem(w, Invalid("Укажите новый срок исключения.",
			FieldError{"expires_in_days", "Число суток от сохранения (1–365) или expires_at."}))
		return
	}
	by = d.withPolicyConfirm(r, by, req.reauthFields, versions.ActionExceptionExtend)
	doc, e, err := d.Policies.ExtendException(r.Context(), by, slug, req.BaseVersion, id, req.ExpiresInDays, req.ExpiresAt,
		req.Reason, req.Comment)
	if err != nil {
		WriteProblem(w, exceptionProblem(d, err))
		return
	}
	v := exceptionView(versions.ExceptionStatus{ExceptionSpec: e})
	WriteJSON(w, http.StatusOK, ExceptionChangeResult{Policy: policyView(doc), Exception: &v})
}

func (d Deps) deletePolicyException(w http.ResponseWriter, r *http.Request) {
	by, ok := policyActor(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	id, ok := pathExceptionID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	for k := range q {
		if k != "base_version" && k != "comment" {
			WriteProblem(w, Invalid("Неизвестный параметр запроса.", FieldError{k, "Допустимы base_version и comment."}))
			return
		}
	}
	base, p := queryInt(r, "base_version", maxVersion)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	doc, err := d.Policies.DeleteException(r.Context(), by, slug, base, id, q.Get("comment"))
	if err != nil {
		WriteProblem(w, exceptionProblem(d, err))
		return
	}
	WriteJSON(w, http.StatusOK, ExceptionChangeResult{Policy: policyView(doc)})
}

// draftTTLDays — срок черновика исключения по умолчанию, сутки.
var draftTTLDays = int(policy.DefaultExceptionTTL.Hours() / 24)
