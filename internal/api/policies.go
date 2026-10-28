package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Пределы тел запросов политик: политика до 1 МиБ в YAML (policy.MaxSpecSize),
// в JSON с экранированием — больше; песочница — как Check API шлюза по
// умолчанию с запасом на поля запроса.
const (
	policyMaxBody  = policy.MaxSpecSize + 256<<10
	importMaxBody  = policy.MaxSpecSize
	sandboxMaxBody = 256 << 10
)

const policyNotFound = "Политика не найдена."

// policyRoutes — политики (ТЗ 5.3, УПД.2, DM-40; задача 2.12). Версии
// неизменяемы: изменение, откат и загрузка YAML создают новую версию.
// Песочница проверяет текст конвейером шлюза без событий и без обращения
// к модели.
func policyRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/policies", Permission: auth.PermPoliciesRead, Handler: needPolicies(d, d.listPolicies)},
		{Method: http.MethodPost, Path: "/api/v1/policies", Permission: auth.PermPoliciesManage, Idempotent: true,
			MaxBody: policyMaxBody, Handler: needPolicies(d, d.createPolicy)},
		{Method: http.MethodPost, Path: "/api/v1/policies/import", Permission: auth.PermPoliciesManage,
			MaxBody: policyMaxBody, Handler: needPolicies(d, d.importPolicy)},
		{Method: http.MethodPost, Path: "/api/v1/policies/test", Permission: auth.PermPoliciesTest,
			MaxBody: sandboxMaxBody, Handler: needPolicies(d, d.testPolicy)},
		{Method: http.MethodGet, Path: "/api/v1/policies/{id}", Permission: auth.PermPoliciesRead, Handler: needPolicies(d, d.showPolicy)},
		{Method: http.MethodPut, Path: "/api/v1/policies/{id}", Permission: auth.PermPoliciesManage,
			MaxBody: policyMaxBody, Handler: needPolicies(d, d.updatePolicy)},
		{Method: http.MethodGet, Path: "/api/v1/policies/{id}/versions", Permission: auth.PermPoliciesRead,
			Handler: needPolicies(d, d.listPolicyVersions)},
		{Method: http.MethodGet, Path: "/api/v1/policies/{id}/versions/{n}", Permission: auth.PermPoliciesRead,
			Handler: needPolicies(d, d.getPolicyVersion)},
		{Method: http.MethodGet, Path: "/api/v1/policies/{id}/diff", Permission: auth.PermPoliciesRead,
			Handler: needPolicies(d, d.diffPolicy)},
		{Method: http.MethodPost, Path: "/api/v1/policies/{id}/rollback", Permission: auth.PermPoliciesManage,
			MaxBody: smallMaxBody, Handler: needPolicies(d, d.rollbackPolicy)},
		{Method: http.MethodGet, Path: "/api/v1/policies/{id}/export", Permission: auth.PermPoliciesRead,
			Handler: needPolicies(d, d.exportPolicy)},
	}
}

// needPolicies — 503, если политики не подключены (нет БД).
func needPolicies(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Policies == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Политики не подключены на сервере."))
			return
		}
		h(w, r)
	}
}

// policyIDRe — ID политики или шаблона (как в схеме этапа 1).
var policyIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// policySlug — ID политики из пути; недопустимый — 404, как и отсутствующий.
func policySlug(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !policyIDRe.MatchString(id) {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, policyNotFound))
		return "", false
	}
	return id, true
}

// queryInt — необязательный целый параметр запроса от 0 до max; пусто — 0.
func queryInt(r *http.Request, name string, max int) (int, *Problem) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > max {
		return 0, Invalid("Проверьте параметры запроса.", FieldError{name, fmt.Sprintf("Целое число от 0 до %d.", max)})
	}
	return n, nil
}

// maxVersion — предел номера версии в запросах (номер — integer в БД).
const maxVersion = 1<<31 - 1

// policyRuleRe — ошибка правила или исключения: «rules[N] (id): поле — …».
var policyRuleRe = regexp.MustCompile(`^(rules|exceptions)\[(\d+)\](?: \([^)]*\))?: (?:([a-z_]+) — )?`)

// policyField — поле ошибки проверки политики: rules[2].action, mode…
// Префикс «политика ID: » из internal/policy снимается.
func policyField(msg string) (string, string) {
	if rest, ok := strings.CutPrefix(msg, "политика "); ok {
		if _, after, ok := strings.Cut(rest, ": "); ok {
			msg = after
		}
	}
	if m := policyRuleRe.FindStringSubmatch(msg); m != nil {
		f := m[1] + "[" + m[2] + "]"
		if m[3] != "" {
			f += "." + m[3]
		}
		return f, msg
	}
	if m := fieldRe.FindStringSubmatch(msg); m != nil {
		return m[1], msg
	}
	return "", msg
}

// policiesProblem переводит ошибки internal/policy/versions.
func policiesProblem(logger *slog.Logger, err error) *Problem {
	var ie *versions.InputError
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.Is(err, versions.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Версия ослабляет защиту: сохраните её в консоли с вводом текущего пароля или кода.")
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Errs))
		for _, e := range ie.Errs {
			f, msg := policyField(e.Error())
			fields = append(fields, FieldError{Field: f, Detail: msg})
		}
		return Invalid("Политика не прошла проверку.", fields...)
	case errors.Is(err, versions.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, policyNotFound)
	case errors.Is(err, versions.ErrExists):
		return NewProblem(http.StatusConflict, CodeConflict, "Политика с таким ID уже есть: выберите другой ID.")
	case errors.Is(err, versions.ErrConflict):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Политику изменили, пока вы её редактировали: откройте текущую версию и повторите изменение.")
	case errors.Is(err, versions.ErrTemplate):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Шаблон не меняется, его ID занять нельзя: создайте политику копией шаблона.")
	case errors.Is(err, versions.ErrBreaksBundle):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, err.Error()+".")
	case errors.Is(err, versions.ErrTooMany):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, "Достигнут предел числа политик.")
	case errors.Is(err, versions.ErrExceptionNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Исключение не найдено в текущей версии политики.")
	}
	logger.Error("политики: ошибка обработки запроса", "error", err)
	return errInternal()
}

// policyActor — субъект запроса для журнала аудита.
func policyActor(r *http.Request) (versions.By, bool) {
	by, ok := actorOf(r)
	return versions.By{Actor: by.Actor, IP: by.IP}, ok
}

// withPolicyConfirm — повторная проверка перед версией, ослабляющей защиту
// (В23 ревью 2.r5).
func (d Deps) withPolicyConfirm(r *http.Request, by versions.By, re reauthFields, action string) versions.By {
	by.Confirm = d.confirmFunc(r, re, action, versions.ErrConfirmRequired)
	return by
}

// PolicyRuleJSON — правило политики в API: поля как в YAML (ТЗ 5.3).
type PolicyRuleJSON struct {
	ID         string   `json:"id"`
	Detector   string   `json:"detector"`
	Directions []string `json:"directions,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Threshold  *float64 `json:"threshold,omitempty"`
	Action     string   `json:"action"`
	Severity   string   `json:"severity"`
	Message    string   `json:"message,omitempty"`
}

// PolicySpecJSON — содержимое политики в API. ID и номер версии задаёт сервер.
type PolicySpecJSON struct {
	Name          string           `json:"name"`
	Mode          string           `json:"mode"`
	NonText       string           `json:"non_text,omitempty"`
	ResponseCheck string           `json:"response_check,omitempty"`
	BlockMessage  string           `json:"block_message,omitempty"`
	Rules         []PolicyRuleJSON `json:"rules"`
	// Exceptions — исключения (задача 3.22). При сохранении: поле не
	// передано — исключения текущей версии сохраняются; пустой список —
	// удаляются. Автора и created_at ставит сервер.
	Exceptions *[]PolicyExceptionJSON `json:"exceptions,omitempty"`
	// Tools — политика вызовов инструментов агентами (ADR-0023). При
	// сохранении: поле не передано — раздел текущей версии сохраняется, у
	// новой политики — блокировать неодобренное и не разрешённое правилом.
	Tools *PolicyToolsJSON `json:"tools,omitempty"`
}

// PolicyExceptionJSON — исключение политики в API: поля как в YAML.
type PolicyExceptionJSON struct {
	ID        string     `json:"id"`
	Detector  string     `json:"detector"`
	Category  string     `json:"category,omitempty"`
	Pattern   string     `json:"pattern,omitempty"`
	Fragment  string     `json:"fragment,omitempty"`
	App       string     `json:"app,omitempty"`
	User      string     `json:"user,omitempty"`
	Source    string     `json:"source,omitempty"`
	Reason    string     `json:"reason"`
	Author    string     `json:"author,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Event     string     `json:"event_id,omitempty"`
}

func (e PolicyExceptionJSON) spec() policy.ExceptionSpec {
	out := policy.ExceptionSpec{ID: e.ID, Detector: e.Detector, Category: e.Category, Pattern: e.Pattern, Fragment: e.Fragment,
		App: e.App, User: e.User, Source: detect.Source(e.Source), Reason: e.Reason, Author: e.Author, Event: e.Event}
	if e.CreatedAt != nil {
		out.CreatedAt = e.CreatedAt.UTC()
	}
	if e.ExpiresAt != nil {
		out.ExpiresAt = e.ExpiresAt.UTC()
	}
	return out
}

func exceptionJSON(e policy.ExceptionSpec) PolicyExceptionJSON {
	return PolicyExceptionJSON{ID: e.ID, Detector: e.Detector, Category: e.Category, Pattern: e.Pattern, Fragment: e.Fragment,
		App: e.App, User: e.User, Source: string(e.Source), Reason: e.Reason, Author: e.Author,
		CreatedAt: optTime(e.CreatedAt), ExpiresAt: optTime(e.ExpiresAt), Event: e.Event}
}

func convert[T, U ~string](in []T) []U {
	if len(in) == 0 {
		return nil
	}
	out := make([]U, len(in))
	for i, v := range in {
		out[i] = U(v)
	}
	return out
}

func (s PolicySpecJSON) spec(id string) (*policy.Spec, error) {
	out := &policy.Spec{ID: id, Name: s.Name, Mode: policy.Mode(s.Mode), NonText: policy.NonText(s.NonText),
		ResponseCheck: policy.ResponseCheck(s.ResponseCheck), BlockMessage: s.BlockMessage}
	for _, r := range s.Rules {
		out.Rules = append(out.Rules, policy.RuleSpec{ID: r.ID, Detector: r.Detector,
			Directions: convert[string, detect.Direction](r.Directions), Categories: convert[string, string](r.Categories),
			Sources: convert[string, detect.Source](r.Sources), Threshold: r.Threshold, Action: policy.Action(r.Action),
			Severity: policy.Severity(r.Severity), Message: r.Message})
	}
	if s.Exceptions != nil {
		out.Exceptions = make([]policy.ExceptionSpec, 0, len(*s.Exceptions))
		for _, e := range *s.Exceptions {
			out.Exceptions = append(out.Exceptions, e.spec())
		}
	}
	tools, err := s.Tools.toolsSpec()
	if err != nil {
		return nil, &versions.InputError{Errs: []error{err}}
	}
	out.Tools = tools
	return out, nil
}

func ruleJSON(r policy.RuleSpec) PolicyRuleJSON {
	return PolicyRuleJSON{ID: r.ID, Detector: r.Detector, Directions: convert[detect.Direction, string](r.Directions),
		Categories: convert[string, string](r.Categories), Sources: convert[detect.Source, string](r.Sources),
		Threshold: r.Threshold, Action: string(r.Action), Severity: string(r.Severity), Message: r.Message}
}

func specJSON(s *policy.Spec) PolicySpecJSON {
	out := PolicySpecJSON{Name: s.Name, Mode: string(s.Mode), NonText: string(s.NonText), ResponseCheck: string(s.ResponseCheck),
		BlockMessage: s.BlockMessage, Rules: make([]PolicyRuleJSON, 0, len(s.Rules))}
	for _, r := range s.Rules {
		out.Rules = append(out.Rules, ruleJSON(r))
	}
	ex := make([]PolicyExceptionJSON, 0, len(s.Exceptions))
	for _, e := range s.Exceptions {
		ex = append(ex, exceptionJSON(e))
	}
	out.Exceptions = &ex
	out.Tools = toolsJSON(s.Tools)
	return out
}

// PolicySummaryView — строка списка политик.
type PolicySummaryView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	Template bool   `json:"template"`
	// CurrentVersion и UpdatedAt — только у политик организации.
	CurrentVersion int        `json:"current_version,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

// PolicyVersionView — версия политики без содержимого.
type PolicyVersionView struct {
	Version int `json:"version"`
	// Hash — хеш каноничного YAML версии (hex), HashAlg — алгоритм профиля.
	Hash           string    `json:"hash"`
	HashAlg        string    `json:"hash_alg"`
	Source         string    `json:"source"`
	Comment        string    `json:"comment"`
	RolledBackFrom int       `json:"rolled_back_from,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
}

func versionView(v versions.Version) PolicyVersionView {
	return PolicyVersionView{Version: v.Version, Hash: hex.EncodeToString(v.Hash), HashAlg: v.HashAlg, Source: v.Source,
		Comment: v.Comment, RolledBackFrom: v.RolledBackFrom, CreatedAt: v.CreatedAt.UTC(), CreatedBy: v.CreatedBy}
}

// PolicyView — политика (версия) или шаблон с содержимым.
type PolicyView struct {
	PolicySummaryView
	// Version — показанная версия; у шаблона нет.
	Version *PolicyVersionView `json:"version,omitempty"`
	Spec    PolicySpecJSON     `json:"spec"`
}

func policyView(d versions.Doc) PolicyView {
	v := PolicyView{PolicySummaryView: PolicySummaryView{ID: d.Policy.Slug, Name: d.Spec.Name, Mode: string(d.Spec.Mode),
		Template: d.Template}, Spec: specJSON(d.Spec)}
	if !d.Template {
		vv := versionView(d.Version)
		v.Version, v.CurrentVersion, v.UpdatedAt = &vv, d.Policy.Current, optTime(d.Policy.UpdatedAt)
	}
	return v
}

func (d Deps) listPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := d.Policies.List(r.Context())
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	resp := struct {
		Items []PolicySummaryView `json:"items"`
	}{Items: make([]PolicySummaryView, 0, len(list))}
	for _, s := range list {
		v := PolicySummaryView{ID: s.Slug, Name: s.Name, Mode: s.Mode, Template: s.Template, CurrentVersion: s.Current}
		if !s.Template {
			v.UpdatedAt = optTime(s.UpdatedAt)
		}
		resp.Items = append(resp.Items, v)
	}
	WriteJSON(w, http.StatusOK, resp)
}

type createPolicyRequest struct {
	ID string `json:"id"`
	// Ровно одно из Spec и FromTemplate; Name — название копии шаблона.
	Spec         *PolicySpecJSON `json:"spec"`
	FromTemplate string          `json:"from_template"`
	Name         string          `json:"name"`
	Comment      string          `json:"comment"`
}

func (d Deps) createPolicy(w http.ResponseWriter, r *http.Request) {
	by, ok := policyActor(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req createPolicyRequest
	if p := DecodeJSON(w, r, &req, policyMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	var (
		spec   *policy.Spec
		source = versions.SourceAPI
	)
	switch {
	case (req.Spec == nil) == (req.FromTemplate == ""):
		WriteProblem(w, Invalid("Укажите содержимое политики или шаблон.",
			FieldError{"spec", "Нужно ровно одно из spec и from_template."}))
		return
	case req.Spec != nil:
		if req.Name != "" {
			WriteProblem(w, Invalid("Проверьте введённые данные.", FieldError{"name", "Название задаётся в spec.name."}))
			return
		}
		var err error
		if spec, err = req.Spec.spec(req.ID); err != nil {
			WriteProblem(w, policiesProblem(d.Logger, err))
			return
		}
	default:
		var err error
		if spec, err = d.Policies.FromTemplate(req.FromTemplate, req.ID, req.Name); err != nil {
			WriteProblem(w, policiesProblem(d.Logger, err))
			return
		}
		source = versions.SourceTemplate
	}
	doc, err := d.Policies.Create(r.Context(), by, spec, source, req.Comment, versions.ConsoleDefaults)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	w.Header().Set("Location", "/api/v1/policies/"+doc.Policy.Slug)
	WriteJSON(w, http.StatusCreated, policyView(doc))
}

func (d Deps) showPolicy(w http.ResponseWriter, r *http.Request) {
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	doc, err := d.Policies.Get(r.Context(), slug, 0)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, policyView(doc))
}

type updatePolicyRequest struct {
	BaseVersion int            `json:"base_version"`
	Spec        PolicySpecJSON `json:"spec"`
	Comment     string         `json:"comment"`
	reauthFields
}

func (d Deps) updatePolicy(w http.ResponseWriter, r *http.Request) {
	by, ok := policyActor(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	var req updatePolicyRequest
	if p := DecodeJSON(w, r, &req, policyMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by = d.withPolicyConfirm(r, by, req.reauthFields, "policy.update")
	defaults := versions.ConsoleDefaults
	defaults.KeepExceptions = req.Spec.Exceptions == nil
	defaults.KeepTools = req.Spec.Tools == nil
	spec, err := req.Spec.spec(slug)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	doc, err := d.Policies.Update(r.Context(), by, slug, req.BaseVersion, spec, versions.SourceAPI, req.Comment, defaults)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, policyView(doc))
}

func (d Deps) listPolicyVersions(w http.ResponseWriter, r *http.Request) {
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	before, p := queryInt(r, "before", maxVersion)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	limit, p := queryInt(r, "limit", versions.MaxVersionsListed)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	if limit == 0 {
		limit = versions.MaxVersionsListed
	}
	vs, err := d.Policies.Versions(r.Context(), slug, before, limit)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	resp := struct {
		Items []PolicyVersionView `json:"items"`
		// NextBefore — значение before для следующей страницы.
		NextBefore int `json:"next_before,omitempty"`
	}{Items: make([]PolicyVersionView, 0, len(vs))}
	for _, v := range vs {
		resp.Items = append(resp.Items, versionView(v))
	}
	if len(vs) == limit && vs[len(vs)-1].Version > 1 {
		resp.NextBefore = vs[len(vs)-1].Version
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) getPolicyVersion(w http.ResponseWriter, r *http.Request) {
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 1 {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Версия политики не найдена."))
		return
	}
	doc, err := d.Policies.Get(r.Context(), slug, n)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, policyView(doc))
}

// FieldChangeView — изменённое поле политики.
type FieldChangeView struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// RuleChangeView — изменённое правило: имена изменённых полей, до и после.
type RuleChangeView struct {
	ID     string         `json:"id"`
	Fields []string       `json:"fields"`
	Before PolicyRuleJSON `json:"before"`
	After  PolicyRuleJSON `json:"after"`
}

// WeakeningView — ослабление защиты (DM-40); Rule пуст для полей политики,
// Exception — ID исключения для ослаблений исключениями.
type WeakeningView struct {
	Kind      string `json:"kind"`
	Rule      string `json:"rule,omitempty"`
	Exception string `json:"exception,omitempty"`
	ToolRule  string `json:"tool_rule,omitempty"`
}

// ExceptionChangeView — изменённое исключение: имена полей, до и после.
type ExceptionChangeView struct {
	ID     string              `json:"id"`
	Fields []string            `json:"fields"`
	Before PolicyExceptionJSON `json:"before"`
	After  PolicyExceptionJSON `json:"after"`
}

// PolicyDiffView — сравнение двух версий.
type PolicyDiffView struct {
	From             int               `json:"from"`
	To               int               `json:"to"`
	Fields           []FieldChangeView `json:"fields"`
	Added            []PolicyRuleJSON  `json:"rules_added"`
	Removed          []PolicyRuleJSON  `json:"rules_removed"`
	Changed          []RuleChangeView  `json:"rules_changed"`
	Reordered        bool              `json:"reordered"`
	Weakening        bool              `json:"weakening"`
	WeakeningReasons []WeakeningView   `json:"weakening_reasons"`
	// Исключения (задача 3.22).
	ExceptionsAdded   []PolicyExceptionJSON `json:"exceptions_added"`
	ExceptionsRemoved []PolicyExceptionJSON `json:"exceptions_removed"`
	ExceptionsChanged []ExceptionChangeView `json:"exceptions_changed"`
	// Политика вызовов (ADR-0023): поля раздела tools и его правила.
	ToolsFields      []FieldChangeView    `json:"tools_fields"`
	ToolRulesAdded   []PolicyToolRuleJSON `json:"tool_rules_added"`
	ToolRulesRemoved []PolicyToolRuleJSON `json:"tool_rules_removed"`
	ToolRulesChanged []ToolRuleChangeView `json:"tool_rules_changed"`
}

func diffView(df versions.Diff) PolicyDiffView {
	v := PolicyDiffView{From: df.From, To: df.To, Fields: []FieldChangeView{}, Added: []PolicyRuleJSON{}, Removed: []PolicyRuleJSON{},
		Changed: []RuleChangeView{}, Reordered: df.Reordered, Weakening: df.Weakened(), WeakeningReasons: []WeakeningView{},
		ExceptionsAdded: []PolicyExceptionJSON{}, ExceptionsRemoved: []PolicyExceptionJSON{}, ExceptionsChanged: []ExceptionChangeView{},
		ToolsFields: []FieldChangeView{}, ToolRulesAdded: []PolicyToolRuleJSON{}, ToolRulesRemoved: []PolicyToolRuleJSON{},
		ToolRulesChanged: []ToolRuleChangeView{}}
	for _, f := range df.ToolsFields {
		v.ToolsFields = append(v.ToolsFields, FieldChangeView(f))
	}
	for _, r := range df.ToolRulesAdded {
		v.ToolRulesAdded = append(v.ToolRulesAdded, toolRuleJSON(r))
	}
	for _, r := range df.ToolRulesRemoved {
		v.ToolRulesRemoved = append(v.ToolRulesRemoved, toolRuleJSON(r))
	}
	for _, c := range df.ToolRulesChanged {
		v.ToolRulesChanged = append(v.ToolRulesChanged, ToolRuleChangeView{ID: c.ID, Fields: c.Fields,
			Before: toolRuleJSON(c.Before), After: toolRuleJSON(c.After)})
	}
	for _, e := range df.ExceptionsAdded {
		v.ExceptionsAdded = append(v.ExceptionsAdded, exceptionJSON(e))
	}
	for _, e := range df.ExceptionsRemoved {
		v.ExceptionsRemoved = append(v.ExceptionsRemoved, exceptionJSON(e))
	}
	for _, c := range df.ExceptionsChanged {
		v.ExceptionsChanged = append(v.ExceptionsChanged, ExceptionChangeView{ID: c.ID, Fields: c.Fields,
			Before: exceptionJSON(c.Before), After: exceptionJSON(c.After)})
	}
	for _, f := range df.Fields {
		v.Fields = append(v.Fields, FieldChangeView(f))
	}
	for _, r := range df.Added {
		v.Added = append(v.Added, ruleJSON(r))
	}
	for _, r := range df.Removed {
		v.Removed = append(v.Removed, ruleJSON(r))
	}
	for _, c := range df.Changed {
		v.Changed = append(v.Changed, RuleChangeView{ID: c.ID, Fields: c.Fields, Before: ruleJSON(c.Before), After: ruleJSON(c.After)})
	}
	for _, w := range df.Weakening {
		v.WeakeningReasons = append(v.WeakeningReasons, WeakeningView(w))
	}
	return v
}

func (d Deps) diffPolicy(w http.ResponseWriter, r *http.Request) {
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	from, p := queryInt(r, "from", maxVersion)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	to, p := queryInt(r, "to", maxVersion)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	// По умолчанию — текущая версия с предыдущей.
	if to == 0 {
		cur, err := d.Policies.Get(r.Context(), slug, 0)
		if err != nil {
			WriteProblem(w, policiesProblem(d.Logger, err))
			return
		}
		if cur.Template {
			WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "У шаблона нет версий."))
			return
		}
		to = cur.Version.Version
	}
	if from == 0 {
		from = max(to-1, 1)
	}
	df, err := d.Policies.Diff(r.Context(), slug, from, to)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, diffView(df))
}

type rollbackPolicyRequest struct {
	Version     int    `json:"version"`
	BaseVersion int    `json:"base_version"`
	Comment     string `json:"comment"`
	reauthFields
}

func (d Deps) rollbackPolicy(w http.ResponseWriter, r *http.Request) {
	by, ok := policyActor(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	var req rollbackPolicyRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by = d.withPolicyConfirm(r, by, req.reauthFields, "policy.rollback")
	doc, err := d.Policies.Rollback(r.Context(), by, slug, req.Version, req.BaseVersion, req.Comment)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, policyView(doc))
}

// recordPolicyAudit пишет необязательную запись (выгрузка, песочница):
// сбой записи только журналируется.
func (d Deps) recordPolicyAudit(ctx context.Context, by versions.By, action, objID string, details map[string]any) {
	if d.Audit == nil {
		return
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	e := audit.Entry{Actor: by.Actor, SourceIP: by.IP, Action: action, Object: audit.Object{Type: "policy", ID: objID},
		Result: audit.ResultSuccess, Details: details}
	if err := d.Audit.Record(actx, e); err != nil {
		d.Logger.Error("действие с политикой не записано в журнал аудита", "action", action, "error", err)
	}
}

func (d Deps) exportPolicy(w http.ResponseWriter, r *http.Request) {
	by, ok := policyActor(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	slug, ok := policySlug(w, r)
	if !ok {
		return
	}
	n, p := queryInt(r, "version", maxVersion)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	y, doc, err := d.Policies.Export(r.Context(), slug, n)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	name := slug + ".yaml"
	details := map[string]any{"slug": slug, "template": doc.Template}
	objID := slug
	if !doc.Template {
		name = fmt.Sprintf("%s-v%d.yaml", slug, doc.Version.Version)
		details["version"], details["spec_hash"] = doc.Version.Version, hex.EncodeToString(doc.Version.Hash)
		objID = doc.Policy.ID
	}
	d.recordPolicyAudit(r.Context(), by, "policy.export", objID, details)
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	// Имя файла — только [a-z0-9-] из ID и номер версии: экранирование не нужно.
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(y) //nolint:gosec // G104: клиент мог уйти, ответ уже начат
}

// yamlTypes — допустимые Content-Type тела загрузки.
var yamlTypes = map[string]bool{"application/yaml": true, "application/x-yaml": true, "text/yaml": true}

// importPolicyRequest — загрузка в обёртке JSON: так вместе с документом
// передаётся пароль или код, если версия ослабляет защиту (В23 ревью 2.r5).
type importPolicyRequest struct {
	Document    string `json:"document"`
	BaseVersion int    `json:"base_version"`
	Comment     string `json:"comment"`
	reauthFields
}

// PolicyImportPreviewView — проверка загрузки без сохранения (задача 3.35).
type PolicyImportPreviewView struct {
	DryRun         bool           `json:"dry_run"`
	Policy         string         `json:"policy"`
	Created        bool           `json:"created"`
	CurrentVersion int            `json:"current_version"`
	Diff           PolicyDiffView `json:"diff"`
}

// importPolicy — POST /api/v1/policies/import: тело — YAML политики по
// строгой схеме этапа 1 или обёртка JSON с тем же документом. Новой
// политики нет — создаётся (201), есть — новая версия поверх base_version
// (200). Версия, ослабляющая защиту, — только из обёртки с паролем или кодом.
// С dry_run=true — тот же разбор и те же пределы, но только различия с
// текущей версией и признак ослабления: ни версии, ни записи аудита, пароль
// или код не нужны (задача 3.35). Право то же — policies.manage: просмотр
// различий — шаг загрузки, а проверка сборки пакета называет приложения,
// которым изменение помешает; policies.test (песочница аналитика) для
// этого не годится — загрузить по итогу проверки он всё равно не может.
func (d Deps) importPolicy(w http.ResponseWriter, r *http.Request) {
	by, ok := policyActor(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var dryRun bool
	switch r.URL.Query().Get("dry_run") {
	case "", "false":
	case "true":
		dryRun = true
	default:
		WriteProblem(w, Invalid("Проверьте параметры запроса.", FieldError{"dry_run", "true или false."}))
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !yamlTypes[mt] && mt != "application/json" {
		WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
			"Тело запроса должно быть файлом политики YAML (Content-Type: application/yaml) или JSON с полем document."))
		return
	}
	var req importPolicyRequest
	if mt == "application/json" {
		if p := DecodeJSON(w, r, &req, policyMaxBody); p != nil {
			WriteProblem(w, p)
			return
		}
		switch {
		case req.Document == "":
			WriteProblem(w, Invalid("Вставьте документ политики.", FieldError{"document", "Документ YAML политики."}))
			return
		case len(req.Document) > importMaxBody:
			WriteProblem(w, Invalid("Документ слишком большой.", FieldError{"document", "Не больше 1 МиБ."}))
			return
		case req.BaseVersion < 0 || req.BaseVersion > maxVersion:
			WriteProblem(w, Invalid("Проверьте введённые данные.", FieldError{"base_version", "Номер версии."}))
			return
		}
	} else {
		base, p := queryInt(r, "base_version", maxVersion)
		if p != nil {
			WriteProblem(w, p)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, importMaxBody))
		if err != nil {
			WriteProblem(w, bodyProblem(err))
			return
		}
		req = importPolicyRequest{Document: string(body), BaseVersion: base, Comment: r.URL.Query().Get("comment")}
	}
	if dryRun {
		pv, err := d.Policies.PreviewImport(r.Context(), by, strings.NewReader(req.Document), req.BaseVersion)
		if err != nil {
			WriteProblem(w, policiesProblem(d.Logger, err))
			return
		}
		WriteJSON(w, http.StatusOK, PolicyImportPreviewView{DryRun: true, Policy: pv.Slug, Created: pv.Created,
			CurrentVersion: pv.Current, Diff: diffView(pv.Diff)})
		return
	}
	by = d.withPolicyConfirm(r, by, req.reauthFields, "policy.import")
	doc, created, err := d.Policies.Import(r.Context(), by, strings.NewReader(req.Document), req.BaseVersion, req.Comment)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		w.Header().Set("Location", "/api/v1/policies/"+doc.Policy.Slug)
	}
	WriteJSON(w, status, policyView(doc))
}

// testPolicyRequest — песочница. Ровно одно из PolicyID (сохранённая
// версия или шаблон) и Spec (черновик). Request — тело запроса Check API
// шлюза как есть.
type testPolicyRequest struct {
	PolicyID      string          `json:"policy_id"`
	Version       int             `json:"version"`
	Spec          *PolicySpecJSON `json:"spec"`
	ApplicationID string          `json:"application_id"`
	Request       json.RawMessage `json:"request"`
}

// SandboxFindingView — находка песочницы с правилом.
type SandboxFindingView struct {
	Detector string  `json:"detector"`
	Category string  `json:"category"`
	Score    float64 `json:"score"`
	Start    int     `json:"start"`
	End      int     `json:"end"`
	Location string  `json:"location"`
	Threat   string  `json:"threat,omitempty"`
	Rule     string  `json:"rule,omitempty"`
	Action   string  `json:"action,omitempty"`
	Apply    string  `json:"apply,omitempty"`
}

// SandboxTextView — фрагмент после защиты данных.
type SandboxTextView struct {
	Location string `json:"location"`
	Role     string `json:"role,omitempty"`
	Text     string `json:"text"`
	Changed  bool   `json:"changed"`
}

// SandboxFailureView — сбой детектора.
type SandboxFailureView struct {
	Detector string `json:"detector"`
	Location string `json:"location"`
	Reason   string `json:"reason"`
}

// PolicyTestResult — ответ песочницы.
type PolicyTestResult struct {
	PolicyID      string               `json:"policy_id,omitempty"`
	Version       int                  `json:"version,omitempty"`
	Draft         bool                 `json:"draft"`
	ApplicationID string               `json:"application_id,omitempty"`
	Direction     string               `json:"direction"`
	Mode          string               `json:"mode"`
	Decision      string               `json:"decision"`
	Action        string               `json:"action"`
	Rule          string               `json:"rule,omitempty"`
	Blocked       bool                 `json:"blocked"`
	FailBlock     bool                 `json:"fail_block"`
	Message       string               `json:"message,omitempty"`
	Incomplete    bool                 `json:"incomplete"`
	Unchecked     bool                 `json:"unchecked"`
	MLUnavailable bool                 `json:"ml_unavailable"`
	Failures      []SandboxFailureView `json:"failures"`
	Findings      []SandboxFindingView `json:"findings"`
	Truncated     bool                 `json:"findings_truncated,omitempty"`
	Texts         []SandboxTextView    `json:"texts"`
}

// sandboxApp — настройки приложения для песочницы. Нужна область
// applications.read на это приложение: чужое приложение — 404.
func (d Deps) sandboxApp(w http.ResponseWriter, r *http.Request, id string) (config.Application, bool, bool) {
	if d.Apps == nil {
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Приложения не подключены на сервере."))
		return config.Application{}, false, false
	}
	pr, ok := PrincipalFrom(r.Context())
	if !ok || !pr.Grants.Allows(auth.PermApplicationsRead) {
		WriteProblem(w, NewProblem(http.StatusForbidden, CodeForbidden, "Нет права на просмотр приложений: проверьте политику без приложения."))
		return config.Application{}, false, false
	}
	owner, ok := ownerScope(r, auth.PermApplicationsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return config.Application{}, false, false
	}
	a, err := d.Apps.Application(r.Context(), id, owner)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return config.Application{}, false, false
	}
	prov, err := d.Apps.Provider(r.Context(), a.ProviderID)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, "Провайдер приложения не найден."))
		return config.Application{}, false, false
	}
	ls := make([]lists.Spec, 0, len(a.Lists))
	for _, l := range a.Lists {
		ls = append(ls, lists.Spec(l))
	}
	return config.Application{ID: a.Slug, PolicyMode: a.PolicyMode, FailMode: a.FailMode, Lists: ls,
		ExfilAllowDomains: a.ExfilAllowDomains, Quotas: config.Quotas{MaxMessages: a.Quotas.MaxMessages}}, prov.External, true
}

// testPolicy — POST /api/v1/policies/test: проверка текста политикой без
// сохранения чего-либо и без обращения к модели (ТЗ 5.3). В журнал аудита
// идёт только сводка без текста (РСБ.3).
func (d Deps) testPolicy(w http.ResponseWriter, r *http.Request) {
	by, ok := policyActor(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req testPolicyRequest
	if p := DecodeJSON(w, r, &req, sandboxMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if len(req.Request) == 0 {
		WriteProblem(w, Invalid("Укажите проверяемый текст.", FieldError{"request", "Тело запроса Check API: direction и text или messages."}))
		return
	}
	var (
		spec *policy.Spec
		res  = PolicyTestResult{Draft: req.Spec != nil, Failures: []SandboxFailureView{}, Texts: []SandboxTextView{}}
	)
	switch {
	case (req.Spec == nil) == (req.PolicyID == ""):
		WriteProblem(w, Invalid("Укажите политику или черновик.", FieldError{"policy_id", "Нужно ровно одно из policy_id и spec."}))
		return
	case req.Spec != nil:
		if req.Version != 0 {
			WriteProblem(w, Invalid("Проверьте введённые данные.", FieldError{"version", "Версия указывается только с policy_id."}))
			return
		}
		var err error
		if spec, err = req.Spec.spec("draft"); err != nil {
			WriteProblem(w, policiesProblem(d.Logger, err))
			return
		}
		spec.Version = 1
		if err := spec.Validate(); err != nil {
			WriteProblem(w, policiesProblem(d.Logger, &versions.InputError{Errs: unjoin(err)}))
			return
		}
	default:
		if !policyIDRe.MatchString(req.PolicyID) || req.Version < 0 {
			WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, policyNotFound))
			return
		}
		doc, err := d.Policies.Get(r.Context(), req.PolicyID, req.Version)
		if err != nil {
			WriteProblem(w, policiesProblem(d.Logger, err))
			return
		}
		spec, res.PolicyID = doc.Spec, req.PolicyID
		if !doc.Template {
			res.Version = doc.Version.Version
		}
	}
	// Без приложения провайдер считается внешним: так видно всё, что
	// политика маскирует перед отправкой во внешнюю модель (ТЗ 5.3).
	var (
		app      config.Application
		external = true
	)
	if req.ApplicationID != "" {
		id, ok := pathlessID(w, req.ApplicationID)
		if !ok {
			return
		}
		if app, external, ok = d.sandboxApp(w, r, id); !ok {
			return
		}
		res.ApplicationID = id
	}
	out, err := gateway.Sandbox(r.Context(), gateway.SandboxRequest{Spec: spec, App: app, External: external, Body: req.Request})
	var se *gateway.SandboxError
	switch {
	case errors.As(err, &se):
		WriteProblem(w, Invalid("Проверяемый текст не принят.", FieldError{"request", se.Message}))
		return
	case errors.Is(err, gateway.ErrSandboxPolicy):
		p := NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Правила политики ссылаются на детекторы или категории, которых нет у приложения.")
		for _, e := range sandboxCauses(err) {
			f, msg := policyField(e.Error())
			p.Errors = append(p.Errors, FieldError{Field: f, Detail: msg})
		}
		WriteProblem(w, p)
		return
	case err != nil && r.Context().Err() != nil:
		return
	case err != nil:
		d.Logger.Error("песочница политик: ошибка проверки", "error", err)
		WriteProblem(w, errInternal())
		return
	}
	res.Direction, res.Mode, res.Decision, res.Action, res.Rule = string(out.Direction), string(out.Mode), out.Decision, string(out.Action), out.Rule
	res.Blocked, res.FailBlock, res.Message, res.Incomplete, res.Unchecked = out.Blocked, out.FailBlock, out.Message, out.Incomplete, out.Unchecked
	res.MLUnavailable = out.MLUnavailable
	res.Truncated = out.Truncated
	for _, f := range out.Failures {
		res.Failures = append(res.Failures, SandboxFailureView{Detector: f.Detector, Location: f.Location, Reason: f.Reason})
	}
	res.Findings = make([]SandboxFindingView, 0, len(out.Findings))
	for _, f := range out.Findings {
		res.Findings = append(res.Findings, SandboxFindingView{Detector: f.Detector, Category: f.Category, Score: f.Score,
			Start: f.Start, End: f.End, Location: f.Location, Threat: f.Threat, Rule: f.Rule, Action: string(f.Action), Apply: string(f.Apply)})
	}
	for _, t := range out.Texts {
		res.Texts = append(res.Texts, SandboxTextView{Location: t.Location, Role: t.Role, Text: t.Text, Changed: t.Changed})
	}
	objID := res.PolicyID
	if res.Draft {
		objID = "draft"
	}
	// Только сводка: текст и находки с позициями в журнал не пишутся.
	d.recordPolicyAudit(r.Context(), by, "policy.test", objID, map[string]any{"version": res.Version, "draft": res.Draft,
		"application_id": res.ApplicationID, "direction": res.Direction, "decision": res.Decision, "findings": len(res.Findings),
		"request_bytes": len(req.Request)})
	WriteJSON(w, http.StatusOK, res)
}

// pathlessID — UUID из тела запроса; неверный — 404, как и отсутствующий объект.
func pathlessID(w http.ResponseWriter, s string) (string, bool) {
	id, err := store.ParseUUID(s)
	if err != nil {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, appNotFound))
		return "", false
	}
	return string(id), true
}

// sandboxCauses — ошибки компиляции политики без ErrSandboxPolicy.
func sandboxCauses(err error) []error {
	var out []error
	for _, e := range unjoin(err) {
		if errors.Is(e, gateway.ErrSandboxPolicy) {
			continue
		}
		out = append(out, unjoin(e)...)
	}
	return out
}

// unjoin — ошибки, собранные errors.Join, по одной.
func unjoin(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}
