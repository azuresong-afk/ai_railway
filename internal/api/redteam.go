package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/redteam"
	"github.com/azuresong-afk/ai_railway/internal/reports"
)

// Тестирование устойчивости (ТЗ 5.13; задача 5.32 этапа 5, ADR-0031).
// Чтение — redteam.read; цели — право безопасности redteam.targets.manage
// и только сессия консоли (адрес, на который продукт отправит атаки; у
// цели endpoint добавление и смена адреса — с повторной проверкой паролем
// или кодом); запуск и отмена — redteam.run (доступно токену: запуск из CI
// заказчика, 5.33); база сценариев — redteam.scenarios.load. Промптов атак
// и ответов целей в ответах нет: только сведения о сценариях и итоги.

const (
	// redteamTargetMaxBody — цель: шаблон до 16 КиБ, корневой сертификат до
	// 64 КиБ, основание и заголовки.
	redteamTargetMaxBody = 128 << 10
	// redteamRunMaxBody — запуск: фильтр сценариев (до 1000 ID) и значение
	// секретного заголовка.
	redteamRunMaxBody = 96 << 10
	// redteamScenariosMaxBody — подписанный файл базы (aisecCrypto.MaxServiceDBSize).
	redteamScenariosMaxBody = 4 << 20
	// redteamScheduleMaxBody — расписание: название и до 64 строк матрицы.
	redteamScheduleMaxBody = 16 << 10
	// redteamTimeout — предел обработки запроса (проверка подписи базы,
	// чтение итогов запуска).
	redteamTimeout = 30 * time.Second
)

func redteamRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/redteam/targets", Permission: auth.PermRedteamRead, Handler: needRedTeam(d, d.listRedTeamTargets)},
		{Method: http.MethodPost, Path: "/api/v1/redteam/targets", Permission: auth.PermRedteamTargetsManage, SessionOnly: true,
			MaxBody: redteamTargetMaxBody, Handler: needRedTeam(d, d.createRedTeamTarget)},
		{Method: http.MethodGet, Path: "/api/v1/redteam/targets/{id}", Permission: auth.PermRedteamRead, Handler: needRedTeam(d, d.getRedTeamTarget)},
		{Method: http.MethodPut, Path: "/api/v1/redteam/targets/{id}", Permission: auth.PermRedteamTargetsManage, SessionOnly: true,
			MaxBody: redteamTargetMaxBody, Handler: needRedTeam(d, d.updateRedTeamTarget)},
		{Method: http.MethodDelete, Path: "/api/v1/redteam/targets/{id}", Permission: auth.PermRedteamTargetsManage, SessionOnly: true,
			Handler: needRedTeam(d, d.deleteRedTeamTarget)},
		{Method: http.MethodGet, Path: "/api/v1/redteam/scenarios", Permission: auth.PermRedteamRead, Handler: needRedTeam(d, d.getRedTeamScenarios)},
		{Method: http.MethodPut, Path: "/api/v1/redteam/scenarios", Permission: auth.PermRedteamScenariosLoad,
			MaxBody: redteamScenariosMaxBody, Handler: needRedTeam(d, d.putRedTeamScenarios)},
		{Method: http.MethodPost, Path: "/api/v1/redteam/scenarios/rollback", Permission: auth.PermRedteamScenariosLoad, SessionOnly: true,
			MaxBody: smallMaxBody, Handler: needRedTeam(d, d.rollbackRedTeamScenarios)},
		{Method: http.MethodGet, Path: "/api/v1/redteam/runs", Permission: auth.PermRedteamRead, Handler: needRedTeam(d, d.listRedTeamRuns)},
		{Method: http.MethodPost, Path: "/api/v1/redteam/runs", Permission: auth.PermRedteamRun, MaxBody: redteamRunMaxBody,
			Handler: needRedTeam(d, d.startRedTeamRun)},
		{Method: http.MethodGet, Path: "/api/v1/redteam/runs/{id}", Permission: auth.PermRedteamRead, Handler: needRedTeam(d, d.getRedTeamRun)},
		{Method: http.MethodPost, Path: "/api/v1/redteam/runs/{id}/cancel", Permission: auth.PermRedteamRun, MaxBody: smallMaxBody,
			Handler: needRedTeam(d, d.cancelRedTeamRun)},
		{Method: http.MethodGet, Path: "/api/v1/redteam/runs/{id}/report", Permission: auth.PermRedteamExport,
			Handler: needRedTeam(d, d.getRedTeamReport)},
		{Method: http.MethodGet, Path: "/api/v1/redteam/schedules", Permission: auth.PermRedteamRead, Handler: needRedTeam(d, d.listRedTeamSchedules)},
		{Method: http.MethodPost, Path: "/api/v1/redteam/schedules", Permission: auth.PermRedteamSchedulesManage, SessionOnly: true,
			MaxBody: redteamScheduleMaxBody, Handler: needRedTeam(d, d.createRedTeamSchedule)},
		{Method: http.MethodGet, Path: "/api/v1/redteam/schedules/{id}", Permission: auth.PermRedteamRead, Handler: needRedTeam(d, d.getRedTeamSchedule)},
		{Method: http.MethodPut, Path: "/api/v1/redteam/schedules/{id}", Permission: auth.PermRedteamSchedulesManage, SessionOnly: true,
			MaxBody: redteamScheduleMaxBody, Handler: needRedTeam(d, d.updateRedTeamSchedule)},
		{Method: http.MethodDelete, Path: "/api/v1/redteam/schedules/{id}", Permission: auth.PermRedteamSchedulesManage, SessionOnly: true,
			Handler: needRedTeam(d, d.deleteRedTeamSchedule)},
	}
}

func needRedTeam(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.RedTeam == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Тестирование устойчивости не подключено на сервере."))
			return
		}
		h(w, r)
	}
}

const (
	redteamTargetNotFound = "Цель тестирования не найдена."
	redteamRunNotFound    = "Запуск не найден."
)

// redteamProblem переводит ошибки тестирования устойчивости. Неизвестная
// ошибка — 500, причина — в техническом журнале (без секретов: значение
// секретного заголовка в ошибки не попадает).
func redteamProblem(logger *slog.Logger, err error, notFound string) *Problem {
	var ie *redteam.InputError
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
		return Invalid("Проверьте данные.", fields...)
	case errors.Is(err, redteam.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, notFound)
	case errors.Is(err, redteam.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Адрес цели задаётся в консоли с вводом текущего пароля или кода.")
	case errors.Is(err, redteam.ErrBusy):
		return NewProblem(http.StatusConflict, CodeConflict,
			"У цели уже идёт запуск или сервер выполняет "+strconv.Itoa(redteam.MaxParallelRuns)+" запуска. Дождитесь завершения.")
	case errors.Is(err, redteam.ErrNotRunning):
		return NewProblem(http.StatusConflict, CodeConflict, "Запуск уже завершён.")
	case errors.Is(err, redteam.ErrNoScenarios):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Нет сценариев: загрузите базу сценариев или измените условия запуска.")
	case errors.Is(err, redteam.ErrGatewayNotConfigured):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Адрес шлюза для тестирования не задан: запустите сервер с флагом -redteam-gateway-url.")
	case errors.Is(err, redteam.ErrTooManySchedules):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Расписаний уже "+strconv.Itoa(redteam.MaxSchedules)+": удалите ненужные.")
	case errors.Is(err, redteam.ErrVersionConflict):
		return NewProblem(http.StatusConflict, CodeConflict, "Расписание изменено другим пользователем: обновите страницу.")
	case errors.Is(err, redteam.ErrTooManyTargets):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Целей уже "+strconv.Itoa(redteam.MaxTargets)+": удалите ненужные.")
	}
	logger.Error("тестирование устойчивости: ошибка обработки запроса", "error", err)
	return errInternal()
}

func (d Deps) redteamBy(r *http.Request, re reauthFields, action string) (redteam.By, bool) {
	a, ok := actorOf(r)
	if !ok {
		return redteam.By{}, false
	}
	return redteam.By{Actor: a.Actor, IP: a.IP, Confirm: d.confirmFunc(r, re, action, redteam.ErrConfirmRequired)}, true
}

// RedTeamTargetView — цель без секретов: значения секретного заголовка в
// продукте нет, есть только его имя.
type RedTeamTargetView struct {
	ID                string           `json:"id"`
	Name              string           `json:"name"`
	Kind              string           `json:"kind"`
	AppID             string           `json:"app_id,omitempty"`
	Model             string           `json:"model,omitempty"`
	URL               string           `json:"url,omitempty"`
	RequestTemplate   string           `json:"request_template,omitempty"`
	ResponsePath      string           `json:"response_path,omitempty"`
	Headers           []redteam.Header `json:"headers"`
	AuthHeader        string           `json:"auth_header,omitempty"`
	CAPEM             string           `json:"ca_pem,omitempty"`
	AuthorizationNote string           `json:"authorization_note,omitempty"`
	Storage           string           `json:"storage,omitempty"`
	JudgeProvider     string           `json:"judge_provider,omitempty"`
	JudgeModel        string           `json:"judge_model,omitempty"`
	Limits            redteam.Limits   `json:"limits"`
	CreatedAt         time.Time        `json:"created_at"`
	CreatedBy         string           `json:"created_by"`
	UpdatedAt         time.Time        `json:"updated_at"`
	UpdatedBy         string           `json:"updated_by"`
}

func redteamTargetView(t redteam.Target) RedTeamTargetView {
	v := RedTeamTargetView{ID: t.ID, Name: t.Name, Kind: t.Kind, AppID: t.AppID, Model: t.Model, URL: t.URL,
		RequestTemplate: t.RequestTemplate, ResponsePath: t.ResponsePath, Headers: t.Headers, AuthHeader: t.AuthHeader,
		CAPEM: t.CAPEM, AuthorizationNote: t.AuthorizationNote, Storage: t.Storage, JudgeProvider: t.JudgeProvider,
		JudgeModel: t.JudgeModel, Limits: t.Limits, CreatedAt: t.CreatedAt, CreatedBy: t.CreatedBy, UpdatedAt: t.UpdatedAt,
		UpdatedBy: t.UpdatedBy}
	if v.Headers == nil {
		v.Headers = []redteam.Header{}
	}
	return v
}

// RedTeamTargetList — цели и признак настроенного адреса шлюза (без него
// цели gateway не запускаются).
type RedTeamTargetList struct {
	Items             []RedTeamTargetView `json:"items"`
	GatewayConfigured bool                `json:"gateway_configured"`
}

type redteamTargetRequest struct {
	redteam.TargetInput
	reauthFields
}

func (d Deps) listRedTeamTargets(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	list, err := d.RedTeam.Targets(ctx)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamTargetNotFound))
		return
	}
	out := RedTeamTargetList{Items: make([]RedTeamTargetView, 0, len(list)), GatewayConfigured: d.RedTeam.GatewayConfigured()}
	for _, t := range list {
		out.Items = append(out.Items, redteamTargetView(t))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) getRedTeamTarget(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	t, err := d.RedTeam.Target(ctx, r.PathValue("id"))
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamTargetNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, redteamTargetView(t))
}

func (d Deps) createRedTeamTarget(w http.ResponseWriter, r *http.Request) {
	var req redteamTargetRequest
	if p := DecodeJSON(w, r, &req, redteamTargetMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.redteamBy(r, req.reauthFields, "redteam.target_created")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	t, err := d.RedTeam.CreateTarget(ctx, by, req.TargetInput)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamTargetNotFound))
		return
	}
	WriteJSON(w, http.StatusCreated, redteamTargetView(t))
}

func (d Deps) updateRedTeamTarget(w http.ResponseWriter, r *http.Request) {
	var req redteamTargetRequest
	if p := DecodeJSON(w, r, &req, redteamTargetMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.redteamBy(r, req.reauthFields, "redteam.target_updated")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	t, err := d.RedTeam.UpdateTarget(ctx, by, r.PathValue("id"), req.TargetInput)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamTargetNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, redteamTargetView(t))
}

func (d Deps) deleteRedTeamTarget(w http.ResponseWriter, r *http.Request) {
	by, ok := d.redteamBy(r, reauthFields{}, "redteam.target_deleted")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	if err := d.RedTeam.DeleteTarget(ctx, by, r.PathValue("id")); err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamTargetNotFound))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) getRedTeamScenarios(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	v, err := d.RedTeam.Scenarios(ctx)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, ""))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

// putRedTeamScenarios принимает подписанный файл базы сценариев телом
// запроса (application/octet-stream) целиком: он не больше 4 МиБ.
func (d Deps) putRedTeamScenarios(w http.ResponseWriter, r *http.Request) {
	by, ok := d.redteamBy(r, reauthFields{}, "")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if !fileContentType(r, "application/octet-stream") {
		WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
			"Тело запроса — подписанный файл базы сценариев (Content-Type: application/octet-stream)."))
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			WriteProblem(w, NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "Файл базы больше 4 МиБ."))
			return
		}
		d.Logger.Debug("тестирование устойчивости: тело запроса не прочитано", "error", err)
		WriteProblem(w, NewProblem(http.StatusBadRequest, CodeInvalidRequest, "Тело запроса не прочитано."))
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	v, err := d.RedTeam.UploadScenarios(ctx, by, data)
	if p := serviceDBProblem(err, "базу", false); p != nil {
		WriteProblem(w, p)
		return
	}
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, ""))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

func (d Deps) rollbackRedTeamScenarios(w http.ResponseWriter, r *http.Request) {
	by, ok := d.redteamBy(r, reauthFields{}, "")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	v, err := d.RedTeam.RollbackScenarios(ctx, by)
	if p := serviceDBProblem(err, "базу", true); p != nil {
		WriteProblem(w, p)
		return
	}
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, ""))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

// RedTeamRunView — запуск: без ключа запуска (его префикс и хеш — только
// для пакета шлюзов).
type RedTeamRunView struct {
	ID         string         `json:"id"`
	TargetID   string         `json:"target_id,omitempty"`
	TargetName string         `json:"target_name"`
	TargetKind string         `json:"target_kind"`
	AppID      string         `json:"app_id,omitempty"`
	Status     string         `json:"status"`
	Reason     string         `json:"reason,omitempty"`
	Scenarios  int            `json:"scenarios"`
	Counts     redteam.Counts `json:"counts"`
	DBVersion  uint64         `json:"db_version"`
	StartedAt  time.Time      `json:"started_at"`
	StartedBy  string         `json:"started_by"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Deadline   time.Time      `json:"deadline"`
}

func redteamRunView(x redteam.Run) RedTeamRunView {
	v := RedTeamRunView{ID: x.ID, TargetID: x.TargetID, TargetName: x.TargetName, TargetKind: x.TargetKind, AppID: x.AppID,
		Status: x.Status, Reason: x.Reason, Scenarios: x.Scenarios, Counts: x.Counts, DBVersion: x.DBVersion,
		StartedAt: x.StartedAt, StartedBy: x.StartedBy, FinishedAt: x.FinishedAt, Deadline: x.Deadline}
	if v.Counts == nil {
		v.Counts = redteam.Counts{}
	}
	return v
}

// RedTeamResultView — итог сценария: без промптов и ответа. Выдержка ответа
// (цель endpoint, режим masked) здесь не выдаётся: её показывает отчёт 5.33
// с правом events.content.read (ADR-0031, раздел 7).
type RedTeamResultView struct {
	ScenarioID string            `json:"scenario_id"`
	Lang       string            `json:"lang"`
	Threat     string            `json:"threat"`
	Category   string            `json:"category"`
	Verdict    string            `json:"verdict"`
	Step       int               `json:"step"`
	Matched    []string          `json:"matched"`
	Findings   []redteam.Finding `json:"findings"`
	Judge      string            `json:"judge,omitempty"`
	EventIDs   []string          `json:"event_ids"`
	HTTPStatus int               `json:"http_status,omitempty"`
	LatencyMS  int64             `json:"latency_ms"`
	ErrorCode  string            `json:"error_code,omitempty"`
}

// RedTeamRunCard — запуск с итогами сценариев.
type RedTeamRunCard struct {
	RedTeamRunView
	Results []RedTeamResultView `json:"results"`
}

// RedTeamRunList — запуски, новые первыми.
type RedTeamRunList struct {
	Items []RedTeamRunView `json:"items"`
}

func (d Deps) listRedTeamRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 0
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > redteam.MaxRunsList {
			WriteProblem(w, Invalid("Проверьте параметры.", FieldError{Field: "limit",
				Detail: "limit — от 1 до " + strconv.Itoa(redteam.MaxRunsList)}))
			return
		}
		limit = n
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	list, err := d.RedTeam.Runs(ctx, q.Get("target_id"), limit)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamRunNotFound))
		return
	}
	out := RedTeamRunList{Items: make([]RedTeamRunView, 0, len(list))}
	for _, x := range list {
		out.Items = append(out.Items, redteamRunView(x))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) getRedTeamRun(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	x, res, err := d.RedTeam.Run(ctx, r.PathValue("id"))
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamRunNotFound))
		return
	}
	card := RedTeamRunCard{RedTeamRunView: redteamRunView(x), Results: make([]RedTeamResultView, 0, len(res))}
	for _, v := range res {
		rv := RedTeamResultView{ScenarioID: v.ScenarioID, Lang: v.Lang, Threat: v.Threat, Category: v.Category, Verdict: v.Verdict,
			Step: v.Step, Matched: v.Matched, Findings: v.Findings, Judge: v.Judge, EventIDs: v.EventIDs, HTTPStatus: v.HTTPStatus,
			LatencyMS: v.LatencyMS, ErrorCode: v.ErrorCode}
		if rv.Matched == nil {
			rv.Matched = []string{}
		}
		if rv.Findings == nil {
			rv.Findings = []redteam.Finding{}
		}
		if rv.EventIDs == nil {
			rv.EventIDs = []string{}
		}
		card.Results = append(card.Results, rv)
	}
	WriteJSON(w, http.StatusOK, card)
}

// startRedTeamRun запускает тестирование: ответ 202 сразу, запуск идёт
// в фоне. Значение секретного заголовка цели endpoint (auth_value) живёт
// только в памяти исполнителя до конца запуска.
func (d Deps) startRedTeamRun(w http.ResponseWriter, r *http.Request) {
	var in redteam.StartInput
	if p := DecodeJSON(w, r, &in, redteamRunMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.redteamBy(r, reauthFields{}, "")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	x, err := d.RedTeam.StartRun(ctx, by, in)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamTargetNotFound))
		return
	}
	WriteJSON(w, http.StatusAccepted, redteamRunView(x))
}

func (d Deps) cancelRedTeamRun(w http.ResponseWriter, r *http.Request) {
	by, ok := d.redteamBy(r, reauthFields{}, "")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	if err := d.RedTeam.Cancel(ctx, by, r.PathValue("id")); err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamRunNotFound))
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// RedTeamScheduleView — расписание запусков.
type RedTeamScheduleView struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	TargetID       string     `json:"target_id"`
	Frequency      string     `json:"frequency"`
	Weekday        int        `json:"weekday,omitempty"`
	Day            int        `json:"day,omitempty"`
	At             string     `json:"at"`
	Threats        []string   `json:"threats"`
	Lang           string     `json:"lang,omitempty"`
	Enabled        bool       `json:"enabled"`
	NextRunAt      time.Time  `json:"next_run_at"`
	LastRunAt      *time.Time `json:"last_run_at,omitempty"`
	LastRunID      string     `json:"last_run_id,omitempty"`
	LastStatus     string     `json:"last_status,omitempty"`
	LastStatusText string     `json:"last_status_text,omitempty"`
	Retries        int        `json:"retries"`
	Version        int        `json:"version"`
	CreatedAt      time.Time  `json:"created_at"`
	CreatedBy      string     `json:"created_by"`
	UpdatedAt      time.Time  `json:"updated_at"`
	UpdatedBy      string     `json:"updated_by"`
}

func redteamScheduleView(s redteam.Schedule) RedTeamScheduleView {
	v := RedTeamScheduleView{ID: s.ID, Name: s.Name, TargetID: s.TargetID, Frequency: s.Frequency, Weekday: s.Weekday, Day: s.Day, At: s.At,
		Threats: s.Threats, Lang: s.Lang, Enabled: s.Enabled, NextRunAt: s.NextRunAt, LastRunAt: s.LastRunAt, LastRunID: s.LastRunID,
		LastStatus: s.LastStatus, Retries: s.Retries, Version: s.Version, CreatedAt: s.CreatedAt, CreatedBy: s.CreatedBy,
		UpdatedAt: s.UpdatedAt, UpdatedBy: s.UpdatedBy}
	if s.LastStatus != "" {
		v.LastStatusText = redteam.ScheduleStatusText(s.LastStatus)
	}
	if v.Threats == nil {
		v.Threats = []string{}
	}
	return v
}

// RedTeamScheduleList — расписания по названию.
type RedTeamScheduleList struct {
	Items []RedTeamScheduleView `json:"items"`
}

const redteamScheduleNotFound = "Расписание не найдено."

func (d Deps) listRedTeamSchedules(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	list, err := d.RedTeam.Schedules(ctx)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamScheduleNotFound))
		return
	}
	out := RedTeamScheduleList{Items: make([]RedTeamScheduleView, 0, len(list))}
	for _, s := range list {
		out.Items = append(out.Items, redteamScheduleView(s))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) getRedTeamSchedule(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	s, err := d.RedTeam.Schedule(ctx, r.PathValue("id"))
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamScheduleNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, redteamScheduleView(s))
}

func (d Deps) createRedTeamSchedule(w http.ResponseWriter, r *http.Request) {
	var in redteam.ScheduleInput
	if p := DecodeJSON(w, r, &in, redteamScheduleMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.redteamBy(r, reauthFields{}, "")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	s, err := d.RedTeam.CreateSchedule(ctx, by, in)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamScheduleNotFound))
		return
	}
	WriteJSON(w, http.StatusCreated, redteamScheduleView(s))
}

func (d Deps) updateRedTeamSchedule(w http.ResponseWriter, r *http.Request) {
	var in redteam.ScheduleInput
	if p := DecodeJSON(w, r, &in, redteamScheduleMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.redteamBy(r, reauthFields{}, "")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	s, err := d.RedTeam.UpdateSchedule(ctx, by, r.PathValue("id"), in)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamScheduleNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, redteamScheduleView(s))
}

func (d Deps) deleteRedTeamSchedule(w http.ResponseWriter, r *http.Request) {
	by, ok := d.redteamBy(r, reauthFields{}, "")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, redteamTimeout)
	defer cancel()
	if err := d.RedTeam.DeleteSchedule(ctx, by, r.PathValue("id")); err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamScheduleNotFound))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getRedTeamReport выдаёт отчёт по запуску (html, csv, xlsx) и пишет
// data.export до выдачи данных. Выдержки ответов целей (режим masked) —
// только по examples=true и с правом events.content.read; без права — 403,
// а не отчёт без выдержек: человек просил содержимое. Промптов атак в
// отчёте нет.
func (d Deps) getRedTeamReport(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		WriteProblem(w, errForbidden())
		return
	}
	q := r.URL.Query()
	for k := range q {
		switch k {
		case "format", "delimiter", "examples":
		default:
			WriteProblem(w, Invalid("Параметры отчёта заданы неверно.", FieldError{Field: k, Detail: "неизвестный параметр"}))
			return
		}
	}
	one := func(k string) (string, bool) {
		vs := q[k]
		if len(vs) > 1 || len(vs) == 1 && len(vs[0]) > 32 {
			return "", false
		}
		if len(vs) == 0 {
			return "", true
		}
		return vs[0], true
	}
	format, ok1 := one("format")
	ds, ok2 := one("delimiter")
	ex, ok3 := one("examples")
	if format == "" {
		format = reports.FormatHTML
	}
	delim, okd := events.ParseDelimiter(ds)
	switch {
	case !ok1 || !ok2 || !ok3 || !reports.ValidFormat(format):
		WriteProblem(w, Invalid("Параметры отчёта заданы неверно.", FieldError{Field: "format", Detail: "format — html, csv или xlsx"}))
		return
	case !okd || ds != "" && format != reports.FormatCSV:
		WriteProblem(w, Invalid("Параметры отчёта заданы неверно.", FieldError{Field: "delimiter", Detail: "delimiter — semicolon или comma, только для csv"}))
		return
	case ex != "" && ex != "true" && ex != "false":
		WriteProblem(w, Invalid("Параметры отчёта заданы неверно.", FieldError{Field: "examples", Detail: "examples — true или false"}))
		return
	}
	examples := ex == "true"
	// Выдержки — ответы целей: только с полной областью events.content.read,
	// как содержимое событий (у цели endpoint нет владельца-приложения, по
	// которому отбирала бы область own). Отказ пишется в журнал аудита, как
	// у маршрутизатора (5Н27 ревью 5.r4).
	if examples && !p.Grants.Full(auth.PermEventsContentRead) {
		if p.Caller != nil && d.Auth != nil {
			reason := DenyReasonPermission
			if p.Grants.Allows(auth.PermEventsContentRead) {
				reason = DenyReasonScope
			}
			if aerr := d.Auth.AccessDenied(r.Context(), *p.Caller, r.Method, "/api/v1/redteam/runs/{id}/report",
				auth.PermEventsContentRead, reason); aerr != nil {
				d.Logger.Error("отказ в доступе не записан в журнал аудита", "error", aerr)
			}
		}
		WriteProblem(w, errForbidden())
		return
	}
	subject := exportSubject(p)
	if d.Exports != nil {
		if !d.Exports.Acquire(subject) {
			w.Header().Set("Retry-After", exportRetryAfter)
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited,
				"Выгрузка уже выполняется: дождитесь её окончания и повторите."))
			return
		}
		defer d.Exports.Release(subject)
	}
	ctx, cancel := contextTimeout(r, reportBuildTimeout)
	defer cancel()
	id := r.PathValue("id")
	doc, err := d.RedTeam.Report(ctx, id, examples)
	if err != nil {
		WriteProblem(w, redteamProblem(d.Logger, err, redteamRunNotFound))
		return
	}
	var buf bytes.Buffer
	if err := reports.Render(&buf, doc, format, delim); err != nil {
		if errors.Is(err, reports.ErrTooLarge) {
			WriteProblem(w, NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, "Отчёт не помещается в формат: сузьте запуск."))
			return
		}
		d.Logger.Error("тестирование устойчивости: отчёт не построен", "error", err)
		WriteProblem(w, errInternal())
		return
	}
	actx, acancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer acancel()
	details := map[string]any{"report": redteam.KindReport, "run_id": id, "format": format, "delimiter": delimName(delim, format),
		"rows": doc.Rows(), "examples": examples}
	if err := d.Audit.Record(actx, audit.Entry{Actor: eventsActor(p), SourceIP: clientAddr(r), Action: "data.export",
		Object: audit.Object{Type: "report", ID: redteam.KindReport}, Result: audit.ResultSuccess, Details: details}); err != nil {
		d.Logger.Error("выгрузка отчёта не записана в журнал аудита: выгрузка отменена", "class", "redteam", "error", err)
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Не удалось записать выгрузку в журнал аудита: выгрузка отменена. Повторите позже."))
		return
	}
	h := w.Header()
	h.Set("Content-Type", reports.ContentType(format))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Export-Rows", strconv.Itoa(doc.Rows()))
	name := "aisec-redteam-" + id + "." + format
	if format == reports.FormatHTML {
		h.Set("Content-Security-Policy", reportHTMLCSP)
		h.Del("X-Frame-Options")
		h.Set("Content-Disposition", `inline; filename="`+name+`"`)
	} else {
		h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes()) //nolint:gosec // G104: клиент мог закрыть соединение, запись data.export уже сделана
}
