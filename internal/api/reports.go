package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/reports"
)

// Отчёты и рассылка по расписанию (ТЗ 5.8, S10; задачи 3.24 и 3.25 этапа 3,
// решения Р5 и Р6). Отчёт строится из агрегатов без содержимого запросов;
// любая выгрузка (HTML, CSV, XLSX) пишет data.export до выдачи данных
// (DM-41). Владелец приложения (ScopeOwn) видит только сводный отчёт по
// своему приложению (УПД.8); остальные виды требуют права на все объекты.

const (
	// reportBuildTimeout — предел построения отчёта по запросу.
	reportBuildTimeout = 60 * time.Second
	// reportScheduleBodyMax — тело запроса расписания.
	reportScheduleBodyMax = 16 << 10
	// reportHTMLCSP — политика страницы отчёта: ни скриптов, ни внешних
	// ресурсов; стили внутри страницы нужны для печати. Показывать страницу
	// в рамке может только консоль того же адреса.
	reportHTMLCSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
)

func reportRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/reports/{kind}", Permission: auth.PermReportsRead, Scoped: true,
			Handler: needReports(d, d.getReport)},
		{Method: http.MethodGet, Path: "/api/v1/report-schedules", Permission: auth.PermReportSchedulesRead,
			Handler: needReports(d, d.listReportSchedules)},
		{Method: http.MethodPost, Path: "/api/v1/report-schedules", Permission: auth.PermReportSchedulesManage, Idempotent: true,
			MaxBody: reportScheduleBodyMax, Handler: needReports(d, d.createReportSchedule)},
		{Method: http.MethodGet, Path: "/api/v1/report-schedules/{id}", Permission: auth.PermReportSchedulesRead,
			Handler: needReports(d, d.getReportSchedule)},
		{Method: http.MethodPut, Path: "/api/v1/report-schedules/{id}", Permission: auth.PermReportSchedulesManage,
			MaxBody: reportScheduleBodyMax, Handler: needReports(d, d.updateReportSchedule)},
		{Method: http.MethodDelete, Path: "/api/v1/report-schedules/{id}", Permission: auth.PermReportSchedulesManage,
			Handler: needReports(d, d.deleteReportSchedule)},
		{Method: http.MethodGet, Path: "/api/v1/report-schedules/{id}/runs", Permission: auth.PermReportSchedulesRead,
			Handler: needReports(d, d.listReportRuns)},
		{Method: http.MethodGet, Path: "/api/v1/report-channels", Permission: auth.PermReportSchedulesManage,
			Handler: needReports(d, d.listReportChannels)},
		{Method: http.MethodGet, Path: "/api/v1/report-recipients", Permission: auth.PermReportSchedulesManage,
			Handler: needReports(d, d.listReportRecipients)},
	}
}

func needReports(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Reports == nil || d.Auth == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Отчёты не подключены на сервере."))
			return
		}
		h(w, r)
	}
}

const (
	reportScheduleNotFound = "Расписание рассылки не найдено."
	reportAppNotFound      = "Приложение не найдено."
)

// reportProblem переводит ошибки сервиса отчётов в ответы API.
func (d Deps) reportProblem(err error) *Problem {
	var ie *reports.InputError
	switch {
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Fields))
		for _, k := range sortedKeys(ie.Fields) {
			fields = append(fields, FieldError{Field: k, Detail: ie.Fields[k]})
		}
		return Invalid("Проверьте введённые данные.", fields...)
	case errors.Is(err, reports.ErrPeriod):
		return Invalid("Период задан неверно.", FieldError{Field: "from", Detail: "Укажите дни в формате ГГГГ-ММ-ДД; начало не в будущем, период не длиннее 366 суток."})
	case errors.Is(err, reports.ErrScope):
		return NewProblem(http.StatusForbidden, CodeForbidden, "Отчёт «По инцидентам» доступен только с правом просмотра инцидентов.")
	case errors.Is(err, reports.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, reportScheduleNotFound)
	case errors.Is(err, reports.ErrVersionConflict):
		return NewProblem(http.StatusConflict, CodeConflict, "Расписание изменил другой пользователь: обновите страницу и повторите изменение.")
	case errors.Is(err, reports.ErrTooMany):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			fmt.Sprintf("Достигнут предел в %d расписаний: удалите ненужные.", reports.MaxSchedules))
	case errors.Is(err, reports.ErrChannel):
		return Invalid("Проверьте введённые данные.", FieldError{Field: "channel_id", Detail: "Канал не найден, не почтовый или отключён."})
	case errors.Is(err, reports.ErrNoRecipients):
		return Invalid("Проверьте введённые данные.", FieldError{Field: "channel_id", Detail: "У почтового канала нет получателей."})
	case errors.Is(err, reports.ErrTooLarge):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, "Отчёт не помещается в формат: сузьте период.")
	case errors.Is(err, context.DeadlineExceeded):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Отчёт не успел построиться: сузьте период или повторите позже.")
	}
	d.Logger.Error("отчёты: ошибка обработки запроса", "class", "reports", "error", err)
	return errInternal()
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ownsApp — приложение со slug принадлежит пользователю ownerID.
func (d Deps) ownsApp(ctx context.Context, ownerID, slug string) (bool, error) {
	if d.Apps == nil {
		return false, errors.New("приложения не подключены")
	}
	var after *apps.Cursor
	for {
		page, err := d.Apps.Applications(ctx, ownerID, after, 500)
		if err != nil {
			return false, err
		}
		for _, a := range page {
			if a.Slug == slug && a.ArchivedAt.IsZero() {
				return true, nil
			}
		}
		if len(page) < 500 {
			return false, nil
		}
		last := page[len(page)-1]
		after = &apps.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
}

func (d Deps) getReport(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		WriteProblem(w, errForbidden())
		return
	}
	kind := r.PathValue("kind")
	if !reports.ValidKind(kind) {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Такого отчёта нет."))
		return
	}
	loc, err := d.Reports.Location(r.Context())
	if err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	params, err := reports.ParseParams(kind, r.URL.Query(), loc, time.Now().UTC())
	if err != nil {
		if errors.Is(err, reports.ErrPeriod) {
			WriteProblem(w, d.reportProblem(err))
		} else {
			WriteProblem(w, Invalid("Параметры отчёта заданы неверно.", FieldError{Field: "format", Detail: err.Error()}))
		}
		return
	}
	// Права на уровне объектов (УПД.8): без права на все объекты — только
	// сводный отчёт по своему приложению.
	full := p.Grants.Full(auth.PermReportsRead)
	if !full {
		if kind != reports.KindSummary || params.App == "" {
			WriteProblem(w, errForbidden())
			return
		}
		own, err := d.ownsApp(r.Context(), p.Caller.User.ID, params.App)
		if err != nil {
			WriteProblem(w, d.reportProblem(err))
			return
		}
		if !own {
			WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, reportAppNotFound))
			return
		}
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
	doc, err := d.Reports.Build(ctx, params, reportScope(p, full))
	if err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	var buf bytes.Buffer
	if err := reports.Render(&buf, doc, params.Format, params.Delimiter); err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	// Запись data.export — до выдачи данных; без записи отчёт не выдаётся.
	actx, acancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer acancel()
	if err := d.Audit.Record(actx, audit.Entry{Actor: eventsActor(p), SourceIP: clientAddr(r), Action: "data.export",
		Object: audit.Object{Type: "report", ID: kind}, Result: audit.ResultSuccess, Details: map[string]any{
			"report": kind, "format": params.Format, "delimiter": delimName(params.Delimiter, params.Format), "from": params.Period.First, "to": params.Period.Last, "app": params.App,
			"rows": doc.Rows(),
		}}); err != nil {
		d.Logger.Error("выгрузка отчёта не записана в журнал аудита: выгрузка отменена", "class", "reports", "error", err)
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Не удалось записать выгрузку в журнал аудита: выгрузка отменена. Повторите позже."))
		return
	}
	h := w.Header()
	h.Set("Content-Type", reports.ContentType(params.Format))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Export-Rows", strconv.Itoa(doc.Rows()))
	name := fmt.Sprintf("aisec-%s-%s_%s.%s", kind, params.Period.First, params.Period.Last, params.Format)
	if params.Format == reports.FormatHTML {
		// Страница для просмотра и печати: своя политика без скриптов; рамка
		// допустима только в консоли того же адреса.
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

// reportScope — разделы отчёта по правам вызывающего (УПД.2, 3В31 ревью
// 3.r4): инциденты, оповещения и бюджеты — только с правом их чтения на все
// объекты; без права на все отчёты (владелец приложения) — ни одного.
func reportScope(p Principal, full bool) reports.Scope {
	return reports.Scope{Budgets: full && p.Grants.Full(auth.PermBudgetsRead),
		Incidents: full && p.Grants.Full(auth.PermIncidentsRead), Alerts: full && p.Grants.Full(auth.PermAlertsRead)}
}

// reportsBy — субъект запроса.
func reportsBy(r *http.Request) (reports.By, bool) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		return reports.By{}, false
	}
	return reports.By{Actor: eventsActor(p), IP: clientAddr(r), Scope: reportScope(p, p.Grants.Full(auth.PermReportsRead))}, true
}

// ReportScheduleView — расписание в ответах.
type ReportScheduleView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Report    string `json:"report"`
	Frequency string `json:"frequency"`
	Weekday   int    `json:"weekday,omitempty"`
	Day       int    `json:"day,omitempty"`
	At        string `json:"at"`
	Format    string `json:"format"`
	ChannelID string `json:"channel_id"`
	Enabled   bool   `json:"enabled"`
	// RecipientUserIDs — получатели-пользователи: адрес берётся из учётной записи.
	RecipientUserIDs []string   `json:"recipient_user_ids"`
	NextRunAt        time.Time  `json:"next_run_at"`
	LastRunAt        *time.Time `json:"last_run_at,omitempty"`
	Version          int        `json:"version"`
	CreatedAt        time.Time  `json:"created_at"`
	CreatedBy        string     `json:"created_by"`
	UpdatedAt        time.Time  `json:"updated_at"`
	UpdatedBy        string     `json:"updated_by"`
}

func reportScheduleView(s reports.Schedule) ReportScheduleView {
	return ReportScheduleView{ID: s.ID, Name: s.Name, Report: s.Report, Frequency: s.Frequency, Weekday: s.Weekday, Day: s.Day,
		At: s.At, Format: s.Format, ChannelID: s.ChannelID, Enabled: s.Enabled, RecipientUserIDs: nonNilIDs(s.RecipientUserIDs), NextRunAt: s.NextRunAt.UTC(), LastRunAt: optTime(s.LastRunAt),
		Version: s.Version, CreatedAt: s.CreatedAt.UTC(), CreatedBy: s.CreatedBy, UpdatedAt: s.UpdatedAt.UTC(), UpdatedBy: s.UpdatedBy}
}

// ReportScheduleList — расписания установки (не больше 50).
type ReportScheduleList struct {
	Items []ReportScheduleView `json:"items"`
}

func (d Deps) listReportSchedules(w http.ResponseWriter, r *http.Request) {
	list, err := d.Reports.Schedules(r.Context())
	if err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	out := ReportScheduleList{Items: make([]ReportScheduleView, 0, len(list))}
	for _, s := range list {
		out.Items = append(out.Items, reportScheduleView(s))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) getReportSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, reportScheduleNotFound)
	if !ok {
		return
	}
	s, err := d.Reports.Schedule(r.Context(), id)
	if err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	WriteJSON(w, http.StatusOK, reportScheduleView(s))
}

func (d Deps) createReportSchedule(w http.ResponseWriter, r *http.Request) {
	by, ok := reportsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req reports.ScheduleInput
	if p := DecodeJSON(w, r, &req, reportScheduleBodyMax); p != nil {
		WriteProblem(w, p)
		return
	}
	s, err := d.Reports.CreateSchedule(r.Context(), by, req)
	if err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	w.Header().Set("Location", "/api/v1/report-schedules/"+s.ID)
	WriteJSON(w, http.StatusCreated, reportScheduleView(s))
}

func (d Deps) updateReportSchedule(w http.ResponseWriter, r *http.Request) {
	by, ok := reportsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, reportScheduleNotFound)
	if !ok {
		return
	}
	var req reports.ScheduleInput
	if p := DecodeJSON(w, r, &req, reportScheduleBodyMax); p != nil {
		WriteProblem(w, p)
		return
	}
	s, err := d.Reports.UpdateSchedule(r.Context(), by, id, req)
	if err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	WriteJSON(w, http.StatusOK, reportScheduleView(s))
}

func (d Deps) deleteReportSchedule(w http.ResponseWriter, r *http.Request) {
	by, ok := reportsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, reportScheduleNotFound)
	if !ok {
		return
	}
	if err := d.Reports.DeleteSchedule(r.Context(), by, id); err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ReportRunView — строка журнала рассылки: без содержимого, ошибка — код.
type ReportRunView struct {
	ID          string     `json:"id"`
	DueAt       time.Time  `json:"due_at"`
	PeriodFirst string     `json:"period_first"`
	PeriodLast  string     `json:"period_last"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	NextAt      *time.Time `json:"next_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	SentAt      *time.Time `json:"sent_at,omitempty"`
	// SkippedNoEmail — получателей-пользователей пропущено в последней попытке
	// (нет адреса, деактивирован или нет права на отчёт).
	SkippedNoEmail int `json:"skipped_no_email"`
}

// ReportRunList — последние запуски расписания.
type ReportRunList struct {
	Items []ReportRunView `json:"items"`
}

func (d Deps) listReportRuns(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, reportScheduleNotFound)
	if !ok {
		return
	}
	runs, err := d.Reports.Runs(r.Context(), id, reports.MaxRunsPage)
	if err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	out := ReportRunList{Items: make([]ReportRunView, 0, len(runs))}
	for _, x := range runs {
		v := ReportRunView{ID: x.ID, DueAt: x.DueAt.UTC(), PeriodFirst: x.PeriodFirst, PeriodLast: x.PeriodLast, Status: x.Status,
			Attempts: x.Attempts, Error: x.Error, CreatedAt: x.CreatedAt.UTC(), SentAt: optTime(x.SentAt), SkippedNoEmail: x.SkippedNoEmail}
		if x.Status == reports.RunPending {
			v.NextAt = optTime(x.NextAt)
		}
		out.Items = append(out.Items, v)
	}
	WriteJSON(w, http.StatusOK, out)
}

// ReportChannelView — почтовый канал для расписания: только ID и название,
// без адресов и сервера (3Н46 ревью 3.r4: администратор системы выбирает
// канал без права на каналы уведомлений).
type ReportChannelView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ReportChannelList — включённые почтовые каналы с получателями.
type ReportChannelList struct {
	Items []ReportChannelView `json:"items"`
}

func (d Deps) listReportChannels(w http.ResponseWriter, r *http.Request) {
	list, err := d.Reports.MailChannels(r.Context())
	if err != nil {
		WriteProblem(w, d.reportProblem(err))
		return
	}
	out := ReportChannelList{Items: make([]ReportChannelView, 0, len(list))}
	for _, c := range list {
		out.Items = append(out.Items, ReportChannelView{ID: c.ID, Name: c.Name})
	}
	WriteJSON(w, http.StatusOK, out)
}

func nonNilIDs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ReportRecipientView — пользователь, которому можно слать отчёты: без адреса,
// только признак, задан ли он.
type ReportRecipientView struct {
	ID          string `json:"id"`
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
	HasEmail    bool   `json:"has_email"`
}

// ReportRecipientList — пользователи для выбора получателей расписания.
type ReportRecipientList struct {
	Items []ReportRecipientView `json:"items"`
}

// maxReportRecipientUsers — сколько пользователей просматривается для выбора.
const maxReportRecipientUsers = 1000

// listReportRecipients — активные пользователи с правом на отчёты (reports.read
// на все объекты и разделы не уже, чем у вызывающего): тот, кто ведёт
// расписания, выбирает получателей без права users.read. Адреса не
// выдаются — только признак «задан».
func (d Deps) listReportRecipients(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		WriteProblem(w, errForbidden())
		return
	}
	scope := reportScope(p, p.Grants.Full(auth.PermReportsRead))
	dir := ReportDirectory{Auth: d.Auth}
	out := ReportRecipientList{Items: []ReportRecipientView{}}
	grants := map[auth.Role]auth.Grants{}
	var after *auth.UserCursor
	for seen := 0; seen < maxReportRecipientUsers; {
		page, err := d.Auth.Users(r.Context(), after, 200)
		if err != nil {
			WriteProblem(w, authProblem(d.Logger, err))
			return
		}
		for _, u := range page {
			rc, err := dir.of(r.Context(), u, grants)
			if err != nil {
				WriteProblem(w, authProblem(d.Logger, err))
				return
			}
			if rc.Eligible(scope) {
				out.Items = append(out.Items, ReportRecipientView{ID: u.ID, Login: u.Login, DisplayName: u.DisplayName, HasEmail: rc.Email != ""})
			}
		}
		seen += len(page)
		if len(page) < 200 {
			break
		}
		last := page[len(page)-1]
		after = &auth.UserCursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	WriteJSON(w, http.StatusOK, out)
}
