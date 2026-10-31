package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/compliance"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
	"github.com/azuresong-afk/ai_railway/internal/notify"
	"github.com/azuresong-afk/ai_railway/internal/reports"
)

const testReportChannel = "01900000-0000-7000-8000-0000000000c1"

type fakeReportIncidents struct{}

func (fakeReportIncidents) List(_ context.Context, q incidents.Query) ([]incidents.Incident, error) {
	if q.After != nil {
		return nil, nil
	}
	return []incidents.Incident{{ID: "i1", Number: 1, Title: "Утечка", Severity: "high", Category: "data_leak", Status: incidents.StatusNew,
		CreatedAt: time.Now().UTC().Add(-time.Hour)}}, nil
}

type fakeReportAlerts struct{}

func (fakeReportAlerts) Alerts(context.Context, alerting.AlertQuery) ([]alerting.Alert, error) {
	return nil, nil
}

type fakeReportFacts struct{}

func (fakeReportFacts) Marks(context.Context, time.Time, time.Time, string) (reports.MarkStats, error) {
	return reports.MarkStats{}, nil
}
func (fakeReportFacts) Inventory(context.Context) (reports.Inventory, error) {
	return reports.Inventory{AppsByEnv: map[string]int{}}, nil
}
func (fakeReportFacts) Budgets(context.Context, string) ([]reports.BudgetLine, error) {
	return nil, nil
}

type fakeReportChannels struct{}

func (fakeReportChannels) Channel(_ context.Context, id string) (notify.Channel, error) {
	if id == testReportChannel {
		return notify.Channel{ID: id, Type: notify.TypeEmail, Enabled: true, Settings: notify.Settings{To: []string{"soc@example.org"}}}, nil
	}
	return notify.Channel{}, notify.ErrNotFound
}

func (f fakeReportChannels) Channels(ctx context.Context) ([]notify.Channel, error) {
	c, err := f.Channel(ctx, testReportChannel)
	c.Name = "Почта SOC"
	return []notify.Channel{c, {ID: "01900000-0000-7000-8000-0000000000c2", Name: "Вебхук", Type: notify.TypeWebhook, Enabled: true},
		{ID: "01900000-0000-7000-8000-0000000000c3", Name: "Выключенная почта", Type: notify.TypeEmail,
			Settings: notify.Settings{To: []string{"x@example.org"}}}}, err
}

// newTestReports собирает сервис отчётов на подменах источников.
func newTestReports(t testing.TB, d reports.Dash, dir reports.Directory) *reports.Service {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := reports.New(reports.Options{Store: reports.NewMemory(),
		Builder:  &reports.Builder{Dash: d, Incidents: fakeReportIncidents{}, Alerts: fakeReportAlerts{}, Facts: fakeReportFacts{}, Compliance: fakeReportCompliance{}},
		Channels: fakeReportChannels{}, Directory: dir, IDs: ids.NewGenerator(r),
		Location: func(context.Context) (*time.Location, error) { return time.UTC, nil },
		Logger:   slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func reportPath(kind, format, app string) string {
	day := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02")
	q := "from=" + day + "&to=" + day
	if format != "" {
		q += "&format=" + format
	}
	if app != "" {
		q += "&app=" + app
	}
	return "/api/v1/reports/" + kind + "?" + q
}

// Отчёты: администраторы, аналитик и аудитор строят все виды во всех
// форматах; каждая выгрузка пишет data.export; страница HTML отдаётся со
// своей политикой CSP без скриптов и допускает рамку консоли.
func TestReportsViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	for _, login := range []string{"admin", "sysadm", "analyst", "auditor"} {
		s := e.mustLogin(t, login)
		for _, kind := range reports.Kinds() {
			w := e.call(s, "GET", reportPath(kind, "", ""), "", false)
			if (login == "sysadm" && kind == reports.KindIncidents) || (login == "analyst" && kind == reports.KindCompliance) {
				// Нет incidents.read — отчёта по инцидентам нет (3В31 ревью 3.r4);
				// нет compliance.read — отчёта «Соответствие» нет (задача 4.25).
				mustProblem(t, w, 403, CodeForbidden)
				continue
			}
			if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("%s %s: %d %s", login, kind, w.Code, w.Body)
			}
			csp := w.Header().Get("Content-Security-Policy")
			if csp != reportHTMLCSP || strings.Contains(csp, "script-src") || strings.Contains(csp, "'unsafe-eval'") || !strings.Contains(csp, "default-src 'none'") {
				t.Fatalf("CSP страницы отчёта: %q", csp)
			}
			if w.Header().Get("X-Frame-Options") != "" || !strings.Contains(csp, "frame-ancestors 'self'") {
				t.Errorf("рамка консоли: X-Frame-Options=%q", w.Header().Get("X-Frame-Options"))
			}
			if w.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "inline;") {
				t.Errorf("заголовки: %v", w.Header())
			}
			if strings.Contains(strings.ToLower(w.Body.String()), "<script") {
				t.Error("в странице отчёта скрипт")
			}
		}
	}
	s := e.mustLogin(t, "analyst")
	w := e.call(s, "GET", reportPath("summary", "csv", ""), "", false)
	if w.Code != 200 || !strings.HasPrefix(w.Body.String(), "\xef\xbb\xbf") || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") ||
		!strings.Contains(w.Header().Get("Content-Disposition"), ".csv") || w.Header().Get("Content-Security-Policy") != DefaultCSP {
		t.Fatalf("CSV: %d %v", w.Code, w.Header())
	}
	w = e.call(s, "GET", reportPath("pilot", "xlsx", ""), "", false)
	if w.Code != 200 || !strings.HasPrefix(w.Body.String(), "PK") || w.Header().Get("Content-Type") != reports.ContentType(reports.FormatXLSX) {
		t.Fatalf("XLSX: %d %v", w.Code, w.Header())
	}
	exports := e.rec.find("data.export")
	if len(exports) != 4*4-2+2 { // без отчёта по инцидентам у sysadm и «Соответствие» у аналитика
		t.Fatalf("записей data.export %d", len(exports))
	}
	last := exports[len(exports)-1]
	if last.Object.Type != "report" || last.Object.ID != "pilot" || last.Actor.Name != "analyst" {
		t.Errorf("запись: %+v", last)
	}
	for _, key := range []string{`"format":"xlsx"`, `"report":"pilot"`, `"rows":`, `"from":`} {
		if !strings.Contains(e.rec.canon[len(e.rec.canon)-1], key) {
			t.Errorf("в подробностях нет %s: %s", key, e.rec.canon[len(e.rec.canon)-1])
		}
	}
	// Отчёт «Соответствие» (задача 4.25): все три формата, запись data.export,
	// без права compliance.read — 403, владелец приложения — 403.
	for _, f := range []string{"html", "csv", "xlsx"} {
		w := e.call(e.mustLogin(t, "auditor"), "GET", reportPath("compliance", f, ""), "", false)
		if w.Code != 200 || w.Header().Get("X-Export-Rows") == "" {
			t.Fatalf("соответствие %s: %d %s", f, w.Code, w.Body)
		}
		if f == "html" && !strings.Contains(w.Body.String(), "Соответствие требованиям") {
			t.Errorf("страница отчёта: %s", w.Body)
		}
	}
	mustProblem(t, e.call(e.mustLogin(t, "owner"), "GET", reportPath("compliance", "", ""), "", false), 403, CodeForbidden)
	mustProblem(t, e.call(e.mustLogin(t, "analyst"), "GET", reportPath("compliance", "csv", ""), "", false), 403, CodeForbidden)
	mustProblem(t, e.call(session{}, "GET", reportPath("compliance", "", ""), "", false), 401, CodeUnauthorized)
	// Применимость (задача 5.12 этапа 5): только у отчёта соответствия;
	// одна сессия аудитора — без лишних входов.
	aud := e.mustLogin(t, "auditor")
	if w := e.call(aud, "GET", reportPath("compliance", "html", "")+"&applies=commercial", "", false); w.Code != 200 ||
		!strings.Contains(w.Body.String(), "Коммерческий оператор") {
		t.Fatalf("соответствие с применимостью: %d", w.Code)
	}
	// 5Н8 ревью 5.r1: применимость — в подробностях data.export.
	if last := e.rec.canon[len(e.rec.canon)-1]; !strings.Contains(last, `"applies":"commercial"`) || !strings.Contains(last, `"report":"compliance"`) {
		t.Errorf("в подробностях data.export нет применимости: %s", last)
	}
	mustProblem(t, e.call(aud, "GET", reportPath("summary", "", "")+"&applies=commercial", "", false), 400, CodeInvalidRequest)
	mustProblem(t, e.call(aud, "GET", reportPath("compliance", "", "")+"&applies=x", "", false), 400, CodeInvalidRequest)
}

// УПД.8: владелец приложения видит только сводный отчёт по своему
// приложению; остальные виды и отчёт без приложения — отказ, чужое
// приложение — 404. Без права и без входа — отказ.
func TestReportsOwnerScope(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	prov := e.provider(t, sys, "openai-main")
	e.application(t, sys, "mine", prov.ID, tOwnerID)
	e.application(t, sys, "other", prov.ID, tOwner2ID)
	owner := e.mustLogin(t, "owner")
	for _, kind := range []string{"incidents", "pilot"} {
		mustProblem(t, e.call(owner, "GET", reportPath(kind, "", ""), "", false), 403, CodeForbidden)
		mustProblem(t, e.call(owner, "GET", reportPath(kind, "", "mine"), "", false), 400, CodeInvalidRequest)
	}
	mustProblem(t, e.call(owner, "GET", reportPath("summary", "", ""), "", false), 403, CodeForbidden)
	mustProblem(t, e.call(owner, "GET", reportPath("summary", "", "other"), "", false), 404, CodeNotFound)
	mustProblem(t, e.call(owner, "GET", reportPath("summary", "", "missing"), "", false), 404, CodeNotFound)
	before := len(e.rec.find("data.export"))
	w := e.call(owner, "GET", reportPath("summary", "csv", "mine"), "", false)
	if w.Code != 200 || e.dash.lastQuery().App != "mine" {
		t.Fatalf("своё приложение: %d %s %+v", w.Code, w.Body, e.dash.lastQuery())
	}
	if strings.Contains(w.Body.String(), "Инциденты за период") || strings.Contains(w.Body.String(), "Исполнение бюджетов") {
		t.Error("в отчёте владельца данные всей установки")
	}
	if got := len(e.rec.find("data.export")); got != before+1 {
		t.Errorf("отказы записаны как выгрузки: %d → %d", before, got)
	}
	keymgr := e.mustLogin(t, "keymgr")
	mustProblem(t, e.call(keymgr, "GET", reportPath("summary", "", ""), "", false), 403, CodeForbidden)
	mustProblem(t, e.call(session{}, "GET", reportPath("summary", "", ""), "", false), 401, CodeUnauthorized)
}

func TestReportsInvalidParams(t *testing.T) {
	e := newAppsEnv(t)
	s := e.mustLogin(t, "analyst")
	day := time.Now().UTC().Format("2006-01-02")
	future := time.Now().UTC().Add(72 * time.Hour).Format("2006-01-02")
	for _, q := range []string{
		"from=" + day, "to=" + day, "from=" + day + "&to=" + day + "&format=pdf", "from=" + day + "&to=" + day + "&x=1",
		"from=2024-01-01&to=2026-01-01", "from=" + future + "&to=" + future, "from=2026-02-30&to=" + day,
		"from=" + day + "&to=" + day + "&app=A%2FB", "from=" + day + "&from=" + day + "&to=" + day,
	} {
		w := e.call(s, "GET", "/api/v1/reports/summary?"+q, "", false)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: %d %s", q, w.Code, w.Body)
		}
	}
	for _, q := range []string{"&format=csv&delimiter=tab", "&format=html&delimiter=comma"} {
		w := e.call(s, "GET", "/api/v1/reports/summary?from="+day+"&to="+day+q, "", false)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: %d %s", q, w.Code, w.Body)
		}
	}
	mustProblem(t, e.call(s, "GET", "/api/v1/reports/unknown?from="+day+"&to="+day, "", false), 404, CodeNotFound)
	if n := len(e.rec.find("data.export")); n != 0 {
		t.Errorf("отказы записаны как выгрузки: %d", n)
	}
}

// Без записи data.export отчёт не выдаётся (DM-41).
func TestReportsAuditFailure(t *testing.T) {
	e := newAppsEnv(t)
	s := e.mustLogin(t, "analyst")
	e.rec.err = errors.New("база аудита недоступна")
	w := e.call(s, "GET", reportPath("summary", "csv", ""), "", false)
	mustProblem(t, w, 503, CodeUnavailable)
	if w.Body.Len() > 600 || strings.Contains(w.Body.String(), "Запросов проверено") {
		t.Errorf("данные выданы без записи аудита: %s", w.Body)
	}
}

func scheduleBody(name string) string {
	return fmt.Sprintf(`{"name":%q,"report":"summary","frequency":"weekly","weekday":1,"at":"08:30","format":"xlsx","channel_id":%q}`, name, testReportChannel)
}

// Расписания рассылки: управление — администраторы; аналитик и владелец
// приложения не видят и не меняют; аудитор только читает.
func TestReportSchedulesViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	admin := e.mustLogin(t, "admin")
	w := e.call(admin, "POST", "/api/v1/report-schedules", scheduleBody("Недельный"), true)
	if w.Code != http.StatusCreated || !strings.HasPrefix(w.Header().Get("Location"), "/api/v1/report-schedules/") {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	sch := decode[ReportScheduleView](t, w.Body.Bytes())
	if sch.Version != 1 || sch.Weekday != 1 || sch.At != "08:30" || !sch.Enabled || sch.NextRunAt.Before(time.Now()) {
		t.Fatalf("расписание: %+v", sch)
	}
	// Чтение: администраторы и аудитор; изменение — администраторы.
	for _, login := range []string{"sysadm", "auditor"} {
		s := e.mustLogin(t, login)
		if w := e.call(s, "GET", "/api/v1/report-schedules", "", false); w.Code != 200 || !strings.Contains(w.Body.String(), sch.ID) {
			t.Errorf("%s: список %d %s", login, w.Code, w.Body)
		}
		if w := e.call(s, "GET", "/api/v1/report-schedules/"+sch.ID, "", false); w.Code != 200 {
			t.Errorf("%s: чтение %d", login, w.Code)
		}
		if w := e.call(s, "GET", "/api/v1/report-schedules/"+sch.ID+"/runs", "", false); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
			t.Errorf("%s: журнал %d %s", login, w.Code, w.Body)
		}
	}
	for _, login := range []string{"auditor", "analyst", "owner", "keymgr"} {
		s := e.mustLogin(t, login)
		mustProblem(t, e.call(s, "POST", "/api/v1/report-schedules", scheduleBody("Чужой"), true), 403, CodeForbidden)
		mustProblem(t, e.call(s, "PUT", "/api/v1/report-schedules/"+sch.ID, scheduleBody("Недельный"), true), 403, CodeForbidden)
		mustProblem(t, e.call(s, "DELETE", "/api/v1/report-schedules/"+sch.ID, "", true), 403, CodeForbidden)
	}
	for _, login := range []string{"analyst", "owner", "keymgr"} {
		s := e.mustLogin(t, login)
		mustProblem(t, e.call(s, "GET", "/api/v1/report-schedules", "", false), 403, CodeForbidden)
		mustProblem(t, e.call(s, "GET", "/api/v1/report-schedules/"+sch.ID, "", false), 403, CodeForbidden)
		mustProblem(t, e.call(s, "GET", "/api/v1/report-schedules/"+sch.ID+"/runs", "", false), 403, CodeForbidden)
	}
	mustProblem(t, e.call(session{}, "GET", "/api/v1/report-schedules", "", false), 401, CodeUnauthorized)

	// 3Н46 ревью 3.r4: каналы для расписания — без права на каналы
	// уведомлений, только ID и название включённых почтовых.
	for _, login := range []string{"admin", "sysadm"} {
		w := e.call(e.mustLogin(t, login), "GET", "/api/v1/report-channels", "", false)
		if w.Code != 200 || w.Body.String() != `{"items":[{"id":"`+testReportChannel+`","name":"Почта SOC"}]}`+"\n" {
			t.Errorf("%s: каналы %d %s", login, w.Code, w.Body)
		}
	}
	for _, login := range []string{"auditor", "analyst", "owner"} {
		mustProblem(t, e.call(e.mustLogin(t, login), "GET", "/api/v1/report-channels", "", false), 403, CodeForbidden)
	}
	// Консоль отличает владельца приложения по own_scope, а не по applications.read.
	for login, own := range map[string]bool{"owner": true, "sysadm": false, "analyst": false} {
		me := decode[MeResponse](t, e.call(e.mustLogin(t, login), "GET", "/api/v1/me", "", false).Body.Bytes())
		if me.OwnScope == nil || slices.Contains(me.OwnScope, "reports.read") != own || !slices.Contains(me.Permissions, "reports.read") {
			t.Errorf("%s: own_scope %v, permissions %v", login, me.OwnScope, me.Permissions)
		}
	}

	// Рассылка не шире прав автора (3В31 ревью 3.r4): администратор системы
	// без incidents.read не рассылает отчёт по инцидентам, а в его сводном —
	// только бюджеты из трёх разделов по правам.
	sysadm := e.mustLogin(t, "sysadm")
	incBody := strings.Replace(scheduleBody("Инциденты"), `"report":"summary"`, `"report":"incidents"`, 1)
	mustProblem(t, e.call(sysadm, "POST", "/api/v1/report-schedules", incBody, true), 403, CodeForbidden)
	if w := e.call(sysadm, "POST", "/api/v1/report-schedules", scheduleBody("Сводный sysadm"), true); w.Code != http.StatusCreated {
		t.Fatalf("сводный от sysadm: %d %s", w.Code, w.Body)
	}
	list, err := e.reports.Schedules(context.Background())
	if err != nil || len(list) != 2 {
		t.Fatalf("расписания: %+v %v", list, err)
	}
	for _, x := range list {
		want := reports.Scope{Budgets: true, Incidents: true, Alerts: true}
		if x.Name == "Сводный sysadm" {
			want = reports.Scope{Budgets: true}
		}
		if x.Scope != want {
			t.Errorf("разделы расписания %q: %+v", x.Name, x.Scope)
		}
	}

	// Изменение с версией, конфликт, ошибки ввода.
	upd := strings.Replace(scheduleBody("Недельный 2"), `"channel_id"`, `"version":1,"channel_id"`, 1)
	if w := e.call(admin, "PUT", "/api/v1/report-schedules/"+sch.ID, upd, true); w.Code != 200 || decode[ReportScheduleView](t, w.Body.Bytes()).Version != 2 {
		t.Fatalf("изменение: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", "/api/v1/report-schedules/"+sch.ID, upd, true), 409, CodeConflict)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/report-schedules/01900000-0000-7000-8000-0000000000ff", upd, true), 404, CodeNotFound)
	mustProblem(t, e.call(admin, "GET", "/api/v1/report-schedules/not-a-uuid", "", false), 404, CodeNotFound)
	for _, bad := range []string{
		`{"name":"","report":"summary","frequency":"daily","at":"08:30","format":"xlsx","channel_id":"` + testReportChannel + `"}`,
		`{"name":"x","report":"summary","frequency":"monthly","day":31,"at":"08:30","format":"xlsx","channel_id":"` + testReportChannel + `"}`,
		`{"name":"x","report":"summary","frequency":"daily","at":"8:30","format":"xlsx","channel_id":"` + testReportChannel + `"}`,
		`{"name":"x","report":"summary","frequency":"daily","at":"08:30","format":"csv","channel_id":"` + testReportChannel + `"}`,
		`{"name":"x","report":"summary","frequency":"daily","at":"08:30","format":"xlsx","channel_id":"01900000-0000-7000-8000-0000000000fe"}`,
		`{"name":"x","report":"summary","frequency":"daily","at":"08:30","format":"xlsx","channel_id":"` + testReportChannel + `","unknown":1}`,
	} {
		if w := e.call(admin, "POST", "/api/v1/report-schedules", bad, true); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", bad, w.Code, w.Body)
		}
	}
	if w := e.call(admin, "POST", "/api/v1/report-schedules", scheduleBody("Недельный 2"), true); w.Code != http.StatusBadRequest {
		t.Errorf("повтор названия: %d %s", w.Code, w.Body)
	}
	if w := e.call(admin, "DELETE", "/api/v1/report-schedules/"+sch.ID, "", true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "GET", "/api/v1/report-schedules/"+sch.ID, "", false), 404, CodeNotFound)
	// Без CSRF-токена изменение отклоняется.
	if w := e.call(admin, "POST", "/api/v1/report-schedules", scheduleBody("Без CSRF"), false); w.Code != http.StatusForbidden {
		t.Errorf("без CSRF: %d", w.Code)
	}
}

// Задача 4.6: получатели рассылки — пользователи консоли. Список для выбора
// без адресов, только с reports.schedules.manage; в расписание попадают
// активные пользователи с правом на отчёты (не владелец приложения).
func TestReportRecipientsViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	admin := e.mustLogin(t, "admin")
	if w := e.call(admin, "PUT", "/api/v1/users/"+tAuditorID+"/email", `{"email":"auditor@example.ru","password":"`+tPhrase+`"}`, true); w.Code != 200 {
		t.Fatalf("e-mail аудитора: %d %s", w.Code, w.Body)
	}
	w := e.call(admin, "GET", "/api/v1/report-recipients", "", false)
	if w.Code != 200 || strings.Contains(w.Body.String(), "@") {
		t.Fatalf("список: %d %s", w.Code, w.Body)
	}
	var list ReportRecipientList
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	has := map[string]bool{}
	for _, it := range list.Items {
		has[it.ID] = it.HasEmail
	}
	if !has[tAuditorID] || has[tAnalystID] || len(has) == 0 {
		t.Fatalf("признак адреса: %v", has)
	}
	if _, ok := has[tOwnerID]; ok {
		t.Fatalf("владелец приложения (reports.read со ScopeOwn) в списке получателей: %v", has)
	}
	for _, login := range []string{"auditor", "analyst", "owner", "keymgr"} {
		mustProblem(t, e.call(e.mustLogin(t, login), "GET", "/api/v1/report-recipients", "", false), 403, CodeForbidden)
	}
	mustProblem(t, e.call(session{}, "GET", "/api/v1/report-recipients", "", false), 401, CodeUnauthorized)

	body := func(name string, ids ...string) string {
		b, _ := json.Marshal(ids) //nolint:gosec // тест: ошибка маршалинга среза строк невозможна
		return strings.Replace(scheduleBody(name), `"channel_id"`, `"recipient_user_ids":`+string(b)+`,"channel_id"`, 1)
	}
	mustProblem(t, e.call(admin, "POST", "/api/v1/report-schedules", body("С владельцем", tOwnerID), true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "POST", "/api/v1/report-schedules", body("Неизвестный", "01900000-0000-7000-8000-0000000000ff"), true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "POST", "/api/v1/report-schedules", body("Не UUID", "ivanov"), true), 400, CodeInvalidRequest)
	w = e.call(admin, "POST", "/api/v1/report-schedules", body("С получателями", tAuditorID, tAnalystID), true)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	sch := decode[ReportScheduleView](t, w.Body.Bytes())
	if !slices.Equal(sch.RecipientUserIDs, []string{tAuditorID, tAnalystID}) {
		t.Fatalf("получатели: %+v", sch.RecipientUserIDs)
	}
	// Без получателей-пользователей поле — пустой список, не null.
	w = e.call(admin, "POST", "/api/v1/report-schedules", scheduleBody("Без получателей"), true)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"recipient_user_ids":[]`) {
		t.Fatalf("без получателей: %d %s", w.Code, w.Body)
	}
	// Деактивированный получатель при следующем изменении расписания — отказ.
	if w := e.call(admin, "POST", "/api/v1/users/"+tAnalystID+"/deactivate", "", true); w.Code != 200 {
		t.Fatalf("деактивация: %d %s", w.Code, w.Body)
	}
	upd := strings.Replace(body("С получателями", tAuditorID, tAnalystID), `"channel_id"`, `"version":1,"channel_id"`, 1)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/report-schedules/"+sch.ID, upd, true), 400, CodeInvalidRequest)
	if w := e.call(admin, "GET", "/api/v1/report-schedules/"+sch.ID+"/runs", "", false); w.Code != 200 {
		t.Fatalf("журнал: %d", w.Code)
	}
}

// fakeReportCompliance — обзор соответствия для отчёта «Соответствие».
type fakeReportCompliance struct{}

func (fakeReportCompliance) Evaluate(context.Context, compliance.Filter) (compliance.Overview, error) {
	pct := 50
	return compliance.Overview{GeneratedAt: time.Now().UTC(), Base: compliance.BaseInfo{Version: 1, Date: "2026-10-28", Origin: "builtin", Requirements: 1},
		Summary: compliance.Summary{Percent: &pct, Counted: 2},
		Items: []compliance.Item{{Requirement: compliance.Requirement{ID: "t.one", Source: "s", Clause: "п. 1", Title: "Тест", Applies: []string{"gis"}},
			SourceTitle: "Источник", Status: compliance.StatusMet}}}, nil
}
