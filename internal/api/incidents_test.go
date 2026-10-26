package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
)

// Инциденты (задача 3.16 этапа 3) на хранилищах Memory: права, автомат
// статусов, создание из оповещения, канарейка, выгрузка, инструкции.

type incidentsEnv struct {
	*alertsEnv
	store *incidents.Memory
	// incRetention, alertRetention — сроки хранения в памяти (3Н37 ревью 3.r2).
	incRetention   *memIncidentRetention
	alertRetention *memAlertRetention
}

func newIncidentsEnv(t *testing.T) *incidentsEnv {
	t.Helper()
	ae := newAlertsEnv(t)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	e := &incidentsEnv{alertsEnv: ae, store: incidents.NewMemory(ae.alerts, ae.ids),
		incRetention:   &memIncidentRetention{days: incidents.DefaultRetentionDays},
		alertRetention: &memAlertRetention{days: alerting.DefaultRetentionDays}}
	alertsSvc, err := alerting.New(alerting.Options{Store: ae.alerts, Provider: p, Retention: e.alertRetention})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := incidents.New(incidents.Options{Store: e.store, Provider: p, Alerts: alertsSvc, Retention: e.incRetention,
		UserCheck: func(ctx context.Context, id string) error {
			u, err := e.mem.UserByID(ctx, audit.DefaultOrgID, id)
			if errors.Is(err, auth.ErrNotFound) {
				return incidents.ErrUserInactive
			}
			if err != nil {
				return err
			}
			if r, ok := auth.LookupBuiltinRole(u.Role); !ok || !r.Grants.Allows(auth.PermIncidentsRead) {
				return incidents.ErrUserInactive
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	h, _, err := New(Options{Hasher: testHasher(t), Logger: slog.New(slog.NewTextHandler(e.log, nil)),
		Auth: testAuth(t, e.mem, auth.WithClock(e.clock.now)), Alerts: alertsSvc, Incidents: svc,
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 100000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e
}

// canary — синтетическое событие с канарейкой системного промпта в ответе (DM-08).
func (e *incidentsEnv) canary(t *testing.T, app string) *events.Event {
	t.Helper()
	ev := e.blocked(t, app)
	ev.Decision = &events.Decision{Action: "block", Rule: "canary", Severity: "critical"}
	ev.Threats = []string{"DM-08"}
	ev.Findings = []events.Finding{{Detector: "canary", Version: "1.1.0", Category: "leak", Threat: "DM-08", Score: 1,
		Location: "choices[0].message.content"}}
	return ev
}

func (e *incidentsEnv) records(action string) int {
	n := 0
	for _, r := range append(e.store.Records(), e.alerts.Records()...) {
		if r.Action == action {
			n++
		}
	}
	return n
}

// ТЗ 5.7, УПД.1–3: чтение — incidents.read (аналитик, аудитор,
// администратор безопасности); изменение — incidents.manage (не у
// аудитора); владелец приложения и администратор системы не видят.
func TestIncidentsViaAPI(t *testing.T) {
	e := newIncidentsEnv(t)
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	sys := e.mustLogin(t, "sysadm")
	e.ingest(t, e.blocked(t, "crm-bot"))
	w := e.call(analyst, "GET", "/api/v1/alerts?severity=high", "", false)
	alerts := decode[PageResponse[AlertView]](t, w.Body.Bytes())
	if len(alerts.Items) != 1 {
		t.Fatalf("оповещения: %s", w.Body)
	}
	alertID := alerts.Items[0].ID

	// Отказ в доступе на каждом эндпоинте.
	const missing = "/api/v1/incidents/01900000-0000-7000-8000-0000000fffff"
	reads := [][2]string{{"GET", "/api/v1/incidents"}, {"GET", missing}, {"GET", "/api/v1/incident-categories"}}
	writes := [][3]string{
		{"POST", "/api/v1/incidents", `{"title":"x","severity":"low","category":"other"}`},
		{"POST", missing + "/status", `{"status":"in_progress"}`},
		{"PUT", missing + "/assignee", `{"user_id":null}`},
		{"POST", missing + "/comments", `{"body":"x"}`},
		{"POST", missing + "/stages/intake", `{}`},
		{"POST", missing + "/alerts", `{"alert_id":"` + alertID + `"}`},
	}
	for _, s := range []session{owner, sys} {
		for _, r := range reads {
			mustProblem(t, e.call(s, r[0], r[1], "", false), 403, CodeForbidden)
		}
		mustProblem(t, e.call(s, "GET", missing+"/export", "", false), 403, CodeForbidden)
	}
	for _, s := range []session{auditor, owner, sys} {
		for _, r := range writes {
			mustProblem(t, e.call(s, r[0], r[1], r[2], true), 403, CodeForbidden)
		}
	}
	for _, s := range []session{analyst, auditor, owner, sys} {
		mustProblem(t, e.call(s, "PUT", "/api/v1/incident-categories/other", `{"body":"x","version":1}`, true), 403, CodeForbidden)
	}

	// Создание из оповещения: повтор возвращает тот же инцидент.
	body := `{"title":"Инъекции в crm-bot","severity":"high","category":"prompt_injection","alert_id":"` + alertID + `"}`
	w = e.call(analyst, "POST", "/api/v1/incidents", body, true)
	inc := decode[incidents.View](t, w.Body.Bytes())
	if w.Code != http.StatusCreated || inc.Number != 1 || inc.Status != "new" || inc.Source != "alert" ||
		w.Header().Get("Location") != "/api/v1/incidents/"+inc.ID {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	w = e.call(analyst, "POST", "/api/v1/incidents", body, true)
	if again := decode[incidents.View](t, w.Body.Bytes()); w.Code != http.StatusOK || again.ID != inc.ID {
		t.Fatalf("повтор: %d %s", w.Code, w.Body)
	}
	for _, b := range []string{`{"title":"","severity":"high","category":"other"}`, `{"title":"x","severity":"urgent","category":"other"}`,
		`{"title":"x","severity":"high","category":"phishing"}`, `{"title":"x","severity":"high","category":"other","extra":1}`,
		`{"title":"` + strings.Repeat("я", incidents.MaxTitle+1) + `","severity":"high","category":"other"}`} {
		mustProblem(t, e.call(analyst, "POST", "/api/v1/incidents", b, true), 400, CodeInvalidRequest)
	}
	mustProblem(t, e.call(analyst, "POST", "/api/v1/incidents",
		`{"title":"x","severity":"high","category":"other","alert_id":"01900000-0000-7000-8000-0000000fffff"}`, true), 400, CodeInvalidRequest)

	// Список и карточка у аудитора; фильтры с ошибками — 400.
	w = e.call(auditor, "GET", "/api/v1/incidents?status=open&category=prompt_injection", "", false)
	if page := decode[IncidentPage](t, w.Body.Bytes()); w.Code != 200 || len(page.Items) != 1 {
		t.Fatalf("список: %d %s", w.Code, w.Body)
	}
	for _, q := range []string{"status=reopened", "severity=urgent", "category=x", "status=new&status=closed", "cursor=bad"} {
		mustProblem(t, e.call(auditor, "GET", "/api/v1/incidents?"+q, "", false), 400, CodeInvalidRequest)
	}
	path := "/api/v1/incidents/" + inc.ID
	w = e.call(auditor, "GET", path, "", false)
	card := decode[incidents.CardView](t, w.Body.Bytes())
	if w.Code != 200 || len(card.Alerts) != 1 || len(card.Events) != 1 || len(card.Stages) != 4 || card.Instruction.Body == "" {
		t.Fatalf("карточка: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(auditor, "GET", missing, "", false), 404, CodeNotFound)
	mustProblem(t, e.call(auditor, "GET", "/api/v1/incidents/not-a-uuid", "", false), 404, CodeNotFound)

	// Работа с инцидентом.
	w = e.call(analyst, "PUT", path+"/assignee", `{"user_id":"`+tAnalystID+`"}`, true)
	if got := decode[incidents.View](t, w.Body.Bytes()); w.Code != 200 || got.AssigneeID != tAnalystID {
		t.Fatalf("назначение: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "PUT", path+"/assignee", `{"user_id":"01900000-0000-7000-8000-0000000fffff"}`, true),
		400, CodeInvalidRequest)
	// Владелец приложения инцидентов не видит — назначить нельзя.
	mustProblem(t, e.call(analyst, "PUT", path+"/assignee", `{"user_id":"`+tOwnerID+`"}`, true), 400, CodeInvalidRequest)
	w = e.call(analyst, "POST", path+"/comments", `{"body":"Смотрю журнал шлюза"}`, true)
	c := decode[incidents.CommentView](t, w.Body.Bytes())
	if w.Code != http.StatusCreated || c.ID == "" {
		t.Fatalf("комментарий: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "POST", path+"/comments", `{"body":"`+strings.Repeat("я", incidents.MaxComment+1)+`"}`, true),
		400, CodeInvalidRequest)
	w = e.call(analyst, "POST", path+"/comments", `{"body":"Смотрю журнал шлюза и аудита","replaces":"`+c.ID+`"}`, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("исправление: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "POST", path+"/comments", `{"body":"ещё","replaces":"`+c.ID+`"}`, true), 409, CodeConflict)
	if w = e.call(analyst, "POST", path+"/stages/intake", `{"note":"Принято"}`, true); w.Code != 200 {
		t.Fatalf("этап: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "POST", path+"/stages/intake", `{}`, true), 409, CodeConflict)
	mustProblem(t, e.call(analyst, "POST", path+"/stages/unknown", `{}`, true), 400, CodeInvalidRequest)

	// Автомат статусов: назад нельзя, закрытие — с резолюцией.
	status := path + "/status"
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"contained"}`, true), 409, CodeConflict)
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"new"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"closed"}`, true), 400, CodeInvalidRequest)
	for _, st := range []string{"in_progress", "contained"} {
		if w = e.call(analyst, "POST", status, `{"status":"`+st+`"}`, true); w.Code != 200 {
			t.Fatalf("%s: %d %s", st, w.Code, w.Body)
		}
	}
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"in_progress"}`, true), 409, CodeConflict)
	w = e.call(analyst, "POST", status, `{"status":"closed","resolution":"resolved","comment":"Правило усилено"}`, true)
	if got := decode[incidents.View](t, w.Body.Bytes()); w.Code != 200 || got.Status != "closed" || got.Resolution != "resolved" {
		t.Fatalf("закрытие: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "POST", status, `{"status":"closed","resolution":"resolved"}`, true), 409, CodeConflict)
	mustProblem(t, e.call(analyst, "POST", path+"/comments", `{"body":"после закрытия"}`, true), 409, CodeConflict)
	// Закрытие инцидента закрывает связанное оповещение.
	w = e.call(analyst, "GET", "/api/v1/alerts/"+alertID, "", false)
	if a := decode[AlertCardView](t, w.Body.Bytes()); a.Status != "closed" {
		t.Fatalf("оповещение после закрытия инцидента: %s", w.Body)
	}

	// Повторное открытие — новый инцидент со ссылкой.
	w = e.call(analyst, "POST", "/api/v1/incidents", `{"title":"Снова инъекции","severity":"high","category":"prompt_injection","reopen_of":"`+inc.ID+`"}`, true)
	if re := decode[incidents.View](t, w.Body.Bytes()); w.Code != http.StatusCreated || re.ReopenedFrom != inc.ID || re.Number != 2 {
		t.Fatalf("повторное открытие: %d %s", w.Code, w.Body)
	}

	for _, code := range []string{"incident.create", "incident.status_changed", "incident.assigned", "incident.comment_added",
		"incident.stage_completed"} {
		if e.records(code) == 0 {
			t.Errorf("нет записи аудита %s", code)
		}
	}
	if _, n := lastDenied(t, e.mem); n == 0 {
		t.Fatal("нет записей access.denied")
	}
}

// DM-08: канарейка в ответе открывает инцидент; связь с оповещением,
// выгрузка без содержимого с записью data.export.
func TestIncidentsCanaryAndExportViaAPI(t *testing.T) {
	e := newIncidentsEnv(t)
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	if err := e.alerts.IngestWithIncidents(context.Background(), "01900000-0000-7000-8000-0000000000a1",
		[]*events.Event{e.canary(t, "crm-bot")}, e.store); err != nil {
		t.Fatal(err)
	}
	w := e.call(auditor, "GET", "/api/v1/incidents?source=auto", "", false)
	page := decode[IncidentPage](t, w.Body.Bytes())
	if len(page.Items) != 1 || page.Items[0].Category != "system_prompt_leak" || page.Items[0].Severity != "critical" {
		t.Fatalf("автоинцидент: %s", w.Body)
	}
	id := page.Items[0].ID

	// Ручная привязка оповещения к существующему инциденту.
	e.ingest(t, e.blocked(t, "hr-bot"))
	w = e.call(analyst, "GET", "/api/v1/alerts?severity=high", "", false)
	var other string
	for _, a := range decode[PageResponse[AlertView]](t, w.Body.Bytes()).Items {
		if a.Group["app"] == "hr-bot" {
			other = a.ID
		}
	}
	if w = e.call(analyst, "POST", "/api/v1/incidents/"+id+"/alerts", `{"alert_id":"`+other+`"}`, true); w.Code != 200 {
		t.Fatalf("привязка: %d %s", w.Code, w.Body)
	}

	// Выгрузка — incidents.export (аналитик, не аудитор); содержимого событий нет.
	mustProblem(t, e.call(auditor, "GET", "/api/v1/incidents/"+id+"/export", "", false), 403, CodeForbidden)
	before := e.records("data.export")
	w = e.call(analyst, "GET", "/api/v1/incidents/"+id+"/export", "", false)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "incident-1.json") {
		t.Fatalf("выгрузка: %d %s", w.Code, w.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc["format"] != incidents.DocumentFormat {
		t.Fatalf("документ: %v %s", err, w.Body)
	}
	for _, leak := range []string{"choices[0]", "a1b2c3", "prompt", "content"} {
		if strings.Contains(w.Body.String(), `"`+leak) {
			t.Errorf("в выгрузке есть %q", leak)
		}
	}
	if e.records("data.export") != before+1 {
		t.Fatal("нет записи data.export")
	}

	// Инструкции категории меняет только администратор безопасности.
	w = e.call(admin, "PUT", "/api/v1/incident-categories/system_prompt_leak", `{"body":"Сменить канарейку и промпт.","version":1}`, true)
	ins := decode[incidents.InstructionView](t, w.Body.Bytes())
	if w.Code != 200 || ins.Version != 2 {
		t.Fatalf("инструкция: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", "/api/v1/incident-categories/system_prompt_leak", `{"body":"Старая версия","version":1}`, true),
		409, CodeConflict)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/incident-categories/phishing", `{"body":"x","version":1}`, true), 404, CodeNotFound)
	w = e.call(auditor, "GET", "/api/v1/incident-categories", "", false)
	if l := decode[IncidentCategoryList](t, w.Body.Bytes()); w.Code != 200 || len(l.Items) != len(incidents.Categories()) {
		t.Fatalf("категории: %d %s", w.Code, w.Body)
	}
	if e.records("incident_category.update") != 1 {
		t.Fatal("нет записи incident_category.update")
	}
}

// Токен (SOAR, IRP) разбирает инциденты, но не правит инструкции.
func TestIncidentsByAPIToken(t *testing.T) {
	e := newIncidentsEnv(t)
	admin := e.mustLogin(t, "admin")
	created := e.issueToken(t, admin, auth.PermIncidentsRead, auth.PermIncidentsManage)
	bearer := session{bearer: created.Token}
	w := e.call(bearer, "POST", "/api/v1/incidents", `{"title":"Из IRP","severity":"medium","category":"other"}`, false)
	inc := decode[incidents.View](t, w.Body.Bytes())
	if w.Code != http.StatusCreated || !strings.HasPrefix(inc.CreatedBy, "api_token:") {
		t.Fatalf("создание по токену: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(bearer, "PUT", "/api/v1/incident-categories/other", `{"body":"x","version":1}`, false), 403, CodeForbidden)
	mustProblem(t, e.call(bearer, "GET", "/api/v1/incidents/"+inc.ID+"/export", "", false), 403, CodeForbidden)
	if auth.TokenGrantable(auth.PermIncidentCategoriesManage) {
		t.Fatal("инструкции инцидентов выдаются токену")
	}
}
