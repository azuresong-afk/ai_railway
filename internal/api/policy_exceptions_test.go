package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Отметки событий, черновик и исключения в политиках (задача 3.22 этапа 3)
// на хранилищах Memory: права, повторная проверка, аудит, отсутствие
// содержимого запроса в отметке и черновике.

const tFragment = "0123456789abcdef0123456789abcdef"

// blockedEvent — событие блокировки инъекции политикой support версии 1:
// находка инъекции решила итог, находка ПДн — нет.
func (e *appsEnv) blockedEvent(t *testing.T) string {
	t.Helper()
	ts := time.Now().UTC().Add(-time.Minute)
	ev := events.Event{
		ID: liveEventID(ts, 7), Time: ts, Type: events.TypeGatewayRequest, App: "support-bot", Env: "prod",
		PolicyMode: events.ModeEnforce, Storage: events.StorageFull, Threats: []string{"DM-01"},
		Decision: &events.Decision{Action: "block", Applied: []string{"block"}, Rule: "injection", Severity: "high",
			Policy: "support", PolicyVersion: 1, Trace: []events.TraceStep{
				{Rule: "injection", Detector: "injection.heuristic", Matched: true, Action: "block"},
				{Rule: "pii", Detector: "pii.ru", Matched: true, Action: "redact"},
			}},
		Findings: []events.Finding{
			{Detector: "injection.heuristic", Category: "injection.override", Score: 0.9, Threat: "DM-01", Location: "messages[0].content",
				Rule: "ignore_previous", Fragment: tFragment},
			{Detector: "pii.ru", Category: "pii.email", Score: 0.9, Threat: "DM-05", Location: "messages[0].content", Fragment: tFragment},
		},
		Content: &events.Content{Request: promptMarker},
	}
	if _, err := e.ev.Insert(context.Background(), events.Ingest{GatewayID: testGatewayID, ReceivedAt: time.Now(), Events: []events.Event{ev}}); err != nil {
		t.Fatal(err)
	}
	return ev.ID
}

func (e *appsEnv) auditCount(action string) int { return len(e.rec.find(action)) }

func TestEventMarkAndExceptionViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	if w := e.call(admin, "POST", "/api/v1/policies", `{"id":"support","spec":`+tPolicySpec+`}`, true); w.Code != http.StatusCreated {
		t.Fatalf("политика: %d %s", w.Code, w.Body)
	}
	id := e.blockedEvent(t)
	markURL := "/api/v1/events/" + id + "/mark"

	// Отметка: оператор безопасности (events.mark); аудитор и владелец — нет.
	fp := `{"mark":"false_positive","comment":"Скрипт оператора поддержки"}`
	for _, s := range []session{auditor, owner} {
		mustProblem(t, e.call(s, "PUT", markURL, fp, true), 403, CodeForbidden)
	}
	mustProblem(t, e.call(analyst, "PUT", markURL, `{"mark":"wrong"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(analyst, "PUT", markURL, `{"mark":"confirmed","comment":"`+strings.Repeat("я", events.MaxMarkComment+1)+`"}`, true),
		400, CodeInvalidRequest)
	mustProblem(t, e.call(analyst, "PUT", "/api/v1/events/01900000-0000-7000-8000-000000000099/mark", fp, true), 404, CodeNotFound)
	w := e.call(analyst, "PUT", markURL, fp, true)
	if w.Code != http.StatusOK {
		t.Fatalf("отметка: %d %s", w.Code, w.Body)
	}
	res := decode[MarkResult](t, w.Body.Bytes())
	if res.Mark.Mark != events.MarkFalsePositive || res.Mark.By != "user:"+tAnalystID || res.Draft == nil {
		t.Fatalf("отметка: %s", w.Body)
	}
	// Черновик: только находка, давшая итог; условие — без содержимого запроса.
	dr := res.Draft
	if dr.Policy != "support" || dr.BaseVersion != 1 || dr.Template || len(dr.Items) != 1 {
		t.Fatalf("черновик: %s", w.Body)
	}
	it := dr.Items[0]
	// Хеш фрагмента аналитику не показывается (3Н41 ревью 3.r3): только с
	// events.content.read или policies.manage.
	if it.Detector != "injection.heuristic" || it.Pattern != "ignore_previous" || it.Fragment != "" || it.App != "support-bot" ||
		it.ExpiresInDays != 30 || it.EventID != id {
		t.Fatalf("условие черновика: %+v", it)
	}
	if strings.Contains(w.Body.String(), "4510") || strings.Contains(w.Body.String(), "Паспорт") {
		t.Fatalf("содержимое запроса в ответе: %s", w.Body)
	}
	if n := e.auditCount(events.ActionMarkSet); n != 1 {
		t.Fatalf("аудит отметки: %d", n)
	}
	for _, c := range e.rec.canon {
		if strings.Contains(c, "Скрипт оператора") {
			t.Fatalf("комментарий в журнале аудита: %s", c)
		}
	}
	// Отметка видна в карточке и в фильтрах.
	if w := e.call(analyst, "GET", "/api/v1/events/"+id, "", false); !strings.Contains(w.Body.String(), `"mark":"false_positive"`) {
		t.Fatalf("карточка: %s", w.Body)
	}
	for f, want := range map[string]bool{`mark = "false_positive"`: true, `mark = "none"`: false, `mark != "confirmed"`: true} {
		w := e.call(analyst, "GET", "/api/v1/events?filter="+url.QueryEscape(f), "", false)
		if w.Code != 200 || strings.Contains(w.Body.String(), id) != want {
			t.Fatalf("фильтр %s: %d %s", f, w.Code, w.Body)
		}
	}
	// Черновик отдельно — по events.read; хеш фрагмента — только
	// администратору безопасности, в карточке события — так же (3Н41).
	if w := e.call(auditor, "GET", "/api/v1/events/"+id+"/exception-draft", "", false); w.Code != 200 ||
		strings.Contains(w.Body.String(), tFragment) || !strings.Contains(w.Body.String(), "ignore_previous") {
		t.Fatalf("черновик аудитора: %d %s", w.Code, w.Body)
	}
	if w := e.call(admin, "GET", "/api/v1/events/"+id+"/exception-draft", "", false); w.Code != 200 ||
		!strings.Contains(w.Body.String(), tFragment) {
		t.Fatalf("черновик администратора безопасности: %d %s", w.Code, w.Body)
	}
	for _, c := range []struct {
		s    session
		want bool
	}{{analyst, false}, {auditor, false}, {admin, true}} {
		want := c.want
		w := e.call(c.s, "GET", "/api/v1/events/"+id, "", false)
		if w.Code != 200 || strings.Contains(w.Body.String(), tFragment) != want || !strings.Contains(w.Body.String(), "ignore_previous") {
			t.Fatalf("хеш фрагмента в карточке (виден: %v): %d %s", want, w.Code, w.Body)
		}
	}
	mustProblem(t, e.call(owner, "GET", "/api/v1/events/"+id+"/exception-draft", "", false), 403, CodeForbidden)

	// Исключение по черновику: только администратор безопасности, с паролем.
	item, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}
	body := func(extra string) string {
		var m map[string]any
		if err := json.Unmarshal(item, &m); err != nil {
			t.Fatal(err)
		}
		m["base_version"], m["reason"] = 1, "Скрипт поддержки"
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSuffix(string(b), "}") + extra + "}"
	}
	excURL := "/api/v1/policies/support/exceptions"
	mustProblem(t, e.call(analyst, "POST", excURL, body(""), true), 403, CodeForbidden)
	w = e.call(admin, "POST", excURL, body(""), true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"password"`) {
		t.Fatalf("без пароля: %s", w.Body)
	}
	mustProblem(t, e.call(admin, "POST", excURL, body(`,"password":"неверный"`), true), 403, CodeReauthFailed)
	broad := `{"base_version":1,"detector":"injection.heuristic","reason":"всё","password":"` + tPhrase + `"}`
	w = e.call(admin, "POST", excURL, broad, true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), "слишком широкое") {
		t.Fatalf("широкое исключение: %s", w.Body)
	}
	mustProblem(t, e.call(admin, "POST", excURL, `{"base_version":1,"detector":"injection.heuristic","app":"a","reason":"r","expires_in_days":400,"password":"`+tPhrase+`"}`, true),
		400, CodeInvalidRequest)
	w = e.call(admin, "POST", excURL, body(`,"password":"`+tPhrase+`"`), true)
	if w.Code != http.StatusCreated {
		t.Fatalf("исключение: %d %s", w.Code, w.Body)
	}
	cr := decode[ExceptionChangeResult](t, w.Body.Bytes())
	if cr.Policy.Version == nil || cr.Policy.Version.Version != 2 || cr.Exception == nil || cr.Exception.Status != "active" ||
		cr.Exception.Author != "user:"+tAdminID || cr.Exception.Event != id {
		t.Fatalf("результат: %s", w.Body)
	}
	exc := cr.Exception.ID
	rec, n := e.polAction("policy.exception_add")
	if d, _ := rec.Details.(map[string]any); n != 1 || d["weakening"] != true || d["exception"] != exc {
		t.Fatalf("аудит исключения: %+v", rec)
	}
	mustProblem(t, e.call(admin, "POST", excURL, body(`,"password":"`+tPhrase+`"`), true), 409, CodeConflict)
	// Список — по policies.read, с состоянием.
	w = e.call(analyst, "GET", excURL, "", false)
	lv := decode[PolicyExceptionsView](t, w.Body.Bytes())
	if w.Code != 200 || lv.Version != 2 || len(lv.Items) != 1 || lv.Items[0].Status != "active" {
		t.Fatalf("список: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(owner, "GET", excURL, "", false), 403, CodeForbidden)
	// Исключение — в спецификации версии; полная замена без exceptions его сохраняет.
	if w := e.call(analyst, "GET", "/api/v1/policies/support", "", false); !strings.Contains(w.Body.String(), exc) {
		t.Fatalf("политика: %s", w.Body)
	}
	if w := e.call(admin, "PUT", "/api/v1/policies/support", `{"base_version":2,"spec":`+tPolicySpec+`}`, true); w.Code != 200 ||
		!strings.Contains(w.Body.String(), exc) {
		t.Fatalf("замена без exceptions: %d %s", w.Code, w.Body)
	}
	// Продление — с паролем; удаление — без.
	extURL := excURL + "/" + exc + "/extend"
	mustProblem(t, e.call(analyst, "POST", extURL, `{"base_version":3,"expires_in_days":60}`, true), 403, CodeForbidden)
	mustProblem(t, e.call(admin, "POST", extURL, `{"base_version":3}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "POST", extURL, `{"base_version":3,"expires_in_days":60}`, true), 400, CodeInvalidRequest)
	if w := e.call(admin, "POST", extURL, `{"base_version":3,"expires_in_days":60,"password":"`+tPhrase+`"}`, true); w.Code != 200 {
		t.Fatalf("продление: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "POST", excURL+"/exc-000000000000/extend", `{"base_version":4,"expires_in_days":1}`, true), 404, CodeNotFound)
	mustProblem(t, e.call(analyst, "DELETE", excURL+"/"+exc+"?base_version=4", "", true), 403, CodeForbidden)
	mustProblem(t, e.call(admin, "DELETE", excURL+"/"+exc+"?base_version=4&x=1", "", true), 400, CodeInvalidRequest)
	if w := e.call(admin, "DELETE", excURL+"/"+exc+"?base_version=4&comment=done", "", true); w.Code != 200 {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "DELETE", excURL+"/"+exc+"?base_version=5", "", true), 404, CodeNotFound)
	if _, n := e.polAction("policy.exception_delete"); n != 1 {
		t.Fatal("нет записи об удалении")
	}

	// Снятие отметки — mark = none: 204, повтор — 404.
	if w := e.call(analyst, "PUT", markURL, `{"mark":"none"}`, true); w.Code != http.StatusNoContent {
		t.Fatalf("снятие: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "PUT", markURL, `{"mark":"none"}`, true), 404, CodeNotFound)
	if n := e.auditCount(events.ActionMarkRemoved); n != 1 {
		t.Fatalf("аудит снятия: %d", n)
	}
	// «Подтверждено» — без черновика.
	w = e.call(analyst, "PUT", markURL, `{"mark":"confirmed"}`, true)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"draft"`) {
		t.Fatalf("подтверждено: %d %s", w.Code, w.Body)
	}
}

// FuzzExceptionRequest — тело создания исключения не роняет обработчик и
// не создаёт исключение без пароля.
func FuzzExceptionRequest(f *testing.F) {
	e := newAppsEnv(f)
	admin := e.mustLogin(f, "admin")
	if w := e.call(admin, "POST", "/api/v1/policies", `{"id":"support","spec":`+tPolicySpec+`}`, true); w.Code != http.StatusCreated {
		f.Fatal(w.Body)
	}
	f.Add(`{"base_version":1,"detector":"injection.heuristic","app":"a","reason":"r"}`)
	f.Add(`{"base_version":1,"detector":"pii.ru","fragment":"` + tFragment + `","reason":"r","expires_at":"2026-11-01T00:00:00Z"}`)
	f.Add(`{"base_version":1,"detector":"pii.ru","user":"x","reason":"r","expires_in_days":-5}`)
	f.Fuzz(func(t *testing.T, body string) {
		w := e.call(admin, "POST", "/api/v1/policies/support/exceptions", body, true)
		if w.Code == http.StatusCreated || w.Code >= 500 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
}

// 3В24 ревью 3.r3: черновик исключения берёт источник из находки события:
// находка в ответе модели — source: output, во входе — source: user;
// одинаковые находки из разных источников — разные пункты черновика.
func TestExceptionDraftHasSource(t *testing.T) {
	e := newAppsEnv(t)
	analyst := e.mustLogin(t, "analyst")
	ts := time.Now().UTC().Add(-time.Minute)
	ev := events.Event{
		ID: liveEventID(ts, 8), Time: ts, Type: events.TypeGatewayRequest, App: "support-bot", Env: "prod",
		PolicyMode: events.ModeEnforce, Storage: events.StorageNone,
		Decision: &events.Decision{Action: "allow", Applied: []string{"allow"}, Policy: "support", PolicyVersion: 1},
		Findings: []events.Finding{
			{Detector: "secrets.generic", Category: "secret.key", Score: 0.9, Location: "choices[0].message.content", Rule: "api_key", Source: "output"},
			{Detector: "secrets.generic", Category: "secret.key", Score: 0.9, Location: "messages[0].content", Rule: "api_key", Source: "user"},
		},
	}
	if _, err := e.ev.Insert(context.Background(), events.Ingest{GatewayID: testGatewayID, ReceivedAt: time.Now(), Events: []events.Event{ev}}); err != nil {
		t.Fatal(err)
	}
	w := e.call(analyst, "GET", "/api/v1/events/"+ev.ID+"/exception-draft", "", false)
	if w.Code != 200 {
		t.Fatalf("черновик: %d %s", w.Code, w.Body)
	}
	dr := decode[ExceptionDraftView](t, w.Body.Bytes())
	if len(dr.Items) != 2 || dr.Items[0].Source != "output" || dr.Items[1].Source != "user" {
		t.Fatalf("источники черновика: %+v", dr.Items)
	}
}
