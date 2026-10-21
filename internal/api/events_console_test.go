package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// События в консоли (задача 2.16) на хранилище Memory: права, причина
// доступа к содержимому, запись в аудит, выгрузка, фильтры, сроки.

// recAudit — журнал аудита в памяти; err — сбой записи. Подробности
// проходят ту же нормализацию, что в журнале (audit.CanonicalDetails):
// отказ фильтра секретов — сбой записи; canon — что попало бы в журнал.
type recAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
	canon   []string
	err     error
}

func (a *recAudit) Record(_ context.Context, e audit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	d, err := audit.CanonicalDetails(e.Details)
	if err != nil {
		return err
	}
	a.entries = append(a.entries, e)
	a.canon = append(a.canon, string(d))
	return nil
}

func (a *recAudit) find(action string) []audit.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []audit.Entry
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (a *recAudit) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

// promptMarker — содержимое, которое не должно попадать в списки и выгрузку.
const promptMarker = "Паспорт 4510 123456 — секрет содержимого"

// liveEventID — UUIDv7 со временем t и номером n.
func liveEventID(t time.Time, n int) string {
	ms := t.UnixMilli()
	return fmt.Sprintf("%08x-%04x-7000-8000-%012x", ms>>16, ms&0xffff, n)
}

type consoleEnv struct {
	mem   *events.Memory
	audit *recAudit
	ids   []string // от новых к старым
}

// newConsoleEnv — Memory с тремя событиями последних минут: два с
// содержимым, одно без.
func newConsoleEnv(t *testing.T) *consoleEnv {
	t.Helper()
	env := &consoleEnv{mem: events.NewMemory(), audit: &recAudit{}}
	env.mem.SetRetentionAudit(func(e audit.Entry) error { return env.audit.Record(context.Background(), e) })
	now := time.Now().UTC()
	var evs []events.Event
	for i := range 3 {
		ts := now.Add(-time.Duration(i+1) * time.Minute)
		e := events.Event{
			ID: liveEventID(ts, i+1), Time: ts, Type: events.TypeGatewayRequest, App: "support-bot", Env: "prod",
			PolicyMode: events.ModeMonitor, Storage: events.StorageMasked, Threats: []string{"DM-05"},
			Decision: &events.Decision{Action: "allow", Applied: []string{}, Trace: []events.TraceStep{{Rule: "r1", Detector: "pii.inn", Matched: true, Action: "allow"}}},
			Findings: []events.Finding{{Detector: "pii.inn", Category: "pii", Threat: "DM-05", Location: "messages[0]"}},
			Tokens:   &events.Tokens{Prompt: 10, Completion: 5},
			Content:  &events.Content{Request: promptMarker},
		}
		if i == 2 {
			e.App, e.Storage, e.Content = "=HYPERLINK(\"x\")", events.StorageNone, nil
		}
		evs = append(evs, e)
		env.ids = append(env.ids, e.ID)
	}
	if _, err := env.mem.Insert(context.Background(), events.Ingest{GatewayID: testGatewayID, ReceivedAt: now, Events: evs}); err != nil {
		t.Fatal(err)
	}
	return env
}

func (env *consoleEnv) handler(t *testing.T, perms ...string) http.Handler {
	t.Helper()
	return env.handlerWith(t, env.mem, perms...)
}

func (env *consoleEnv) handlerWith(t *testing.T, st EventsAPI, perms ...string) http.Handler {
	t.Helper()
	a := allowPerm{}
	for _, p := range perms {
		a[p] = true
	}
	return env.handlerWithAuthz(t, st, a, nil)
}

func (env *consoleEnv) handlerWithAuthz(t *testing.T, st EventsAPI, a Authorizer, svc *auth.Service) http.Handler {
	t.Helper()
	h, _ := newHandler(t, Options{Authorizer: a, Auth: svc, Events: st, Audit: env.audit})
	return h
}

// reauthHandler — обработчик, где у пользователя сессии есть пароль tPhrase
// в хранилище входа: для повторной проверки (В13 ревью 2.r3a).
func (env *consoleEnv) reauthHandler(t *testing.T, perms ...string) (http.Handler, *authtest.Memory) {
	t.Helper()
	a := allowPerm{}
	for _, p := range perms {
		a[p] = true
	}
	mem := authtest.NewMemory()
	now := time.Now().UTC().Truncate(time.Microsecond)
	u := passwordPerm{allow: a, user: auth.User{ID: allowPermUserID, OrgID: audit.DefaultOrgID, Login: "u1", DisplayName: "u1",
		Role: auth.RoleSecurityAdmin, Status: auth.StatusActive, PasswordHash: authtest.HashOf(tPhrase),
		PasswordChangedAt: now, CreatedAt: now, CreatedBy: "test"}}
	mem.AddUser(u.user)
	return env.handlerWithAuthz(t, env.mem, u, testAuth(t, mem)), mem
}

// passwordPerm — allowPerm с полной учётной записью пользователя.
type passwordPerm struct {
	allow allowPerm
	user  auth.User
}

func (a passwordPerm) Authorize(r *http.Request, perm string) (Principal, Decision) {
	p, d := a.allow.Authorize(r, perm)
	p.Caller.User = a.user
	return p, d
}

// tokenPerm — вызов по токену API с заданными правами.
type tokenPerm map[string]bool

func (a tokenPerm) Authorize(r *http.Request, perm string) (Principal, Decision) {
	p, d := allowPerm(a).Authorize(r, perm)
	p.Caller.Token = &auth.APIToken{ID: "01900000-0000-7000-8000-0000000000b9", Prefix: "aisec_pat_abcdefgh"}
	p.Caller.Session = auth.Session{}
	return p, d
}

func jsonCT() []string { return []string{"Content-Type", "application/json"} }

func TestEventsListPagesAndFilter(t *testing.T) {
	env := newConsoleEnv(t)
	h := env.handler(t, auth.PermEventsRead)
	w := do(h, "GET", "/api/v1/events?limit=2", "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var page struct {
		Items      []events.View `json:"items"`
		NextCursor string        `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].ID != env.ids[0] || page.Items[1].ID != env.ids[1] || page.NextCursor == "" {
		t.Fatalf("первая страница: %s", w.Body)
	}
	if page.Items[0].Details != nil || strings.Contains(w.Body.String(), promptMarker) || strings.Contains(w.Body.String(), `"content":`) {
		t.Fatalf("в списке подробности или содержимое: %s", w.Body)
	}
	w = do(h, "GET", "/api/v1/events?limit=2&cursor="+page.NextCursor, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), env.ids[2]) || strings.Contains(w.Body.String(), "next_cursor") {
		t.Fatalf("вторая страница: %d %s", w.Code, w.Body)
	}
	w = do(h, "GET", "/api/v1/events?filter="+url.QueryEscape(`storage = "none" and threat = "DM-05"`), "")
	if w.Code != 200 || strings.Count(w.Body.String(), `"id"`) != 1 || !strings.Contains(w.Body.String(), env.ids[2]) {
		t.Fatalf("фильтр: %d %s", w.Code, w.Body)
	}
	if got := env.audit.find("events.list"); len(got) != 3 {
		t.Fatalf("записей events.list: %d", len(got))
	}
}

func TestEventsListRejects(t *testing.T) {
	env := newConsoleEnv(t)
	h := env.handler(t, auth.PermEventsRead)
	now := time.Now().UTC()
	for _, q := range []string{
		"filter=" + url.QueryEscape(`app = crm`),
		"filter=" + url.QueryEscape(`nope = "x"`),
		"filter=a&filter=b",
		"filter=" + url.QueryEscape(strings.Repeat(" ", events.MaxFilterLen+1)),
		"from=вчера",
		"from=" + now.Add(-32*24*time.Hour).Format(time.RFC3339),
		"from=" + now.Format(time.RFC3339) + "&to=" + now.Add(-time.Hour).Format(time.RFC3339),
		"limit=0", "limit=201", "cursor=abc!", "sort=time",
	} {
		w := do(h, "GET", "/api/v1/events?"+q, "")
		mustProblem(t, w, 400, CodeInvalidRequest)
	}
	// Ошибка фильтра указывает позицию и не повторяет ввод.
	w := do(h, "GET", "/api/v1/events?filter="+url.QueryEscape(`app = "x" and secretfield = "y"`), "")
	if !strings.Contains(w.Body.String(), "Позиция 14") || strings.Contains(w.Body.String(), "secretfield") {
		t.Fatalf("ошибка фильтра: %s", w.Body)
	}
}

func TestEventCard(t *testing.T) {
	env := newConsoleEnv(t)
	h := env.handler(t, auth.PermEventsRead)
	w := do(h, "GET", "/api/v1/events/"+env.ids[0], "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"trace"`) || !strings.Contains(w.Body.String(), `"has_content":true`) ||
		strings.Contains(w.Body.String(), promptMarker) {
		t.Fatalf("карточка: %d %s", w.Code, w.Body)
	}
	if got := env.audit.find("events.view"); len(got) != 1 || got[0].Object.ID != env.ids[0] {
		t.Fatalf("events.view: %+v", got)
	}
	mustProblem(t, do(h, "GET", "/api/v1/events/"+liveEventID(time.Now(), 99), ""), 404, CodeNotFound)
	mustProblem(t, do(h, "GET", "/api/v1/events/not-an-id", ""), 404, CodeNotFound)
}

// В4 ревью 2.r1: причина со строкой вида «Bearer …» не ломает запись
// аудита — содержимое выдаётся, запись есть, токена в ней нет.
func TestEventContentReasonWithBearer(t *testing.T) {
	env := newConsoleEnv(t)
	h := env.handler(t, auth.PermEventsContentRead)
	w := do(h, "POST", "/api/v1/events/"+env.ids[0]+"/content", `{"reason":"Bearer abc123 утёк, разбор"}`, jsonCT()...)
	if w.Code != 200 || !strings.Contains(w.Body.String(), promptMarker) {
		t.Fatalf("содержимое: %d %s", w.Code, w.Body)
	}
	if got := env.audit.find("events.content_read"); len(got) != 1 {
		t.Fatalf("записей о доступе: %d", len(got))
	}
	env.audit.mu.Lock()
	defer env.audit.mu.Unlock()
	last := env.audit.canon[len(env.audit.canon)-1]
	if strings.Contains(last, "abc123") || !strings.Contains(last, `"reason":"Bearer [скрыто] утёк, разбор"`) {
		t.Fatalf("подробности в журнале: %s", last)
	}
}

// УПД.7: содержимое — только с events.content.read и причиной; каждое
// обращение — в аудит до ответа.
func TestEventContentRequiresPermissionAndReason(t *testing.T) {
	env := newConsoleEnv(t)
	path := "/api/v1/events/" + env.ids[0] + "/content"
	body := `{"reason":"Разбор инцидента INC-42"}`

	// Без разрешения — отказ, содержимого нет.
	w := do(env.handler(t, auth.PermEventsRead), "POST", path, body, jsonCT()...)
	mustProblem(t, w, 403, CodeForbidden)
	if strings.Contains(w.Body.String(), promptMarker) || len(env.audit.find("events.content_read")) != 0 {
		t.Fatal("содержимое или запись о доступе без разрешения")
	}

	h := env.handler(t, auth.PermEventsContentRead)
	for _, b := range []string{`{}`, `{"reason":""}`, `{"reason":"  ab  "}`, `{"reason":"` + strings.Repeat("я", MaxContentReason+1) + `"}`,
		`{"reason":"строка\nвторая"}`, `{"reason":"ok","extra":1}`} {
		mustProblem(t, do(h, "POST", path, b, jsonCT()...), 400, CodeInvalidRequest)
	}
	if len(env.audit.find("events.content_read")) != 0 {
		t.Fatal("запись о доступе без причины")
	}

	w = do(h, "POST", path, body, jsonCT()...)
	if w.Code != 200 || !strings.Contains(w.Body.String(), promptMarker) {
		t.Fatalf("содержимое: %d %s", w.Code, w.Body)
	}
	got := env.audit.find("events.content_read")
	if len(got) != 1 || got[0].Object.ID != env.ids[0] || got[0].Result != audit.ResultSuccess {
		t.Fatalf("запись о доступе: %+v", got)
	}
	if d, _ := got[0].Details.(map[string]any); d["reason"] != "Разбор инцидента INC-42" {
		t.Fatalf("причина: %+v", got[0].Details)
	}

	// Без содержимого — 404, обращение тоже в аудите.
	w = do(h, "POST", "/api/v1/events/"+env.ids[2]+"/content", body, jsonCT()...)
	mustProblem(t, w, 404, CodeNotFound)
	if got := env.audit.find("events.content_read"); len(got) != 2 || got[1].Result != audit.ResultFailure {
		t.Fatalf("запись об отсутствующем содержимом: %+v", got)
	}
	mustProblem(t, do(h, "POST", "/api/v1/events/"+liveEventID(time.Now(), 77)+"/content", body, jsonCT()...), 404, CodeNotFound)

	// Журнал аудита недоступен — содержимое не выдаётся.
	env.audit.fail(errors.New("журнал недоступен"))
	w = do(h, "POST", path, body, jsonCT()...)
	mustProblem(t, w, 503, CodeUnavailable)
	if strings.Contains(w.Body.String(), promptMarker) {
		t.Fatal("содержимое выдано без записи в аудит")
	}
}

func TestEventsExportCSV(t *testing.T) {
	env := newConsoleEnv(t)
	h := env.handler(t, auth.PermEventsExport)
	w := do(h, "POST", "/api/v1/events/export", `{"format":"csv","filter":"app != \"none\""}`, jsonCT()...)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") ||
		!strings.Contains(w.Header().Get("Content-Disposition"), "attachment") || w.Header().Get("X-Export-Rows") != "3" {
		t.Fatalf("выгрузка: %d %v %s", w.Code, w.Header(), w.Body)
	}
	if strings.Contains(w.Body.String(), promptMarker) {
		t.Fatal("содержимое в выгрузке")
	}
	body, ok := strings.CutPrefix(w.Body.String(), "\ufeff")
	if !ok {
		t.Fatal("нет BOM UTF-8")
	}
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil || len(rows) != 4 {
		t.Fatalf("CSV: %v %v", err, rows)
	}
	if !strings.Contains(w.Body.String(), `'=HYPERLINK(`) {
		t.Fatalf("формула не экранирована: %s", w.Body)
	}
	got := env.audit.find("data.export")
	if len(got) != 1 {
		t.Fatalf("data.export: %+v", got)
	}
	d, _ := got[0].Details.(map[string]any)
	if d["rows"] != 3 || d["filter"] != `app != "none"` || d["format"] != "csv" {
		t.Fatalf("подробности выгрузки: %+v", d)
	}
}

func TestEventsExportJSONAndRejects(t *testing.T) {
	env := newConsoleEnv(t)
	h := env.handler(t, auth.PermEventsExport)
	w := do(h, "POST", "/api/v1/events/export", `{"format":"json"}`, jsonCT()...)
	var out []events.View
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 3 || out[0].Details == nil {
		t.Fatalf("JSON: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), promptMarker) {
		t.Fatal("содержимое в выгрузке")
	}
	for _, b := range []string{`{}`, `{"format":"xml"}`, `{"format":"csv","filter":"app ="}`,
		`{"format":"csv","from":"2026-01-01T00:00:00Z","to":"2026-03-01T00:00:00Z"}`, `{"format":"csv","content":true}`} {
		mustProblem(t, do(h, "POST", "/api/v1/events/export", b, jsonCT()...), 400, CodeInvalidRequest)
	}
	// Больше предела строк — отказ без записи в аудит.
	big := env.handlerWith(t, bigCount{env.mem}, auth.PermEventsExport)
	mustProblem(t, do(big, "POST", "/api/v1/events/export", `{"format":"csv"}`, jsonCT()...), 422, CodeUnprocessable)
	if n := len(env.audit.find("data.export")); n != 1 {
		t.Fatalf("data.export: %d", n)
	}
	// Журнал недоступен — выгрузки нет.
	env.audit.fail(errors.New("журнал недоступен"))
	w = do(h, "POST", "/api/v1/events/export", `{"format":"csv"}`, jsonCT()...)
	mustProblem(t, w, 503, CodeUnavailable)
}

type bigCount struct{ *events.Memory }

func (bigCount) Export(context.Context, events.Query, func(int) error, func(*events.Record) error) error {
	return events.ErrTooManyRows
}

func TestEventFilters(t *testing.T) {
	env := newConsoleEnv(t)
	h := env.handler(t, auth.PermEventsRead)
	w := do(h, "POST", "/api/v1/events/filters", `{"name":"Утечки ПДн","filter":"threat in (\"DM-05\") and app=\"crm\""}`, jsonCT()...)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"filter":"threat = \"DM-05\" and app = \"crm\""`) {
		t.Fatalf("сохранение: %d %s", w.Code, w.Body)
	}
	var sf events.SavedFilter
	if err := json.Unmarshal(w.Body.Bytes(), &sf); err != nil {
		t.Fatal(err)
	}
	mustProblem(t, do(h, "POST", "/api/v1/events/filters", `{"name":"Утечки ПДн","filter":""}`, jsonCT()...), 409, CodeConflict)
	mustProblem(t, do(h, "POST", "/api/v1/events/filters", `{"name":" ","filter":""}`, jsonCT()...), 400, CodeInvalidRequest)
	mustProblem(t, do(h, "POST", "/api/v1/events/filters", `{"name":"x","filter":"or"}`, jsonCT()...), 400, CodeInvalidRequest)
	if w := do(h, "GET", "/api/v1/events/filters", ""); w.Code != 200 || !strings.Contains(w.Body.String(), sf.ID) {
		t.Fatalf("список: %d %s", w.Code, w.Body)
	}
	// Чужой фильтр неотличим от отсутствующего.
	if err := func() error {
		_, err := env.mem.SaveFilter(context.Background(), "01900000-0000-7000-8000-0000000000aa", "чужой", events.Filter{})
		return err
	}(); err != nil {
		t.Fatal(err)
	}
	other, err := env.mem.Filters(context.Background(), "01900000-0000-7000-8000-0000000000aa")
	if err != nil || len(other) != 1 {
		t.Fatalf("чужие фильтры: %v, %v", other, err)
	}
	mustProblem(t, do(h, "DELETE", "/api/v1/events/filters/"+other[0].ID, ""), 404, CodeNotFound)
	if w := do(h, "GET", "/api/v1/events/filters", ""); strings.Contains(w.Body.String(), "чужой") {
		t.Fatalf("чужой фильтр в списке: %s", w.Body)
	}
	if w := do(h, "DELETE", "/api/v1/events/filters/"+sf.ID, ""); w.Code != 204 {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	mustProblem(t, do(h, "DELETE", "/api/v1/events/filters/"+sf.ID, ""), 404, CodeNotFound)
	mustProblem(t, do(h, "DELETE", "/api/v1/events/filters/x", ""), 404, CodeNotFound)
	for i := range events.MaxSavedFilters {
		if w := do(h, "POST", "/api/v1/events/filters", fmt.Sprintf(`{"name":"f%d","filter":""}`, i), jsonCT()...); w.Code != 201 {
			t.Fatalf("фильтр %d: %d", i, w.Code)
		}
	}
	mustProblem(t, do(h, "POST", "/api/v1/events/filters", `{"name":"лишний","filter":""}`, jsonCT()...), 422, CodeUnprocessable)
}

func TestEventSettings(t *testing.T) {
	env := newConsoleEnv(t)
	read := env.handler(t, auth.PermEventsRead)
	if w := do(read, "GET", "/api/v1/events/settings", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"metadata_days":365`) {
		t.Fatalf("чтение: %d %s", w.Code, w.Body)
	}
	mustProblem(t, do(read, "PUT", "/api/v1/events/settings", `{"metadata_days":30,"content_days":7}`, jsonCT()...), 403, CodeForbidden)

	h, mem := env.reauthHandler(t, auth.PermEventsRetentionManage, auth.PermEventsRead)
	for _, b := range []string{`{"metadata_days":29,"content_days":7}`, `{"metadata_days":30,"content_days":31}`,
		`{"metadata_days":30}`, `{"metadata_days":"30","content_days":7}`} {
		mustProblem(t, do(h, "PUT", "/api/v1/events/settings", b, jsonCT()...), 400, CodeInvalidRequest)
	}
	// В13 ревью 2.r3a: сокращение срока без пароля или с неверным паролем
	// отклоняется, сроки не меняются.
	mustProblem(t, do(h, "PUT", "/api/v1/events/settings", `{"metadata_days":180,"content_days":30}`, jsonCT()...),
		400, CodeInvalidRequest)
	mustProblem(t, do(h, "PUT", "/api/v1/events/settings", `{"metadata_days":365,"content_days":30,"password":"неверный"}`, jsonCT()...),
		403, CodeReauthFailed)
	mustProblem(t, do(h, "PUT", "/api/v1/events/settings",
		mustJSON(t, map[string]any{"metadata_days": 180, "content_days": 90, "password": tPhrase, "code": "123456"}), jsonCT()...),
		400, CodeInvalidRequest)
	if r, err := env.mem.Retention(context.Background()); err != nil || r.MetadataDays != 365 || r.ContentDays != 90 {
		t.Fatalf("сроки изменились без повторной проверки: %+v", r)
	}
	if len(env.audit.find("events.settings_changed")) != 0 {
		t.Fatal("отклонённое сокращение записано как изменение")
	}
	var failed []audit.Entry
	for _, e := range mem.Records() {
		if e.Action == "events.settings_changed" {
			failed = append(failed, e)
		}
	}
	if len(failed) != 1 || failed[0].Result != audit.ResultFailure {
		t.Fatalf("неверный пароль не записан в аудит: %+v", failed)
	}
	w := do(h, "PUT", "/api/v1/events/settings",
		mustJSON(t, map[string]any{"metadata_days": 180, "content_days": 30, "password": tPhrase}), jsonCT()...)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"metadata_days":180,"content_days":30`) {
		t.Fatalf("изменение: %d %s", w.Code, w.Body)
	}
	got := env.audit.find("events.settings_changed")
	if len(got) != 1 || got[0].Actor.Type != audit.ActorUser {
		t.Fatalf("events.settings_changed: %+v", got)
	}
	if d, _ := got[0].Details.(map[string]any); d["reduced"] != true {
		t.Fatalf("признак сокращения: %+v", d)
	}
	// Увеличение — без повторной проверки; те же сроки — тоже.
	for _, b := range []string{`{"metadata_days":200,"content_days":30}`, `{"metadata_days":200,"content_days":30}`} {
		if w := do(h, "PUT", "/api/v1/events/settings", b, jsonCT()...); w.Code != 200 {
			t.Fatalf("увеличение: %d %s", w.Code, w.Body)
		}
	}
	// Токен API сокращать сроки не может даже с правом.
	tok := env.handlerWithAuthz(t, env.mem, tokenPerm{auth.PermEventsRetentionManage: true}, nil)
	mustProblem(t, do(tok, "PUT", "/api/v1/events/settings", `{"metadata_days":180,"content_days":30,"password":"x"}`, jsonCT()...),
		403, CodeForbidden)
	if w := do(h, "PUT", "/api/v1/events/settings",
		mustJSON(t, map[string]any{"metadata_days": 180, "content_days": 30, "password": tPhrase}), jsonCT()...); w.Code != 200 {
		t.Fatalf("возврат сроков: %d %s", w.Code, w.Body)
	}
	// Журнал недоступен — сроки не меняются.
	env.audit.fail(errors.New("журнал недоступен"))
	if w := do(h, "PUT", "/api/v1/events/settings", `{"metadata_days":365,"content_days":90}`, jsonCT()...); w.Code < 500 {
		t.Fatalf("без аудита: %d", w.Code)
	}
	if r, err := env.mem.Retention(context.Background()); err != nil || r.MetadataDays != 180 {
		t.Fatalf("сроки изменились без записи в аудит: %+v", r)
	}
}

func TestEventStats(t *testing.T) {
	env := newConsoleEnv(t)
	h := env.handler(t, auth.PermEventsRead)
	w := do(h, "GET", "/api/v1/events/stats?interval=minute&app=support-bot", "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var st StatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	var n, tokens int64
	for _, a := range st.Items {
		n += a.Events
		tokens += a.TokensPrompt
		if a.Threats["DM-05"] != a.Events {
			t.Fatalf("угрозы: %+v", a)
		}
	}
	if n != 2 || tokens != 20 || st.Interval != "minute" {
		t.Fatalf("агрегаты: %s", w.Body)
	}
	for _, q := range []string{"interval=day", "interval=minute&from=" + time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339),
		"bucket=1", "app=a&app=b"} {
		mustProblem(t, do(h, "GET", "/api/v1/events/stats?"+q, ""), 400, CodeInvalidRequest)
	}
}

// Хранилище не подключено — 503, а не паника.
// Выгрузка и просмотр по токену API пишутся в аудит от имени токена, а не
// его владельца (РСБ.1, задача 2.10).
func TestEventsActor(t *testing.T) {
	u := auth.User{ID: "01900000-0000-7000-8000-0000000000a1", Login: "analyst"}
	if a := eventsActor(Principal{Caller: &auth.Caller{User: u}}); a.Type != audit.ActorUser || a.ID != u.ID {
		t.Fatalf("сессия: %+v", a)
	}
	tok := &auth.APIToken{ID: "01900000-0000-7000-8000-0000000000b1", Prefix: "aisec_pat_abcdefgh"}
	a := eventsActor(Principal{Caller: &auth.Caller{User: u, Token: tok}})
	if a.Type != audit.ActorAPIToken || a.ID != tok.ID || a.Name != "analyst (aisec_pat_abcdefgh)" {
		t.Fatalf("токен: %+v", a)
	}
	if a := eventsActor(Principal{ID: "gw"}); a.Type != audit.ActorAPIToken || a.ID != "gw" {
		t.Fatalf("без пользователя: %+v", a)
	}
}

func TestEventsWithoutStore(t *testing.T) {
	h, _ := newHandler(t, Options{Authorizer: allowPerm{auth.PermEventsRead: true}})
	mustProblem(t, do(h, "GET", "/api/v1/events", ""), 503, CodeUnavailable)
}

// Сбой БД — 500 без текста ошибки.
func TestEventsStoreError(t *testing.T) {
	env := newConsoleEnv(t)
	env.mem.ReadErr = errTest
	w := do(env.handler(t, auth.PermEventsRead), "GET", "/api/v1/events", "")
	mustProblem(t, w, 500, CodeInternal)
	if strings.Contains(w.Body.String(), "secret-dsn") {
		t.Fatal("текст ошибки БД в ответе")
	}
}

func FuzzEventsListQuery(f *testing.F) {
	for _, s := range []string{"", "limit=2", "filter=app+%3D+%22x%22", "from=2026-10-21T00:00:00Z&to=2026-10-22T00:00:00Z",
		"cursor=MTIzOmFiYw", "filter=a&filter=b", "limit=-1"} {
		f.Add(s)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, raw string) {
		r, err := http.NewRequestWithContext(context.Background(), "GET", "/api/v1/events", nil)
		if err != nil {
			t.Skip()
		}
		r.URL.RawQuery = raw
		p, prob := parseEventsList(r, now)
		if prob != nil {
			if prob.Status != 400 {
				t.Fatalf("статус %d", prob.Status)
			}
			return
		}
		if err := p.query.Validate(); err != nil {
			t.Fatalf("разобранный запрос не проходит проверку: %v", err)
		}
		if p.query.Limit < 2 || p.query.Limit > MaxPageLimit+1 {
			t.Fatalf("предел %d", p.query.Limit)
		}
	})
}

// blockingExport — выгрузка, которая ждёт release: так тест держит
// выгрузки «идущими» без пауз и зависимости от планировщика.
type blockingExport struct {
	*events.Memory
	entered chan struct{}
	release chan struct{}
}

func (b blockingExport) Export(_ context.Context, _ events.Query, start func(int) error, _ func(*events.Record) error) error {
	b.entered <- struct{}{}
	<-b.release
	return start(0)
}

// subjectAuthz пропускает perm от субъекта из заголовка X-Test-Subject.
type subjectAuthz string

func (a subjectAuthz) Authorize(r *http.Request, perm string) (Principal, Decision) {
	p := Principal{ID: r.Header.Get("X-Test-Subject"), Grants: auth.Grants{string(a): auth.ScopeAll}}
	if perm == string(a) {
		return p, Allow
	}
	return p, Forbidden
}

// Одновременных выгрузок — не больше одной на субъект и двух на сервер
// (В11 ревью 2.r3a); сверх предела — 429 с Retry-After без записи в аудит.
func TestEventsExportConcurrencyLimit(t *testing.T) {
	env := newConsoleEnv(t)
	st := blockingExport{Memory: env.mem, entered: make(chan struct{}, 8), release: make(chan struct{})}
	h, _ := newHandler(t, Options{Authorizer: subjectAuthz(auth.PermEventsExport), Events: st, Audit: env.audit})
	export := func(subject string) *httptest.ResponseRecorder {
		return do(h, "POST", "/api/v1/events/export", `{"format":"csv"}`, "Content-Type", "application/json", "X-Test-Subject", subject)
	}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, subject := range []string{"a", "b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- export(subject).Code
		}()
		<-st.entered
	}
	for name, subject := range map[string]string{"тот же субъект": "a", "третья на сервер": "c"} {
		w := export(subject)
		mustProblem(t, w, http.StatusTooManyRequests, CodeRateLimited)
		if w.Header().Get("Retry-After") == "" {
			t.Fatalf("%s: нет Retry-After", name)
		}
	}
	if n := len(env.audit.find("data.export")); n != 0 {
		t.Fatalf("записей data.export до завершения: %d", n)
	}
	close(st.release)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != http.StatusOK {
			t.Fatalf("занятая выгрузка: %d", c)
		}
	}
	// Места освобождены: выгрузка снова проходит.
	if w := export("a"); w.Code != http.StatusOK {
		t.Fatalf("после завершения: %d %s", w.Code, w.Body)
	}
	if n := len(env.audit.find("data.export")); n != 3 {
		t.Fatalf("записей data.export: %d", n)
	}
}
