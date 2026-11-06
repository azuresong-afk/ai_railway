package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/redteam"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Тестирование устойчивости через API (задача 5.32, ADR-0031): отказ в
// доступе у каждого эндпоинта, цели только в сессии консоли с повторной
// проверкой адреса, база сценариев, запуск токеном и итоги без промптов
// и секретов.

const rtSecret = "rt-auth-value-7f3c9a" //nolint:gosec // G101: синтетическое значение заголовка для проверки, что оно не сохраняется

func newRedTeamEnv(t *testing.T) (*appsEnv, *redteam.Service, *redteam.Memory) {
	t.Helper()
	mem := redteam.NewMemory()
	var svc *redteam.Service
	e := newAppsEnv(t, func(_ *appsEnv, o *Options) {
		p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
		if err != nil {
			t.Fatal(err)
		}
		// Разрешение имён недоступно: сценарии завершаются ошибкой сразу,
		// без обращений в сеть.
		lookup := func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("нет DNS в тесте")
		}
		r, err := p.Random()
		if err != nil {
			t.Fatal(err)
		}
		key, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
		if err != nil {
			t.Fatal(err)
		}
		box, err := keyring.NewStaticKey(p, "01900000-0000-7000-8000-0000000000d1", key)
		if err != nil {
			t.Fatal(err)
		}
		svc, err = redteam.New(redteam.Options{Store: mem, ServiceDBs: servicedb.NewMemory(), Provider: p, Box: box, Apps: o.Apps,
			Logger: o.Logger, Lookup: lookup})
		if err != nil {
			t.Fatal(err)
		}
		o.RedTeam = svc
	})
	t.Cleanup(svc.Wait)
	return e, svc, mem
}

func rtEndpointBody(extra string) string {
	return `{"name":"Бот поддержки","kind":"endpoint","url":"http://bot.example.test:8080/v1/chat/completions",` +
		`"request_template":"{\"messages\":\"{{messages}}\"}","response_path":"choices.0.message.content",` +
		`"auth_header":"X-Api-Key","authorization_note":"Договор № 17 от 01.11.2026, тестирование разрешено",` +
		`"limits":{"rate_per_minute":600,"concurrency":1,"request_timeout_sec":5,"run_timeout_min":1}` + extra + `}`
}

func TestRedTeamAccessDenied(t *testing.T) {
	e, _, _ := newRedTeamEnv(t)
	owner := e.mustLogin(t, "owner")
	auditor := e.mustLogin(t, "auditor")
	analyst := e.mustLogin(t, "analyst")
	sys := e.mustLogin(t, "sysadm")
	const (
		target = "/api/v1/redteam/targets/01900000-0000-7000-8000-0000000000ff"
		run    = "/api/v1/redteam/runs/01900000-0000-7000-8000-0000000000fe"
	)
	body := rtEndpointBody(`,"password":"` + tPhrase + `"`)
	runBody := `{"target_id":"01900000-0000-7000-8000-0000000000ff"}`
	type req struct{ method, path, body string }
	writes := []req{
		{"POST", "/api/v1/redteam/targets", body}, {"PUT", target, body}, {"DELETE", target, ""},
		{"POST", "/api/v1/redteam/scenarios/rollback", ""}, {"POST", "/api/v1/redteam/runs", runBody}, {"POST", run + "/cancel", ""},
	}
	reads := []req{{"GET", "/api/v1/redteam/targets", ""}, {"GET", target, ""}, {"GET", "/api/v1/redteam/scenarios", ""},
		{"GET", "/api/v1/redteam/runs", ""}, {"GET", run, ""}}
	// Владелец приложения не видит ничего; аудитор и аналитик только читают.
	for _, c := range slicesConcat(writes, reads) {
		mustProblem(t, e.call(owner, c.method, c.path, c.body, c.method != "GET"), http.StatusForbidden, CodeForbidden)
	}
	for _, s := range []session{auditor, analyst} {
		for _, c := range writes {
			mustProblem(t, e.call(s, c.method, c.path, c.body, true), http.StatusForbidden, CodeForbidden)
		}
		if w := e.call(s, "GET", "/api/v1/redteam/targets", "", false); w.Code != http.StatusOK {
			t.Fatalf("чтение: %d %s", w.Code, w.Body)
		}
	}
	for _, s := range []session{owner, auditor, analyst} {
		mustProblem(t, e.callFile(s, "PUT", "/api/v1/redteam/scenarios", "application/octet-stream", []byte("x")),
			http.StatusForbidden, CodeForbidden)
	}
	// Администратор системы: цели (право безопасности), запуск и отмена — нет.
	for _, c := range []req{writes[0], writes[1], writes[2], writes[4], writes[5]} {
		mustProblem(t, e.call(sys, c.method, c.path, c.body, true), http.StatusForbidden, CodeForbidden)
	}
	if p, ok := auth.LookupPermission(auth.PermRedteamTargetsManage); !ok || !p.Security {
		t.Fatalf("redteam.targets.manage — не право безопасности: %+v", p)
	}
	// Токен с redteam.scenarios.load не возвращает базу: только сессия консоли.
	tok := session{bearer: e.issueToken(t, sys, auth.PermRedteamScenariosLoad).Token}
	_, before := lastDenied(t, e.mem)
	mustProblem(t, e.call(tok, "POST", "/api/v1/redteam/scenarios/rollback", "", false), http.StatusForbidden, CodeForbidden)
	if rec, after := lastDenied(t, e.mem); after != before+1 || rec.Actor.Type != audit.ActorAPIToken {
		t.Fatalf("отказ токену не записан: %+v", rec)
	}
	// Без входа — 401.
	mustProblem(t, e.call(session{}, "GET", "/api/v1/redteam/runs", "", false), http.StatusUnauthorized, CodeUnauthorized)
}

func slicesConcat[T any](a, b []T) []T { return append(append([]T{}, a...), b...) }

// Цели: создание endpoint — с повторной проверкой, без значения секретного
// заголовка в ответах; база сценариев — загрузка и сведения без промптов;
// запуск токеном CI с auth_value: значение не попадает ни в ответы, ни в
// аудит; итоги — без промптов; отмена завершённого — 409.
func TestRedTeamTargetsRunsAPI(t *testing.T) {
	e, svc, mem := newRedTeamEnv(t)
	admin := e.mustLogin(t, "admin")
	sys := e.mustLogin(t, "sysadm")

	// Без пароля адрес цели не задаётся.
	if w := e.call(admin, "POST", "/api/v1/redteam/targets", rtEndpointBody(""), true); w.Code < 400 {
		t.Fatalf("цель без повторной проверки: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "POST", "/api/v1/redteam/targets", rtEndpointBody(`,"password":"`+tPhrase+`","storage":"full"`), true),
		http.StatusBadRequest, CodeInvalidRequest)
	w := e.call(admin, "POST", "/api/v1/redteam/targets", rtEndpointBody(`,"password":"`+tPhrase+`"`), true)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание цели: %d %s", w.Code, w.Body)
	}
	tg := decode[RedTeamTargetView](t, w.Body.Bytes())
	if tg.Kind != redteam.KindEndpoint || tg.Storage != redteam.StorageNone || strings.Contains(w.Body.String(), tPhrase) {
		t.Fatalf("цель: %s", w.Body)
	}
	list := decode[RedTeamTargetList](t, e.call(admin, "GET", "/api/v1/redteam/targets", "", false).Body.Bytes())
	if len(list.Items) != 1 || list.GatewayConfigured {
		t.Fatalf("список целей: %+v", list)
	}
	// Смена имени — без повторной проверки.
	if w := e.call(admin, "PUT", "/api/v1/redteam/targets/"+tg.ID, strings.Replace(rtEndpointBody(""), "Бот поддержки", "Бот", 1), true); w.Code != http.StatusOK {
		t.Fatalf("смена имени: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "GET", "/api/v1/redteam/targets/bad", "", false), http.StatusNotFound, CodeNotFound)

	// Без базы сценариев запуск невозможен.
	tok := session{bearer: e.issueToken(t, admin, auth.PermRedteamRun, auth.PermRedteamRead).Token}
	runBody := `{"target_id":"` + tg.ID + `","scenarios":["RT-DM01-001"],"auth_value":"` + rtSecret + `"}`
	mustProblem(t, e.call(tok, "POST", "/api/v1/redteam/runs", runBody, false), http.StatusUnprocessableEntity, CodeUnprocessable)

	// База сценариев: администратор системы загружает подписанный файл.
	data, err := os.ReadFile("../../testdata/redteam/scenarios-test.aisecdb")
	if err != nil {
		t.Fatal(err)
	}
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/redteam/scenarios", "application/json", data), http.StatusUnsupportedMediaType, CodeUnsupportedMedia)
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/redteam/scenarios", "application/octet-stream", []byte("не база")),
		http.StatusUnprocessableEntity, CodeUnprocessable)
	if w := e.callFile(sys, "PUT", "/api/v1/redteam/scenarios", "application/octet-stream", data); w.Code != http.StatusOK {
		t.Fatalf("загрузка базы: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/redteam/scenarios", "application/octet-stream", data), http.StatusConflict, CodeConflict)
	w = e.call(sys, "GET", "/api/v1/redteam/scenarios", "", false)
	sc := decode[redteam.ScenariosView](t, w.Body.Bytes())
	if len(sc.Scenarios) != 5 || sc.State.Active != "current" || strings.Contains(w.Body.String(), "ПРОБОЙ-7731") {
		t.Fatalf("сведения о сценариях (без промптов и маркеров): %s", w.Body)
	}

	// Запуск токеном CI: неверный фильтр, нет значения секретного
	// заголовка, затем успешный запуск.
	mustProblem(t, e.call(tok, "POST", "/api/v1/redteam/runs", `{"target_id":"`+tg.ID+`","lang":"de","auth_value":"x"}`, false),
		http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(tok, "POST", "/api/v1/redteam/runs", `{"target_id":"`+tg.ID+`"}`, false), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(tok, "POST", "/api/v1/redteam/runs", `{"target_id":"01900000-0000-7000-8000-0000000000ff"}`, false),
		http.StatusBadRequest, CodeInvalidRequest)
	w = e.call(tok, "POST", "/api/v1/redteam/runs", runBody, false)
	if w.Code != http.StatusAccepted || strings.Contains(w.Body.String(), rtSecret) {
		t.Fatalf("запуск: %d %s", w.Code, w.Body)
	}
	run := decode[RedTeamRunView](t, w.Body.Bytes())
	var card RedTeamRunCard
	for deadline := time.Now().Add(10 * time.Second); ; {
		w = e.call(tok, "GET", "/api/v1/redteam/runs/"+run.ID, "", false)
		card = decode[RedTeamRunCard](t, w.Body.Bytes())
		if card.Status != redteam.RunRunning && card.Status != redteam.RunQueued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("запуск не завершился: %s", w.Body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if card.Status != redteam.RunDone || len(card.Results) != 1 || card.Results[0].Verdict != redteam.VerdictError ||
		card.Results[0].ErrorCode == "" || strings.Contains(w.Body.String(), "ПРОБОЙ") || strings.Contains(w.Body.String(), rtSecret) {
		t.Fatalf("итоги запуска: %s", w.Body)
	}
	runs := decode[RedTeamRunList](t, e.call(admin, "GET", "/api/v1/redteam/runs?target_id="+tg.ID, "", false).Body.Bytes())
	if len(runs.Items) != 1 || runs.Items[0].ID != run.ID {
		t.Fatalf("список запусков: %+v", runs)
	}
	mustProblem(t, e.call(admin, "GET", "/api/v1/redteam/runs?limit=0", "", false), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(tok, "POST", "/api/v1/redteam/runs/"+run.ID+"/cancel", "", false), http.StatusConflict, CodeConflict)
	mustProblem(t, e.call(tok, "POST", "/api/v1/redteam/runs/bad/cancel", "", false), http.StatusNotFound, CodeNotFound)

	// Аудит: цель, запуск и итог; значения секретного заголовка и
	// пароля нет ни в одной записи.
	seen := map[string]bool{}
	for _, a := range mem.Audit() {
		seen[a.Action] = true
		if s := mustJSON(t, a); strings.Contains(s, rtSecret) || strings.Contains(s, tPhrase) {
			t.Fatalf("секрет в аудите: %s", s)
		}
	}
	for _, a := range []string{redteam.ActionTargetCreated, redteam.ActionTargetUpdated, redteam.ActionRunStarted, redteam.ActionRunFinished} {
		if !seen[a] {
			t.Errorf("нет записи %s", a)
		}
	}
	if strings.Contains(e.log.String(), rtSecret) {
		t.Fatal("значение секретного заголовка в техническом журнале")
	}

	// Удаление цели: запуск остаётся.
	if w := e.call(admin, "DELETE", "/api/v1/redteam/targets/"+tg.ID, "", true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	if _, _, err := svc.Run(context.Background(), run.ID); err != nil {
		t.Fatalf("запуск удалённой цели: %v", err)
	}
}

// rtFinishedRun — цель endpoint без секретного заголовка, база сценариев и
// завершённый запуск (сценарии завершаются ошибкой: DNS в тесте недоступен).
func rtFinishedRun(t *testing.T, e *appsEnv, admin, sys session) (RedTeamTargetView, RedTeamRunView) {
	t.Helper()
	body := strings.Replace(rtEndpointBody(`,"password":"`+tPhrase+`","storage":"masked"`), `"auth_header":"X-Api-Key",`, "", 1)
	w := e.call(admin, "POST", "/api/v1/redteam/targets", body, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание цели: %d %s", w.Code, w.Body)
	}
	tg := decode[RedTeamTargetView](t, w.Body.Bytes())
	data, err := os.ReadFile("../../testdata/redteam/scenarios-test.aisecdb")
	if err != nil {
		t.Fatal(err)
	}
	if w := e.callFile(sys, "PUT", "/api/v1/redteam/scenarios", "application/octet-stream", data); w.Code != http.StatusOK {
		t.Fatalf("загрузка базы: %d %s", w.Code, w.Body)
	}
	w = e.call(admin, "POST", "/api/v1/redteam/runs", `{"target_id":"`+tg.ID+`","scenarios":["RT-DM01-001","RT-DM08-001"]}`, true)
	if w.Code != http.StatusAccepted {
		t.Fatalf("запуск: %d %s", w.Code, w.Body)
	}
	run := decode[RedTeamRunView](t, w.Body.Bytes())
	for deadline := time.Now().Add(10 * time.Second); ; {
		w = e.call(admin, "GET", "/api/v1/redteam/runs/"+run.ID, "", false)
		if st := decode[RedTeamRunCard](t, w.Body.Bytes()).Status; st != redteam.RunRunning && st != redteam.RunQueued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("запуск не завершился: %s", w.Body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return tg, run
}

// Расписания (задача 5.33): отказ в доступе без права безопасности, цель с
// секретным заголовком отклоняется, создание, чужая версия, удаление;
// токену расписания недоступны (право безопасности, только сессия).
func TestRedTeamSchedulesAPI(t *testing.T) {
	e, _, mem := newRedTeamEnv(t)
	admin := e.mustLogin(t, "admin")
	sys := e.mustLogin(t, "sysadm")
	owner := e.mustLogin(t, "owner")
	auditor := e.mustLogin(t, "auditor")
	analyst := e.mustLogin(t, "analyst")
	const sched = "/api/v1/redteam/schedules/01900000-0000-7000-8000-0000000000fd"
	body := `{"name":"Ночной прогон","target_id":"01900000-0000-7000-8000-0000000000ff","frequency":"daily","at":"03:00"}`
	for _, s := range []session{owner, auditor, analyst, sys} {
		mustProblem(t, e.call(s, "POST", "/api/v1/redteam/schedules", body, true), http.StatusForbidden, CodeForbidden)
		mustProblem(t, e.call(s, "PUT", sched, body, true), http.StatusForbidden, CodeForbidden)
		mustProblem(t, e.call(s, "DELETE", sched, "", true), http.StatusForbidden, CodeForbidden)
	}
	mustProblem(t, e.call(owner, "GET", "/api/v1/redteam/schedules", "", false), http.StatusForbidden, CodeForbidden)
	for _, s := range []session{auditor, analyst, sys} {
		if w := e.call(s, "GET", "/api/v1/redteam/schedules", "", false); w.Code != http.StatusOK {
			t.Fatalf("чтение расписаний: %d %s", w.Code, w.Body)
		}
	}
	if p, ok := auth.LookupPermission(auth.PermRedteamSchedulesManage); !ok || !p.Security || auth.TokenGrantable(p.Name) {
		t.Fatalf("redteam.schedules.manage — не право безопасности: %+v", p)
	}
	mustProblem(t, e.call(session{}, "POST", "/api/v1/redteam/schedules", body, false), http.StatusUnauthorized, CodeUnauthorized)

	// Цель с секретным заголовком по расписанию не запускается.
	w := e.call(admin, "POST", "/api/v1/redteam/targets", rtEndpointBody(`,"password":"`+tPhrase+`"`), true)
	secretTarget := decode[RedTeamTargetView](t, w.Body.Bytes())
	mustProblem(t, e.call(admin, "POST", "/api/v1/redteam/schedules", strings.Replace(body, "01900000-0000-7000-8000-0000000000ff", secretTarget.ID, 1), true),
		http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "POST", "/api/v1/redteam/schedules", body, true), http.StatusBadRequest, CodeInvalidRequest)

	tg, _ := rtFinishedRun(t, e, admin, sys)
	good := strings.Replace(body, "01900000-0000-7000-8000-0000000000ff", tg.ID, 1)
	mustProblem(t, e.call(admin, "POST", "/api/v1/redteam/schedules", strings.Replace(good, `"daily"`, `"hourly"`, 1), true), http.StatusBadRequest, CodeInvalidRequest)
	w = e.call(admin, "POST", "/api/v1/redteam/schedules", good, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание расписания: %d %s", w.Code, w.Body)
	}
	sc := decode[RedTeamScheduleView](t, w.Body.Bytes())
	if sc.Version != 1 || !sc.Enabled || sc.NextRunAt.IsZero() || sc.Threats == nil {
		t.Fatalf("расписание: %+v", sc)
	}
	put := strings.Replace(good, `"at":"03:00"`, `"at":"04:15","version":1`, 1)
	if w := e.call(admin, "PUT", "/api/v1/redteam/schedules/"+sc.ID, put, true); w.Code != http.StatusOK {
		t.Fatalf("изменение: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", "/api/v1/redteam/schedules/"+sc.ID, put, true), http.StatusConflict, CodeConflict)
	list := decode[RedTeamScheduleList](t, e.call(auditor, "GET", "/api/v1/redteam/schedules", "", false).Body.Bytes())
	if len(list.Items) != 1 || list.Items[0].At != "04:15" || list.Items[0].Version != 2 {
		t.Fatalf("список: %+v", list)
	}
	mustProblem(t, e.call(admin, "GET", "/api/v1/redteam/schedules/bad", "", false), http.StatusNotFound, CodeNotFound)
	if w := e.call(admin, "DELETE", "/api/v1/redteam/schedules/"+sc.ID, "", true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	seen := map[string]bool{}
	for _, a := range mem.Audit() {
		seen[a.Action] = true
		if s := mustJSON(t, a); strings.Contains(s, tPhrase) {
			t.Fatalf("пароль в аудите: %s", s)
		}
	}
	for _, a := range []string{redteam.ActionScheduleCreated, redteam.ActionScheduleUpdated, redteam.ActionScheduleDeleted} {
		if !seen[a] {
			t.Errorf("нет записи %s", a)
		}
	}
}

// Отчёт о запуске (задача 5.33): право redteam.export, форматы, запись
// data.export до выдачи, выдержки — только по examples=true и с правом на
// содержимое событий (токену не выдаётся), промптов атак в отчёте нет.
func TestRedTeamReportAPI(t *testing.T) {
	e, _, _ := newRedTeamEnv(t)
	admin := e.mustLogin(t, "admin")
	sys := e.mustLogin(t, "sysadm")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	_, run := rtFinishedRun(t, e, admin, sys)
	path := "/api/v1/redteam/runs/" + run.ID + "/report"

	for _, s := range []session{owner, analyst, auditor, sys} {
		mustProblem(t, e.call(s, "GET", path, "", false), http.StatusForbidden, CodeForbidden)
	}
	mustProblem(t, e.call(session{}, "GET", path, "", false), http.StatusUnauthorized, CodeUnauthorized)
	for _, q := range []string{"?format=pdf", "?delimiter=comma", "?format=csv&delimiter=tab", "?examples=1", "?x=1", "?format=csv&format=html"} {
		mustProblem(t, e.call(admin, "GET", path+q, "", false), http.StatusBadRequest, CodeInvalidRequest)
	}
	mustProblem(t, e.call(admin, "GET", "/api/v1/redteam/runs/01900000-0000-7000-8000-0000000000fe/report", "", false), http.StatusNotFound, CodeNotFound)

	exports := func() int { return len(e.rec.find("data.export")) }
	before := exports()
	for _, f := range []string{"html", "csv", "xlsx"} {
		w := e.call(admin, "GET", path+"?format="+f, "", false)
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Export-Rows") == "" {
			t.Fatalf("отчёт %s: %d %s", f, w.Code, w.Body)
		}
		// Промптов атак и маркера из базы в отчёте нет.
		if strings.Contains(w.Body.String(), "ПРОБОЙ-7731") || strings.Contains(w.Body.String(), "Забудь все предыдущие") {
			t.Fatalf("промпт атаки в отчёте %s", f)
		}
	}
	if exports() != before+3 {
		t.Fatalf("записей data.export: %d, ожидалось %d", exports()-before, 3)
	}
	// Токен с redteam.export получает отчёт без выдержек; с examples=true — 403.
	tok := session{bearer: e.issueToken(t, admin, auth.PermRedteamExport).Token}
	if w := e.call(tok, "GET", path+"?format=csv", "", false); w.Code != http.StatusOK {
		t.Fatalf("отчёт токеном: %d %s", w.Code, w.Body)
	}
	n := exports()
	denied := func() int { _, n := lastDenied(t, e.mem); return n }
	nd := denied()
	mustProblem(t, e.call(tok, "GET", path+"?examples=true", "", false), http.StatusForbidden, CodeForbidden)
	if exports() != n {
		t.Fatal("отказ в выдержках записан как выгрузка")
	}
	// 5Н27 ревью 5.r4: отказ в выдержках — запись access.denied.
	if denied() != nd+1 {
		t.Fatalf("отказ в выдержках токену без записи access.denied: %d", denied()-nd)
	}
	// Своя роль с redteam.export и events.content.read только на свои
	// объекты: выдержек нет (у цели нет владельца-приложения), причина — scope.
	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := audit.Entry{Actor: audit.Actor{Type: audit.ActorCLI, ID: "test"}, Action: "role.create", Result: audit.ResultSuccess}
	if err := e.mem.CreateRole(context.Background(), audit.DefaultOrgID, "", auth.RoleDef{ID: "rt_own", DisplayName: "rt_own",
		Grants:    auth.Grants{auth.PermRedteamExport: auth.ScopeAll, auth.PermRedteamRead: auth.ScopeAll, auth.PermEventsContentRead: auth.ScopeOwn},
		CreatedAt: now, UpdatedAt: now, CreatedBy: "test"}, func(auth.Actor) (audit.Entry, error) { return rec, nil }); err != nil {
		t.Fatal(err)
	}
	e.mem.AddUser(auth.User{ID: "01900000-0000-7000-8000-0000000000e7", OrgID: audit.DefaultOrgID, Login: "rtown", DisplayName: "rtown",
		Role: "rt_own", Status: auth.StatusActive, PasswordHash: authtest.HashOf(tPhrase), PasswordChangedAt: now, CreatedAt: now, CreatedBy: "test"})
	own := e.mustLogin(t, "rtown")
	if w := e.call(own, "GET", path+"?format=csv", "", false); w.Code != http.StatusOK {
		t.Fatalf("своя роль без выдержек: %d %s", w.Code, w.Body)
	}
	nd, n = denied(), exports()
	mustProblem(t, e.call(own, "GET", path+"?examples=true", "", false), http.StatusForbidden, CodeForbidden)
	if exports() != n || denied() != nd+1 {
		t.Fatalf("область own: выгрузок %d, отказов %d", exports()-n, denied()-nd)
	}
	lastDeny, _ := lastDenied(t, e.mem)
	if d, _ := lastDeny.Details.(map[string]any); lastDeny.Result != audit.ResultDenied || d["reason"] != DenyReasonScope ||
		d["permission"] != auth.PermEventsContentRead || d["path"] != "/api/v1/redteam/runs/{id}/report" {
		t.Fatalf("запись отказа: %+v", lastDeny)
	}
	// Причина с токеном без права — по-прежнему 403, а не 400.
	mustProblem(t, e.call(tok, "GET", path+"?examples=true&reason="+url.QueryEscape("разбор запуска"), "", false), http.StatusForbidden, CodeForbidden)
	// Задача 6.12 (УПД.7): выдержки — только с причиной, пределы как у
	// содержимого события; без причины и с неверной — 400 без выгрузки.
	n = exports()
	long := strings.Repeat("я", MaxContentReason+1)
	for _, q := range []string{"?examples=true", "?examples=true&reason=", "?examples=true&reason=ab", "?examples=true&reason=%20%20ab%20",
		"?examples=true&reason=" + url.QueryEscape(long), "?examples=true&reason=a%00bc", "?examples=true&reason=abc&reason=def",
		"?reason=%07%07%07", "?examples=true&reason=%ff%fe%fd"} {
		mustProblem(t, e.call(admin, "GET", path+q, "", false), http.StatusBadRequest, CodeInvalidRequest)
	}
	if exports() != n {
		t.Fatal("отказ без причины записан как выгрузка")
	}
	// Администратор безопасности — с выдержками и причиной; в аудите видны
	// признак и причина (обрезанная по краям), предел — 500 символов.
	reason := "  разбор инцидента 1234  "
	if w := e.call(admin, "GET", path+"?examples=true&format=csv&reason="+url.QueryEscape(reason), "", false); w.Code != http.StatusOK {
		t.Fatalf("отчёт с выдержками: %d %s", w.Code, w.Body)
	}
	all := e.rec.find("data.export")
	last := all[len(all)-1]
	canon := e.rec.canon[len(e.rec.canon)-1]
	if last.Object.Type != "report" || last.Object.ID != redteam.KindReport || !strings.Contains(canon, `"examples":true`) ||
		!strings.Contains(canon, `"run_id":"`+run.ID+`"`) || !strings.Contains(canon, `"reason":"разбор инцидента 1234"`) {
		t.Fatalf("запись выгрузки: %+v %s", last, canon)
	}
	if w := e.call(admin, "GET", path+"?examples=true&format=csv&reason="+url.QueryEscape(strings.Repeat("я", MaxContentReason)), "", false); w.Code != http.StatusOK {
		t.Fatalf("причина в 500 символов: %d %s", w.Code, w.Body)
	}
	// Без выдержек причина необязательна; если указана — тоже в аудите.
	if w := e.call(admin, "GET", path+"?format=csv&reason="+url.QueryEscape("сверка итогов"), "", false); w.Code != http.StatusOK ||
		!strings.Contains(e.rec.canon[len(e.rec.canon)-1], `"reason":"сверка итогов"`) {
		t.Fatalf("причина без выдержек: %d %s", w.Code, w.Body)
	}
	if w := e.call(admin, "GET", path+"?format=csv", "", false); w.Code != http.StatusOK || strings.Contains(e.rec.canon[len(e.rec.canon)-1], `"reason"`) {
		t.Fatalf("отчёт без причины: %d", w.Code)
	}
}
