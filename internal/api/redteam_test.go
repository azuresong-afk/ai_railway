package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
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
		svc, err = redteam.New(redteam.Options{Store: mem, ServiceDBs: servicedb.NewMemory(), Provider: p, Apps: o.Apps,
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
