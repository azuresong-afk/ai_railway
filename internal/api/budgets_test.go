package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Цены моделей и бюджеты приложений через API (задача 3.18). Отказ в
// доступе по всем маршрутам — ещё и в TestRBACMatrixDenials.
func TestBudgetsViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	analyst := e.mustLogin(t, "analyst")
	owner := e.mustLogin(t, "owner")
	p := e.provider(t, sys, "llm")
	a := e.application(t, sys, "helpdesk", p.ID, tOwnerID)

	body := fmt.Sprintf(`{"provider_id":%q,"model":"gpt-4o-mini","input_price":"0.15","output_price":"0.6"}`, p.ID)
	w := e.call(sys, "POST", "/api/v1/model-prices", body, true)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"input_price":"0.1500"`) ||
		!strings.Contains(w.Body.String(), `"output_price":"0.6000"`) {
		t.Fatalf("создание цены: %d %s", w.Code, w.Body)
	}
	pr := decode[PriceView](t, w.Body.Bytes())
	mustProblem(t, e.call(sys, "POST", "/api/v1/model-prices", body, true), 409, CodeConflict)
	for _, bad := range []string{
		fmt.Sprintf(`{"provider_id":%q,"model":"m","input_price":0.15,"output_price":"1"}`, p.ID),
		fmt.Sprintf(`{"provider_id":%q,"model":"m","input_price":"-1","output_price":"1"}`, p.ID),
		fmt.Sprintf(`{"provider_id":%q,"model":"m","input_price":"1,5","output_price":"1"}`, p.ID),
		fmt.Sprintf(`{"provider_id":%q,"model":"m","input_price":"0.00001","output_price":"1"}`, p.ID),
		fmt.Sprintf(`{"provider_id":%q,"model":"","input_price":"1","output_price":"1"}`, p.ID),
		`{"provider_id":"x","model":"m","input_price":"1","output_price":"1","extra":1}`,
	} {
		mustProblem(t, e.call(sys, "POST", "/api/v1/model-prices", bad, true), 400, CodeInvalidRequest)
	}
	mustProblem(t, e.call(sys, "POST", "/api/v1/model-prices",
		`{"provider_id":"01900000-0000-7000-8000-0000000000ff","model":"m","input_price":"1","output_price":"1"}`, true), 422, CodeUnprocessable)
	if w := e.call(sys, "PUT", "/api/v1/model-prices/"+pr.ID, `{"input_price":"0.2","output_price":"0.8"}`, true); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"input_price":"0.2000"`) {
		t.Fatalf("изменение цены: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "PUT", "/api/v1/model-prices/01900000-0000-7000-8000-0000000000ff", `{"input_price":"1","output_price":"1"}`, true), 404, CodeNotFound)
	// Аналитик видит цены и бюджеты, но не меняет; владелец приложения — не видит.
	if w := e.call(analyst, "GET", "/api/v1/model-prices", "", false); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), pr.ID) {
		t.Fatalf("список цен: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(analyst, "POST", "/api/v1/model-prices", body, true), 403, CodeForbidden)
	mustProblem(t, e.call(analyst, "PUT", "/api/v1/applications/"+a.ID+"/budget", `{"mode":"hard","monthly_limit":"1"}`, true), 403, CodeForbidden)
	mustProblem(t, e.call(owner, "GET", "/api/v1/budgets", "", false), 403, CodeForbidden)
	mustProblem(t, e.call(owner, "GET", "/api/v1/model-prices", "", false), 403, CodeForbidden)

	w = e.call(sys, "PUT", "/api/v1/applications/"+a.ID+"/budget", `{"mode":"hard","monthly_limit":"15000.5"}`, true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"monthly_limit":"15000.50"`) ||
		!strings.Contains(w.Body.String(), `"spent":"0.00"`) || !strings.Contains(w.Body.String(), `"exhausted":false`) {
		t.Fatalf("бюджет: %d %s", w.Code, w.Body)
	}
	for _, bad := range []string{`{"mode":"strict","monthly_limit":"1"}`, `{"mode":"hard","monthly_limit":"0"}`,
		`{"mode":"hard","monthly_limit":"1.001"}`, `{"mode":"hard","monthly_limit":1000}`, `{"mode":"hard"}`} {
		mustProblem(t, e.call(sys, "PUT", "/api/v1/applications/"+a.ID+"/budget", bad, true), 400, CodeInvalidRequest)
	}
	mustProblem(t, e.call(sys, "PUT", "/api/v1/applications/01900000-0000-7000-8000-0000000000ff/budget", `{"mode":"soft","monthly_limit":"1"}`, true), 404, CodeNotFound)
	// Повышение жёсткого бюджета — без повторной проверки, но с отметкой relaxed.
	if w := e.call(sys, "PUT", "/api/v1/applications/"+a.ID+"/budget", `{"mode":"hard","monthly_limit":"20000"}`, true); w.Code != http.StatusOK {
		t.Fatalf("повышение: %d %s", w.Code, w.Body)
	}
	if rec, n := e.appAction("budget.set"); n != 2 || rec.Details.(map[string]any)["relaxed"] != true || rec.Actor.ID != tSysAdminID {
		t.Fatalf("аудит повышения: %d %+v", n, rec)
	}
	w = e.call(analyst, "GET", "/api/v1/budgets", "", false)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"application":"helpdesk"`) || !strings.Contains(w.Body.String(), `"mode":"hard"`) {
		t.Fatalf("список бюджетов: %d %s", w.Code, w.Body)
	}
	if w := e.call(analyst, "GET", "/api/v1/applications/"+a.ID+"/budget?month=2026-09", "", false); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"month":"2026-09"`) {
		t.Fatalf("бюджет за месяц: %d %s", w.Code, w.Body)
	}
	for _, q := range []string{"?month=2026-13", "?month=2026-1", "?month=2026-10&month=2026-11", "?month=2026-100"} {
		mustProblem(t, e.call(analyst, "GET", "/api/v1/budgets"+q, "", false), 400, CodeInvalidRequest)
	}
	if w := e.call(sys, "DELETE", "/api/v1/applications/"+a.ID+"/budget", "", true); w.Code != http.StatusNoContent {
		t.Fatalf("снятие: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "DELETE", "/api/v1/applications/"+a.ID+"/budget", "", true), 404, CodeNotFound)
	if w := e.call(sys, "GET", "/api/v1/applications/"+a.ID+"/budget", "", false); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"budget":null`) {
		t.Fatalf("без бюджета: %d %s", w.Code, w.Body)
	}
	if w := e.call(sys, "DELETE", "/api/v1/model-prices/"+pr.ID, "", true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление цены: %d %s", w.Code, w.Body)
	}
	for _, act := range []string{"model_price.create", "model_price.update", "model_price.delete", "budget.set", "budget.delete"} {
		if _, n := e.appAction(act); n == 0 {
			t.Errorf("нет записи %s", act)
		}
	}
}

// FuzzPriceRequest: разбор тела цены (десятичные строки рублей) не
// приводит к 5xx и панике; принятая цена читается обратно.
func FuzzPriceRequest(f *testing.F) {
	e, s, pid := fuzzSession(f)
	for _, v := range []string{"0.15", "1000000", "1000000.0001", "-1", "1e3", "0.00001", "١", "", " 1", "9223372036854775807"} {
		f.Add(`{"provider_id":"` + pid + `","model":"m","input_price":"` + v + `","output_price":"1"}`)
	}
	f.Add(`{"provider_id":"` + pid + `","model":"m","input_price":1,"output_price":"1"}`)
	f.Fuzz(func(t *testing.T, body string) {
		w := e.call(s, "POST", "/api/v1/model-prices", body, true)
		if w.Code >= 500 {
			t.Fatalf("%d на %q: %s", w.Code, body, w.Body)
		}
		if w.Code == http.StatusCreated {
			p := decode[PriceView](t, w.Body.Bytes())
			if d := e.call(s, "DELETE", "/api/v1/model-prices/"+p.ID, "", true); d.Code != http.StatusNoContent {
				t.Fatalf("созданная цена не удаляется: %d", d.Code)
			}
		}
	})
}
