package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestRouteValidation(t *testing.T) {
	noop := func(http.ResponseWriter, *http.Request) {}
	_, rt := newHandler(t, Options{})
	for name, r := range map[string]Route{
		"без прав и без Public": {Method: "GET", Path: "/api/v1/a", Handler: noop},
		"и права, и Public":     {Method: "GET", Path: "/api/v1/a", Permission: "x", Public: true, Handler: noop},
		"метод":                 {Method: "TRACE", Path: "/api/v1/a", Permission: "x", Handler: noop},
		"путь":                  {Method: "GET", Path: "api", Permission: "x", Handler: noop},
		"без обработчика":       {Method: "GET", Path: "/api/v1/a", Permission: "x"},
		"idempotent для GET":    {Method: "GET", Path: "/api/v1/a", Permission: "x", Idempotent: true, Handler: noop},
		"дубликат":              {Method: "GET", Path: "/healthz", Public: true, Handler: noop},
	} {
		if err := rt.Add(r); err == nil {
			t.Errorf("%s: маршрут принят", name)
		}
	}
}

// Матрица отказов (УПД.3): каждый защищённый маршрут без права — 401, с
// аутентификацией без права — 403, с правом — не отказ.
func TestEveryProtectedRouteDenies(t *testing.T) {
	probe := Options{Extra: []Route{{Method: "POST", Path: "/api/v1/probe/{id}", Permission: "probe.write",
		Handler: func(w http.ResponseWriter, _ *http.Request) { WriteJSON(w, 200, map[string]string{}) }}}}
	_, rt := newHandler(t, probe)
	n := 0
	for _, r := range rt.Routes() {
		if r.Public {
			continue
		}
		n++
		target := strings.ReplaceAll(r.Path, "{id}", "x")
		for name, tc := range map[string]struct {
			authz Authorizer
			want  int
		}{
			"аноним":   {DenyAll{}, 401},
			"без прав": {allowPerm{}, 403},
			"с правом": {allowPerm{r.Permission: true}, 200},
		} {
			o := probe
			o.Authorizer = tc.authz
			h, _ := newHandler(t, o)
			w := do(h, r.Method, target, "", "Content-Type", "application/json")
			// С правом обработчик может отказать по содержимому запроса
			// (400, 404), но не по правам.
			denied := w.Code == 401 || w.Code == 403
			if (tc.want == 200 && denied) || (tc.want != 200 && w.Code != tc.want) {
				t.Errorf("%s %s (%s): %d, ожидалось %d", r.Method, r.Path, name, w.Code, tc.want)
			}
			if tc.want != 200 {
				mustProblem(t, w, tc.want, map[int]string{401: CodeUnauthorized, 403: CodeForbidden}[tc.want])
			}
		}
	}
	if n < 2 {
		t.Fatal("нет защищённых маршрутов для проверки")
	}
}

func TestOnDeniedHook(t *testing.T) {
	var got []string
	h, _ := newHandler(t, Options{OnDenied: func(_ *http.Request, d Denial) {
		got = append(got, d.Permission+":"+map[Decision]string{Unauthenticated: "401", Forbidden: "403"}[d.Decision])
	}})
	do(h, "GET", "/api/v1/system/info", "")
	if len(got) != 1 || got[0] != "system.read:401" {
		t.Fatalf("%v", got)
	}
}

func TestNotFoundAndMethodNotAllowedAreProblems(t *testing.T) {
	h, _ := newHandler(t, Options{})
	mustProblem(t, do(h, "GET", "/api/v1/nope", ""), 404, CodeNotFound)
	w := do(h, "POST", "/healthz", "")
	mustProblem(t, w, 405, CodeMethodNotAllowed)
	if !strings.Contains(w.Header().Get("Allow"), "GET") {
		t.Fatalf("Allow=%q", w.Header().Get("Allow"))
	}
	for _, p := range []string{"/api//v1/system/info", "/api/v1/../v1/system/info", "/api/v1/system/info/", "/api/./v1"} {
		w := do(h, "GET", p, "")
		if w.Code == 301 || w.Code == 307 || w.Code == 308 {
			t.Errorf("%s: перенаправление", p)
		}
		mustProblem(t, w, 404, CodeNotFound)
	}
}

func TestFallbackOnlyOutsideAPI(t *testing.T) {
	fb := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "static", http.StatusOK) })
	h, _ := newHandler(t, Options{Fallback: fb})
	if w := do(h, "GET", "/index.html", ""); w.Body.String() != "static\n" {
		t.Fatal("статика не отдана")
	}
	mustProblem(t, do(h, "GET", "/api/v1/zzz", ""), 404, CodeNotFound)
}

func TestPanicBecomes500WithoutDetails(t *testing.T) {
	h, _ := newHandler(t, Options{Extra: []Route{{Method: "GET", Path: "/panic", Public: true,
		Handler: func(http.ResponseWriter, *http.Request) { panic("секрет-в-панике") }}}})
	w := do(h, "GET", "/panic", "")
	mustProblem(t, w, 500, CodeInternal)
	if strings.Contains(w.Body.String(), "секрет") {
		t.Fatal("значение паники попало в ответ")
	}
}

func TestReadyz(t *testing.T) {
	h, _ := newHandler(t, Options{Ready: func(context.Context) error { return errTest }})
	w := do(h, "GET", "/readyz", "")
	mustProblem(t, w, 503, CodeUnavailable)
	if strings.Contains(w.Body.String(), "secret-dsn") {
		t.Fatal("причина сбоя попала в ответ")
	}
	h, _ = newHandler(t, Options{Ready: okReady})
	if w := do(h, "GET", "/readyz", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestDecodeJSON(t *testing.T) {
	type in struct{ A string }
	h, _ := newHandler(t, Options{Authorizer: allowPerm{"t": true}, Extra: []Route{{Method: "POST", Path: "/api/v1/t", Permission: "t", MaxBody: 64,
		Handler: func(w http.ResponseWriter, r *http.Request) {
			var v in
			if p := DecodeJSON(w, r, &v, 64); p != nil {
				WriteProblem(w, p)
				return
			}
			WriteJSON(w, 200, v)
		}}}})
	ct := []string{"Content-Type", "application/json; charset=utf-8"}
	for name, tc := range map[string]struct {
		body string
		hdr  []string
		want int
	}{
		"верно":            {`{"A":"x"}`, ct, 200},
		"неизвестное поле": {`{"B":1}`, ct, 400},
		"мусор после":      {`{"A":"x"} {}`, ct, 400},
		"не JSON":          {`<xml/>`, ct, 400},
		"слишком большое":  {`{"A":"` + strings.Repeat("x", 100) + `"}`, ct, 413},
		"другой тип":       {`{"A":"x"}`, []string{"Content-Type", "text/plain"}, 415},
		"без типа":         {`{"A":"x"}`, nil, 415},
	} {
		if w := do(h, "POST", "/api/v1/t", tc.body, tc.hdr...); w.Code != tc.want {
			t.Errorf("%s: %d, ожидалось %d (%s)", name, w.Code, tc.want, w.Body.String())
		}
	}
}
