package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

func postJSON(t testing.TB, h http.Handler, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postCheck(t testing.TB, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	return postJSON(t, h, "/guard/v1/check", body, nil)
}

func decodeCheck(t *testing.T, rec *httptest.ResponseRecorder) checkResponse {
	t.Helper()
	var r checkResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("ответ не JSON: %q", rec.Body.String())
	}
	return r
}

func jsonString(t testing.TB, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// lastCheckEvent — последнее событие check.
func lastCheckEvent(t *testing.T, log *eventLog, resp *httptest.ResponseRecorder) events.Event {
	t.Helper()
	evs := log.all()
	if len(evs) == 0 {
		t.Fatal("нет события check")
	}
	e := evs[len(evs)-1]
	if e.Type != events.TypeCheck || e.App != "app" || resp.Header().Get(HeaderEventID) != e.ID {
		t.Fatalf("событие: %+v, X-AISec-Event-Id %q", e, resp.Header().Get(HeaderEventID))
	}
	return e
}

// Покрывает: DM-07
func TestDM07_CheckBlocksIndirectInjectionFromRAGAndTool(t *testing.T) {
	for _, src := range []string{"rag", "tool"} {
		t.Run(src, func(t *testing.T) {
			up, rec := newUpstream(t, nil)
			var log *eventLog
			g := newGateway(t, up.URL, func(o *gwOpts) { o.app = enforce; log = o.events })
			resp := postCheck(t, g, `{"direction":"input","source":"`+src+`","text":`+jsonString(t, "Документ. "+injectionText)+`}`)
			if resp.Code != http.StatusOK || resp.Header().Get(HeaderDecision) != "block" {
				t.Fatalf("%d %s", resp.Code, resp.Body.String())
			}
			r := decodeCheck(t, resp)
			if !r.Blocked || r.Decision != "block" || r.Action != "block" || r.Text != nil || r.Messages != nil || len(r.Findings) == 0 {
				t.Fatalf("ответ: %+v", r)
			}
			// Найденное значение в ответ не попадает — только место и категория.
			if strings.Contains(resp.Body.String(), "password") {
				t.Fatalf("в ответе фрагмент текста: %s", resp.Body.String())
			}
			if _, _, _, calls := rec.get(); calls != 0 {
				t.Fatal("Check API обратился к провайдеру")
			}
			e := lastCheckEvent(t, log, resp)
			if e.Source != src || e.Decision.Action != "block" || !slices.Contains(e.Threats, "DM-07") || e.Model != "" || r.ID != e.ID {
				t.Fatalf("событие: %+v", e)
			}
		})
	}
}

func TestCheckRedactsAndReturnsTransformedText(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { enforce(a); a.Storage = "masked" }
		log = o.events
	})
	resp := postCheck(t, g, `{"direction":"input","text":`+jsonString(t, "Почта "+piiEmail+" в письме")+`}`)
	r := decodeCheck(t, resp)
	if resp.Code != http.StatusOK || r.Blocked || r.Decision != "redact" || r.Text == nil || *r.Text != "Почта "+emailMask+" в письме" {
		t.Fatalf("%d %+v", resp.Code, r)
	}
	if len(r.Findings) != 1 || r.Findings[0].Location != "text" || r.Findings[0].Threat == "" {
		t.Fatalf("находки: %+v", r.Findings)
	}
	e := lastCheckEvent(t, log, resp)
	if e.Source != "user" || e.Content == nil || strings.Contains(e.Content.Request, piiEmail) || e.Content.Response != "" {
		t.Fatalf("содержимое события: %+v", e.Content)
	}
}

// Check API не подставляет псевдонимы: ответа, где их можно вернуть, нет.
func TestCheckPseudonymizeRunsAsRedact(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.app = enforce; log = o.events })
	resp := postCheck(t, g, `{"direction":"input","text":`+jsonString(t, "Почта "+piiEmail)+`}`)
	r := decodeCheck(t, resp)
	if r.Text == nil || strings.Contains(*r.Text, piiEmail) || *r.Text != "Почта "+emailMask {
		t.Fatalf("текст: %+v", r)
	}
	if e := lastCheckEvent(t, log, resp); e.Decision.Trace == nil || !strings.Contains(e.Decision.Trace[0].Note, "как redact") {
		t.Fatalf("трассировка: %+v", e.Decision.Trace)
	}
}

// Покрывает: DM-09
func TestDM09_CheckOutputDirection(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { enforce(a); a.Storage = "masked" }
		log = o.events
	})
	resp := postCheck(t, g, `{"direction":"output","text":`+jsonString(t, "Пишите на "+piiEmail)+`}`)
	r := decodeCheck(t, resp)
	if resp.Code != 200 || r.Blocked || r.Text == nil || strings.Contains(*r.Text, piiEmail) || !strings.Contains(*r.Text, emailMask) {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := lastCheckEvent(t, log, resp)
	if e.Source != "output" || !slices.Contains(e.Threats, "DM-09") || e.Content == nil || e.Content.Request != "" ||
		e.Content.Response == "" || strings.Contains(e.Content.Response, piiEmail) {
		t.Fatalf("событие: %+v %+v", e, e.Content)
	}
	// Входные правила на выходе не действуют: инъекция в тексте ответа не блокируется.
	resp = postCheck(t, g, `{"direction":"output","text":`+jsonString(t, injectionText)+`}`)
	if r := decodeCheck(t, resp); r.Blocked || len(r.Findings) != 0 {
		t.Fatalf("выход проверен входными правилами: %+v", r)
	}
}

func TestCheckMessagesKeepRolesAndUseToolSource(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.app = enforce; log = o.events })
	body := `{"direction":"input","messages":[{"role":"user","content":"Привет"},{"role":"tool","content":` + jsonString(t, injectionText) + `}]}`
	resp := postCheck(t, g, body)
	r := decodeCheck(t, resp)
	if !r.Blocked || len(r.Findings) == 0 || r.Findings[0].Location != "messages[1].content" {
		t.Fatalf("ответ: %s", resp.Body.String())
	}
	_ = lastCheckEvent(t, log, resp)
	resp = postCheck(t, g, `{"direction":"input","messages":[{"role":"system","content":"Будь вежлив"},{"role":"user","content":`+jsonString(t, "Почта "+piiEmail)+`}]}`)
	r = decodeCheck(t, resp)
	if r.Blocked || len(r.Messages) != 2 || r.Messages[0].Role != "system" || r.Messages[0].Content != "Будь вежлив" ||
		r.Messages[1].Role != "user" || strings.Contains(r.Messages[1].Content, piiEmail) || r.Text != nil {
		t.Fatalf("сообщения: %+v", r)
	}
}

func TestCheckMonitorReportsButDoesNotBlock(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g := newGateway(t, up.URL, nil)
	resp := postCheck(t, g, `{"direction":"input","text":`+jsonString(t, injectionText)+`}`)
	r := decodeCheck(t, resp)
	if resp.Code != 200 || r.Blocked || r.Action != "block" || r.Decision != "allow" || r.Text == nil || *r.Text != injectionText {
		t.Fatalf("monitor: %s", resp.Body.String())
	}
}

func TestCheckRejectsInvalidRequests(t *testing.T) {
	up, rec := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { log = o.events })
	cases := map[string]string{
		"нет direction":          `{"text":"x"}`,
		"неизвестный direction":  `{"direction":"both","text":"x"}`,
		"нет текста":             `{"direction":"input"}`,
		"и text, и messages":     `{"direction":"input","text":"x","messages":[{"role":"user","content":"x"}]}`,
		"пустой text":            `{"direction":"input","text":""}`,
		"неизвестное поле":       `{"direction":"input","text":"x","model":"m"}`,
		"данные после объекта":   `{"direction":"input","text":"x"}{}`,
		"source output на входе": `{"direction":"input","source":"output","text":"x"}`,
		"source user на выходе":  `{"direction":"output","source":"user","text":"x"}`,
		"source image":           `{"direction":"input","source":"image","text":"x"}`,
		"неизвестный source":     `{"direction":"input","source":"web","text":"x"}`,
		"неизвестная роль":       `{"direction":"input","messages":[{"role":"admin","content":"x"}]}`,
		"пустое сообщение":       `{"direction":"input","messages":[{"role":"user","content":""}]}`,
		"content — не строка":    `{"direction":"input","messages":[{"role":"user","content":[{"type":"text","text":"x"}]}]}`,
		"text — не строка":       `{"direction":"input","text":5}`,
		"тело — не объект":       `[]`,
		"слишком длинный user":   `{"direction":"input","text":"x","user":"` + strings.Repeat("u", 300) + `"}`,
	}
	for name, body := range cases {
		resp := postCheck(t, g, body)
		if resp.Code != http.StatusBadRequest && resp.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s", name, resp.Code, resp.Body.String())
		}
	}
	if n := len(log.all()); n != 0 {
		t.Errorf("ошибки разбора создали события: %d", n)
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("Check API обратился к провайдеру")
	}
	// Неверный тип содержимого и слишком большое тело.
	if resp := postJSON(t, g, "/guard/v1/check", `{}`, map[string]string{"Content-Type": "text/plain"}); resp.Code != http.StatusUnsupportedMediaType {
		t.Errorf("Content-Type: %d", resp.Code)
	}
	big := `{"direction":"input","text":"` + strings.Repeat("a", 2<<10) + `"}`
	if resp := postCheck(t, g, big); resp.Code != http.StatusRequestEntityTooLarge || errCode(t, resp) != "request_too_large" {
		t.Errorf("большое тело: %d %s", resp.Code, resp.Body.String())
	}
	// Больше сообщений, чем разрешено приложению.
	g2 := newGateway(t, up.URL, func(o *gwOpts) { o.quotas.MaxMessages = 2 })
	msgs := `{"role":"user","content":"x"},`
	if resp := postCheck(t, g2, `{"direction":"input","messages":[`+strings.Repeat(msgs, 2)+`{"role":"user","content":"x"}]}`); resp.Code != http.StatusBadRequest ||
		errCode(t, resp) != "request_too_large" {
		t.Errorf("сообщений больше предела: %d %s", resp.Code, resp.Body.String())
	}
}

// Каждый маршрут приложений требует действующий ключ (RBAC шлюза).
func TestCheckAndEmbeddingsDenyWithoutValidKey(t *testing.T) {
	up, rec := newUpstream(t, nil)
	for _, c := range []struct{ path, body string }{
		{"/guard/v1/check", `{"direction":"input","text":"x"}`},
		{"/v1/embeddings", `{"model":"m","input":"x"}`},
	} {
		var log *eventLog
		g := newGateway(t, up.URL, func(o *gwOpts) { o.noKey = true; log = o.events })
		for name, hdr := range map[string]map[string]string{
			"без ключа":      nil,
			"чужой ключ":     {"Authorization": "Bearer aisec_wrong"},
			"не Bearer":      {"Authorization": "Basic abc"},
			"пустой Bearer":  {"Authorization": "Bearer "},
			"два заголовка?": {"Authorization": "Bearer a, Bearer b"},
		} {
			resp := postJSON(t, g, c.path, c.body, hdr)
			if resp.Code != http.StatusUnauthorized || errCode(t, resp) != "invalid_api_key" {
				t.Errorf("%s %s: %d %s", c.path, name, resp.Code, resp.Body.String())
			}
		}
		if len(log.all()) != 0 {
			t.Errorf("%s: отказ в доступе создал событие обработки запроса", c.path)
		}
		// Метод GET на маршруте не поддерживается.
		if resp := do(t, g, http.MethodGet, c.path); resp.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: %d", c.path, resp.Code)
		}
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос без ключа дошёл до провайдера")
	}
}

// Покрывает: DM-36
func TestDM36_CheckQuotas(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g := newGateway(t, up.URL, func(o *gwOpts) { o.quotas.RequestsPerMinute = 1; o.quotas.MaxInputBytes = 100 })
	if resp := postCheck(t, g, `{"direction":"input","text":"раз"}`); resp.Code != 200 {
		t.Fatalf("первый: %d %s", resp.Code, resp.Body.String())
	}
	resp := postCheck(t, g, `{"direction":"input","text":"два"}`)
	if resp.Code != http.StatusTooManyRequests || errCode(t, resp) != "quota_exceeded" || resp.Header().Get("Retry-After") == "" {
		t.Fatalf("второй: %d %s", resp.Code, resp.Body.String())
	}
	g = newGateway(t, up.URL, func(o *gwOpts) { o.quotas.MaxInputBytes = 20 })
	if resp := postCheck(t, g, `{"direction":"input","text":"`+strings.Repeat("a", 50)+`"}`); resp.Code != http.StatusTooManyRequests {
		t.Fatalf("размер: %d", resp.Code)
	}
}

func TestCheckFailClosedAndFailOpen(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.FailMode = "fail_closed" }
		o.setup, o.detTimeout, log = withDetector(t, slow), 10*time.Millisecond, o.events
	})
	resp := postCheck(t, g, `{"direction":"input","text":"Привет"}`)
	if resp.Code != http.StatusServiceUnavailable || errCode(t, resp) != "check_unavailable" || resp.Header().Get(HeaderDecision) != "block" {
		t.Fatalf("fail_closed: %d %s", resp.Code, resp.Body.String())
	}
	if e := lastCheckEvent(t, log, resp); e.Decision.Rule != ruleFailClosed {
		t.Fatalf("событие: %+v", e.Decision)
	}
	g = newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.FailMode = "fail_open" }
		o.setup, o.detTimeout = withDetector(t, slow), 10*time.Millisecond
	})
	r := decodeCheck(t, postCheck(t, g, `{"direction":"input","text":"Привет"}`))
	if r.Blocked || !r.Incomplete {
		t.Fatalf("fail_open: %+v", r)
	}
}

func FuzzParseCheck(f *testing.F) {
	for _, s := range []string{
		`{"direction":"input","text":"x"}`,
		`{"direction":"output","source":"output","messages":[{"role":"assistant","content":"x"}]}`,
		`{"direction":"input","source":"rag","text":"x","user":"u"}`,
		`{"direction":"input"}`, `{}`, `[]`, `null`, "{\"direction\":\"input\",\"text\":\"\xff\"}",
	} {
		f.Add([]byte(s), 4)
	}
	f.Fuzz(func(t *testing.T, body []byte, maxMessages int) {
		req, dir, texts, err := parseCheck(body, maxMessages)
		if err != nil {
			if req != nil || texts != nil || err.Message == "" || err.Code == "" {
				t.Fatalf("ошибка с результатом: %+v", err)
			}
			return
		}
		if len(texts) == 0 || dir == "" {
			t.Fatalf("пустой результат без ошибки: %+v", texts)
		}
		for _, x := range texts {
			if x.Text == "" || x.Location == "" || x.Source == "" {
				t.Fatalf("фрагмент: %+v", x)
			}
		}
	})
}

// Политика без правил для направления: allow не должен выглядеть как «проверено».
func TestCheckMarksUncheckedDirection(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.setup = func(a *App) { a.Policy = onlyInputPolicy(t, a) }
	})
	if r := decodeCheck(t, postCheck(t, g, `{"direction":"input","text":"Привет"}`)); r.Unchecked {
		t.Fatalf("вход помечен непроверенным: %+v", r)
	}
	if r := decodeCheck(t, postCheck(t, g, `{"direction":"output","text":"Привет"}`)); !r.Unchecked || r.Blocked {
		t.Fatalf("выход без правил: %+v", r)
	}
}

func onlyInputPolicy(t *testing.T, a *App) *policy.Policy {
	t.Helper()
	p, err := policy.Compile(&policy.Spec{ID: "in", Name: "in", Version: 1, Mode: policy.Monitor, Rules: []policy.RuleSpec{
		{ID: "pii", Detector: "pii.ru", Directions: []detect.Direction{detect.Input}, Action: policy.Redact, Severity: policy.Medium},
	}}, a.Detectors)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
