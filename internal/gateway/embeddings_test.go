package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

const embResponse = `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.5,-0.25]}],"model":"up-model","usage":{"prompt_tokens":3,"total_tokens":3},"extra":"x"}`

func embUpstream(t *testing.T) (*httptest.Server, *upstreamRecord) {
	t.Helper()
	return newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, embResponse); err != nil {
			t.Error(err)
		}
	})
}

func postEmb(t testing.TB, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	return postJSON(t, h, "/v1/embeddings", body, nil)
}

func lastEmbEvent(t *testing.T, log *eventLog, resp *httptest.ResponseRecorder) events.Event {
	t.Helper()
	return lastEvent(t, log, resp)
}

func TestEmbeddingsPassesRequestAndResponse(t *testing.T) {
	up, rec := embUpstream(t)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.key = "sk-provider"; log = o.events })
	resp := postEmb(t, g, `{"model":"default","input":"привет"}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	var out struct {
		Object string
		Model  string
		Data   []struct {
			Embedding []float64
		}
		Extra string
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// Имя модели — то, что запросило приложение; лишние поля провайдера отброшены.
	if out.Object != "list" || out.Model != "default" || len(out.Data) != 1 || !slices.Equal(out.Data[0].Embedding, []float64{0.5, -0.25}) || out.Extra != "" {
		t.Fatalf("ответ: %s", resp.Body.String())
	}
	path, hdr, body, _ := rec.get()
	if path != "/v1/embeddings" || hdr.Get("Authorization") != "Bearer sk-provider" ||
		body != `{"model":"m","input":["привет"],"encoding_format":"float"}` {
		t.Fatalf("провайдер получил %s %s %v", path, body, hdr)
	}
	e := lastEmbEvent(t, log, resp)
	if e.Model != "m" || e.Tokens == nil || e.Tokens.Prompt != 3 || e.Decision.Action != "allow" {
		t.Fatalf("событие: %+v", e)
	}
}

func TestEmbeddingsRedactsPIIBeforeProvider(t *testing.T) {
	up, rec := embUpstream(t)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { enforce(a); a.Storage = "masked" }
		log = o.events
	})
	resp := postEmb(t, g, `{"model":"m","input":["Почта `+piiEmail+`"]}`)
	if resp.Code != 200 || resp.Header().Get(HeaderDecision) != "redact" {
		t.Fatalf("%d %s %q", resp.Code, resp.Body.String(), resp.Header().Get(HeaderDecision))
	}
	if _, _, body, _ := rec.get(); strings.Contains(body, piiEmail) || !strings.Contains(body, emailMask) {
		t.Fatalf("провайдер получил: %s", body)
	}
	e := lastEmbEvent(t, log, resp)
	if len(e.Findings) != 1 || e.Findings[0].Location != "input[0]" || e.Content == nil || strings.Contains(e.Content.Request, piiEmail) {
		t.Fatalf("событие: %+v", e)
	}
	// Правило pseudonymize политики выполнено как redact — это видно в трассировке.
	if len(e.Decision.Trace) == 0 || !strings.Contains(e.Decision.Trace[0].Note, "как redact") {
		t.Fatalf("трассировка: %+v", e.Decision.Trace)
	}
}

// Покрывает: DM-01
func TestDM01_EmbeddingsBlockedInEnforce(t *testing.T) {
	up, rec := embUpstream(t)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.app = enforce; log = o.events })
	resp := postEmb(t, g, `{"model":"m","input":["Привет",`+jsonString(t, injectionText)+`]}`)
	if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" || resp.Header().Get(HeaderDecision) != "block" {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("заблокированный запрос дошёл до провайдера")
	}
	e := lastEmbEvent(t, log, resp)
	if e.Decision.Action != "block" || !slices.Contains(e.Threats, "DM-01") || e.Findings[0].Location != "input[1]" {
		t.Fatalf("событие: %+v", e)
	}
}

// Покрывает: DM-33
func TestDM33_EmbeddingsModelNotAllowed(t *testing.T) {
	up, rec := embUpstream(t)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { log = o.events })
	resp := postEmb(t, g, `{"model":"text-embedding-secret","input":"x"}`)
	if resp.Code != http.StatusNotFound || errCode(t, resp) != "model_not_found" {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос дошёл до провайдера")
	}
	if e := lastEmbEvent(t, log, resp); e.Decision.Rule != ruleModel || e.Model != "text-embedding-secret" {
		t.Fatalf("событие: %+v", e)
	}
}

func TestEmbeddingsInternalProviderKeepsUser(t *testing.T) {
	up, rec := embUpstream(t)
	g := newGateway(t, up.URL, func(o *gwOpts) { o.internal = true })
	postEmb(t, g, `{"model":"m","input":"x","user":"ivan"}`)
	if _, _, body, _ := rec.get(); !strings.Contains(body, `"user":"ivan"`) {
		t.Fatalf("внутреннему провайдеру: %s", body)
	}
	up2, rec2 := embUpstream(t)
	g = newGateway(t, up2.URL, nil)
	postEmb(t, g, `{"model":"m","input":"x","user":"ivan"}`)
	if _, _, body, _ := rec2.get(); strings.Contains(body, "ivan") {
		t.Fatalf("внешнему провайдеру ушёл идентификатор пользователя: %s", body)
	}
}

func TestEmbeddingsRejectsInvalidRequests(t *testing.T) {
	up, rec := embUpstream(t)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { log = o.events })
	for name, body := range map[string]string{
		"нет model":            `{"input":"x"}`,
		"нет input":            `{"model":"m"}`,
		"пустой input":         `{"model":"m","input":[]}`,
		"пустая строка":        `{"model":"m","input":[""]}`,
		"токены":               `{"model":"m","input":[1,2,3]}`,
		"массив токенов":       `{"model":"m","input":[[1,2],[3]]}`,
		"число":                `{"model":"m","input":5}`,
		"base64":               `{"model":"m","input":"x","encoding_format":"base64"}`,
		"dimensions":           `{"model":"m","input":"x","dimensions":0}`,
		"неизвестное поле":     `{"model":"m","input":"x","foo":1}`,
		"данные после объекта": `{"model":"m","input":"x"}{}`,
	} {
		resp := postEmb(t, g, body)
		if resp.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, resp.Code, resp.Body.String())
		}
	}
	if len(log.all()) != 0 {
		t.Error("ошибки разбора создали события")
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос дошёл до провайдера")
	}
}

func TestEmbeddingsProviderErrorsAndBadResponse(t *testing.T) {
	for name, c := range map[string]struct {
		upstream http.HandlerFunc
		code     int
		errCode  string
	}{
		"ошибка провайдера": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"message":"лимит","type":"rate_limit_error","code":"rate_limit"}}`) //nolint:gosec // G104: тестовый провайдер, ошибка записи не важна
		}, http.StatusTooManyRequests, "rate_limit"},
		"векторов меньше, чем строк": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"object":"list","data":[],"model":"m"}`) //nolint:gosec // G104: тестовый провайдер, ошибка записи не важна
		}, http.StatusBadGateway, "upstream_bad_response"},
		"не JSON": {func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `<html>`) }, //nolint:gosec // G104: тестовый провайдер, ошибка записи не важна
			http.StatusBadGateway, "upstream_bad_response"},
		"пустой вектор": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"object":"list","data":[{"index":0,"embedding":[]}]}`) //nolint:gosec // G104: тестовый провайдер, ошибка записи не важна
		}, http.StatusBadGateway, "upstream_bad_response"},
	} {
		t.Run(name, func(t *testing.T) {
			up, _ := newUpstream(t, c.upstream)
			g := newGateway(t, up.URL, nil)
			resp := postEmb(t, g, `{"model":"m","input":"x"}`)
			if resp.Code != c.code || errCode(t, resp) != c.errCode {
				t.Fatalf("%d %s", resp.Code, resp.Body.String())
			}
		})
	}
}

// Провайдеры без поддержки эмбеддингов отвечают 501, события нет.
func TestEmbeddingsUnsupportedProvider(t *testing.T) {
	up, _ := embUpstream(t)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		log = o.events
		o.setup = func(a *App) { a.Provider = noEmbeddings{a.Provider} }
	})
	resp := postEmb(t, g, `{"model":"m","input":"x"}`)
	if resp.Code != http.StatusNotImplemented || errCode(t, resp) != "embeddings_not_supported" || len(log.all()) != 0 {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
}

// Покрывает: DM-36
func TestDM36_EmbeddingsQuotas(t *testing.T) {
	up, _ := embUpstream(t)
	g := newGateway(t, up.URL, func(o *gwOpts) { o.quotas.RequestsPerMinute = 1 })
	if resp := postEmb(t, g, `{"model":"m","input":"x"}`); resp.Code != 200 {
		t.Fatalf("первый: %d %s", resp.Code, resp.Body.String())
	}
	if resp := postEmb(t, g, `{"model":"m","input":"x"}`); resp.Code != http.StatusTooManyRequests || errCode(t, resp) != "quota_exceeded" {
		t.Fatalf("второй: %d %s", resp.Code, resp.Body.String())
	}
}

// noEmbeddings скрывает у провайдера метод Embeddings.
type noEmbeddings struct{ providers.Provider }
