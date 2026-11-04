package redteam

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTargetInputDefaultsAndRejects(t *testing.T) {
	tg, err := endpointInput(func(in *TargetInput) { in.Limits, in.Storage = nil, "" }).Target()
	if err != nil {
		t.Fatal(err)
	}
	if tg.Limits != (Limits{DefaultRate, DefaultConcurrency, DefaultRequestTimeout, DefaultRunTimeout}) || tg.Storage != StorageNone {
		t.Fatalf("умолчания: %+v", tg)
	}
	cases := map[string]func(*TargetInput){
		"name":        func(in *TargetInput) { in.Name = "" },
		"kind":        func(in *TargetInput) { in.Kind = "proxy" },
		"rate":        func(in *TargetInput) { in.Limits = &Limits{RatePerMinute: MaxRate + 1} },
		"concurrency": func(in *TargetInput) { in.Limits = &Limits{Concurrency: MaxConcurrency + 1} },
		"timeout":     func(in *TargetInput) { in.Limits = &Limits{RequestTimeoutSec: 1} },
		"run":         func(in *TargetInput) { in.Limits = &Limits{RunTimeoutMin: MaxRunTimeout + 1} },
		"template":    func(in *TargetInput) { in.RequestTemplate = `{"q": "текст"}` },
		"template-js": func(in *TargetInput) { in.RequestTemplate = `{"q": "{{prompt}}"} {}` },
		"template-big": func(in *TargetInput) {
			in.RequestTemplate = `{"q":"{{prompt}}","p":"` + strings.Repeat("a", MaxTemplate) + `"}`
		},
		"path":         func(in *TargetInput) { in.ResponsePath = "choices[0].text" },
		"path-empty":   func(in *TargetInput) { in.ResponsePath = "" },
		"header-host":  func(in *TargetInput) { in.Headers = []Header{{Name: "Host", Value: "evil"}} },
		"header-proxy": func(in *TargetInput) { in.Headers = []Header{{Name: "Proxy-Authorization", Value: "x"}} },
		"header-crlf":  func(in *TargetInput) { in.Headers = []Header{{Name: "X-A", Value: "a\r\nX-B: b"}} },
		"header-dup":   func(in *TargetInput) { in.Headers = []Header{{Name: "X-A", Value: "1"}, {Name: "x-a", Value: "2"}} },
		"header-auth":  func(in *TargetInput) { in.AuthHeader, in.Headers = "X-Key", []Header{{Name: "X-Key", Value: "v"}} },
		"header-many":  func(in *TargetInput) { in.Headers = make([]Header, MaxHeaders+1) },
		"auth-name":    func(in *TargetInput) { in.AuthHeader = "Bad Header" },
		"note":         func(in *TargetInput) { in.AuthorizationNote = "" },
		"storage":      func(in *TargetInput) { in.Storage = "full" },
		"https-no-ca":  func(in *TargetInput) { in.URL = "https://bot.example.test:443/x" },
		"http-ca":      func(in *TargetInput) { in.CAPEM = "-----BEGIN CERTIFICATE-----" },
		"judge-half":   func(in *TargetInput) { in.JudgeProvider = "local-llm" },
		"app-on-ep":    func(in *TargetInput) { in.AppID = testAppID },
		"fragment":     func(in *TargetInput) { in.URL = testTarget + "#x" },
	}
	for name, mod := range cases {
		if _, err := endpointInput(mod).Target(); !isInput(err) {
			t.Errorf("%s: принято (%v)", name, err)
		}
	}
	if _, err := (TargetInput{Name: "a", Kind: KindGateway, AppID: testAppID, Model: "m", Storage: StorageMasked}).Target(); !isInput(err) {
		t.Error("storage у цели gateway принят")
	}
}

// Секрет в постоянных заголовках или в шаблоне тела — отказ (5Н21 ревью
// 5.r3): они хранятся открыто и видны с redteam.read. Текст ошибки не
// содержит значения; обычные заголовки и шаблон принимаются.
func TestTargetRejectsSecrets(t *testing.T) {
	// Синтетические значения собираются при выполнении.
	jwt := "Bearer " + "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjMifQ" + ".c2lnbmF0dXJlLXRlc3QtdmFsdWU"
	key := "Zq8vT3mK1pW9" + "xR4nL7bH2cF6dJ0sY5gA"
	for _, name := range []string{"Authorization", "x-api-key", "Api-Key", "X-Auth-Token", "X-Session-Token"} {
		_, err := endpointInput(func(in *TargetInput) { in.Headers = []Header{{Name: name, Value: "v"}} }).Target()
		if !isInput(err) || !strings.Contains(err.Error(), "auth_header") {
			t.Errorf("заголовок %s: %v", name, err)
		}
	}
	cases := map[string]func(*TargetInput){
		"header-value": func(in *TargetInput) { in.Headers = []Header{{Name: "X-Custom", Value: jwt}} },
		"template-key": func(in *TargetInput) { in.RequestTemplate = `{"q":"{{prompt}}","api_key":"` + key + `"}` },
	}
	for name, mod := range cases {
		_, err := endpointInput(mod).Target()
		if !isInput(err) || strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "eyJ") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := endpointInput(func(in *TargetInput) {
		in.Headers = []Header{{Name: "X-Tenant", Value: "crm-prod-01"}}
		in.RequestTemplate = `{"model":"gpt-4o-mini","messages":"{{messages}}","temperature":0}`
		in.AuthHeader = "Authorization"
	}).Target(); err != nil {
		t.Fatalf("обычная цель: %v", err)
	}
}

func TestRenderTemplateAndExtract(t *testing.T) {
	hist := []message{{Role: "user", Content: "привет"}, {Role: "assistant", Content: "здравствуйте"}, {Role: "user", Content: `"кавычки" <b>`}}
	body, err := renderTemplate(`{"input": {"text": "{{prompt}}", "n": 1.50}, "h": "{{messages}}", "keep": "{{other}}"}`, hist[2].Content, hist)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["input"].(map[string]any)["text"] != `"кавычки" <b>` || len(got["h"].([]any)) != 3 || got["keep"] != "{{other}}" ||
		!strings.Contains(string(body), `1.50`) || strings.Contains(string(body), `\`+"u003c") || strings.Contains(string(body), "{{messages}}") {
		t.Fatalf("тело: %s", body)
	}
	for path, want := range map[string]string{"choices.0.message.content": "ответ", "meta.list.1": "b"} {
		v, ok := extractPath([]byte(`{"choices":[{"message":{"content":"ответ"}}],"meta":{"list":["a","b"]}}`), path)
		if !ok || v != want {
			t.Errorf("%s: %q %v", path, v, ok)
		}
	}
	for _, path := range []string{"choices.1.message.content", "choices.x", "meta", "meta.list.-1", "none"} {
		if _, ok := extractPath([]byte(`{"choices":[{"message":{"content":"ответ"}}],"meta":{"list":["a"]}}`), path); ok {
			t.Errorf("%s: найдено", path)
		}
	}
}

// FuzzTargetInput: поля цели из недоверенного тела API — проверка не
// падает; принятая цель годится для подстановки шаблона.
func FuzzTargetInput(f *testing.F) {
	ok, _ := json.Marshal(endpointInput(nil)) //nolint:gosec // G104: кодирование тестовой цели без ошибок
	f.Add(ok)
	f.Add([]byte(`{"name":"a","kind":"gateway","app_id":"01900000-0000-7000-8000-0000000000a1","model":"m"}`))
	f.Add([]byte(`{"kind":"endpoint","url":"http://[::1]:80/","request_template":"[\"{{prompt}}\"]"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var in TargetInput
		if json.Unmarshal(data, &in) != nil {
			return
		}
		tg, err := in.Target()
		if err != nil {
			return
		}
		if tg.Kind == KindEndpoint {
			if _, err := renderTemplate(tg.RequestTemplate, "p", []message{{Role: "user", Content: "p"}}); err != nil {
				t.Fatalf("принятый шаблон не подставляется: %v", err)
			}
		}
	})
}

// FuzzExtractPath: недоверенный ответ цели — разбор пути не падает.
func FuzzExtractPath(f *testing.F) {
	f.Add([]byte(`{"choices":[{"message":{"content":"ответ"}}]}`), "choices.0.message.content")
	f.Add([]byte(`[[[["a"]]]]`), "0.0.0.0")
	f.Add([]byte(`{"a":1e999}`), "a")
	f.Fuzz(func(t *testing.T, body []byte, path string) {
		if len(path) > MaxResponsePath {
			return
		}
		_, _ = extractPath(body, path)
	})
}
