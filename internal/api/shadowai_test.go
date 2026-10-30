package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

// shadowTestNow — «сейчас» сервиса теневого ИИ в тестах: синтетические
// журналы testdata/shadowai датированы 27.10.2026.
var shadowTestNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const shadowPeriod = "from=2026-10-20T00:00:00Z&to=2026-10-28T12:00:00Z"

func shadowTestMAC(t testing.TB, p aisecCrypto.Provider) aisecCrypto.MAC {
	t.Helper()
	m, err := p.NewMAC(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func shadowFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/shadowai/" + name) //nolint:gosec // G304: фикстура теста из репозитория
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// callFile — запрос с телом-файлом и заданным Content-Type.
func (e *authEnv) callFile(s session, method, target, contentType string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, target, bytes.NewReader(body))
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("Content-Type", contentType)
	for _, c := range s.cookies {
		if c.Name == SessionCookie {
			r.AddCookie(c)
		}
	}
	if s.csrf != "" {
		r.Header.Set(CSRFHeader, s.csrf)
	}
	if s.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+s.bearer)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// DM-37, ADR-0027: каталог загружает shadow_ai.manage и только подписанный;
// импорт хранит сводки без логинов и адресов; чтение — shadow_ai.read.
func TestShadowAIViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	const octet = "application/octet-stream"
	catalog := shadowFile(t, "catalog-test.aisecdb")

	// Отказы в доступе: владелец приложения не читает; аналитик и аудитор не меняют.
	for _, p := range []string{"/api/v1/shadow-ai/services", "/api/v1/shadow-ai/catalog", "/api/v1/shadow-ai/settings"} {
		mustProblem(t, e.call(owner, "GET", p, "", false), 403, CodeForbidden)
	}
	for _, s := range []session{analyst, auditor} {
		mustProblem(t, e.callFile(s, "PUT", "/api/v1/shadow-ai/catalog", octet, catalog), 403, CodeForbidden)
		mustProblem(t, e.callFile(s, "POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", []byte("x")), 403, CodeForbidden)
		mustProblem(t, e.call(s, "PUT", "/api/v1/shadow-ai/settings", `{"retention_days":400}`, true), 403, CodeForbidden)
	}

	if w := e.call(analyst, "GET", "/api/v1/shadow-ai/catalog", "", false); w.Code != 200 || !strings.Contains(w.Body.String(), `"loaded":false`) {
		t.Fatalf("каталог до загрузки: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", shadowFile(t, "access-squid.log")),
		409, CodeConflict)
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/shadow-ai/catalog", "application/json", catalog), 415, CodeUnsupportedMedia)
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/shadow-ai/catalog", octet, []byte("мусор")), 422, CodeUnprocessable)
	w := e.callFile(sys, "PUT", "/api/v1/shadow-ai/catalog", octet, catalog)
	if v := decode[shadowai.CatalogView](t, w.Body.Bytes()); w.Code != 200 || !v.Valid || v.Version != 1 || len(v.Services) != 28 {
		t.Fatalf("загрузка каталога: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/shadow-ai/catalog", octet, catalog), 409, CodeConflict)

	// Импорт: неверные параметры и тип, успех, повтор, gzip.
	mustProblem(t, e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=json", "text/plain", []byte("x")), 400, CodeInvalidRequest)
	mustProblem(t, e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=csv&compression=zip", "text/plain", []byte("x")),
		400, CodeInvalidRequest)
	mustProblem(t, e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=csv", "multipart/form-data; boundary=x", []byte("x")),
		415, CodeUnsupportedMedia)
	mustProblem(t, e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=csv", "text/csv", []byte("a;b\n1;2\n")), 400, CodeInvalidRequest)
	mustProblem(t, e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=cef&compression=gzip", "application/gzip", []byte("не gzip")),
		400, CodeInvalidRequest)
	broken := gzipped(t, shadowFile(t, "usergate-cef.log"))
	for i := 12; i < len(broken)-8; i++ {
		broken[i] ^= 0xff
	}
	mustProblem(t, e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=cef&compression=gzip", "application/gzip", broken),
		400, CodeInvalidRequest)
	w = e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", shadowFile(t, "access-squid.log"))
	imp := decode[shadowai.ImportRecord](t, w.Body.Bytes())
	if w.Code != 201 || imp.Matched != 5 || imp.Errors != 2 || len(imp.ErrorLines) != 2 || !imp.UsersPseudonymized {
		t.Fatalf("импорт: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", shadowFile(t, "access-squid.log")),
		409, CodeConflict)
	w = e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=cef&compression=gzip", "application/gzip",
		gzipped(t, shadowFile(t, "usergate-cef.log")))
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"matched":2`) {
		t.Fatalf("импорт gzip: %d %s", w.Code, w.Body)
	}
	if w := e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=csv", "text/csv", shadowFile(t, "access.csv")); w.Code != 201 {
		t.Fatalf("импорт CSV: %d %s", w.Code, w.Body)
	}

	// Чтение: логинов, адресов и узлов из журналов в ответах нет.
	reads := map[string]string{
		"/api/v1/shadow-ai/services?" + shadowPeriod:           `"id":"chatgpt"`,
		"/api/v1/shadow-ai/users?" + shadowPeriod:              `"kind":"user"`,
		"/api/v1/shadow-ai/timeline?step=hour&" + shadowPeriod: `"step":"hour"`,
		"/api/v1/shadow-ai/imports":                            `"format":"csv"`,
		"/api/v1/shadow-ai/settings":                           `"retention_days":365,"users_pseudonymized":true`,
	}
	for path, want := range reads {
		for _, s := range []session{analyst, auditor} {
			w := e.call(s, "GET", path, "", false)
			body := strings.ToLower(w.Body.String())
			if w.Code != 200 || !strings.Contains(body, want) {
				t.Fatalf("%s: %d %s", path, w.Code, w.Body)
			}
			for _, bad := range []string{"ivanov", "petrova", "10.0.12", "10.0.20", "example.ru", "chatgpt.com/"} {
				if strings.Contains(body, bad) {
					t.Fatalf("%s: в ответе %q", path, bad)
				}
			}
		}
	}
	for _, q := range []string{"from=вчера", "from=2026-10-28T00:00:00Z&to=2026-10-01T00:00:00Z", "service=Bad", "limit=0"} {
		mustProblem(t, e.call(analyst, "GET", "/api/v1/shadow-ai/users?"+q, "", false), 400, CodeInvalidRequest)
	}
	mustProblem(t, e.call(analyst, "GET", "/api/v1/shadow-ai/timeline?step=week", "", false), 400, CodeInvalidRequest)

	// Срок хранения: увеличение без проверки, сокращение — с паролем;
	// токен API не сокращает срок (повторной проверки по токену нет).
	if w := e.call(sys, "PUT", "/api/v1/shadow-ai/settings", `{"retention_days":400}`, true); w.Code != 200 {
		t.Fatalf("увеличение срока: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "PUT", "/api/v1/shadow-ai/settings", `{"retention_days":10}`, true), 400, CodeInvalidRequest)
	w = e.call(sys, "PUT", "/api/v1/shadow-ai/settings", `{"retention_days":30}`, true)
	if p := decode[Problem](t, w.Body.Bytes()); w.Code != 400 || len(p.Errors) != 1 || p.Errors[0].Field != "password" {
		t.Fatalf("сокращение без пароля: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "PUT", "/api/v1/shadow-ai/settings", `{"retention_days":30,"password":"не тот"}`, true), 403, CodeReauthFailed)
	tok := session{bearer: e.issueToken(t, sys, auth.PermShadowAIRead, auth.PermShadowAIManage).Token}
	mustProblem(t, e.call(tok, "PUT", "/api/v1/shadow-ai/settings", `{"retention_days":30}`, false), 403, CodeForbidden)
	if w := e.call(tok, "GET", "/api/v1/shadow-ai/services?"+shadowPeriod, "", false); w.Code != 200 {
		t.Fatalf("чтение по токену: %d %s", w.Code, w.Body)
	}
	if w := e.call(sys, "PUT", "/api/v1/shadow-ai/settings", `{"retention_days":30,"password":"`+tPhrase+`"}`, true); w.Code != 200 {
		t.Fatalf("сокращение с паролем: %d %s", w.Code, w.Body)
	}

	// Аудит: коды есть, содержимого журналов нет.
	got := map[string]int{}
	for _, r := range e.shadow.Records() {
		got[r.Action]++
		if strings.Contains(strings.ToLower(mustJSON(t, r.Details)), "ivanov") {
			t.Fatalf("логин в аудите: %+v", r)
		}
	}
	for action, n := range map[string]int{"shadow_ai.catalog_loaded": 1, "shadow_ai.catalog_rejected": 2, "shadow_ai.import": 3,
		"shadow_ai.settings_changed": 2} {
		if got[action] != n {
			t.Errorf("%s: %d записей, ждали %d (%v)", action, got[action], n, got)
		}
	}
}

// Пока идёт импорт, второй получает 429 с Retry-After.
func TestShadowAIImportBusy(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	if w := e.callFile(sys, "PUT", "/api/v1/shadow-ai/catalog", "application/octet-stream", shadowFile(t, "catalog-test.aisecdb")); w.Code != 200 {
		t.Fatalf("каталог: %d %s", w.Code, w.Body)
	}
	pr, pw := io.Pipe()
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/v1/shadow-ai/imports?format=squid", pr)
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Content-Type", "text/plain")
		r.Header.Set(CSRFHeader, sys.csrf)
		for _, c := range sys.cookies {
			if c.Name == SessionCookie {
				r.AddCookie(c)
			}
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		done <- w
	}()
	// Первая строка прочитана — значит, первый импорт занял место.
	if _, err := pw.Write(shadowFile(t, "access-squid.log")); err != nil {
		t.Fatal(err)
	}
	w := e.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", []byte("x\n"))
	mustProblem(t, w, http.StatusTooManyRequests, CodeRateLimited)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("нет Retry-After")
	}
	_ = pw.Close() //nolint:gosec // G104: конец тела первого запроса
	if w := <-done; w.Code != 201 {
		t.Fatalf("первый импорт: %d %s", w.Code, w.Body)
	}
}

// Исключения (задача 4.23): чтение — shadow_ai.read, изменение — право
// безопасности shadow_ai.exclusions.manage (только security_admin, 4В26) с
// повторной проверкой, токенам не выдаётся; логина нет ни в ответе, ни в
// аудите. Состояние приёма по syslog — shadow_ai.read.
func TestShadowAIExclusionsViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sec := e.mustLogin(t, "admin")
	sysadm := e.mustLogin(t, "sysadm")
	analyst := e.mustLogin(t, "analyst")
	owner := e.mustLogin(t, "owner")
	for _, p := range []string{"/api/v1/shadow-ai/exclusions", "/api/v1/shadow-ai/syslog"} {
		mustProblem(t, e.call(owner, "GET", p, "", false), 403, CodeForbidden)
	}
	mustProblem(t, e.call(analyst, "POST", "/api/v1/shadow-ai/exclusions", `{"kind":"service","service":"chatgpt"}`, true), 403, CodeForbidden)
	mustProblem(t, e.call(analyst, "DELETE", "/api/v1/shadow-ai/exclusions/service/chatgpt", "", true), 403, CodeForbidden)
	// 4В26: у администратора системы shadow_ai.manage, но не исключения.
	mustProblem(t, e.call(sysadm, "POST", "/api/v1/shadow-ai/exclusions", `{"kind":"user","login":"ivanov.ia","password":"`+tPhrase+`"}`, true),
		403, CodeForbidden)
	mustProblem(t, e.call(sysadm, "DELETE", "/api/v1/shadow-ai/exclusions/service/chatgpt", "", true), 403, CodeForbidden)

	if w := e.call(analyst, "GET", "/api/v1/shadow-ai/syslog", "", false); w.Code != 200 ||
		!strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("syslog: %d %s", w.Code, w.Body)
	}
	if w := e.call(analyst, "GET", "/api/v1/shadow-ai/exclusions", "", false); w.Code != 200 || w.Body.String() != `{"items":[]}`+"\n" {
		t.Fatalf("пустой список: %d %q", w.Code, w.Body)
	}
	// Без пароля — 400 по полю password; неверный — 403; токену право не
	// выдаётся, токен с shadow_ai.manage — 403.
	w := e.call(sec, "POST", "/api/v1/shadow-ai/exclusions", `{"kind":"user","login":"ivanov.ia"}`, true)
	if p := decode[Problem](t, w.Body.Bytes()); w.Code != 400 || len(p.Errors) != 1 || p.Errors[0].Field != "password" {
		t.Fatalf("без пароля: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sec, "POST", "/api/v1/shadow-ai/exclusions", `{"kind":"user","login":"ivanov.ia","password":"не тот"}`, true),
		403, CodeReauthFailed)
	if auth.TokenGrantable(auth.PermShadowAIExclusionsManage) {
		t.Fatal("право исключений выдаётся токенам API")
	}
	tok := session{bearer: e.issueToken(t, sec, auth.PermShadowAIRead, auth.PermShadowAIManage).Token}
	mustProblem(t, e.call(tok, "POST", "/api/v1/shadow-ai/exclusions", `{"kind":"service","service":"chatgpt"}`, false), 403, CodeForbidden)
	mustProblem(t, e.call(tok, "DELETE", "/api/v1/shadow-ai/exclusions/service/chatgpt", "", false), 403, CodeForbidden)
	for _, body := range []string{`{"kind":"group"}`, `{"kind":"service","service":"Chat GPT"}`, `{"kind":"user"}`,
		`{"kind":"service","service":"chatgpt","extra":1}`} {
		if w := e.call(sec, "POST", "/api/v1/shadow-ai/exclusions", body[:len(body)-1]+`,"password":"`+tPhrase+`"}`, true); w.Code != 400 {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	w = e.call(sec, "POST", "/api/v1/shadow-ai/exclusions", `{"kind":"user","login":"ivanov.ia","comment":"шлюз","password":"`+tPhrase+`"}`, true)
	ex := decode[shadowai.Exclusion](t, w.Body.Bytes())
	if w.Code != 201 || len(ex.Value) != 32 || strings.Contains(w.Body.String(), "ivanov") {
		t.Fatalf("исключение пользователя: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sec, "POST", "/api/v1/shadow-ai/exclusions", `{"kind":"user","alias":"`+ex.Value+`","password":"`+tPhrase+`"}`, true),
		409, CodeConflict)
	if w := e.call(sec, "POST", "/api/v1/shadow-ai/exclusions", `{"kind":"service","service":"chatgpt","password":"`+tPhrase+`"}`, true); w.Code != 201 {
		t.Fatalf("исключение сервиса: %d %s", w.Code, w.Body)
	}
	w = e.call(analyst, "GET", "/api/v1/shadow-ai/exclusions", "", false)
	if list := decode[ShadowExclusionList](t, w.Body.Bytes()); w.Code != 200 || len(list.Items) != 2 {
		t.Fatalf("список: %d %s", w.Code, w.Body)
	}
	if w := e.call(sec, "DELETE", "/api/v1/shadow-ai/exclusions/service/chatgpt", "", true); w.Code != 204 {
		t.Fatalf("снятие: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sec, "DELETE", "/api/v1/shadow-ai/exclusions/service/chatgpt", "", true), 404, CodeNotFound)
	if w := e.call(sec, "DELETE", "/api/v1/shadow-ai/exclusions/user/"+ex.Value, "", true); w.Code != 204 {
		t.Fatalf("снятие пользователя: %d %s", w.Code, w.Body)
	}
	got := map[string]int{}
	for _, r := range e.shadow.Records() {
		got[r.Action]++
		if strings.Contains(mustJSON(t, r.Details), "ivanov") {
			t.Fatalf("логин в аудите: %+v", r)
		}
	}
	if got["shadow_ai.exclusion_added"] != 2 || got["shadow_ai.exclusion_removed"] != 2 {
		t.Fatalf("аудит: %v", got)
	}
}
