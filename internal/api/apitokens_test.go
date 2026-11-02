package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// issueToken выпускает токен через API от имени сессии s.
func (e *authEnv) issueToken(t *testing.T, s session, perms ...string) CreatedAPIToken {
	t.Helper()
	req := createAPITokenRequest{Name: "Автоматизация", Password: tPhrase}
	for _, p := range perms {
		req.Permissions = append(req.Permissions, GrantView{Permission: p})
	}
	w := e.call(s, "POST", "/api/v1/api-tokens", mustJSON(t, req), true)
	if w.Code != http.StatusCreated {
		t.Fatalf("выпуск токена: %d %s", w.Code, w.Body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("ответ с токеном кэшируется: %q", cc)
	}
	var out CreatedAPIToken
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func lastAction(t *testing.T, e *authEnv, action string) (audit.Entry, int) {
	t.Helper()
	var (
		last audit.Entry
		n    int
	)
	for _, r := range e.mem.Records() {
		if r.Action == action {
			last, n = r, n+1
		}
	}
	return last, n
}

// ИАФ.9: токен выпускается из сессии и показывается один раз; запрос по
// токену проверяется только по нему, без CSRF и без отката на cookie;
// каждый пропущенный запрос пишет api_token.used; свои данные и функции
// безопасности токену недоступны.
func TestAPITokenBearerFlow(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")
	created := e.issueToken(t, admin, auth.PermUsersRead, auth.PermSystemRead)
	if !strings.HasPrefix(created.Token, created.APIToken.Prefix+"_") || created.APIToken.Status != "active" {
		t.Fatalf("ответ выпуска: %+v", created.APIToken)
	}
	bearer := session{bearer: created.Token}

	w := e.call(bearer, "GET", "/api/v1/users", "", false)
	if w.Code != http.StatusOK {
		t.Fatalf("чтение пользователей по токену: %d %s", w.Code, w.Body)
	}
	used, n := lastAction(t, e, "api_token.used")
	d, _ := used.Details.(map[string]any)
	if n != 1 || used.Actor.Type != audit.ActorAPIToken || used.Actor.ID != created.APIToken.ID ||
		d["path"] != "/api/v1/users" || d["method"] != "GET" || d["status"] != http.StatusOK {
		t.Fatalf("запись использования: %+v", used)
	}

	// Свои данные, функции безопасности и сами токены — 403 с записью отказа.
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/v1/me", ""},
		{"POST", "/api/v1/auth/logout", ""},
		{"POST", "/api/v1/users", `{"login":"x","display_name":"x","role":"analyst"}`},
		{"GET", "/api/v1/api-tokens", ""},
		{"POST", "/api/v1/api-tokens", `{"name":"x","password":"Синтетический-Пароль-42","permissions":[{"permission":"system.read"}]}`},
	} {
		_, before := lastAction(t, e, "access.denied")
		if w := e.call(bearer, c.method, c.path, c.body, false); w.Code != http.StatusForbidden {
			t.Errorf("%s %s по токену: %d", c.method, c.path, w.Code)
		}
		rec, after := lastAction(t, e, "access.denied")
		if after != before+1 || rec.Actor.Type != audit.ActorAPIToken {
			t.Errorf("%s %s: отказ не записан от имени токена: %+v", c.method, c.path, rec)
		}
	}
	if _, n2 := lastAction(t, e, "api_token.used"); n2 != 1 {
		t.Fatalf("api_token.used при отказе: %d записей", n2)
	}

	// С Authorization cookie не проверяется: права — только токена.
	both := admin
	both.bearer = created.Token
	if w := e.call(both, "POST", "/api/v1/users", `{"login":"y","display_name":"y","role":"analyst"}`, true); w.Code != http.StatusForbidden {
		t.Fatalf("Bearer вместе с cookie администратора: %d", w.Code)
	}
	both.bearer = "aisec_pat_00000000_" + strings.Repeat("A", 43)
	if w := e.call(both, "GET", "/api/v1/users", "", false); w.Code != http.StatusUnauthorized {
		t.Fatalf("неверный токен с действующей cookie: %d", w.Code)
	}
	if rec, _ := lastAction(t, e, "api_token.auth_failed"); rec.Details.(map[string]any)["reason"] != auth.ReasonInvalid {
		t.Fatalf("запись отказа: %+v", rec)
	}

	// Отзыв из консоли: токен больше не принимается.
	if w := e.call(admin, "DELETE", "/api/v1/api-tokens/"+created.APIToken.ID, "", true); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"status":"revoked"`) {
		t.Fatalf("отзыв: %d %s", w.Code, w.Body)
	}
	if w := e.call(admin, "DELETE", "/api/v1/api-tokens/"+created.APIToken.ID, "", true); w.Code != http.StatusConflict {
		t.Fatalf("повторный отзыв: %d", w.Code)
	}
	if w := e.call(bearer, "GET", "/api/v1/users", "", false); w.Code != http.StatusUnauthorized {
		t.Fatalf("отозванный токен: %d", w.Code)
	}

	// Секрет токена — только в ответе на выпуск: ни в аудите, ни в журнале.
	secret := created.Token[len(created.APIToken.Prefix)+1:]
	if strings.Contains(e.log.String(), secret) || strings.Contains(fmt.Sprintf("%+v", e.mem.Records()), secret) {
		t.Fatal("секрет токена в журналах")
	}
	w = e.call(admin, "GET", "/api/v1/api-tokens/"+created.APIToken.ID, "", false)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), secret) {
		t.Fatalf("чтение токена: %d %s", w.Code, w.Body)
	}
}

func TestAPITokenCreateRejects(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")
	for name, body := range map[string]string{
		"безопасность": `{"name":"x","password":"Синтетический-Пароль-42","permissions":[{"permission":"users.manage"}]}`,
		"токены":       `{"name":"x","password":"Синтетический-Пароль-42","permissions":[{"permission":"api_tokens.manage"}]}`,
		"без прав":     `{"name":"x","password":"Синтетический-Пароль-42","permissions":[]}`,
		"срок":         `{"name":"x","password":"Синтетический-Пароль-42","expires_in_days":400,"permissions":[{"permission":"system.read"}]}`,
		"лишнее поле":  `{"name":"x","password":"Синтетический-Пароль-42","token":"aisec_pat_x","permissions":[{"permission":"system.read"}]}`,
	} {
		if w := e.call(admin, "POST", "/api/v1/api-tokens", body, true); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// Без CSRF выпуск из сессии не проходит.
	if w := e.call(admin, "POST", "/api/v1/api-tokens", `{"name":"x","password":"Синтетический-Пароль-42","permissions":[{"permission":"system.read"}]}`, false); w.Code != http.StatusForbidden {
		t.Fatalf("без CSRF: %d", w.Code)
	}
	// Аналитику токены не положены.
	if w := e.call(e.mustLogin(t, "analyst"), "GET", "/api/v1/api-tokens", "", false); w.Code != http.StatusForbidden {
		t.Fatalf("список токенов аналитика: %d", w.Code)
	}
}

// УПД.3 для токенов: для каждой предустановленной роли — токен с наибольшей
// возможной областью; каждая пара «маршрут × токен роли» проверена. Права
// токена — TokenGrants: функции безопасности, свои данные и токены — отказ
// 403 с записью access.denied от имени токена.
func TestRBACMatrixTokenDenials(t *testing.T) {
	s := loadSpec(t)
	e := newRBACEnv(t)
	h := testHasher(t)
	widest := auth.Grants{}
	for _, p := range auth.Permissions() {
		if auth.TokenGrantable(p.Name) {
			widest[p.Name] = auth.ScopeAll
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	tokens := map[auth.Role]string{}
	for i, r := range e.roles {
		raw := fmt.Sprintf("aisec_pat_m%07d_", i) + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%032d", i)))
		tok := auth.APIToken{ID: fmt.Sprintf("01900000-0000-7000-8000-0000000ee%03d", i), OrgID: audit.DefaultOrgID,
			UserID: tUserIDPrefix + string(rune('a'+i)) + "0", Name: "матрица", Prefix: raw[:18], Hash: h.Sum([]byte(raw)),
			HashAlg: h.Name(), Grants: widest, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
		rec := audit.Entry{Actor: audit.Actor{Type: audit.ActorCLI, ID: "test"}, Action: "api_token.create", Result: audit.ResultSuccess}
		if err := e.mem.CreateAPIToken(context.Background(), tok, func(auth.Actor) (audit.Entry, error) { return rec, nil }); err != nil {
			t.Fatal(err)
		}
		tokens[r.ID] = raw
	}
	pairs, denials := 0, 0
	for _, r := range e.rt.Routes() {
		if r.Public {
			continue
		}
		if op := s.Paths[r.Path][strings.ToLower(r.Method)]; op.Permission != r.Permission {
			t.Errorf("%s %s: x-permission %q", r.Method, r.Path, op.Permission)
			continue
		}
		for _, role := range e.roles {
			pairs++
			_, before := lastDenied(t, e.mem)
			w := e.call(session{bearer: tokens[role.ID]}, r.Method, target(r.Path), "", false)
			g := auth.TokenGrants(widest, role.Grants)
			deny := !g.Full(r.Permission)
			if r.Scoped {
				deny = !g.Allows(r.Permission)
			}
			deny = deny || r.SessionOnly
			if !deny {
				if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
					t.Errorf("%s %s, токен роли %s: ожидался доступ, ответ %d %s", r.Method, r.Path, role.ID, w.Code, w.Body)
				}
				continue
			}
			denials++
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s, токен роли %s: ожидался отказ 403, ответ %d", r.Method, r.Path, role.ID, w.Code)
				continue
			}
			rec, after := lastDenied(t, e.mem)
			if after != before+1 || rec.Actor.Type != audit.ActorAPIToken {
				t.Errorf("%s %s, токен роли %s: отказ не записан от имени токена: %+v", r.Method, r.Path, role.ID, rec)
			}
		}
	}
	if pairs == 0 || denials == 0 {
		t.Fatalf("пар %d, отказов %d", pairs, denials)
	}
}

// fixedToken — проверка прав, которая всегда пропускает запрос по токену.
type fixedToken struct{}

func (fixedToken) Authorize(*http.Request, string) (Principal, Decision) {
	return Principal{ID: "api_token:t", Caller: &auth.Caller{Token: &auth.APIToken{ID: "t"}},
		Grants: auth.Grants{auth.PermSystemRead: auth.ScopeAll}}, Allow
}

// Паника обработчика запроса по токену тоже попадает в api_token.used (как 500).
func TestTokenUsedRecordedOnPanic(t *testing.T) {
	var got []int
	h, _ := newHandler(t, Options{Authorizer: fixedToken{},
		OnTokenUsed: func(_ *http.Request, _ Principal, _, path string, status int) {
			if path == "/api/v1/test/{x}" {
				got = append(got, status)
			}
		},
		Extra: []Route{{Method: http.MethodGet, Path: "/api/v1/test/{x}", Permission: auth.PermSystemRead,
			Handler: func(w http.ResponseWriter, r *http.Request) {
				if r.PathValue("x") == "panic" {
					panic("сбой")
				}
				w.WriteHeader(http.StatusAccepted)
			}}}})
	for _, p := range []string{"/api/v1/test/ok", "/api/v1/test/panic"} {
		do(h, "GET", p, "")
	}
	if len(got) != 2 || got[0] != http.StatusAccepted || got[1] != http.StatusInternalServerError {
		t.Fatalf("коды в api_token.used: %v", got)
	}
}

// В8 ревью 2.r2: неверный пароль при выпуске токена — 403
// reauthentication_failed (не 401: сессия действительна); завершение
// сессий по умолчанию отзывает токены, revoke_api_tokens=false — нет.
func TestAPITokenReauthAndRevokeViaAPI(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")
	mustProblem(t, e.call(admin, "POST", "/api/v1/api-tokens",
		`{"name":"x","password":"неверный","permissions":[{"permission":"system.read"}]}`, true), http.StatusForbidden, CodeReauthFailed)
	mustProblem(t, e.call(admin, "POST", "/api/v1/api-tokens",
		`{"name":"x","permissions":[{"permission":"system.read"}]}`, true), http.StatusBadRequest, CodeInvalidRequest)
	if w := e.call(admin, "GET", "/api/v1/me", "", false); w.Code != http.StatusOK {
		t.Fatalf("сессия после неверного пароля: %d", w.Code)
	}
	created := e.issueToken(t, admin, auth.PermUsersRead)
	bearer := session{bearer: created.Token}
	mustProblem(t, e.call(admin, "DELETE", "/api/v1/users/"+tAdminID+"/sessions?revoke_api_tokens=нет", "", true),
		http.StatusBadRequest, CodeInvalidRequest)
	if w := e.call(admin, "DELETE", "/api/v1/users/"+tAdminID+"/sessions?revoke_api_tokens=false", "", true); w.Code != http.StatusOK {
		t.Fatalf("завершение сессий без отзыва токенов: %d %s", w.Code, w.Body)
	}
	if w := e.call(bearer, "GET", "/api/v1/users", "", false); w.Code != http.StatusOK {
		t.Fatalf("токен после revoke_api_tokens=false: %d", w.Code)
	}
	admin = e.mustLogin(t, "admin")
	if w := e.call(admin, "DELETE", "/api/v1/users/"+tAdminID+"/sessions", "", true); w.Code != http.StatusOK {
		t.Fatalf("завершение сессий: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(bearer, "GET", "/api/v1/users", "", false), http.StatusUnauthorized, CodeUnauthorized)
}

// callAuthz — запрос с сессией s и заголовком Authorization как есть.
func (e *authEnv) callAuthz(s session, method, target, authz string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	r.RemoteAddr = "192.0.2.1:1234"
	for _, c := range s.cookies {
		if c.Name == SessionCookie {
			r.AddCookie(c)
		}
	}
	r.Header.Set("Authorization", authz)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// Н10 ревью 2.r2: заголовок другой схемы (Basic от обратного прокси) не
// отключает сессию консоли и не пишет api_token.auth_failed.
func TestNonBearerAuthorizationUsesSession(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")
	if w := e.callAuthz(admin, "GET", "/api/v1/users", "Basic cHJveHk6cHJveHk="); w.Code != http.StatusOK {
		t.Fatalf("Basic с сессией: %d %s", w.Code, w.Body)
	}
	if _, n := lastAction(t, e, "api_token.auth_failed"); n != 0 {
		t.Fatalf("записей api_token.auth_failed: %d", n)
	}
	mustProblem(t, e.callAuthz(session{}, "GET", "/api/v1/users", "Basic cHJveHk6cHJveHk="), http.StatusUnauthorized, CodeUnauthorized)
}

// В9 ревью 2.r2: неверный формат Bearer в аудит не пишется; после порога
// неудач с адреса — 429 без записей, о блокировке — одна запись.
func TestBearerFailureLimiter(t *testing.T) {
	e := newAuthEnv(t)
	for range 3 {
		mustProblem(t, e.callAuthz(session{}, "GET", "/api/v1/users", "Bearer мусор"), http.StatusUnauthorized, CodeUnauthorized)
	}
	if _, n := lastAction(t, e, "api_token.auth_failed"); n != 0 {
		t.Fatalf("неверный формат записан в аудит: %d", n)
	}
	bad := "Bearer aisec_pat_00000000_" + strings.Repeat("A", 43)
	for range 7 {
		mustProblem(t, e.callAuthz(session{}, "GET", "/api/v1/users", bad), http.StatusUnauthorized, CodeUnauthorized)
	}
	// 3 + 7 неудач — порог; записаны 7 неверных токенов и одна запись о блокировке.
	rec, n := lastAction(t, e, "api_token.auth_failed")
	if n != 8 || rec.Details.(map[string]any)["reason"] != auth.ReasonRateLimited {
		t.Fatalf("записей %d, последняя %v", n, rec.Details)
	}
	for range 5 {
		w := e.callAuthz(session{}, "GET", "/api/v1/users", bad)
		mustProblem(t, w, http.StatusTooManyRequests, CodeRateLimited)
		if w.Header().Get("Retry-After") == "" {
			t.Fatal("нет Retry-After")
		}
	}
	if _, n2 := lastAction(t, e, "api_token.auth_failed"); n2 != n {
		t.Fatalf("записи во время блокировки: %d", n2-n)
	}
	// Сессия консоли с того же адреса работает: ограничение — только для токенов.
	if w := e.call(e.mustLogin(t, "admin"), "GET", "/api/v1/users", "", false); w.Code != http.StatusOK {
		t.Fatalf("сессия во время блокировки токенов: %d", w.Code)
	}
}
