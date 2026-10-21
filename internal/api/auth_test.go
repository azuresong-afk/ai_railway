package api

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

// Синтетические учётные записи и пароль.
const (
	tAdminID   = "01900000-0000-7000-8000-00000000a001"
	tAnalystID = "01900000-0000-7000-8000-00000000b001"
	tAuditorID = "01900000-0000-7000-8000-00000000c001"
	tPhrase    = "Синтетический-Пароль-42"
	tWrong     = "Неверный-Пароль-0"
	tPhrase2   = "Новый-Пароль-Для-Теста-5"
)

type authEnv struct {
	h     http.Handler
	mem   *authtest.Memory
	log   *bytes.Buffer
	clock *testClock
	// secrets — секреты TOTP по логину (приложение-аутентификатор теста).
	secrets map[string][]byte
}

// testClock — часы сервиса входа: каждый код TOTP берётся на следующем
// шаге, чтобы повторные входы не упирались в защиту от повтора.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) next() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(30 * time.Second)
	return c.t
}

func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	e := &authEnv{mem: authtest.NewMemory(), log: &bytes.Buffer{}, clock: &testClock{t: time.Now()}, secrets: map[string][]byte{}}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, u := range []struct {
		id, login string
		role      auth.Role
	}{{tAdminID, "admin", auth.RoleSecurityAdmin}, {tAnalystID, "analyst", auth.RoleAnalyst}, {tAuditorID, "auditor", auth.RoleAuditor}} {
		e.mem.AddUser(auth.User{ID: u.id, OrgID: audit.DefaultOrgID, Login: u.login, DisplayName: u.login, Role: u.role,
			Status: auth.StatusActive, PasswordHash: authtest.HashOf(tPhrase), PasswordChangedAt: now, CreatedAt: now, CreatedBy: "test"})
	}
	logger := slog.New(slog.NewTextHandler(e.log, nil))
	h, _, err := New(Options{Hasher: testHasher(t), Logger: logger, Auth: testAuth(t, e.mem, auth.WithClock(e.clock.now)),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 10000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e
}

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// session — cookie и CSRF-токен после входа.
type session struct {
	cookies []*http.Cookie
	csrf    string
	// bearer — токен API для заголовка Authorization (задача 2.10).
	bearer string
}

func (e *authEnv) login(t testing.TB, login, password string) (*httptest.ResponseRecorder, session) {
	t.Helper()
	w := do(e.h, "POST", "/api/v1/auth/login", mustJSON(t, loginRequest{Login: login, Password: password}), "Content-Type", "application/json")
	var s session
	for _, c := range w.Result().Cookies() {
		s.cookies = append(s.cookies, c)
		if c.Name == CSRFCookie {
			s.csrf = c.Value
		}
	}
	return w, s
}

// mustLogin — полный вход: пароль и второй фактор (подключение при первом
// входе роли, где он обязателен).
func (e *authEnv) mustLogin(t testing.TB, login string) session {
	t.Helper()
	w, s := e.login(t, login, tPhrase)
	if w.Code != 200 {
		t.Fatalf("вход %s: %d %s", login, w.Code, w.Body)
	}
	var me MeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	switch me.SessionState {
	case string(auth.SessionMFASetup):
		e.enroll(t, s, login)
		w = e.call(s, "POST", "/api/v1/auth/mfa/setup/confirm", mustJSON(t, mfaCodeRequest{Code: e.code(t, login)}), true)
	case string(auth.SessionMFAPending):
		w = e.call(s, "POST", "/api/v1/auth/mfa/verify", mustJSON(t, mfaVerifyRequest{Code: e.code(t, login)}), true)
	}
	if w.Code != 200 {
		t.Fatalf("второй фактор %s: %d %s", login, w.Code, w.Body)
	}
	return s.renewed(w)
}

// renewed — сессия с cookie из ответа, если сервер их сменил (второй
// фактор пройден: сессия заменена полной).
func (s session) renewed(w *httptest.ResponseRecorder) session {
	var fresh session
	for _, c := range w.Result().Cookies() {
		fresh.cookies = append(fresh.cookies, c)
		if c.Name == CSRFCookie {
			fresh.csrf = c.Value
		}
	}
	if fresh.csrf == "" {
		return s
	}
	return fresh
}

// enroll выдаёт секрет TOTP в сессии и запоминает его.
func (e *authEnv) enroll(t testing.TB, s session, login string) MFASetup {
	t.Helper()
	w := e.call(s, "POST", "/api/v1/auth/mfa/setup", mustJSON(t, mfaSetupRequest{CurrentPassword: tPhrase}), true)
	var en MFASetup
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &en) != nil {
		t.Fatalf("выдача секрета: %d %s", w.Code, w.Body)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en.Secret)
	if err != nil {
		t.Fatal(err)
	}
	e.secrets[login] = secret
	return en
}

// code — код TOTP пользователя на следующем шаге часов сервиса.
func (e *authEnv) code(t testing.TB, login string) string {
	t.Helper()
	c, err := cryptotest.TOTPCode(e.secrets[login], e.clock.next())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// call выполняет запрос в сессии; csrf = false — без заголовка X-CSRF-Token.
func (e *authEnv) call(s session, method, target, body string, csrf bool) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:1234"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, c := range s.cookies {
		if c.Name == SessionCookie {
			r.AddCookie(c)
		}
	}
	if csrf {
		r.Header.Set(CSRFHeader, s.csrf)
	}
	if s.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+s.bearer)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func TestLoginSetsSecureCookies(t *testing.T) {
	e := newAuthEnv(t)
	w, s := e.login(t, "analyst", tPhrase)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	cookies := map[string]*http.Cookie{}
	for _, c := range s.cookies {
		cookies[c.Name] = c
	}
	sc, cc := cookies[SessionCookie], cookies[CSRFCookie]
	// Префикс __Host-: браузер примет cookie только с Secure, Path=/ и без Domain.
	if sc == nil || !strings.HasPrefix(sc.Name, "__Host-") || !strings.HasPrefix(cc.Name, "__Host-") || sc.Domain != "" || cc.Domain != "" ||
		cc.Path != "/" {
		t.Fatalf("префикс cookie: %+v %+v", sc, cc)
	}
	if !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteStrictMode || sc.Path != "/" || sc.MaxAge != 0 {
		t.Fatalf("cookie сессии: %+v", sc)
	}
	if cc == nil || cc.HttpOnly || !cc.Secure || cc.SameSite != http.SameSiteStrictMode || len(cc.Value) != auth.TokenLen {
		t.Fatalf("cookie CSRF: %+v", cc)
	}
	var me MeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil || me.User.Login != "analyst" || me.SessionState != "active" ||
		me.MFA.Enabled || me.MFA.Required {
		t.Fatalf("ответ: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), sc.Value) || strings.Contains(w.Body.String(), "$fake$") {
		t.Fatal("токен или хеш пароля в теле ответа")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("ответ входа кэшируется")
	}
}

// Ответы на неизвестный логин, неверный пароль и заблокированную запись
// не различаются (ADR-0006, ИАФ.4).
func TestLoginFailuresIndistinguishable(t *testing.T) {
	e := newAuthEnv(t)
	w1, _ := e.login(t, "nobody", tPhrase)
	w2, _ := e.login(t, "analyst", tWrong)
	if w1.Code != 401 || w2.Code != 401 || w1.Body.String() != w2.Body.String() {
		t.Fatalf("%d %s / %d %s", w1.Code, w1.Body, w2.Code, w2.Body)
	}
	if len(w1.Result().Cookies()) != 0 {
		t.Fatal("cookie при отказе")
	}
	mustProblem(t, w1, 401, CodeUnauthorized)
}

// DM-39 через API: после N неудач верный пароль получает тот же 401, в
// аудите — auth.locked.
func TestDM39_LockoutViaAPI(t *testing.T) {
	e := newAuthEnv(t)
	for range auth.DefaultPolicy().LockoutThreshold {
		e.login(t, "analyst", tWrong)
	}
	w, _ := e.login(t, "analyst", tPhrase)
	wrong, _ := e.login(t, "analyst", tWrong)
	if w.Code != 401 || w.Body.String() != wrong.Body.String() {
		t.Fatalf("вход во время блокировки: %d %s", w.Code, w.Body)
	}
	if !slices.Contains(e.mem.Actions(), "auth.locked") {
		t.Fatalf("аудит: %v", e.mem.Actions())
	}
	// Администратор снимает блокировку активацией.
	admin := e.mustLogin(t, "admin")
	if w := e.call(admin, "POST", "/api/v1/users/"+tAnalystID+"/activate", "", true); w.Code != 200 {
		t.Fatalf("активация: %d %s", w.Code, w.Body)
	}
	e.mustLogin(t, "analyst")
}

func TestLoginValidation(t *testing.T) {
	e := newAuthEnv(t)
	mustProblem(t, do(e.h, "POST", "/api/v1/auth/login", `{"login":"admin","password":"x"}`), 415, CodeUnsupportedMedia)
	mustProblem(t, do(e.h, "POST", "/api/v1/auth/login", `{"login":"admin"}`, "Content-Type", "application/json"), 400, CodeInvalidRequest)
	mustProblem(t, do(e.h, "POST", "/api/v1/auth/login", `{"login":"admin","password":"x","extra":1}`, "Content-Type", "application/json"), 400, CodeInvalidRequest)
	long := `{"login":"admin","password":"` + strings.Repeat("a", 9000) + `"}`
	mustProblem(t, do(e.h, "POST", "/api/v1/auth/login", long, "Content-Type", "application/json"), 413, CodePayloadTooLarge)
	if n := len(e.mem.Records()); n != 0 {
		t.Fatalf("неверный запрос записан как попытка входа: %v", e.mem.Actions())
	}
}

// Р6: изменяющий запрос без CSRF-токена своей сессии — 403.
func TestCSRFRequired(t *testing.T) {
	e := newAuthEnv(t)
	a := e.mustLogin(t, "admin")
	b := e.mustLogin(t, "admin")
	mustProblem(t, e.call(a, "POST", "/api/v1/auth/logout", "", false), 403, CodeForbidden)
	foreign := a
	foreign.csrf = b.csrf
	mustProblem(t, e.call(foreign, "POST", "/api/v1/auth/logout", "", true), 403, CodeForbidden)
	// GET не требует CSRF.
	if w := e.call(a, "GET", "/api/v1/me", "", false); w.Code != 200 {
		t.Fatalf("GET /me: %d", w.Code)
	}
	if w := e.call(a, "POST", "/api/v1/auth/logout", "", true); w.Code != 204 {
		t.Fatalf("выход: %d %s", w.Code, w.Body)
	}
	cleared := false
	for _, c := range httptestCookies(e.call(b, "POST", "/api/v1/auth/logout", "", true)) {
		cleared = cleared || (c.Name == SessionCookie && c.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("cookie сессии не удалена при выходе")
	}
	mustProblem(t, e.call(a, "GET", "/api/v1/me", "", false), 401, CodeUnauthorized)
}

func httptestCookies(w *httptest.ResponseRecorder) []*http.Cookie { return w.Result().Cookies() }

// Права ролей (статическая таблица до задачи 2.9) и отказ без сессии.
func TestRolePermissions(t *testing.T) {
	e := newAuthEnv(t)
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	mustProblem(t, e.call(analyst, "GET", "/api/v1/users", "", false), 403, CodeForbidden)
	mustProblem(t, e.call(analyst, "GET", "/api/v1/auth/policy", "", false), 403, CodeForbidden)
	if w := e.call(auditor, "GET", "/api/v1/users", "", false); w.Code != 200 {
		t.Fatalf("аудитор читает пользователей: %d", w.Code)
	}
	mustProblem(t, e.call(auditor, "POST", "/api/v1/users", `{"login":"x","display_name":"x","role":"analyst"}`, true), 403, CodeForbidden)
	mustProblem(t, e.call(auditor, "DELETE", "/api/v1/users/"+tAnalystID+"/sessions", "", true), 403, CodeForbidden)
	mustProblem(t, e.call(session{}, "GET", "/api/v1/me", "", false), 401, CodeUnauthorized)
	bogus := session{cookies: []*http.Cookie{{Name: SessionCookie, Value: strings.Repeat("A", auth.TokenLen),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}}}
	mustProblem(t, e.call(bogus, "GET", "/api/v1/me", "", false), 401, CodeUnauthorized)
}

// ИАФ.3 через API: создание с временным паролем, вход в режиме смены
// пароля, смена, полный доступ.
func TestUserLifecycleViaAPI(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")
	w := e.call(admin, "POST", "/api/v1/users", `{"login":"Petrova","display_name":"Петрова А.","role":"auditor"}`, true)
	if w.Code != 201 {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	var created CreatedUser
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.TemporaryPassword == "" || !created.User.MustChangePassword {
		t.Fatalf("ответ: %s", w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/api/v1/users/"+created.User.ID {
		t.Fatalf("Location: %q", loc)
	}
	mustProblem(t, e.call(admin, "POST", "/api/v1/users", `{"login":"petrova","display_name":"Дубль","role":"auditor"}`, true), 409, CodeConflict)
	mustProblem(t, e.call(admin, "POST", "/api/v1/users", `{"login":"-x","display_name":"X","role":"auditor"}`, true), 400, CodeInvalidRequest)

	lw, user := e.login(t, "petrova", created.TemporaryPassword)
	if lw.Code != 200 || !strings.Contains(lw.Body.String(), `"session_state":"password_change"`) {
		t.Fatalf("вход с временным паролем: %d %s", lw.Code, lw.Body)
	}
	mustProblem(t, e.call(user, "GET", "/api/v1/users", "", false), 403, CodeForbidden)
	short := "короткий"
	w = e.call(user, "POST", "/api/v1/auth/password", mustJSON(t, passwordRequest{created.TemporaryPassword, short}), true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"new_password"`) {
		t.Fatalf("нет поля new_password: %s", w.Body)
	}
	mustProblem(t, e.call(user, "POST", "/api/v1/auth/password", mustJSON(t, passwordRequest{tWrong, tPhrase}), true), 400, CodeInvalidRequest)
	if w := e.call(user, "POST", "/api/v1/auth/password", mustJSON(t, passwordRequest{created.TemporaryPassword, tPhrase}), true); w.Code != 204 {
		t.Fatalf("смена пароля: %d %s", w.Code, w.Body)
	}
	if w := e.call(user, "GET", "/api/v1/users", "", false); w.Code != 200 {
		t.Fatalf("после смены пароля: %d", w.Code)
	}

	id := created.User.ID
	if w := e.call(admin, "GET", "/api/v1/users/"+id+"/sessions", "", false); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"active"`) {
		t.Fatalf("сессии: %d %s", w.Code, w.Body)
	}
	w = e.call(admin, "POST", "/api/v1/users/"+id+"/password-reset", "", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "temporary_password") {
		t.Fatalf("сброс: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(user, "GET", "/api/v1/me", "", false), 401, CodeUnauthorized)
	if w := e.call(admin, "POST", "/api/v1/users/"+id+"/deactivate", "", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"deactivated"`) {
		t.Fatalf("деактивация: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "POST", "/api/v1/users/"+tAdminID+"/deactivate", "", true), 422, CodeUnprocessable)
	mustProblem(t, e.call(admin, "GET", "/api/v1/users/not-a-uuid", "", false), 404, CodeNotFound)
	mustProblem(t, e.call(admin, "GET", "/api/v1/users/01900000-0000-7000-8000-0000000000ee", "", false), 404, CodeNotFound)
	if w := e.call(admin, "DELETE", "/api/v1/users/"+tAnalystID+"/sessions", "", true); w.Code != 200 {
		t.Fatalf("завершение сессий: %d %s", w.Code, w.Body)
	}
	for _, a := range []string{"user.create", "auth.password_changed", "user.password_reset", "user.deactivate", "auth.sessions_revoked"} {
		if !slices.Contains(e.mem.Actions(), a) {
			t.Errorf("нет записи %s: %v", a, e.mem.Actions())
		}
	}
}

func TestUsersPagination(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")
	seen := map[string]bool{}
	next := ""
	for range 5 {
		target := "/api/v1/users?limit=2"
		if next != "" {
			target += "&cursor=" + next
		}
		w := e.call(admin, "GET", target, "", false)
		var page PageResponse[UserView]
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		for _, u := range page.Items {
			if seen[u.ID] {
				t.Fatalf("повтор %s", u.ID)
			}
			seen[u.ID] = true
		}
		if next = page.NextCursor; next == "" {
			break
		}
	}
	if len(seen) != 3 {
		t.Fatalf("пользователей %d", len(seen))
	}
	mustProblem(t, e.call(admin, "GET", "/api/v1/users?limit=0", "", false), 400, CodeInvalidRequest)
}

func TestPolicyViaAPI(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")
	w := e.call(admin, "GET", "/api/v1/auth/policy", "", false)
	var p auth.Policy
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p != auth.DefaultPolicy() {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", "/api/v1/auth/policy", `{"password_min_length":12}`, true), 400, CodeInvalidRequest)
	p.PasswordMinLength = 4
	mustProblem(t, e.call(admin, "PUT", "/api/v1/auth/policy", mustJSON(t, p), true), 400, CodeInvalidRequest)
	p.PasswordMinLength = 14
	if w := e.call(admin, "PUT", "/api/v1/auth/policy", mustJSON(t, p), true); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// Сбой хранилища — 500 без подробностей; в технический журнал не попадают
// пароль и токены.
func TestAuthErrorsDoNotLeakSecrets(t *testing.T) {
	e := newAuthEnv(t)
	s := e.mustLogin(t, "admin")
	e.mem.Fail = errors.New("БД недоступна")
	w, _ := e.login(t, "admin", tPhrase)
	mustProblem(t, w, 500, CodeInternal)
	e.call(s, "GET", "/api/v1/me", "", false)
	e.mem.Fail = nil
	logs := e.log.String()
	for _, secret := range []string{tPhrase, s.csrf, s.cookies[0].Value, s.cookies[1].Value} {
		if strings.Contains(logs, secret) || strings.Contains(w.Body.String(), secret) {
			t.Fatal("секрет в журнале или ответе")
		}
	}
	if !strings.Contains(logs, "БД недоступна") {
		t.Fatalf("причина сбоя не записана: %s", logs)
	}
}

// ЗИ.4 через API: состояние настройки, отказ по чужому токену (403 без
// причины), создание первого администратора (201), повтор — 403.
func TestSetupViaAPI(t *testing.T) {
	mem := authtest.NewMemory()
	raw := bytes.Repeat([]byte{0x2a}, 32)
	token := "aisec_setup_" + base64.RawURLEncoding.EncodeToString(raw)
	h := testHasher(t)
	mem.AddSetupToken(audit.DefaultOrgID, h.Name(), h.Sum([]byte(token)), time.Now().Add(time.Hour))
	hd, _, err := New(Options{Hasher: h, Auth: testAuth(t, mem),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 10000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	status := func() bool {
		w := do(hd, "GET", "/api/v1/auth/setup", "")
		var st SetupStatus
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &st) != nil {
			t.Fatalf("состояние: %d %s", w.Code, w.Body)
		}
		return st.SetupRequired
	}
	if !status() {
		t.Fatal("настройка не требуется до создания администратора")
	}
	post := func(tok, password string) *httptest.ResponseRecorder {
		return do(hd, "POST", "/api/v1/auth/setup", mustJSON(t, setupRequest{Token: tok, Login: "admin", DisplayName: "Администратор",
			Password: password}), "Content-Type", "application/json")
	}
	wrong := "aisec_setup_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	if w := post(wrong, tPhrase); w.Code != 403 || strings.Contains(w.Body.String(), wrong) {
		t.Fatalf("чужой токен: %d %s", w.Code, w.Body)
	}
	if w := post(token, "короткий"); w.Code != 400 || !strings.Contains(w.Body.String(), `"password"`) {
		t.Fatalf("слабый пароль: %d %s", w.Code, w.Body)
	}
	if w := post("", tPhrase); w.Code != 400 {
		t.Fatalf("пустой токен: %d %s", w.Code, w.Body)
	}
	w := post(token, tPhrase)
	var u UserView
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &u) != nil || u.Role != string(auth.RoleSecurityAdmin) ||
		strings.Contains(w.Body.String(), "$fake$") {
		t.Fatalf("настройка: %d %s", w.Code, w.Body)
	}
	if status() {
		t.Fatal("настройка требуется после создания администратора")
	}
	if w := post(token, tPhrase); w.Code != 403 {
		t.Fatalf("повтор: %d %s", w.Code, w.Body)
	}
}

// Смена пароля, пока запись заблокирована, — 409 (ИАФ.4).
func TestChangePasswordLockedViaAPI(t *testing.T) {
	e := newAuthEnv(t)
	s := e.mustLogin(t, "analyst")
	for range auth.DefaultPolicy().LockoutThreshold {
		if w, _ := e.login(t, "analyst", tWrong); w.Code != 401 {
			t.Fatalf("неудача: %d", w.Code)
		}
	}
	w := e.call(s, "POST", "/api/v1/auth/password", mustJSON(t, passwordRequest{CurrentPassword: tPhrase, NewPassword: tPhrase2}), true)
	if w.Code != 409 {
		t.Fatalf("смена при блокировке: %d %s", w.Code, w.Body)
	}
}

// Сессию завершили, пока шёл запрос: 401, а не 500 с записью в журнал.
func TestAuthProblemUnauthenticated(t *testing.T) {
	var buf bytes.Buffer
	p := authProblem(slog.New(slog.NewTextHandler(&buf, nil)), fmt.Errorf("смена пароля: %w", auth.ErrUnauthenticated))
	if p.Status != http.StatusUnauthorized || buf.Len() != 0 {
		t.Fatalf("%d, журнал %q", p.Status, buf.String())
	}
}
