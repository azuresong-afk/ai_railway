package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

// Вход через внешний IdP по HTTP (ИАФ.7; ADR-0025, задача 4.17):
// синтетический IdP на 127.0.0.1, внешних адресов нет.

const (
	tIdPClient  = "aisec-console"
	tIdPSecret  = "synthetic-client-credential-1"
	tConsoleURL = "https://console.example.test"
)

func newOIDCEnv(t *testing.T) (*authEnv, *cryptotest.IdP) {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	c, err := oidc.New(p)
	if err != nil {
		t.Fatal(err)
	}
	c.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	idp, err := cryptotest.NewIdP(tIdPClient, tIdPSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	mem := authtest.NewMemory()
	return newAuthEnvMem(t, mem, auth.WithOIDC(mem, c)), idp
}

func idpBody(t *testing.T, idp *cryptotest.IdP, password string) string {
	t.Helper()
	m := map[string]any{"enabled": true, "display_name": "Корпоративный вход", "issuer": idp.Issuer,
		"client_id": tIdPClient, "client_secret": tIdPSecret, "console_url": tConsoleURL, "ca_pem": string(idp.RootPEM),
		"group_roles": []map[string]string{{"group": "aisec-analysts", "role": "analyst"}}}
	if password != "" {
		m["password"] = password
	}
	return mustJSON(t, m)
}

// browse — переход браузера с cookie (без сессии консоли).
func (e *authEnv) browse(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	r.RemoteAddr = "192.0.2.1:1234"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func cookieOf(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// oidcStart — начало входа: cookie входа и адрес IdP.
func (e *authEnv) oidcStart(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	w := e.browse("/api/v1/auth/oidc/start")
	c := cookieOf(w, OIDCCookie)
	if w.Code != http.StatusSeeOther || c == nil {
		t.Fatalf("начало входа: %d %v", w.Code, w.Header())
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 600 || c.Path != "/" {
		t.Fatalf("cookie входа: %+v", c)
	}
	return c, w.Header().Get("Location")
}

func wantLocation(t *testing.T, w *httptest.ResponseRecorder, loc string) {
	t.Helper()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != loc {
		t.Fatalf("ожидался переход на %s: %d %s", loc, w.Code, w.Header().Get("Location"))
	}
}

func TestOIDCLoginOverHTTP(t *testing.T) {
	e, idp := newOIDCEnv(t)
	ctx := context.Background()
	if w := e.browse("/api/v1/auth/oidc"); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"enabled":false}` {
		t.Fatalf("кнопка до настройки: %d %s", w.Code, w.Body)
	}
	wantLocation(t, e.browse("/api/v1/auth/oidc/start"), "/?oidc=unavailable")

	// Настройка: только с правом auth_idp.manage и повторной проверкой.
	analyst := e.mustLogin(t, "analyst")
	if w := e.call(analyst, "PUT", "/api/v1/auth/idp", idpBody(t, idp, tPhrase), true); w.Code != http.StatusForbidden {
		t.Fatalf("аналитик: %d", w.Code)
	}
	if w := e.call(analyst, "GET", "/api/v1/auth/idp", "", false); w.Code != http.StatusForbidden {
		t.Fatalf("чтение аналитиком: %d", w.Code)
	}
	admin := e.mustLogin(t, "admin")
	mustProblem(t, e.call(admin, "PUT", "/api/v1/auth/idp", idpBody(t, idp, ""), true), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/auth/idp", idpBody(t, idp, tWrong), true), http.StatusForbidden, CodeReauthFailed)
	w := e.call(admin, "PUT", "/api/v1/auth/idp", idpBody(t, idp, tPhrase), true)
	if w.Code != 200 {
		t.Fatalf("сохранение: %d %s", w.Code, w.Body)
	}
	var view IdPView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Configured || view.RedirectURI != tConsoleURL+oidc.CallbackPath || strings.Contains(w.Body.String(), tIdPSecret) {
		t.Fatalf("ответ настроек: %s", w.Body)
	}
	auditor := e.mustLogin(t, "auditor")
	if w := e.call(auditor, "GET", "/api/v1/auth/idp", "", false); w.Code != 200 || strings.Contains(w.Body.String(), tIdPSecret) {
		t.Fatalf("чтение аудитором: %d %s", w.Code, w.Body)
	}
	if w := e.browse("/api/v1/auth/oidc"); !strings.Contains(w.Body.String(), `"display_name":"Корпоративный вход"`) {
		t.Fatalf("кнопка: %s", w.Body)
	}

	// Вход: начало → IdP → возврат с cookie → сессия консоли.
	c, loc := e.oidcStart(t)
	if !strings.HasPrefix(loc, idp.Issuer+"/auth?") {
		t.Fatalf("адрес IdP: %s", loc)
	}
	back, err := idp.Authorize(ctx, loc)
	if err != nil {
		t.Fatal(err)
	}
	callback := oidc.CallbackPath + "?" + url.Values{"state": {back.Get("state")}, "code": {back.Get("code")}}.Encode()
	w = e.browse(callback, c)
	wantLocation(t, w, "/")
	if gone := cookieOf(w, OIDCCookie); gone == nil || gone.MaxAge >= 0 {
		t.Fatal("cookie входа не удалена")
	}
	sess := session{}.renewed(w)
	if sess.csrf == "" {
		t.Fatal("нет cookie сессии")
	}
	w = e.call(sess, "GET", "/api/v1/me", "", false)
	var me MeResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &me) != nil || me.User.Login != "ivanov" || me.User.Role != "analyst" {
		t.Fatalf("сессия после входа: %d %s", w.Code, w.Body)
	}
	// Пароля у внешней записи нет.
	mustProblem(t, e.call(sess, "POST", "/api/v1/auth/password",
		mustJSON(t, map[string]string{"current_password": tPhrase, "new_password": tPhrase2}), true), http.StatusForbidden, CodeForbidden)

	// Повтор возврата, возврат без cookie и отказ IdP — на экран входа с кодом.
	wantLocation(t, e.browse(callback, c), "/?oidc=failed")
	_, loc2 := e.oidcStart(t)
	back2, err := idp.Authorize(ctx, loc2)
	if err != nil {
		t.Fatal(err)
	}
	wantLocation(t, e.browse(oidc.CallbackPath+"?"+url.Values{"state": {back2.Get("state")}, "code": {back2.Get("code")}}.Encode()),
		"/?oidc=failed")
	idp.Deny("access_denied")
	c3, loc3 := e.oidcStart(t)
	back3, err := idp.Authorize(ctx, loc3)
	if err != nil {
		t.Fatal(err)
	}
	wantLocation(t, e.browse(oidc.CallbackPath+"?"+back3.Encode(), c3), "/?oidc=denied")
	if strings.Contains(e.log.String(), "<script>") {
		t.Fatal("текст IdP в техническом журнале")
	}

	// Удаление настроек завершает сессии внешних пользователей.
	mustProblem(t, e.call(sess, "DELETE", "/api/v1/auth/idp", mustJSON(t, map[string]string{"password": tPhrase}), true),
		http.StatusForbidden, CodeForbidden)
	if w := e.call(admin, "DELETE", "/api/v1/auth/idp", mustJSON(t, map[string]string{"password": tPhrase}), true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	if w := e.call(sess, "GET", "/api/v1/me", "", false); w.Code != http.StatusUnauthorized {
		t.Fatalf("сессия внешней записи после удаления: %d", w.Code)
	}
	wantLocation(t, e.browse("/api/v1/auth/oidc/start"), "/?oidc=unavailable")
	if w := e.call(admin, "GET", "/api/v1/auth/idp", "", false); w.Code != 200 || !strings.Contains(w.Body.String(), `"configured":false`) {
		t.Fatalf("после удаления: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "DELETE", "/api/v1/auth/idp", mustJSON(t, map[string]string{"password": tPhrase}), true),
		http.StatusNotFound, CodeNotFound)
}

// Без клиента IdP на сервере: кнопки нет, начало входа — на экран входа,
// настройки — 503.
func TestOIDCUnavailableOverHTTP(t *testing.T) {
	e := newAuthEnv(t)
	if w := e.browse("/api/v1/auth/oidc"); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"enabled":false}` {
		t.Fatalf("кнопка: %d %s", w.Code, w.Body)
	}
	wantLocation(t, e.browse("/api/v1/auth/oidc/start"), "/?oidc=unavailable")
	wantLocation(t, e.browse(oidc.CallbackPath+"?state=x&code=y"), "/?oidc=unavailable")
	admin := e.mustLogin(t, "admin")
	mustProblem(t, e.call(admin, "GET", "/api/v1/auth/idp", "", false), http.StatusServiceUnavailable, CodeUnavailable)
}
