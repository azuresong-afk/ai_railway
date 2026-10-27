package api

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap/ldaptest"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Вход через каталог LDAP по HTTP (ИАФ.7; ADR-0025, задача 4.16):
// синтетический каталог LDAPS на 127.0.0.1, внешних адресов нет.

const (
	tDirSvcDN    = "uid=aisec-svc,cn=sysaccounts,dc=example,dc=test"
	tDirSvcPass  = "synthetic-service-credential-1"
	tDirUsersDN  = "cn=users,dc=example,dc=test"
	tDirAnalysts = "cn=aisec-analysts,cn=groups,dc=example,dc=test"
	tDirPass     = "synthetic-dir-pass"
)

func newLDAPEnv(t *testing.T) (*authEnv, *ldaptest.Directory) {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ldap.New(p)
	if err != nil {
		t.Fatal(err)
	}
	c.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	dir, err := ldaptest.New(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dir.Close)
	dir.Add("dc=example,dc=test", nil, "")
	dir.Add(tDirUsersDN, nil, "")
	dir.Add(tDirSvcDN, nil, tDirSvcPass)
	dir.Add("uid=petrova,"+tDirUsersDN, map[string][]string{"objectClass": {"person"}, "uid": {"petrova"},
		"entryUUID": {"3e9a1f2c-5b6d-4e7f-8a9b-0c1d2e3f4a5b"}, "displayName": {"Петрова Анна"},
		"memberOf": {tDirAnalysts}}, tDirPass)
	mem := authtest.NewMemory()
	return newAuthEnvMem(t, mem, auth.WithLDAP(mem, c)), dir
}

func ldapBody(t *testing.T, dir *ldaptest.Directory, password string) string {
	t.Helper()
	m := map[string]any{"enabled": true, "url": dir.URL, "ca_pem": string(dir.RootPEM), "bind_dn": tDirSvcDN,
		"bind_password": tDirSvcPass, "user_base_dn": tDirUsersDN, "user_filter": "(&(objectClass=person)(uid={login}))",
		"id_attribute": "entryUUID", "group_mode": "member_of",
		"group_roles": []map[string]string{{"group": tDirAnalysts, "role": "analyst"}}}
	if password != "" {
		m["password"] = password
	}
	return mustJSON(t, m)
}

func TestLDAPLoginOverHTTP(t *testing.T) {
	e, dir := newLDAPEnv(t)
	if w, _ := e.login(t, "petrova", tDirPass); w.Code != http.StatusUnauthorized {
		t.Fatalf("вход до настройки: %d", w.Code)
	}

	// Настройка: только с правом auth_idp.manage и повторной проверкой.
	analyst := e.mustLogin(t, "analyst")
	if w := e.call(analyst, "PUT", "/api/v1/auth/ldap", ldapBody(t, dir, tPhrase), true); w.Code != http.StatusForbidden {
		t.Fatalf("аналитик: %d", w.Code)
	}
	if w := e.call(analyst, "GET", "/api/v1/auth/ldap", "", false); w.Code != http.StatusForbidden {
		t.Fatalf("чтение аналитиком: %d", w.Code)
	}
	if w := e.call(analyst, "DELETE", "/api/v1/auth/ldap", mustJSON(t, map[string]string{"password": tPhrase}), true); w.Code != http.StatusForbidden {
		t.Fatalf("удаление аналитиком: %d", w.Code)
	}
	admin := e.mustLogin(t, "admin")
	if w := e.call(admin, "GET", "/api/v1/auth/ldap", "", false); w.Code != 200 || !strings.Contains(w.Body.String(), `"configured":false`) {
		t.Fatalf("до настройки: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", "/api/v1/auth/ldap", ldapBody(t, dir, ""), true), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/auth/ldap", ldapBody(t, dir, tWrong), true), http.StatusForbidden, CodeReauthFailed)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/auth/ldap", `{"password":"`+tPhrase+`"}`, true), http.StatusBadRequest, CodeInvalidRequest)
	w := e.call(admin, "PUT", "/api/v1/auth/ldap", ldapBody(t, dir, tPhrase), true)
	if w.Code != 200 {
		t.Fatalf("сохранение: %d %s", w.Code, w.Body)
	}
	var view LDAPView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Configured || !view.Enabled || view.DisplayAttribute != "displayName" || strings.Contains(w.Body.String(), tDirSvcPass) {
		t.Fatalf("ответ настроек: %s", w.Body)
	}
	auditor := e.mustLogin(t, "auditor")
	if w := e.call(auditor, "GET", "/api/v1/auth/ldap", "", false); w.Code != 200 || strings.Contains(w.Body.String(), tDirSvcPass) {
		t.Fatalf("чтение аудитором: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(auditor, "PUT", "/api/v1/auth/ldap", ldapBody(t, dir, tPhrase), true), http.StatusForbidden, CodeForbidden)

	// Вход пользователя каталога обычной формой входа.
	if w, _ := e.login(t, "petrova", "wrong-dir-pass"); w.Code != http.StatusUnauthorized {
		t.Fatalf("неверный пароль каталога: %d", w.Code)
	}
	w, sess := e.login(t, "petrova", tDirPass)
	var me MeResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &me) != nil || me.User.Role != "analyst" || me.User.DisplayName != "Петрова Анна" {
		t.Fatalf("вход через каталог: %d %s", w.Code, w.Body)
	}
	// Настройки каталога меняет только локальная запись — даже при праве.
	mustProblem(t, e.call(sess, "GET", "/api/v1/auth/ldap", "", false), http.StatusForbidden, CodeForbidden)
	if strings.Contains(e.log.String(), tDirPass) || strings.Contains(e.log.String(), tDirSvcPass) {
		t.Fatal("пароль в техническом журнале")
	}

	// Удаление настроек завершает сессии пользователей каталога.
	if w := e.call(admin, "DELETE", "/api/v1/auth/ldap", mustJSON(t, map[string]string{"password": tPhrase}), true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	if w := e.call(sess, "GET", "/api/v1/me", "", false); w.Code != http.StatusUnauthorized {
		t.Fatalf("сессия пользователя каталога после удаления: %d", w.Code)
	}
	if w, _ := e.login(t, "petrova", tDirPass); w.Code != http.StatusUnauthorized {
		t.Fatalf("вход после удаления: %d", w.Code)
	}
	mustProblem(t, e.call(admin, "DELETE", "/api/v1/auth/ldap", mustJSON(t, map[string]string{"password": tPhrase}), true),
		http.StatusNotFound, CodeNotFound)
}

// Без клиента каталога на сервере настройки — 503.
func TestLDAPUnavailableOverHTTP(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")
	mustProblem(t, e.call(admin, "GET", "/api/v1/auth/ldap", "", false), http.StatusServiceUnavailable, CodeUnavailable)
	mustProblem(t, e.call(admin, "DELETE", "/api/v1/auth/ldap", mustJSON(t, map[string]string{"password": tPhrase}), true),
		http.StatusServiceUnavailable, CodeUnavailable)
}
