package api

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// ИАФ.5 через API: первый вход администратора — подключение второго
// фактора, дальше вход в два шага; до второго фактора права роли не действуют.
func TestMFAViaAPI(t *testing.T) {
	e := newAuthEnv(t)
	w, s := e.login(t, "admin", tPhrase)
	var me MeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil || me.SessionState != string(auth.SessionMFASetup) ||
		!me.MFA.Required || me.MFA.Enabled {
		t.Fatalf("первый вход: %s", w.Body)
	}
	// Отказы до второго фактора: права роли и смена пароля недоступны.
	mustProblem(t, e.call(s, "GET", "/api/v1/users", "", false), 403, CodeForbidden)
	mustProblem(t, e.call(s, "POST", "/api/v1/auth/password", `{"current_password":"a","new_password":"b"}`, true), 403, CodeForbidden)
	mustProblem(t, e.call(s, "POST", "/api/v1/auth/mfa/verify", `{"code":"123456"}`, true), 409, CodeConflict)
	if w := e.call(s, "GET", "/api/v1/me", "", false); w.Code != 200 {
		t.Fatalf("GET /me в mfa_setup: %d", w.Code)
	}
	// Изменяющие запросы второго фактора — только с CSRF-токеном своей сессии.
	mustProblem(t, e.call(s, "POST", "/api/v1/auth/mfa/setup", "{}", false), 403, CodeForbidden)
	en := e.enroll(t, s, "admin")
	if !strings.HasPrefix(en.URI, "otpauth://totp/") || len(en.QR) < 21 {
		t.Fatalf("ответ выдачи секрета: %+v", en)
	}
	mustProblem(t, e.call(s, "POST", "/api/v1/auth/mfa/setup/confirm", `{"code":"000000"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(s, "POST", "/api/v1/auth/mfa/setup/confirm", `{"code":""}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(s, "POST", "/api/v1/auth/mfa/setup/confirm", `{"code":"1","x":1}`, true), 400, CodeInvalidRequest)
	w = e.call(s, "POST", "/api/v1/auth/mfa/setup/confirm", mustJSON(t, mfaCodeRequest{Code: e.code(t, "admin")}), true)
	var rc RecoveryCodes
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &rc) != nil || len(rc.RecoveryCodes) != auth.RecoveryCodeCount ||
		rc.SessionState != string(auth.SessionActive) {
		t.Fatalf("подтверждение: %d %s", w.Code, w.Body)
	}
	// Сессия заменена полной с новыми cookie; прежние больше не действуют.
	full := s.renewed(w)
	if full.csrf == s.csrf {
		t.Fatal("cookie сессии не сменились после второго фактора")
	}
	mustProblem(t, e.call(s, "GET", "/api/v1/me", "", false), 401, CodeUnauthorized)
	if w := e.call(full, "GET", "/api/v1/users", "", false); w.Code != 200 {
		t.Fatalf("после подключения: %d", w.Code)
	}
	mustProblem(t, e.call(full, "POST", "/api/v1/auth/mfa/setup", mustJSON(t, mfaSetupRequest{CurrentPassword: tPhrase}), true), 409, CodeConflict)

	// Второй вход — код обязателен.
	w, s2 := e.login(t, "admin", tPhrase)
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil || me.SessionState != string(auth.SessionMFAPending) || !me.MFA.Enabled {
		t.Fatalf("второй вход: %s", w.Body)
	}
	mustProblem(t, e.call(s2, "GET", "/api/v1/users", "", false), 403, CodeForbidden)
	mustProblem(t, e.call(s2, "POST", "/api/v1/auth/mfa/recovery-codes", `{"code":"123456"}`, true), 409, CodeConflict)
	// Ровно одно из полей.
	mustProblem(t, e.call(s2, "POST", "/api/v1/auth/mfa/verify", `{}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(s2, "POST", "/api/v1/auth/mfa/verify",
		mustJSON(t, mfaVerifyRequest{Code: "123456", RecoveryCode: rc.RecoveryCodes[0]}), true), 400, CodeInvalidRequest)
	w = e.call(s2, "POST", "/api/v1/auth/mfa/verify", mustJSON(t, mfaVerifyRequest{RecoveryCode: rc.RecoveryCodes[0]}), true)
	if err := json.Unmarshal(w.Body.Bytes(), &me); w.Code != 200 || err != nil || me.SessionState != string(auth.SessionActive) {
		t.Fatalf("вход кодом восстановления: %d %s", w.Code, w.Body)
	}
	s2 = s2.renewed(w)
	// Новые коды восстановления — по коду TOTP.
	w = e.call(s2, "POST", "/api/v1/auth/mfa/recovery-codes", mustJSON(t, mfaCodeRequest{Code: e.code(t, "admin")}), true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &rc) != nil || len(rc.RecoveryCodes) != auth.RecoveryCodeCount {
		t.Fatalf("перевыпуск кодов: %d %s", w.Code, w.Body)
	}
	for _, a := range []string{"auth.mfa_enabled", "auth.mfa_failed", "auth.recovery_code_used", "auth.recovery_codes_regenerated"} {
		if !slices.Contains(e.mem.Actions(), a) {
			t.Errorf("нет записи %s: %v", a, e.mem.Actions())
		}
	}
}

// Без сессии эндпоинты второго фактора — 401.
func TestMFARequiresSession(t *testing.T) {
	e := newAuthEnv(t)
	for _, path := range []string{"/api/v1/auth/mfa/setup", "/api/v1/auth/mfa/setup/confirm", "/api/v1/auth/mfa/verify",
		"/api/v1/auth/mfa/recovery-codes", "/api/v1/users/" + tAnalystID + "/mfa/reset"} {
		mustProblem(t, e.call(session{}, "POST", path, `{"code":"123456"}`, false), 401, CodeUnauthorized)
	}
}

// Сброс второго фактора — право users.manage; отказ остальным ролям.
func TestMFAResetViaAPI(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	// Аналитик подключает фактор сам.
	// Из полной сессии — только с текущим паролем.
	mustProblem(t, e.call(analyst, "POST", "/api/v1/auth/mfa/setup", "{}", true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(analyst, "POST", "/api/v1/auth/mfa/setup", mustJSON(t, mfaSetupRequest{CurrentPassword: tWrong}), true),
		400, CodeInvalidRequest)
	e.enroll(t, analyst, "analyst")
	if w := e.call(analyst, "POST", "/api/v1/auth/mfa/setup/confirm", mustJSON(t, mfaCodeRequest{Code: e.code(t, "analyst")}), true); w.Code != 200 {
		t.Fatalf("подключение аналитиком: %d %s", w.Code, w.Body)
	}
	reset := "/api/v1/users/" + tAnalystID + "/mfa/reset"
	mustProblem(t, e.call(analyst, "POST", "/api/v1/users/"+tAdminID+"/mfa/reset", "", true), 403, CodeForbidden)
	mustProblem(t, e.call(auditor, "POST", reset, "", true), 403, CodeForbidden)
	mustProblem(t, e.call(admin, "POST", reset, "", false), 403, CodeForbidden)
	mustProblem(t, e.call(admin, "POST", "/api/v1/users/"+tAdminID+"/mfa/reset", "", true), 422, CodeUnprocessable)
	mustProblem(t, e.call(admin, "POST", "/api/v1/users/"+tAuditorID+"/mfa/reset", "", true), 409, CodeConflict)
	mustProblem(t, e.call(admin, "POST", "/api/v1/users/not-a-uuid/mfa/reset", "", true), 404, CodeNotFound)
	if w := e.call(admin, "POST", reset, "", true); w.Code != 204 {
		t.Fatalf("сброс: %d %s", w.Code, w.Body)
	}
	// Сессии пользователя завершены, следующий вход — без второго фактора.
	mustProblem(t, e.call(analyst, "GET", "/api/v1/me", "", false), 401, CodeUnauthorized)
	if w, _ := e.login(t, "analyst", tPhrase); !strings.Contains(w.Body.String(), `"session_state":"active"`) {
		t.Fatalf("вход после сброса: %s", w.Body)
	}
	if !slices.Contains(e.mem.Actions(), "auth.mfa_reset") {
		t.Fatalf("аудит: %v", e.mem.Actions())
	}
}

// Секрет, коды и токены не попадают в технический журнал.
func TestMFASecretsNotLogged(t *testing.T) {
	e := newAuthEnv(t)
	w, s := e.login(t, "admin", tPhrase)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	en := e.enroll(t, s, "admin")
	code := e.code(t, "admin")
	w = e.call(s, "POST", "/api/v1/auth/mfa/setup/confirm", mustJSON(t, mfaCodeRequest{Code: code}), true)
	var rc RecoveryCodes
	if json.Unmarshal(w.Body.Bytes(), &rc) != nil {
		t.Fatal(w.Body)
	}
	logs := e.log.String()
	for _, secret := range append([]string{en.Secret, code}, rc.RecoveryCodes...) {
		if strings.Contains(logs, secret) {
			t.Fatalf("секрет в журнале: %s", logs)
		}
	}
	for _, r := range e.mem.Records() {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range append([]string{en.Secret}, rc.RecoveryCodes...) {
			if strings.Contains(string(b), secret) {
				t.Fatalf("секрет в аудите: %s", b)
			}
		}
	}
}

// Без ключа данных вход роли с обязательным вторым фактором — 503.
func TestMFAUnavailableViaAPI(t *testing.T) {
	e := newAuthEnv(t)
	h, _, err := New(Options{Hasher: testHasher(t), Logger: quiet(), Auth: testAuth(t, e.mem, auth.WithSecretBox(nil)),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 10000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	w, _ := e.login(t, "admin", tPhrase)
	mustProblem(t, w, 503, CodeUnavailable)
	if w, _ := e.login(t, "analyst", tPhrase); w.Code != 200 {
		t.Fatalf("вход аналитика без ключа: %d %s", w.Code, w.Body)
	}
}
