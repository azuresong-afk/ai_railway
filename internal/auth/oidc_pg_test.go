package auth_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Вход через внешний IdP на PostgreSQL (ИАФ.7; ADR-0025, задача 4.17):
// синтетический IdP на 127.0.0.1, внешних адресов нет.

const (
	idpClientID     = "aisec-console"
	idpClientSecret = "synthetic-client-credential-1"
	idpConsoleURL   = "https://console.example.test"
)

type oidcEnv struct {
	*pgEnv
	idp   *cryptotest.IdP
	admin auth.Caller
}

func setupOIDC(t *testing.T) *oidcEnv {
	t.Helper()
	e := setupPG(t)
	idp, err := cryptotest.NewIdP(idpClientID, idpClientSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	return &oidcEnv{pgEnv: e, idp: idp, admin: e.mfa.complete(t, mustPGLogin(t, e, "admin"))}
}

func (e *oidcEnv) input() auth.IdPInput {
	return auth.IdPInput{Enabled: true, DisplayName: "Корпоративный вход", Issuer: e.idp.Issuer, ClientID: idpClientID,
		ClientSecret: idpClientSecret, ConsoleURL: idpConsoleURL, CAPEM: string(e.idp.RootPEM),
		GroupRoles: []auth.GroupRole{{Group: "aisec-analysts", Role: auth.RoleAnalyst},
			{Group: "aisec-auditors", Role: auth.RoleAuditor}, {Group: "aisec-admins", Role: auth.RoleSecurityAdmin}}}
}

// flight — начатый вход: cookie браузера и параметры возврата от IdP.
type flight struct {
	cookie, state, code, idpErr string
}

func (e *oidcEnv) begin(t *testing.T) flight {
	t.Helper()
	start, err := e.svc.StartOIDC(pgCtx(t))
	if err != nil {
		t.Fatalf("начало входа: %v", err)
	}
	back, err := e.idp.Authorize(pgCtx(t), start.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	return flight{cookie: start.Cookie, state: back.Get("state"), code: back.Get("code"), idpErr: back.Get("error")}
}

func (e *oidcEnv) finish(t *testing.T, f flight) (auth.LoginResult, error) {
	t.Helper()
	return e.svc.FinishOIDC(pgCtx(t), auth.OIDCCallbackInput{Cookie: f.cookie, State: f.state, Code: f.code,
		Error: f.idpErr, SourceIP: testIP, UserAgent: "test"})
}

func (e *oidcEnv) loginAs(t *testing.T, groups ...string) (auth.LoginResult, error) {
	t.Helper()
	e.idp.SetClaims(map[string]any{"sub": "idp-user-1", "preferred_username": "ivanov", "name": "Иванов Иван",
		"groups": groups})
	return e.finish(t, e.begin(t))
}

// wantDenied — отказ с кодом для пользователя и причиной в последней
// записи auth.login_failed.
func (e *oidcEnv) wantDenied(t *testing.T, err error, code, reason string) {
	t.Helper()
	var oe *auth.OIDCError
	if !errors.As(err, &oe) || oe.Code != code {
		t.Fatalf("ожидался отказ %s: %v", code, err)
	}
	var got, method string
	if err := e.owner.QueryRow(pgCtx(t), `SELECT details->>'reason', details->>'method' FROM audit_log
		WHERE action = 'auth.login_failed' ORDER BY seq DESC LIMIT 1`).Scan(&got, &method); err != nil {
		t.Fatal(err)
	}
	if got != reason || method != "oidc" {
		t.Fatalf("причина в аудите %q (%s), ожидалась %q", got, method, reason)
	}
}

func lastDetails(t *testing.T, e *pgEnv, action string) map[string]any {
	t.Helper()
	var raw []byte
	if err := e.owner.QueryRow(pgCtx(t), `SELECT details FROM audit_log WHERE action = $1 ORDER BY seq DESC LIMIT 1`,
		action).Scan(&raw); err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// Полный путь: настройка, создание внешней записи, смена роли по группам,
// отказы (конфликт групп, нет роли, второй фактор, деактивация, повтор,
// подложенный state, отказ IdP), удаление настроек.
func TestPGOIDCLogin(t *testing.T) {
	e := setupOIDC(t)
	ctx := pgCtx(t)
	if _, err := e.svc.StartOIDC(ctx); !errors.Is(err, auth.ErrIdPNotConfigured) {
		t.Fatalf("без настроек: %v", err)
	}
	// Без повторной проверки и с неверным паролем — отказ.
	if _, err := e.svc.SetIdP(ctx, e.admin, e.input(), "", ""); err == nil {
		t.Fatal("сохранено без повторной проверки")
	}
	if _, err := e.svc.SetIdP(ctx, e.admin, e.input(), wrongPhrase, ""); !errors.Is(err, auth.ErrReauthentication) {
		t.Fatalf("неверный пароль: %v", err)
	}
	st, err := e.svc.SetIdP(ctx, e.admin, e.input(), phrase, "")
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != 1 || st.Secret != nil {
		t.Fatalf("настройки: %+v", st)
	}
	d := lastDetails(t, e.pgEnv, "auth.idp_changed")
	if d["weakening"] != true || d["client_auth_changed"] != true {
		t.Fatalf("аудит настроек: %v", d)
	}
	var sealed []byte
	if err := e.owner.QueryRow(ctx, "SELECT client_secret FROM oidc_settings").Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(idpClientSecret)) {
		t.Fatal("секрет клиента хранится открыто")
	}
	if opt, err := e.svc.IdPLoginOption(ctx); err != nil || !opt.Enabled || opt.DisplayName != "Корпоративный вход" {
		t.Fatalf("кнопка входа: %+v %v", opt, err)
	}

	// Первый вход создаёт внешнюю запись с ролью по группе.
	res, err := e.loginAs(t, "aisec-analysts", "other")
	if err != nil {
		t.Fatal(err)
	}
	u := res.Caller.User
	if !u.External() || u.Login != "ivanov" || u.Role != auth.RoleAnalyst || u.IdPIssuer != e.idp.Issuer ||
		u.IdPSubject != "idp-user-1" || u.DisplayName != "Иванов Иван" || res.Caller.Session.MFAVerified {
		t.Fatalf("внешняя запись: %+v", u)
	}
	if _, err := e.svc.Authenticate(ctx, res.Token, testIP); err != nil {
		t.Fatal(err)
	}
	if lastDetails(t, e.pgEnv, "auth.login")["method"] != "oidc" || auditCount(t, e.pgEnv, "user.create") != 2 {
		t.Fatal("аудит входа и создания записи")
	}
	// Внешняя запись не становится локальной и в обход сервиса: столбцы
	// источника серверу не изменить, пароль — только заглушка (CHECK).
	if _, err := e.app.Exec(ctx, "UPDATE users SET auth_source = 'local' WHERE id = $1", u.ID); sqlState(err) != "42501" {
		t.Fatalf("смена источника ролью сервера: %v", err)
	}
	if _, err := e.app.Exec(ctx, "UPDATE users SET password_hash = $2 WHERE id = $1", u.ID, "$argon2id$x"); sqlState(err) != "23514" {
		t.Fatalf("пароль внешней записи: %v", err)
	}
	// Пароля у внешней записи нет; её действия с паролем и TOTP недоступны.
	if _, err := e.login(t, "ivanov", phrase); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("вход паролем: %v", err)
	}
	if lastDetails(t, e.pgEnv, "auth.login_failed")["reason"] != "external_user" {
		t.Fatal("причина отказа входа паролем")
	}
	if err := e.svc.ChangePassword(ctx, res.Caller, phrase, phrase2); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("смена пароля: %v", err)
	}
	if _, err := e.svc.SetIdP(ctx, res.Caller, e.input(), phrase, ""); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("настройки внешней записью: %v", err)
	}

	// Повтор того же возврата: вход одноразовый.
	f := e.begin(t)
	if _, err := e.finish(t, f); err != nil {
		t.Fatal(err)
	}
	_, err = e.finish(t, f)
	e.wantDenied(t, err, auth.OIDCFailed, "login_expired")
	// Подложенный state.
	f = e.begin(t)
	if f.state[0] == 'A' {
		f.state = "B" + f.state[1:]
	} else {
		f.state = "A" + f.state[1:]
	}
	_, err = e.finish(t, f)
	e.wantDenied(t, err, auth.OIDCFailed, "state_mismatch")
	// Отказ IdP: его код в аудите, наружу — только «отказано».
	e.idp.Deny("access_denied")
	_, err = e.finish(t, e.begin(t))
	e.wantDenied(t, err, auth.OIDCDenied, "idp_error")
	e.idp.Deny("")

	// Смена группы меняет роль и завершает прежние сессии.
	res2, err := e.loginAs(t, "aisec-auditors")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Caller.User.ID != u.ID || res2.Caller.User.Role != auth.RoleAuditor {
		t.Fatalf("роль: %+v", res2.Caller.User)
	}
	if _, err := e.svc.Authenticate(ctx, res.Token, testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия с прежней ролью: %v", err)
	}
	if d := lastDetails(t, e.pgEnv, "user.role_changed"); d["before"] != "analyst" || d["after"] != "auditor" {
		t.Fatalf("аудит смены роли: %v", d)
	}
	// Группы с разными ролями — отказ, а не выбор старшей.
	_, err = e.loginAs(t, "aisec-analysts", "aisec-admins")
	e.wantDenied(t, err, auth.OIDCDenied, "group_conflict")
	_, err = e.loginAs(t, "nobody")
	e.wantDenied(t, err, auth.OIDCDenied, "no_role")
	// Роль с обязательным вторым фактором без подтверждения acr/amr.
	_, err = e.loginAs(t, "aisec-admins")
	e.wantDenied(t, err, auth.OIDCDenied, "mfa_not_asserted")

	// Требование acr в настройках: токен с ним входит, сессия с MFA.
	in := e.input()
	in.ClientSecret = "" // прежний секрет
	in.RequiredACR = []string{"urn:aisec:mfa"}
	if _, err := e.svc.SetIdP(ctx, e.admin, in, phrase, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, res2.Token, testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессии внешних после смены настроек: %v", err)
	}
	if d := lastDetails(t, e.pgEnv, "auth.idp_changed"); d["client_auth_changed"] != false || d["weakening"] != nil {
		t.Fatalf("аудит ужесточения: %v", d)
	}
	_, err = e.loginAs(t, "aisec-analysts")
	e.wantDenied(t, err, auth.OIDCDenied, "mfa_not_asserted")
	e.idp.SetClaims(map[string]any{"sub": "idp-user-1", "preferred_username": "ivanov", "groups": []string{"aisec-admins"},
		"acr": "urn:aisec:mfa"})
	res3, err := e.finish(t, e.begin(t))
	if err != nil {
		t.Fatal(err)
	}
	if res3.Caller.User.Role != auth.RoleSecurityAdmin || !res3.Caller.Session.MFAVerified ||
		res3.Caller.Session.State != auth.SessionActive {
		t.Fatalf("вход администратора через IdP: %+v %+v", res3.Caller.User, res3.Caller.Session)
	}

	// Деактивированная запись не входит.
	if err := e.svc.SetStatus(ctx, e.admin, u.ID, auth.StatusDeactivated); err != nil {
		t.Fatal(err)
	}
	_, err = e.finish(t, e.begin(t))
	e.wantDenied(t, err, auth.OIDCDenied, "deactivated")

	// Удаление настроек: вход недоступен, учётная запись остаётся.
	if err := e.svc.DeleteIdP(ctx, e.admin, phrase, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.StartOIDC(ctx); !errors.Is(err, auth.ErrIdPNotConfigured) {
		t.Fatalf("после удаления: %v", err)
	}
	if auditCount(t, e.pgEnv, "auth.idp_disabled") != 1 {
		t.Fatal("аудит удаления")
	}
	if _, err := e.store.UserByIdentity(ctx, u.OrgID, e.idp.Issuer, "idp-user-1"); err != nil {
		t.Fatal(err)
	}
}

// Занятый логин: внешняя запись получает запасной «oidc-…», локальная
// запись с тем же логином не захватывается.
func TestPGOIDCLoginTaken(t *testing.T) {
	e := setupOIDC(t)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	if _, err := e.svc.SetIdP(pgCtx(t), e.admin, e.input(), phrase, ""); err != nil {
		t.Fatal(err)
	}
	res, err := e.loginAs(t, "aisec-auditors")
	if err != nil {
		t.Fatal(err)
	}
	if res.Caller.User.ID == userID || len(res.Caller.User.Login) != len("oidc-")+16 || res.Caller.User.Role != auth.RoleAuditor {
		t.Fatalf("запасной логин: %+v", res.Caller.User)
	}
	local, err := e.store.UserByID(pgCtx(t), res.Caller.User.OrgID, userID)
	if err != nil || local.External() || local.Role != auth.RoleAnalyst {
		t.Fatalf("локальная запись: %+v %v", local, err)
	}
}

// Внешняя запись — последний администратор безопасности: роль по группам
// не снимается, вход отклоняется.
func TestPGOIDCLastAdmin(t *testing.T) {
	e := setupOIDC(t)
	in := e.input()
	in.RequiredAMR = []string{"otp"}
	if _, err := e.svc.SetIdP(pgCtx(t), e.admin, in, phrase, ""); err != nil {
		t.Fatal(err)
	}
	e.idp.SetClaims(map[string]any{"sub": "idp-admin", "groups": []string{"aisec-admins"}, "amr": []string{"pwd", "otp"}})
	res, err := e.finish(t, e.begin(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetStatus(pgCtx(t), res.Caller, adminID, auth.StatusDeactivated); err != nil {
		t.Fatal(err)
	}
	e.idp.SetClaims(map[string]any{"sub": "idp-admin", "groups": []string{"aisec-analysts"}, "amr": []string{"otp"}})
	_, err = e.finish(t, e.begin(t))
	e.wantDenied(t, err, auth.OIDCDenied, "last_admin")
}

// Ротация ключа данных: секрет клиента IdP перешифрован новой версией,
// прежняя версия выводится, вход работает (ADR-0018, ADR-0025, 3.2).
func TestPGOIDCSecretRewrap(t *testing.T) {
	e := setupOIDC(t)
	ctx := pgCtx(t)
	if _, err := e.svc.SetIdP(ctx, e.admin, e.input(), phrase, ""); err != nil {
		t.Fatal(err)
	}
	ownerLog, err := audit.New(e.owner, provider(t))
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.Actor{Type: audit.ActorCLI, ID: "uid:0", Name: "root"}
	if _, err := keyring.RotateData(ctx, e.owner, ownerLog, provider(t), e.dir, audit.DefaultOrgID, actor, time.Now()); err != nil {
		t.Fatal(err)
	}
	full, err := keyring.Load(ctx, e.owner, provider(t), e.dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := keyring.Rewrap(ctx, e.owner, full, keyring.RewrapOptions{ContentPurpose: "event-content"})
	if err != nil || n.OIDC != 1 {
		t.Fatalf("перешифрование: %+v %v", n, err)
	}
	if res, err := keyring.DestroyRetired(ctx, e.owner, ownerLog, audit.DefaultOrgID, actor); err != nil || len(res.Destroyed) != 1 {
		t.Fatalf("вывод прежней версии: %+v %v", res, err)
	}
	if err := e.box.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var keyID string
	if err := e.owner.QueryRow(ctx, "SELECT client_secret_key_id::text FROM oidc_settings").Scan(&keyID); err != nil || keyID == e.keyID {
		t.Fatalf("версия ключа секрета: %s %v", keyID, err)
	}
	if _, err := e.loginAs(t, "aisec-analysts"); err != nil {
		t.Fatalf("вход после ротации: %v", err)
	}
}
