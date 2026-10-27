package auth_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap/ldaptest"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Вход по учётной записи каталога LDAP на хранилище в памяти и
// синтетическом каталоге (ADR-0025, раздел 2; задача 4.16). Пароли и
// идентификаторы синтетические.

const (
	dirSvcDN     = "uid=aisec-svc,cn=sysaccounts,dc=example,dc=test"
	dirSvcPass   = "synthetic-service-credential-1"
	dirUsersDN   = "cn=users,dc=example,dc=test"
	dirAnalysts  = "cn=aisec-analysts,cn=groups,dc=example,dc=test"
	dirAdmins    = "cn=aisec-admins,cn=groups,dc=example,dc=test"
	dirAuditors  = "cn=aisec-auditors,cn=groups,dc=example,dc=test"
	dirPetrovaDN = "uid=petrova,cn=users,dc=example,dc=test"
	dirPetrovaID = "3e9a1f2c-5b6d-4e7f-8a9b-0c1d2e3f4a5b"
	dirPass      = "synthetic-dir-pass" // короче политики консоли: правила пароля — у каталога
)

type ldapEnv struct {
	*env
	dir   *ldaptest.Directory
	admin auth.Caller
	box   *keyring.Box
}

// newDirectory — синтетический каталог LDAPS с сервисной учётной записью,
// пользователем petrova и тёзкой локальной записи ivanov.
func newDirectory(t *testing.T) *ldaptest.Directory {
	t.Helper()
	dir, err := ldaptest.New(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dir.Close)
	dir.Add("dc=example,dc=test", nil, "")
	dir.Add(dirUsersDN, nil, "")
	dir.Add(dirSvcDN, nil, dirSvcPass)
	dir.Add(dirPetrovaDN, map[string][]string{"objectClass": {"person"}, "uid": {"petrova"},
		"entryUUID": {dirPetrovaID}, "displayName": {"Петрова Анна"}, "memberOf": {dirAnalysts}}, dirPass)
	// Тёзка локальной записи «ivanov» в каталоге: каталог её не перекрывает.
	dir.Add("uid=ivanov,cn=users,dc=example,dc=test", map[string][]string{"objectClass": {"person"}, "uid": {"ivanov"},
		"entryUUID": {"7c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"}, "memberOf": {dirAdmins}}, dirPass)
	return dir
}

// ldapInput — включённые настройки каталога dir: группа аналитиков — аудитор.
func ldapInput(dir *ldaptest.Directory) auth.LDAPInput {
	return auth.LDAPInput{Enabled: true, URL: dir.URL, CAPEM: string(dir.RootPEM), BindDN: dirSvcDN,
		BindPassword: dirSvcPass, UserBaseDN: dirUsersDN, UserFilter: "(&(objectClass=person)(uid={login}))",
		IDAttribute: "entryUUID", GroupMode: ldap.GroupsMemberOf,
		GroupRoles: []auth.GroupRole{{Group: dirAnalysts, Role: auth.RoleAuditor}}}
}

func newLDAPEnv(t *testing.T) *ldapEnv {
	t.Helper()
	e := newEnv(t)
	dir := newDirectory(t)
	c, err := ldap.New(provider(t))
	if err != nil {
		t.Fatal(err)
	}
	c.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	box := testBox(t)
	if e.svc, err = auth.NewService(context.Background(), e.mem, e.mem, provider(t), auth.WithClock(e.clock.now),
		auth.WithPasswordHasher(e.hash), auth.WithSecretBox(box), auth.WithRoleStore(e.mem),
		auth.WithAPITokenStore(e.mem), auth.WithLDAP(e.mem, c)); err != nil {
		t.Fatal(err)
	}
	e.mfa = newMFAKeys(e.svc, e.mem, e.clock)
	return &ldapEnv{env: e, dir: dir, box: box, admin: e.mfa.complete(t, e.mustLogin(t, "admin", phrase))}
}

func (e *ldapEnv) input() auth.LDAPInput { return ldapInput(e.dir) }

func (e *ldapEnv) save(t *testing.T, in auth.LDAPInput) {
	t.Helper()
	if _, err := e.svc.SetLDAP(context.Background(), e.admin, in, phrase, ""); err != nil {
		t.Fatal(err)
	}
}

// failReason — причина последней записи auth.login_failed.
func failReason(t *testing.T, e *env) map[string]any {
	t.Helper()
	d, _ := lastRecord(t, e.mem, "auth.login_failed").Details.(map[string]any)
	return d
}

func TestLDAPLoginCreatesExternalUser(t *testing.T) {
	e := newLDAPEnv(t)
	e.save(t, e.input())
	// Логин в другом регистре нормализуется, пароль каталога короче политики консоли.
	res := e.mfa.completeLogin(t, e.mustLogin(t, "Petrova", dirPass))
	u := res.Caller.User
	if u.Source != auth.SourceLDAP || u.IdPIssuer != auth.LDAPIssuer || u.IdPSubject != dirPetrovaID ||
		u.Login != "petrova" || u.Role != auth.RoleAuditor || u.DisplayName != "Петрова Анна" || !u.External() {
		t.Fatalf("учётная запись: %+v", u)
	}
	created := lastRecord(t, e.mem, "user.create")
	if d, _ := created.Details.(map[string]any); d["source"] != "ldap" || created.Actor.ID != "ldap" {
		t.Fatalf("создание: %+v", created)
	}
	login := lastRecord(t, e.mem, "auth.login")
	if d, _ := login.Details.(map[string]any); d["method"] != "ldap" {
		t.Fatalf("вход: %+v", login)
	}
	// Повторный вход — та же запись; пароль консоли у неё не работает.
	again := e.mfa.completeLogin(t, e.mustLogin(t, "petrova", dirPass))
	if again.Caller.User.ID != u.ID {
		t.Fatal("повторный вход создал новую запись")
	}
}

func TestLDAPWrongPasswordNotCounted(t *testing.T) {
	e := newLDAPEnv(t)
	e.save(t, e.input())
	e.mfa.completeLogin(t, e.mustLogin(t, "petrova", dirPass))
	for range 7 {
		e.fail(t, "petrova", "synthetic-wrong")
	}
	if d := failReason(t, e.env); d["reason"] != "wrong_password" || d["method"] != "ldap" || d["subject"] != nil {
		t.Fatalf("причина: %v", d)
	}
	// Неверный пароль каталога не блокирует запись консоли: попытки
	// ограничивает политика каталога.
	e.mfa.completeLogin(t, e.mustLogin(t, "petrova", dirPass))
	e.fail(t, "nobody", dirPass)
	if d := failReason(t, e.env); d["reason"] != "unknown_login" {
		t.Fatalf("неизвестный логин: %v", d)
	}
	// Пустой пароль не уходит в каталог.
	n := len(e.dir.Binds())
	e.fail(t, "petrova", "")
	if d := failReason(t, e.env); d["reason"] != "bad_input" || len(e.dir.Binds()) != n {
		t.Fatalf("пустой пароль: %v, bind %d→%d", d, n, len(e.dir.Binds()))
	}
}

// Локальная запись с тем же логином каталогом не перекрывается (ADR-0025, 1.1).
func TestLDAPLocalLoginWins(t *testing.T) {
	e := newLDAPEnv(t)
	in := e.input()
	in.GroupRoles = append(in.GroupRoles, auth.GroupRole{Group: dirAdmins, Role: auth.RoleSecurityAdmin})
	e.save(t, in)
	e.fail(t, "ivanov", dirPass)
	if d := failReason(t, e.env); d["method"] != nil || d["reason"] != "bad_input" && d["reason"] != "wrong_password" {
		t.Fatalf("локальная запись проверена каталогом: %v", d)
	}
	res := e.mustLogin(t, "ivanov", phrase)
	if res.Caller.User.External() || res.Caller.User.ID != userID {
		t.Fatalf("локальный вход: %+v", res.Caller.User)
	}
}

// Роль администратора по группе: TOTP консоли обязателен (ИАФ.5,
// ADR-0025, 2.5) — подключается сразу после входа, дальше вход с кодом.
func TestLDAPAdminRequiresConsoleTOTP(t *testing.T) {
	e := newLDAPEnv(t)
	in := e.input()
	in.GroupRoles = []auth.GroupRole{{Group: dirAnalysts, Role: auth.RoleSecurityAdmin}}
	e.save(t, in)
	res := e.mustLogin(t, "petrova", dirPass)
	if res.Caller.Session.State != auth.SessionMFASetup {
		t.Fatalf("первый вход: %s", res.Caller.Session.State)
	}
	full := e.mfa.complete(t, res)
	if full.Session.State != auth.SessionActive || !full.Session.MFAVerified {
		t.Fatalf("после подключения: %+v", full.Session)
	}
	res = e.mustLogin(t, "petrova", dirPass)
	if res.Caller.Session.State != auth.SessionMFAPending {
		t.Fatalf("второй вход: %s", res.Caller.Session.State)
	}
	ldapAdmin := e.mfa.complete(t, res)
	ctx := context.Background()
	// Повторная проверка — только у локальной записи: администратор из
	// каталога не меняет настройки каталога (ADR-0025, 1.6).
	if _, err := e.svc.SetLDAP(ctx, ldapAdmin, e.input(), dirPass, ""); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("изменение настроек записью каталога: %v", err)
	}
	if err := e.svc.DeleteLDAP(ctx, ldapAdmin, "", e.mfa.code(t, ldapAdmin.User.ID)); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("удаление настроек записью каталога: %v", err)
	}
	if err := e.svc.ChangePassword(ctx, ldapAdmin, dirPass, phrase2); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("смена пароля записи каталога: %v", err)
	}
	if _, err := e.svc.ResetPassword(ctx, e.admin, ldapAdmin.User.ID); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("сброс пароля записи каталога: %v", err)
	}
	// Сброс фактора администратором работает: запись снова подключает его при входе.
	if err := e.svc.ResetMFA(ctx, e.admin, ldapAdmin.User.ID); err != nil {
		t.Fatal(err)
	}
	if res := e.mustLogin(t, "petrova", dirPass); res.Caller.Session.State != auth.SessionMFASetup {
		t.Fatalf("после сброса фактора: %s", res.Caller.Session.State)
	}
}

// В полной сессии запись каталога не подключает фактор: пароль знает только каталог.
func TestLDAPStartMFAInFullSession(t *testing.T) {
	e := newLDAPEnv(t)
	e.save(t, e.input())
	res := e.mustLogin(t, "petrova", dirPass)
	if res.Caller.Session.State != auth.SessionActive {
		t.Skipf("роли нужен второй фактор: %s", res.Caller.Session.State)
	}
	if _, err := e.svc.StartMFA(context.Background(), res.Caller, dirPass); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("подключение фактора в полной сессии: %v", err)
	}
}

func TestLDAPGroupConflictAndNoRole(t *testing.T) {
	e := newLDAPEnv(t)
	in := e.input()
	in.GroupRoles = []auth.GroupRole{{Group: dirAdmins, Role: auth.RoleAuditor}}
	e.save(t, in)
	e.fail(t, "petrova", dirPass)
	if d := failReason(t, e.env); d["reason"] != "no_role" || d["subject"] != dirPetrovaID {
		t.Fatalf("нет роли: %v", d)
	}
	e.dir.Add("uid=sidorov,cn=users,dc=example,dc=test", map[string][]string{"objectClass": {"person"}, "uid": {"sidorov"},
		"entryUUID": {"1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"}, "memberOf": {dirAnalysts, dirAuditors}}, dirPass)
	in.GroupRoles = []auth.GroupRole{{Group: dirAnalysts, Role: auth.RoleAuditor}, {Group: dirAuditors, Role: auth.RoleAnalyst}}
	in.BindPassword = ""
	e.save(t, in)
	e.fail(t, "sidorov", dirPass)
	if d := failReason(t, e.env); d["reason"] != "group_conflict" {
		t.Fatalf("конфликт групп: %v", d)
	}
}

// DN групп сравниваются без учёта регистра и пробелов (ADR-0025, 2.4).
func TestLDAPGroupDNCaseInsensitive(t *testing.T) {
	e := newLDAPEnv(t)
	in := e.input()
	in.GroupRoles = []auth.GroupRole{{Group: "CN=AISec-Analysts, CN=Groups, DC=Example, DC=Test", Role: auth.RoleAuditor}}
	e.save(t, in)
	if u := e.mfa.completeLogin(t, e.mustLogin(t, "petrova", dirPass)).Caller.User; u.Role != auth.RoleAuditor {
		t.Fatalf("роль: %s", u.Role)
	}
}

// Изменение настроек завершает сессии пользователей каталога; роль из
// новой таблицы применяется при входе (user.role_changed).
func TestLDAPRoleChangedOnLogin(t *testing.T) {
	e := newLDAPEnv(t)
	e.save(t, e.input())
	first := e.mfa.completeLogin(t, e.mustLogin(t, "petrova", dirPass))
	in := e.input()
	in.BindPassword = ""
	in.GroupRoles = []auth.GroupRole{{Group: dirAnalysts, Role: auth.RoleAnalyst}}
	e.save(t, in)
	if rec := lastRecord(t, e.mem, "auth.ldap_changed"); rec.Details.(map[string]any)["revoked_sessions"] == int64(0) {
		t.Fatalf("сессии не завершены: %v", rec.Details)
	}
	if _, err := e.svc.Authenticate(context.Background(), first.Token, testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия после изменения настроек: %v", err)
	}
	next := e.mfa.completeLogin(t, e.mustLogin(t, "petrova", dirPass))
	if next.Caller.User.Role != auth.RoleAnalyst {
		t.Fatalf("роль: %s", next.Caller.User.Role)
	}
	rec := lastRecord(t, e.mem, "user.role_changed")
	if d, _ := rec.Details.(map[string]any); d["before"] != string(auth.RoleAuditor) || d["after"] != string(auth.RoleAnalyst) {
		t.Fatalf("смена роли: %v", rec.Details)
	}
}

func TestLDAPDeactivatedAndDisabled(t *testing.T) {
	e := newLDAPEnv(t)
	e.save(t, e.input())
	ctx := context.Background()
	res := e.mfa.completeLogin(t, e.mustLogin(t, "petrova", dirPass))
	if err := e.svc.SetStatus(ctx, e.admin, res.Caller.User.ID, auth.StatusDeactivated); err != nil {
		t.Fatal(err)
	}
	e.fail(t, "petrova", dirPass)
	if d := failReason(t, e.env); d["reason"] != "deactivated" {
		t.Fatalf("деактивированная запись: %v", d)
	}
	// Отключение: каталог не опрашивается, запись каталога паролем консоли не входит.
	if err := e.svc.DeleteLDAP(ctx, e.admin, phrase, ""); err != nil {
		t.Fatal(err)
	}
	n := len(e.dir.Binds())
	e.fail(t, "petrova", dirPass)
	if d := failReason(t, e.env); d["reason"] != "external_user" || len(e.dir.Binds()) != n {
		t.Fatalf("после отключения: %v", d)
	}
	if _, err := e.svc.LDAP(ctx); !errors.Is(err, auth.ErrLDAPNotConfigured) {
		t.Fatalf("настройки после удаления: %v", err)
	}
}

func TestLDAPSettingsValidation(t *testing.T) {
	e := newLDAPEnv(t)
	cases := []struct {
		name, field string
		edit        func(in *auth.LDAPInput)
	}{
		{"ldap без схемы", "url", func(in *auth.LDAPInput) { in.URL = "dc1.example.test" }},
		{"http", "url", func(in *auth.LDAPInput) { in.URL = "http://dc1.example.test" }},
		{"нет корней", "ca_pem", func(in *auth.LDAPInput) { in.CAPEM = "" }},
		{"DN не разобран", "bind_dn", func(in *auth.LDAPInput) { in.BindDN = "aisec-svc" }},
		{"фильтр без логина", "user_filter", func(in *auth.LDAPInput) { in.UserFilter = "(uid=petrova)" }},
		{"логин в имени атрибута", "user_filter", func(in *auth.LDAPInput) { in.UserFilter = "({login}=x)" }},
		{"атрибут идентификатора", "id_attribute", func(in *auth.LDAPInput) { in.IDAttribute = "uid" }},
		{"способ групп", "group_mode", func(in *auth.LDAPInput) { in.GroupMode = "x" }},
		{"нет ветки групп", "group_base_dn", func(in *auth.LDAPInput) { in.GroupMode = ldap.GroupsMember }},
		{"пароль с управляющим", "bind_password", func(in *auth.LDAPInput) { in.BindPassword = "a\x00b" }},
		{"нет групп", "group_roles", func(in *auth.LDAPInput) { in.GroupRoles = nil }},
		{"группа не DN", "group_roles", func(in *auth.LDAPInput) {
			in.GroupRoles = []auth.GroupRole{{Group: "aisec-admins", Role: auth.RoleAuditor}}
		}},
		{"группа дважды", "group_roles", func(in *auth.LDAPInput) {
			in.GroupRoles = []auth.GroupRole{{Group: dirAdmins, Role: auth.RoleAuditor}, {Group: strings.ToUpper(dirAdmins), Role: auth.RoleAnalyst}}
		}},
		{"нет роли", "group_roles", func(in *auth.LDAPInput) {
			in.GroupRoles = []auth.GroupRole{{Group: dirAdmins, Role: "no_such_role"}}
		}},
		{"неверный пароль сервисной записи", "url", func(in *auth.LDAPInput) { in.BindPassword = "synthetic-wrong" }},
		{"чужие корни", "url", func(in *auth.LDAPInput) { in.URL = strings.Replace(in.URL, "ldaps://", "ldap://", 1) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := e.input()
			c.edit(&in)
			_, err := e.svc.SetLDAP(context.Background(), e.admin, in, phrase, "")
			var ie *auth.InputError
			if !errors.As(err, &ie) || ie.Field != c.field {
				t.Fatalf("ожидалась ошибка поля %s: %v", c.field, err)
			}
		})
	}
	if _, err := e.svc.LDAP(context.Background()); !errors.Is(err, auth.ErrLDAPNotConfigured) {
		t.Fatalf("сохранено при ошибке: %v", err)
	}
	in := e.input()
	in.BindPassword = ""
	if _, err := e.svc.SetLDAP(context.Background(), e.admin, in, phrase, ""); err == nil {
		t.Fatal("сохранено без пароля сервисной учётной записи")
	}
	// Повторная проверка обязательна.
	if _, err := e.svc.SetLDAP(context.Background(), e.admin, e.input(), wrongPhrase, ""); !errors.Is(err, auth.ErrReauthentication) {
		t.Fatalf("без повторной проверки: %v", err)
	}
}

// Расширение доступа отмечается weakening (DM-40); пароль сервисной
// учётной записи не попадает в аудит и ответы.
func TestLDAPWeakeningFlags(t *testing.T) {
	e := newLDAPEnv(t)
	ctx := context.Background()
	save := func(in auth.LDAPInput) []string {
		t.Helper()
		st, err := e.svc.SetLDAP(ctx, e.admin, in, phrase, "")
		if err != nil {
			t.Fatal(err)
		}
		if st.Secret != nil || st.SecretKeyID != "" {
			t.Fatal("пароль в ответе")
		}
		rec := lastRecord(t, e.mem, "auth.ldap_changed")
		if d, err := audit.CanonicalDetails(rec.Details); err != nil || strings.Contains(string(d), dirSvcPass) {
			t.Fatal("пароль сервисной учётной записи в журнале аудита")
		}
		return weakReasons(rec)
	}
	in := e.input()
	if got := save(in); !slices.Equal(got, []string{"ldap_enabled", "ldap_group_roles_added"}) {
		t.Fatalf("первое сохранение: %v", got)
	}
	in.BindPassword = ""
	if got := save(in); got != nil {
		t.Fatalf("без изменений: %v", got)
	}
	in.GroupRoles = []auth.GroupRole{{Group: strings.ToUpper(dirAnalysts), Role: auth.RoleAuditor}}
	if got := save(in); got != nil {
		t.Fatalf("тот же DN в другом регистре: %v", got)
	}
	in.UserFilter = "(uid={login})"
	if got := save(in); !slices.Equal(got, []string{"ldap_directory_changed"}) {
		t.Fatalf("смена фильтра: %v", got)
	}
	in.Enabled = false
	in.GroupMode, in.GroupBaseDN = ldap.GroupsMember, "cn=groups,dc=example,dc=test"
	if got := save(in); !slices.Equal(got, []string{"ldap_groups_changed"}) {
		t.Fatalf("смена способа групп: %v", got)
	}
}

// Таблица групп не шире прав того, кто её сохраняет (УПД.2).
func TestLDAPGroupRolesEscalation(t *testing.T) {
	e := newLDAPEnv(t)
	ctx := context.Background()
	if _, err := e.svc.CreateRole(ctx, e.admin, auth.RoleInput{ID: "ldap_operator", DisplayName: "Оператор каталога",
		Permissions: grants(auth.PermAuthIdPRead, auth.PermAuthIdPManage)}); err != nil {
		t.Fatal(err)
	}
	e.mem.AddUser(e.user("01900000-0000-7000-8000-00000000d002", "operator", "ldap_operator"))
	op := e.mfa.complete(t, e.mustLogin(t, "operator", phrase))
	in := e.input()
	in.GroupRoles = []auth.GroupRole{{Group: dirAdmins, Role: auth.RoleSecurityAdmin}}
	if _, err := e.svc.SetLDAP(ctx, op, in, phrase, ""); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("роль шире своих прав: %v", err)
	}
	if rec := lastRecord(t, e.mem, "auth.ldap_changed"); rec.Result != audit.ResultDenied {
		t.Fatalf("отказ не записан: %+v", rec)
	}
}

func TestLDAPUnavailableWithoutClient(t *testing.T) {
	plain := newEnv(t)
	ctx := context.Background()
	if _, err := plain.svc.LDAP(ctx); !errors.Is(err, auth.ErrLDAPUnavailable) {
		t.Fatalf("без клиента каталога: %v", err)
	}
	if _, err := plain.svc.SetLDAP(ctx, plain.adminCaller(t), auth.LDAPInput{}, phrase, ""); !errors.Is(err, auth.ErrLDAPUnavailable) {
		t.Fatalf("изменение без клиента каталога: %v", err)
	}
}
