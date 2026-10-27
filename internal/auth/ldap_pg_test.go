package auth_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Вход через каталог LDAP на PostgreSQL (ИАФ.7; ADR-0025, раздел 2;
// задача 4.16): синтетический каталог на 127.0.0.1.

func TestPGLDAPLogin(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	dir := newDirectory(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	admin := e.mfa.complete(t, mustPGLogin(t, e, "admin"))
	if _, err := e.svc.SetLDAP(ctx, admin, ldapInput(dir), phrase, ""); err != nil {
		t.Fatal(err)
	}
	// Пароль сервисной учётной записи хранится только шифротекстом.
	var sealed []byte
	var keyID string
	if err := e.owner.QueryRow(ctx, "SELECT bind_password, bind_password_key_id::text FROM ldap_settings").Scan(&sealed, &keyID); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(dirSvcPass)) || keyID != e.keyID {
		t.Fatal("пароль сервисной учётной записи не зашифрован")
	}
	res, err := e.login(t, "petrova", dirPass)
	if err != nil {
		t.Fatal(err)
	}
	first := e.mfa.completeLogin(t, res)
	var source, issuer, subject, hash string
	if err := e.owner.QueryRow(ctx, `SELECT auth_source, idp_issuer, idp_subject, password_hash FROM users WHERE login = 'petrova'`).
		Scan(&source, &issuer, &subject, &hash); err != nil {
		t.Fatal(err)
	}
	if source != "ldap" || issuer != auth.LDAPIssuer || subject != dirPetrovaID || hash != "!external" {
		t.Fatalf("запись каталога: %s %s %s %s", source, issuer, subject, hash)
	}
	if d := lastDetails(t, e, "auth.login"); d["method"] != "ldap" {
		t.Fatalf("вход: %v", d)
	}
	// Изменение настроек завершает сессии пользователей каталога (ldap_changed).
	in := ldapInput(dir)
	in.BindPassword = ""
	in.GroupRoles = []auth.GroupRole{{Group: dirAnalysts, Role: auth.RoleAnalyst}}
	if _, err := e.svc.SetLDAP(ctx, admin, in, phrase, ""); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := e.owner.QueryRow(ctx, "SELECT revoke_reason FROM sessions WHERE id = $1", first.Caller.Session.ID).Scan(&reason); err != nil || reason != auth.RevokeLDAPChanged {
		t.Fatalf("сессия: %q %v", reason, err)
	}
	if d := lastDetails(t, e, "auth.ldap_changed"); d["revoked_sessions"] != float64(1) {
		t.Fatalf("аудит изменения: %v", d)
	}
	res, err = e.login(t, "petrova", dirPass)
	if err != nil {
		t.Fatal(err)
	}
	if u := e.mfa.completeLogin(t, res).Caller.User; u.Role != auth.RoleAnalyst || u.ID != first.Caller.User.ID {
		t.Fatalf("роль после изменения таблицы: %+v", u)
	}
	// Локальная запись администратора не затронута; удаление настроек.
	if err := e.svc.DeleteLDAP(ctx, admin, phrase, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.LDAP(ctx); !errors.Is(err, auth.ErrLDAPNotConfigured) {
		t.Fatalf("после удаления: %v", err)
	}
	if _, err := e.login(t, "petrova", dirPass); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("вход после отключения: %v", err)
	}
}

// Вход по устаревшей версии настроек отклоняется: проверка версии под
// блокировкой строки ldap_settings.
func TestPGLDAPSettingsVersionChecked(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	dir := newDirectory(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	admin := e.mfa.complete(t, mustPGLogin(t, e, "admin"))
	st, err := e.svc.SetLDAP(ctx, admin, ldapInput(dir), phrase, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = e.store.ExternalLogin(ctx, auth.ExternalLoginTx{OrgID: audit.DefaultOrgID, SettingsVersion: st.Version + 1,
		Source: auth.SourceLDAP, Issuer: auth.LDAPIssuer, Subject: dirPetrovaID, Login: "petrova", Role: auth.RoleAuditor,
		Now: now, Records: func(auth.User, bool, auth.Role) []audit.Entry { return nil }})
	if !errors.Is(err, auth.ErrIdPChanged) {
		t.Fatalf("устаревшая версия: %v", err)
	}
}

// Ротация ключа данных: пароль сервисной учётной записи перешифрован, вход
// работает (ADR-0018).
func TestPGLDAPPasswordRewrap(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	dir := newDirectory(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	admin := e.mfa.complete(t, mustPGLogin(t, e, "admin"))
	if _, err := e.svc.SetLDAP(ctx, admin, ldapInput(dir), phrase, ""); err != nil {
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
	if err != nil || n.LDAP != 1 {
		t.Fatalf("перешифрование: %+v %v", n, err)
	}
	if res, err := keyring.DestroyRetired(ctx, e.owner, ownerLog, audit.DefaultOrgID, actor); err != nil || len(res.Destroyed) != 1 {
		t.Fatalf("вывод прежней версии: %+v %v", res, err)
	}
	if err := e.box.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.login(t, "petrova", dirPass); err != nil {
		t.Fatalf("вход после ротации: %v", err)
	}
}
