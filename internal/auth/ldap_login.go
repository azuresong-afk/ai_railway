package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Вход по логину и паролю каталога LDAP (ADR-0025, раздел 2): пароль
// проверяет каталог, роль — по группам, второй фактор — TOTP консоли.

// Причины отказа входа через каталог для журнала аудита (наружу — только
// «Неверный логин или пароль»).
const (
	ldapReasonUnavailable = "ldap_unavailable"
	ldapReasonAmbiguous   = "ldap_ambiguous"
	ldapReasonIdentity    = "ldap_identity"
	ldapReasonChanged     = "ldap_changed"
	// ldapActorID — субъект аудита изменений учётных записей по данным каталога.
	ldapActorID = "ldap"
)

// activeLDAP — включённые настройки каталога и расшифрованный пароль
// сервисной учётной записи; ok = false — вход через каталог не подключён,
// не настроен или отключён.
func (s *Service) activeLDAP(ctx context.Context) (LDAPSettings, string, bool, error) {
	if !s.LDAPConfigured() || s.box == nil {
		return LDAPSettings{}, "", false, nil
	}
	st, err := s.ldapStore.LDAPSettings(ctx, s.orgID)
	if errors.Is(err, ErrLDAPNotConfigured) {
		return LDAPSettings{}, "", false, nil
	}
	if err != nil {
		return LDAPSettings{}, "", false, err
	}
	if !st.Enabled {
		return LDAPSettings{}, "", false, nil
	}
	plain, err := s.box.Open(st.SecretKeyID, st.Secret, ldapTable, ldapSecretColumn, s.orgID)
	if err != nil {
		return LDAPSettings{}, "", false, err
	}
	return st, string(plain), true, nil
}

// ldapLogin — вход пользователя каталога: проверка пароля в каталоге,
// учётная запись по неизменяемому идентификатору записи, роль по группам,
// состояние сессии по TOTP консоли (как у локальной записи). Любой отказ —
// ErrInvalidCredentials и auth.login_failed с method ldap.
func (s *Service) ldapLogin(ctx context.Context, in LoginInput, login string, st LDAPSettings, secret string,
	pol Policy, now time.Time) (LoginResult, error) {
	f := ldapFailure{login: login}
	// Пароль каталога может быть короче политики консоли: проверяется
	// только наличие и верхний предел.
	if n := len(in.Password); n == 0 || n > aisecCrypto.MaxPasswordLen {
		f.reason = reasonBadInput
		return LoginResult{}, s.ldapFailed(ctx, in, f)
	}
	id, err := s.ldap.Authenticate(ctx, ldapConfig(st, secret), login, in.Password)
	if err != nil {
		f.reason, f.details = ldapReason(err), map[string]any{"error": ldap.ErrorCode(err), "detail": ldap.Detail(err)}
		return LoginResult{}, s.ldapFailed(ctx, in, f)
	}
	f.subject, f.details = id.ID, map[string]any{}
	if u, err := s.ldapStore.UserByIdentity(ctx, s.orgID, LDAPIssuer, id.ID); err == nil {
		f.user = &u
	} else if !errors.Is(err, ErrNotFound) {
		return LoginResult{}, err
	}
	// Блокировка после неверных кодов TOTP консоли действует и на запись каталога.
	if f.user != nil && f.user.Locked(now) {
		f.reason = reasonLocked
		return LoginResult{}, s.ldapFailed(ctx, in, f)
	}
	role, matched, roles := resolveRoleFunc(id.Groups, st.GroupRoles, ldap.SameDN)
	f.details["groups"] = matched
	switch {
	case len(roles) == 0:
		f.reason = oidcReasonNoRole
		return LoginResult{}, s.ldapFailed(ctx, in, f)
	case len(roles) > 1:
		// Одна роль на пользователя (ADR-0013, ADR-0025, 1.4).
		f.reason, f.details["roles"] = oidcReasonGroupConflict, roles
		return LoginResult{}, s.ldapFailed(ctx, in, f)
	}
	// Второй фактор — TOTP консоли (ИАФ.5, ADR-0025, 2.5): подключён —
	// сессия ждёт код; обязателен роли, но не подключён — сессия только для
	// его подключения.
	mfaOn := false
	if f.user != nil {
		if mfaOn, err = s.mfaEnabled(ctx, f.user.ID); err != nil {
			return LoginResult{}, err
		}
	}
	mfaReq := pol.MFARequiredAll
	if !mfaReq {
		if mfaReq, err = s.RoleRequiresMFA(ctx, role); err != nil {
			return LoginResult{}, err
		}
	}
	state := SessionActive
	switch {
	case mfaOn:
		state = SessionMFAPending
	case mfaReq:
		state = SessionMFASetup
	}
	if state != SessionActive && s.box == nil {
		return LoginResult{}, ErrMFAUnavailable
	}
	display, ok := CleanDisplayName(id.DisplayName)
	if !ok {
		display = login
	}
	token, tokenHash, err := newToken(s.random, s.hasher)
	if err != nil {
		return LoginResult{}, err
	}
	csrf, csrfHash, err := newToken(s.random, s.hasher)
	if err != nil {
		return LoginResult{}, err
	}
	sid, err := store.NewUUIDv7(now, s.random)
	if err != nil {
		return LoginResult{}, err
	}
	uid, err := store.NewUUIDv7(now, s.random)
	if err != nil {
		return LoginResult{}, err
	}
	sess := Session{ID: string(sid), TokenHash: tokenHash, CSRFHash: csrfHash, State: state,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(SessionMaxLifetime),
		SourceIP: in.SourceIP, UserAgent: cleanUserAgent(in.UserAgent)}
	dirActor := audit.Actor{Type: audit.ActorSystem, ID: ldapActorID, Name: "LDAP"}
	h := s.hasher.Sum([]byte(LDAPIssuer + "\x00" + id.ID))
	u, err := s.ldapStore.ExternalLogin(ctx, ExternalLoginTx{
		OrgID: s.orgID, SettingsVersion: st.Version, Source: SourceLDAP, Issuer: LDAPIssuer, Subject: id.ID,
		Login: login, FallbackLogin: "ldap-" + hex.EncodeToString(h)[:fallbackLoginHex], DisplayName: display,
		Role: role, NewUserID: string(uid), Session: sess, SessionLimit: pol.SessionMaxPerUser, Now: now,
		Records: func(u User, created bool, prev Role) []audit.Entry {
			var recs []audit.Entry
			if created {
				recs = append(recs, s.entry(dirActor, in.SourceIP, "user.create", userObject(u.ID), audit.ResultSuccess,
					map[string]any{"login": u.Login, "role": string(role), "source": string(SourceLDAP), "dn": id.DN}))
			} else if prev != role {
				recs = append(recs, s.entry(dirActor, in.SourceIP, "user.role_changed", userObject(u.ID), audit.ResultSuccess,
					map[string]any{"before": string(prev), "after": string(role), "groups": matched}))
			}
			c := Caller{User: u, Session: sess}
			return append(recs, s.entry(c.actor(), in.SourceIP, "auth.login", sessionObject(sess.ID), audit.ResultSuccess,
				map[string]any{"state": string(state), "method": "ldap", "groups": matched}))
		},
	})
	switch {
	case errors.Is(err, ErrDeactivated):
		f.reason = reasonDeactivated
	case errors.Is(err, ErrLastAdmin):
		f.reason, f.details["role"] = oidcReasonLastAdmin, string(role)
	case errors.Is(err, ErrIdPChanged):
		f.reason = ldapReasonChanged
	case errors.Is(err, ErrLoginTaken):
		f.reason = oidcReasonLoginConflict
	case errors.Is(err, ErrRoleNotFound):
		f.reason, f.details["role"] = oidcReasonRoleMissing, string(role)
	case err != nil:
		return LoginResult{}, err
	}
	if f.reason != "" {
		return LoginResult{}, s.ldapFailed(ctx, in, f)
	}
	sess.UserID = u.ID
	return LoginResult{Caller: Caller{User: u, Session: sess, SourceIP: in.SourceIP}, Token: token, CSRF: csrf}, nil
}

// ldapReason — причина отказа в аудите по ошибке клиента каталога.
func ldapReason(err error) string {
	switch ldap.ErrorCode(err) {
	case ldap.CodeCredentials:
		return reasonWrongPassword
	case ldap.CodeNotFound:
		return reasonUnknownLogin
	case ldap.CodeAmbiguous:
		return ldapReasonAmbiguous
	case ldap.CodeIdentity:
		return ldapReasonIdentity
	}
	return ldapReasonUnavailable
}

// ldapFailure — отказ входа через каталог для аудита.
type ldapFailure struct {
	login, reason, subject string
	details                map[string]any
	user                   *User
}

// ldapFailed пишет auth.login_failed (method ldap) и возвращает
// ErrInvalidCredentials. Введённый логин попадает в журнал, только если
// учётная запись найдена (иначе это может быть пароль в поле логина).
// Неверный пароль каталога не считается для блокировки консоли: попытки
// ограничивает политика каталога и предел частоты входа.
func (s *Service) ldapFailed(ctx context.Context, in LoginInput, f ldapFailure) error {
	actor := audit.Actor{Type: audit.ActorUser, ID: unknownActor, Name: unknownLogin}
	var obj audit.Object
	if f.user != nil {
		actor = audit.Actor{Type: audit.ActorUser, ID: f.user.ID, Name: f.user.Login}
		obj = userObject(f.user.ID)
	}
	d := map[string]any{"method": "ldap", "reason": f.reason}
	for k, v := range f.details {
		d[k] = v
	}
	if f.subject != "" {
		d["subject"] = f.subject
	}
	if err := s.audit.Record(ctx, s.entry(actor, in.SourceIP, "auth.login_failed", obj, audit.ResultFailure, d)); err != nil {
		return err
	}
	return ErrInvalidCredentials
}
