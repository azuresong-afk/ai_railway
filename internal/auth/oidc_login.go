package auth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Вход через внешний IdP по коду авторизации с PKCE (ADR-0025, 3.3–3.7).

const (
	// OIDCLoginTTL — срок незавершённого входа и cookie браузера.
	OIDCLoginTTL = 10 * time.Minute
	// maxPendingOIDC — незавершённых входов на организацию (открытый эндпоинт).
	maxPendingOIDC = 10000
	// oidcLoginBytes — случайное значение входа в cookie.
	oidcLoginBytes = 32
	// Пределы утверждений с группами и amr.
	maxClaimGroups = 256
	maxClaimAMR    = 32
	// oidcActorID — субъект аудита изменений учётных записей по данным IdP.
	oidcActorID = "oidc"
	// fallbackLoginHex — длина суффикса логина «oidc-…» из хеша (iss, sub).
	fallbackLoginHex = 16
)

// Метки выведения значений входа из случайного значения cookie: state,
// nonce и code_verifier в БД не хранятся (ADR-0025, 3.3).
const (
	labelState    = "aisec-oidc-state-v1"
	labelNonce    = "aisec-oidc-nonce-v1"
	labelVerifier = "aisec-oidc-pkce-v1"
)

// Коды отказа входа через IdP для пользователя (адрес /login?oidc=…).
const (
	OIDCDenied      = "denied"      // IdP или правила консоли не пустили пользователя
	OIDCFailed      = "failed"      // вход прерван, устарел или подделан — начните заново
	OIDCUnavailable = "unavailable" // IdP недоступен или не настроен
)

// Причины отказа для журнала аудита (наружу не выдаются).
const (
	oidcReasonDisabled      = "idp_disabled"
	oidcReasonNoLogin       = "no_login"
	oidcReasonExpired       = "login_expired"
	oidcReasonState         = "state_mismatch"
	oidcReasonIdPError      = "idp_error"
	oidcReasonExchange      = "token_exchange"
	oidcReasonIDToken       = "id_token"
	oidcReasonGroups        = "groups_claim"
	oidcReasonNoRole        = "no_role"
	oidcReasonGroupConflict = "group_conflict"
	oidcReasonMFA           = "mfa_not_asserted"
	oidcReasonDeactivated   = "deactivated"
	oidcReasonLastAdmin     = "last_admin"
	oidcReasonRoleMissing   = "role_missing"
	oidcReasonChanged       = "idp_changed"
	oidcReasonLoginConflict = "login_conflict"
)

// OIDCError — отказ входа через IdP; Code — для пользователя, причина — в аудите.
type OIDCError struct {
	Code   string
	Reason string
}

func (e *OIDCError) Error() string {
	return "вход через IdP: " + e.Code + " (" + e.Reason + ")"
}

// OIDCStartResult — куда перенаправить браузер и значение cookie входа.
type OIDCStartResult struct {
	RedirectURL string
	Cookie      string
}

// StartOIDC начинает вход через IdP: одноразовое значение для cookie
// браузера, хеш — в БД, адрес авторизации с state, nonce и PKCE S256.
func (s *Service) StartOIDC(ctx context.Context) (OIDCStartResult, error) {
	st, secret, err := s.activeIdP(ctx)
	if err != nil {
		return OIDCStartResult{}, err
	}
	b, err := aisecCrypto.RandomBytes(s.random, oidcLoginBytes)
	if err != nil {
		return OIDCStartResult{}, err
	}
	now := s.clock()
	if err := s.idp.StartOIDCLogin(ctx, s.orgID, s.hasher.Sum(b), now, now.Add(OIDCLoginTTL), maxPendingOIDC); err != nil {
		return OIDCStartResult{}, err
	}
	u, err := s.oidc.AuthURL(ctx, s.oidcConfig(st, secret), oidc.AuthParams{
		State: s.deriveOIDC(labelState, b), Nonce: s.deriveOIDC(labelNonce, b),
		Challenge: aisecCrypto.PKCEChallengeS256(s.deriveOIDC(labelVerifier, b)),
	})
	if err != nil {
		return OIDCStartResult{}, &OIDCError{Code: OIDCUnavailable, Reason: "discovery:" + oidc.ErrorCode(err)}
	}
	return OIDCStartResult{RedirectURL: u, Cookie: base64.RawURLEncoding.EncodeToString(b)}, nil
}

// activeIdP — включённые настройки и расшифрованный секрет клиента.
func (s *Service) activeIdP(ctx context.Context) (IdPSettings, string, error) {
	if !s.IdPConfigured() || s.box == nil {
		return IdPSettings{}, "", ErrIdPUnavailable
	}
	st, err := s.idp.IdPSettings(ctx, s.orgID)
	if err != nil {
		return IdPSettings{}, "", err
	}
	if !st.Enabled {
		return IdPSettings{}, "", ErrIdPNotConfigured
	}
	plain, err := s.box.Open(st.SecretKeyID, st.Secret, idpTable, idpSecretColumn, s.orgID)
	if err != nil {
		return IdPSettings{}, "", err
	}
	return st, string(plain), nil
}

// deriveOIDC — значение входа из случайного b: хеш профиля от метки и b,
// base64url (43 символа — допустимый code_verifier, RFC 7636, 4.1).
func (s *Service) deriveOIDC(label string, b []byte) string {
	msg := make([]byte, 0, len(label)+1+len(b))
	msg = append(append(append(msg, label...), 0), b...)
	return base64.RawURLEncoding.EncodeToString(s.hasher.Sum(msg))
}

// OIDCCallbackInput — возврат браузера от IdP.
type OIDCCallbackInput struct {
	Cookie    string
	State     string
	Code      string
	Error     string // параметр error от IdP
	SourceIP  netip.Addr
	UserAgent string
}

// oidcFailure — неудача для аудита: причина, код для пользователя и что
// известно о пользователе.
type oidcFailure struct {
	code, reason string
	details      map[string]any
	user         *User
	subject      string
}

// FinishOIDC завершает вход через IdP: одноразовый вход из cookie, state,
// обмен кода, проверка ID-токена, роль по группам, второй фактор по
// acr/amr, учётная запись и сессия. Любой отказ — *OIDCError и запись
// auth.login_failed с причиной (ИАФ.7, РСБ.2).
func (s *Service) FinishOIDC(ctx context.Context, in OIDCCallbackInput) (LoginResult, error) {
	res, f, err := s.finishOIDC(ctx, in)
	if err != nil {
		return LoginResult{}, err
	}
	if f != nil {
		return LoginResult{}, s.oidcFailed(ctx, in, f)
	}
	return res, nil
}

func (s *Service) finishOIDC(ctx context.Context, in OIDCCallbackInput) (LoginResult, *oidcFailure, error) {
	fail := func(code, reason string) (LoginResult, *oidcFailure, error) {
		return LoginResult{}, &oidcFailure{code: code, reason: reason}, nil
	}
	st, secret, err := s.activeIdP(ctx)
	if errors.Is(err, ErrIdPNotConfigured) || errors.Is(err, ErrIdPUnavailable) {
		return fail(OIDCUnavailable, oidcReasonDisabled)
	}
	if err != nil {
		return LoginResult{}, nil, err
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(in.Cookie)
	if err != nil || len(b) != oidcLoginBytes {
		return fail(OIDCFailed, oidcReasonNoLogin)
	}
	now := s.clock()
	err = s.idp.TakeOIDCLogin(ctx, s.orgID, s.hasher.Sum(b), now)
	if errors.Is(err, ErrNotFound) {
		return fail(OIDCFailed, oidcReasonExpired)
	}
	if err != nil {
		return LoginResult{}, nil, err
	}
	// state сверяется за постоянное время: он привязывает возврат к
	// браузеру, начавшему вход (защита от подложенного входа).
	if !aisecCrypto.Equal([]byte(in.State), []byte(s.deriveOIDC(labelState, b))) {
		return fail(OIDCFailed, oidcReasonState)
	}
	if in.Error != "" {
		f := &oidcFailure{code: OIDCDenied, reason: oidcReasonIdPError}
		if oidc.SafeCode(in.Error) {
			f.details = map[string]any{"idp_error": in.Error}
		}
		return LoginResult{}, f, nil
	}
	cfg := s.oidcConfig(st, secret)
	token, err := s.oidc.Exchange(ctx, cfg, in.Code, s.deriveOIDC(labelVerifier, b))
	if err != nil {
		code := OIDCFailed
		if c := oidc.ErrorCode(err); c != oidc.CodeGrant && c != oidc.CodeResponse {
			code = OIDCUnavailable
		}
		return LoginResult{}, &oidcFailure{code: code, reason: oidcReasonExchange,
			details: map[string]any{"error": oidc.ErrorCode(err), "detail": oidcDetail(err)}}, nil
	}
	claims, err := s.oidc.VerifyIDToken(ctx, cfg, token, s.deriveOIDC(labelNonce, b))
	if err != nil {
		code := OIDCFailed
		if oidc.ErrorCode(err) != oidc.CodeIDToken {
			code = OIDCUnavailable
		}
		return LoginResult{}, &oidcFailure{code: code, reason: oidcReasonIDToken,
			details: map[string]any{"error": oidc.ErrorCode(err), "jwt": aisecCrypto.JWTReason(err)}}, nil
	}
	return s.externalSession(ctx, in, st, claims, now)
}

// oidcDetail — уточнение ошибки клиента IdP без данных ответа.
func oidcDetail(err error) string {
	var e *oidc.Error
	if errors.As(err, &e) {
		return e.Detail
	}
	return ""
}

// externalSession — роль, второй фактор, учётная запись и сессия по
// проверенным утверждениям ID-токена.
func (s *Service) externalSession(ctx context.Context, in OIDCCallbackInput, st IdPSettings,
	claims aisecCrypto.IDTokenClaims, now time.Time) (LoginResult, *oidcFailure, error) {
	f := &oidcFailure{code: OIDCDenied, subject: claims.Subject, details: map[string]any{}}
	if u, err := s.idp.UserByIdentity(ctx, s.orgID, st.Issuer, claims.Subject); err == nil {
		f.user = &u
	} else if !errors.Is(err, ErrNotFound) {
		return LoginResult{}, nil, err
	}
	groups, ok := claimGroups(claims, st.GroupsClaim)
	if !ok {
		f.reason = oidcReasonGroups
		return LoginResult{}, f, nil
	}
	role, matched, roles := resolveRole(groups, st.GroupRoles)
	f.details["groups"] = matched
	switch {
	case len(roles) == 0:
		f.reason = oidcReasonNoRole
		return LoginResult{}, f, nil
	case len(roles) > 1:
		// Одна роль на пользователя (ADR-0013): разные роли из разных
		// групп — отказ, а не выбор «старшей» (ADR-0025, 1.4).
		f.reason, f.details["roles"] = oidcReasonGroupConflict, roles
		return LoginResult{}, f, nil
	}
	asserted := mfaAsserted(claims, st)
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return LoginResult{}, nil, err
	}
	required := pol.MFARequiredAll
	if !required {
		if required, err = s.RoleRequiresMFA(ctx, role); err != nil {
			return LoginResult{}, nil, err
		}
	}
	if (required || st.MFARequirement()) && !asserted {
		f.reason, f.details["role"] = oidcReasonMFA, string(role)
		return LoginResult{}, f, nil
	}
	login, fallback := s.externalLogins(claims, st.Issuer)
	display, ok := "", false
	if name, has := claims.String("name"); has {
		display, ok = CleanDisplayName(name)
	}
	if !ok {
		display = login
		if display == "" {
			display = fallback
		}
	}
	token, tokenHash, err := newToken(s.random, s.hasher)
	if err != nil {
		return LoginResult{}, nil, err
	}
	csrf, csrfHash, err := newToken(s.random, s.hasher)
	if err != nil {
		return LoginResult{}, nil, err
	}
	sid, err := store.NewUUIDv7(now, s.random)
	if err != nil {
		return LoginResult{}, nil, err
	}
	uid, err := store.NewUUIDv7(now, s.random)
	if err != nil {
		return LoginResult{}, nil, err
	}
	sess := Session{ID: string(sid), TokenHash: tokenHash, CSRFHash: csrfHash, State: SessionActive,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(SessionMaxLifetime),
		SourceIP: in.SourceIP, UserAgent: cleanUserAgent(in.UserAgent), MFAVerified: asserted}
	idpActor := audit.Actor{Type: audit.ActorSystem, ID: oidcActorID, Name: st.DisplayName}
	u, err := s.idp.ExternalLogin(ctx, ExternalLoginTx{
		OrgID: s.orgID, SettingsVersion: st.Version, Source: SourceOIDC, Issuer: st.Issuer, Subject: claims.Subject,
		Login: login, FallbackLogin: fallback, DisplayName: display, Role: role, NewUserID: string(uid),
		Session: sess, SessionLimit: pol.SessionMaxPerUser, Now: now,
		Records: func(u User, created bool, prev Role) []audit.Entry {
			var recs []audit.Entry
			if created {
				recs = append(recs, s.entry(idpActor, in.SourceIP, "user.create", userObject(u.ID), audit.ResultSuccess,
					map[string]any{"login": u.Login, "role": string(role), "source": string(SourceOIDC), "issuer": st.Issuer}))
			} else if prev != role {
				recs = append(recs, s.entry(idpActor, in.SourceIP, "user.role_changed", userObject(u.ID), audit.ResultSuccess,
					map[string]any{"before": string(prev), "after": string(role), "groups": matched}))
			}
			c := Caller{User: u, Session: sess}
			return append(recs, s.entry(c.actor(), in.SourceIP, "auth.login", sessionObject(sess.ID), audit.ResultSuccess,
				map[string]any{"state": string(SessionActive), "method": "oidc", "mfa": asserted, "groups": matched}))
		},
	})
	switch {
	case errors.Is(err, ErrDeactivated):
		f.reason = oidcReasonDeactivated
		return LoginResult{}, f, nil
	case errors.Is(err, ErrLastAdmin):
		f.reason, f.details["role"] = oidcReasonLastAdmin, string(role)
		return LoginResult{}, f, nil
	case errors.Is(err, ErrIdPChanged):
		f.code, f.reason = OIDCFailed, oidcReasonChanged
		return LoginResult{}, f, nil
	case errors.Is(err, ErrLoginTaken):
		// Параллельный первый вход того же пользователя или занятый
		// логин — повторный вход найдёт запись.
		f.code, f.reason = OIDCFailed, oidcReasonLoginConflict
		return LoginResult{}, f, nil
	case errors.Is(err, ErrRoleNotFound):
		f.reason, f.details["role"] = oidcReasonRoleMissing, string(role)
		return LoginResult{}, f, nil
	case err != nil:
		return LoginResult{}, nil, err
	}
	sess.UserID = u.ID
	return LoginResult{Caller: Caller{User: u, Session: sess, SourceIP: in.SourceIP}, Token: token, CSRF: csrf}, nil, nil
}

// claimGroups — группы из утверждения name; ok = false — это не список
// строк в пределах (отказ входа, а не вход без групп).
func claimGroups(c aisecCrypto.IDTokenClaims, name string) ([]string, bool) {
	g, err := c.Strings(name, maxClaimGroups, maxGroupNameLen)
	return g, err == nil
}

// resolveRole — роль по группам: matched — группы из таблицы, roles —
// разные роли совпавших групп по порядку таблицы. Роль одна — role.
func resolveRole(groups []string, table []GroupRole) (role Role, matched, roles []string) {
	return resolveRoleFunc(groups, table, func(a, b string) bool { return a == b })
}

// resolveRoleFunc — resolveRole со сравнением групп same (DN каталога —
// без учёта регистра, ADR-0025, 2.4).
func resolveRoleFunc(groups []string, table []GroupRole, same func(a, b string) bool) (role Role, matched, roles []string) {
	matched, roles = []string{}, []string{}
	for _, gr := range table {
		if !slices.ContainsFunc(groups, func(g string) bool { return same(g, gr.Group) }) {
			continue
		}
		matched = append(matched, gr.Group)
		if !slices.Contains(roles, string(gr.Role)) {
			roles = append(roles, string(gr.Role))
		}
	}
	if len(roles) == 1 {
		role = Role(roles[0])
	}
	return role, matched, roles
}

// mfaAsserted — токен подтверждает второй фактор по настройке: acr из
// списка допустимых или хотя бы одно значение amr из списка (ADR-0025, 3.7).
func mfaAsserted(c aisecCrypto.IDTokenClaims, st IdPSettings) bool {
	if acr, ok := c.String("acr"); ok && slices.Contains(st.RequiredACR, acr) {
		return true
	}
	amr, err := c.Strings("amr", maxClaimAMR, maxIdPListItem)
	if err != nil {
		return false
	}
	for _, v := range amr {
		if slices.Contains(st.RequiredAMR, v) {
			return true
		}
	}
	return false
}

// externalLogins — логин из preferred_username (если он допустим) и
// запасной логин «oidc-<хеш издателя и sub>», если тот занят.
func (s *Service) externalLogins(c aisecCrypto.IDTokenClaims, issuer string) (login, fallback string) {
	if pu, ok := c.String("preferred_username"); ok {
		login, _ = NormalizeLogin(pu)
	}
	h := s.hasher.Sum([]byte(issuer + "\x00" + c.Subject))
	return login, "oidc-" + hex.EncodeToString(h)[:fallbackLoginHex]
}

// oidcFailed пишет auth.login_failed (method oidc) и возвращает *OIDCError.
func (s *Service) oidcFailed(ctx context.Context, in OIDCCallbackInput, f *oidcFailure) error {
	actor := audit.Actor{Type: audit.ActorUser, ID: unknownActor, Name: unknownLogin}
	var obj audit.Object
	if f.user != nil {
		actor = audit.Actor{Type: audit.ActorUser, ID: f.user.ID, Name: f.user.Login}
		obj = userObject(f.user.ID)
	}
	d := map[string]any{"method": "oidc", "reason": f.reason}
	for k, v := range f.details {
		d[k] = v
	}
	if f.subject != "" {
		d["subject"] = f.subject
	}
	if err := s.audit.Record(ctx, s.entry(actor, in.SourceIP, "auth.login_failed", obj, audit.ResultFailure, d)); err != nil {
		return err
	}
	return &OIDCError{Code: f.code, Reason: f.reason}
}
