package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

const (
	// SessionMaxLifetime — абсолютный срок сессии независимо от активности.
	SessionMaxLifetime = 12 * time.Hour
	// touchInterval — как часто отмечается активность сессии: время
	// бездействия считается с точностью до этого интервала.
	touchInterval = time.Minute
	// unknownActor — ID субъекта в аудите, когда учётная запись не найдена.
	unknownActor = "-"
	// unknownLogin — имя субъекта в аудите, если учётной записи с введённым
	// логином нет: в поле логина по ошибке вводят пароль, и его нельзя
	// оставлять в неизменяемом журнале.
	unknownLogin = "(неизвестный логин)"
)

// Причины отказа во входе для журнала аудита (наружу не выдаются).
const (
	reasonUnknownLogin  = "unknown_login"
	reasonWrongPassword = "wrong_password"
	reasonLocked        = "locked"
	reasonDeactivated   = "deactivated"
	reasonTempExpired   = "temp_password_expired"
	// reasonChanged — запись деактивирована или пароль сменён во время проверки.
	reasonChanged  = "changed_during_login"
	reasonBadInput = "bad_input"
	// reasonExternal — вход паролем во внешнюю запись (IdP, ADR-0025).
	reasonExternal = "external_user"
)

// Caller — аутентифицированная сессия консоли и её пользователь.
type Caller struct {
	User    User
	Session Session
	// SourceIP — адрес клиента текущего запроса (для аудита).
	SourceIP netip.Addr
	// Token — токен API запроса (задача 2.10); nil — сессия консоли.
	Token *APIToken
}

func (c Caller) actor() audit.Actor {
	if c.Token != nil {
		return c.Token.actor(c.User)
	}
	return audit.Actor{Type: audit.ActorUser, ID: c.User.ID, Name: c.User.Login}
}

// Service — вход, сессии и учётные записи консоли (ИАФ.1–4, УПД.4–5, ЗИ.4).
// Безопасен для одновременного использования.
type Service struct {
	store  Store
	audit  Auditor
	hasher aisecCrypto.Hasher
	pw     aisecCrypto.PasswordHasher
	random aisecCrypto.Random
	now    func() time.Time
	orgID  string
	// provider — криптопрофиль: проверка кодов TOTP (ИАФ.5).
	provider aisecCrypto.Provider
	// box — ключ данных для секретов TOTP; nil — второй фактор недоступен.
	box SecretBox
	// dummy — хеш случайного пароля с параметрами по умолчанию: проверяется
	// при входе с неизвестным логином, чтобы время ответа не выдавало,
	// есть ли учётная запись (ADR-0006).
	dummy string
	// roles — свои роли (задача 2.9); nil — только предустановленные.
	roles RoleStore
	// tokens — токены API (задача 2.10); nil — токены не принимаются.
	tokens APITokenStore
	// idp и oidc — вход через внешний IdP (задача 4.17, ADR-0025); nil —
	// не подключён.
	idp  IdPStore
	oidc *oidc.Client
	// ldapStore и ldap — вход через каталог LDAP (задача 4.16, ADR-0025);
	// nil — не подключён.
	ldapStore LDAPStore
	ldap      *ldap.Client
}

// Option настраивает Service.
type Option func(*Service)

// WithClock подменяет часы (тесты).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// WithPasswordHasher подменяет хеширование паролей (тесты: Argon2id с
// рабочими параметрами под детектором гонок слишком медленный).
func WithPasswordHasher(h aisecCrypto.PasswordHasher) Option {
	return func(s *Service) { s.pw = h }
}

// NewService создаёт сервис на криптопрофиле p. Вычисляет фиктивный хеш,
// поэтому занимает время одного хеширования пароля.
func NewService(ctx context.Context, st Store, a Auditor, p aisecCrypto.Provider, opts ...Option) (*Service, error) {
	if st == nil || a == nil || p == nil {
		return nil, errors.New("сервис входа: нет хранилища, журнала аудита или криптопрофиля")
	}
	s := &Service{store: st, audit: a, now: time.Now, orgID: audit.DefaultOrgID, provider: p}
	var err error
	if s.hasher, err = p.Hasher(); err != nil {
		return nil, err
	}
	if s.pw, err = p.PasswordHasher(); err != nil {
		return nil, err
	}
	if s.random, err = p.Random(); err != nil {
		return nil, err
	}
	for _, o := range opts {
		o(s)
	}
	b, err := aisecCrypto.RandomBytes(s.random, tokenBytes)
	if err != nil {
		return nil, err
	}
	if s.dummy, err = s.pw.Hash(ctx, b); err != nil {
		return nil, fmt.Errorf("сервис входа: фиктивный хеш: %w", err)
	}
	return s, nil
}

// clock — текущее время с точностью PostgreSQL (микросекунды): курсоры и
// сравнения сроков одинаковы в памяти и в БД.
func (s *Service) clock() time.Time { return s.now().UTC().Truncate(time.Microsecond) }

func (s *Service) entry(by audit.Actor, ip netip.Addr, action string, obj audit.Object, res audit.Result, details map[string]any) audit.Entry {
	e := audit.Entry{OrgID: s.orgID, Actor: by, SourceIP: ip, Action: action, Object: obj, Result: res}
	// nil-карта в интерфейсе сериализуется в null, а журнал ждёт объект.
	if details != nil {
		e.Details = details
	}
	return e
}

func userObject(id string) audit.Object { return audit.Object{Type: "user", ID: id} }

func sessionObject(id string) audit.Object { return audit.Object{Type: "session", ID: id} }

// LoginInput — попытка входа.
type LoginInput struct {
	Login     string
	Password  string
	SourceIP  netip.Addr
	UserAgent string
}

// LoginResult — успешный вход: токены выдаются клиенту один раз.
type LoginResult struct {
	Caller Caller
	Token  string
	CSRF   string
}

// Login проверяет логин и пароль и открывает сессию. Любой отказ —
// ErrInvalidCredentials; причина пишется в журнал аудита (auth.login_failed),
// блокировка после неудач — ещё и auth.locked (ИАФ.4, DM-39).
func (s *Service) Login(ctx context.Context, in LoginInput) (LoginResult, error) {
	now := s.clock()
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return LoginResult{}, err
	}
	login, valid := NormalizeLogin(in.Login)
	var u User
	found := false
	if valid {
		u, err = s.store.UserByLogin(ctx, s.orgID, login)
		switch {
		case err == nil:
			found = true
		case !errors.Is(err, ErrNotFound):
			return LoginResult{}, err
		}
	}
	// Логин без локальной записи или запись каталога — проверка в каталоге
	// LDAP, если вход через него включён (ADR-0025, 2). Локальная запись с
	// тем же логином каталогом не перекрывается: её проверяет только пароль
	// консоли.
	if valid && (!found || u.External()) {
		st, secret, ok, err := s.activeLDAP(ctx)
		if err != nil {
			return LoginResult{}, err
		}
		if ok {
			return s.ldapLogin(ctx, in, login, st, secret, pol, now)
		}
	}
	// Пароль проверяется всегда — с хешем записи или с фиктивным, — чтобы
	// время ответа не зависело от того, есть ли запись и в каком она состоянии.
	hash := s.dummy
	if found && u.Status == StatusActive && !u.External() {
		hash = u.PasswordHash
	}
	pwOK, needsRehash := false, false
	reason := ""
	if n := len(in.Password); n < aisecCrypto.MinPasswordLen || n > aisecCrypto.MaxPasswordLen {
		reason = reasonBadInput
	} else if pwOK, needsRehash, err = s.pw.Verify(ctx, []byte(in.Password), hash); err != nil {
		return LoginResult{}, fmt.Errorf("проверка пароля: %w", err)
	}
	switch {
	case reason != "":
	case !found:
		reason = reasonUnknownLogin
	case u.External():
		// У внешней записи нет пароля консоли: вход — только через IdP или
		// каталог (здесь — когда вход через каталог отключён).
		reason = reasonExternal
	case u.Status != StatusActive:
		reason = reasonDeactivated
	case u.Locked(now):
		reason = reasonLocked
	case !pwOK:
		reason = reasonWrongPassword
	case u.MustChangePassword && !u.TempPasswordExpires.IsZero() && !now.Before(u.TempPasswordExpires):
		reason = reasonTempExpired
	}
	if reason != "" {
		return LoginResult{}, s.loginFailed(ctx, in, login, found, u, reason, pol, now)
	}
	// Хеш с устаревшими параметрами пересчитывается после успешного входа.
	rehash := ""
	if needsRehash {
		if rehash, err = s.pw.Hash(ctx, []byte(in.Password)); err != nil {
			return LoginResult{}, err
		}
	}
	// Второй фактор (ИАФ.5): подключён — сессия ждёт код; обязателен, но не
	// подключён — сессия только для его подключения. Счётчик неудач до
	// принятого кода не сбрасывается: иначе знающий пароль перебирал бы коды
	// TOTP, входя заново перед каждой блокировкой.
	mfaOn, err := s.mfaEnabled(ctx, u.ID)
	if err != nil {
		return LoginResult{}, err
	}
	mfaReq, err := s.mfaRequired(ctx, u, pol)
	if err != nil {
		return LoginResult{}, err
	}
	var state SessionState
	switch {
	case mfaOn:
		state = SessionMFAPending
	case mfaReq:
		state = SessionMFASetup
	default:
		state = afterMFA(u, pol, now)
	}
	if state == SessionMFAPending || state == SessionMFASetup {
		if s.box == nil {
			return LoginResult{}, ErrMFAUnavailable
		}
	}
	res, err := s.openSession(ctx, u, state, in, pol,
		&LoginCheck{VerifiedHash: hash, Rehash: rehash, Now: now, KeepFailures: mfaOn})
	// Пока проверялся пароль, запись заблокировали параллельные неудачи,
	// деактивировали или сменили ей пароль: вход не засчитывается.
	if errors.Is(err, ErrLocked) {
		return LoginResult{}, s.loginFailed(ctx, in, login, found, u, reasonLocked, pol, now)
	}
	if errors.Is(err, ErrInvalidCredentials) {
		return LoginResult{}, s.loginFailed(ctx, in, login, found, u, reasonChanged, pol, now)
	}
	return res, err
}

// loginFailed пишет неудачу в аудит и, для неверного пароля, считает её для
// блокировки — в одной транзакции с записями аудита. Введённая строка
// попадает в журнал, только если такая учётная запись есть: иначе это может
// быть пароль, введённый в поле логина.
func (s *Service) loginFailed(ctx context.Context, in LoginInput, login string, found bool, u User,
	reason string, pol Policy, now time.Time) error {
	actor := audit.Actor{Type: audit.ActorUser, ID: unknownActor, Name: unknownLogin}
	var obj audit.Object
	if found {
		actor = audit.Actor{Type: audit.ActorUser, ID: u.ID, Name: login}
		obj = userObject(u.ID)
	}
	failed := func(details map[string]any) audit.Entry {
		return s.entry(actor, in.SourceIP, "auth.login_failed", obj, audit.ResultFailure, details)
	}
	if reason != reasonWrongPassword {
		if err := s.audit.Record(ctx, failed(map[string]any{"reason": reason})); err != nil {
			return err
		}
		return ErrInvalidCredentials
	}
	until, err := s.lockUntil(ctx, u, pol, now)
	if err != nil {
		return err
	}
	_, _, err = s.store.RecordFailure(ctx, u.ID, now, pol.LockoutThreshold, until,
		func(attempts int, lockedNow bool) []audit.Entry {
			recs := []audit.Entry{failed(map[string]any{"reason": reason, "attempts": attempts})}
			if lockedNow {
				recs = append(recs, s.entry(actor, in.SourceIP, "auth.locked", obj, audit.ResultSuccess,
					map[string]any{"threshold": pol.LockoutThreshold, "lockout_minutes": lockMinutes(until, now)}))
			}
			return recs
		})
	if err != nil {
		return err
	}
	return ErrInvalidCredentials
}

// lastAdminLockout — блокировка администратора безопасности, которого
// некому разблокировать, при бессрочной блокировке в настройках (В7 ревью 2.r2).
const lastAdminLockout = 15 * time.Minute

// lockUntil — конец блокировки u, если она наступит сейчас; нулевое — до
// разблокировки администратором. Администратора безопасности, кроме
// которого нет другого активного и не заблокированного, бессрочно не
// блокируем: снять блокировку было бы некому, и подбор пароля по известному
// логину закрыл бы консоль. Ему — lastAdminLockout.
func (s *Service) lockUntil(ctx context.Context, u User, pol Policy, now time.Time) (time.Time, error) {
	if pol.LockoutMinutes > 0 {
		return now.Add(time.Duration(pol.LockoutMinutes) * time.Minute), nil
	}
	if u.Role != RoleSecurityAdmin {
		return time.Time{}, nil
	}
	n, err := s.store.UnlockedSecurityAdmins(ctx, s.orgID, u.ID, now)
	if err != nil {
		return time.Time{}, err
	}
	if n == 0 {
		return now.Add(lastAdminLockout), nil
	}
	return time.Time{}, nil
}

// lockMinutes — длительность блокировки для аудита; 0 — бессрочная.
func lockMinutes(until, now time.Time) int {
	if until.IsZero() {
		return 0
	}
	return int(until.Sub(now) / time.Minute)
}

func (s *Service) openSession(ctx context.Context, u User, state SessionState, in LoginInput, pol Policy, check *LoginCheck) (LoginResult, error) {
	now := check.Now
	token, tokenHash, err := newToken(s.random, s.hasher)
	if err != nil {
		return LoginResult{}, err
	}
	csrf, csrfHash, err := newToken(s.random, s.hasher)
	if err != nil {
		return LoginResult{}, err
	}
	id, err := store.NewUUIDv7(now, s.random)
	if err != nil {
		return LoginResult{}, err
	}
	sess := Session{
		ID: string(id), UserID: u.ID, TokenHash: tokenHash, CSRFHash: csrfHash, State: state,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(SessionMaxLifetime),
		SourceIP: in.SourceIP, UserAgent: cleanUserAgent(in.UserAgent),
	}
	c := Caller{User: u, Session: sess, SourceIP: in.SourceIP}
	rec := s.entry(c.actor(), in.SourceIP, "auth.login", sessionObject(sess.ID), audit.ResultSuccess,
		map[string]any{"state": string(state)})
	if err := s.store.CreateSession(ctx, sess, pol.SessionMaxPerUser, check, rec); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Caller: c, Token: token, CSRF: csrf}, nil
}

// passiveKey — ключ контекста проверки сессии без отметки активности.
type passiveKey struct{}

// WithoutActivity — контекст повторной проверки сессии, которая не
// считается действием пользователя: тики открытого потока обновления
// дашборда (перенесено из этапа 3, задача 4.5). Срок и бездействие
// проверяются как обычно, активность не отмечается — открытая вкладка не
// продлевает сессию, по простою поток закрывается вместе с ней.
func WithoutActivity(ctx context.Context) context.Context {
	return context.WithValue(ctx, passiveKey{}, true)
}

// Authenticate находит сессию по токену из cookie (УПД.4): завершает
// истёкшую по абсолютному сроку или бездействию, отмечает активность (кроме
// контекста WithoutActivity). Пароль, истёкший во время сессии, переводит
// её в SessionPasswordChange.
func (s *Service) Authenticate(ctx context.Context, token string, ip netip.Addr) (Caller, error) {
	h, err := hashToken(s.hasher, token)
	if err != nil {
		return Caller{}, ErrUnauthenticated
	}
	sess, u, err := s.store.SessionByToken(ctx, h)
	if errors.Is(err, ErrNotFound) {
		return Caller{}, ErrUnauthenticated
	}
	if err != nil {
		return Caller{}, err
	}
	now := s.clock()
	if u.Status != StatusActive {
		return Caller{}, ErrUnauthenticated
	}
	if !now.Before(sess.ExpiresAt) {
		return Caller{}, s.expire(ctx, u, sess, RevokeExpired, ip, now)
	}
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return Caller{}, err
	}
	if now.Sub(sess.LastSeenAt) >= time.Duration(pol.SessionIdleMinutes)*time.Minute {
		return Caller{}, s.expire(ctx, u, sess, RevokeIdle, ip, now)
	}
	if passive, _ := ctx.Value(passiveKey{}).(bool); !passive && now.Sub(sess.LastSeenAt) >= touchInterval {
		if err := s.store.TouchSession(ctx, sess.ID, now); err != nil {
			return Caller{}, err
		}
		sess.LastSeenAt = now
	}
	// Сессия до второго фактора живёт недолго: код вводят сразу после пароля.
	if ttl := mfaStateTTL(sess.State); ttl > 0 && now.Sub(sess.CreatedAt) >= ttl {
		return Caller{}, s.expire(ctx, u, sess, RevokeExpired, ip, now)
	}
	// Второй фактор стал обязателен полной сессии, которая его не проходила
	// (роли добавили права на изменение, включён mfa_required_all): права
	// роли без фактора не действуют, сессия завершается, вход — заново
	// через второй фактор (В6 ревью 2.r2, ADR-0013 п. 6).
	if sess.State == SessionActive && !sess.MFAVerified {
		req, err := s.mfaRequired(ctx, u, pol)
		if err != nil {
			return Caller{}, err
		}
		if req {
			return Caller{}, s.expire(ctx, u, sess, RevokeMFARequired, ip, now)
		}
	}
	if exp := u.PasswordExpires(pol); sess.State == SessionActive && !exp.IsZero() && !now.Before(exp) {
		sess.State = SessionPasswordChange
	}
	return Caller{User: u, Session: sess, SourceIP: ip}, nil
}

// expire завершает сессию по сроку или бездействию (auth.session_expired).
func (s *Service) expire(ctx context.Context, u User, sess Session, reason string, ip netip.Addr, now time.Time) error {
	c := Caller{User: u, Session: sess}
	rec := s.entry(c.actor(), ip, "auth.session_expired", sessionObject(sess.ID), audit.ResultSuccess,
		map[string]any{"reason": reason})
	if err := s.store.RevokeSession(ctx, sess.ID, reason, now, rec); err != nil {
		return err
	}
	return ErrUnauthenticated
}

// CheckCSRF сверяет CSRF-токен из заголовка с токеном сессии за постоянное время.
func (s *Service) CheckCSRF(c Caller, header string) bool {
	h, err := hashToken(s.hasher, header)
	if err != nil {
		return false
	}
	return aisecCrypto.Equal(h, c.Session.CSRFHash)
}

// Logout завершает текущую сессию (auth.logout).
func (s *Service) Logout(ctx context.Context, c Caller) error {
	rec := s.entry(c.actor(), c.SourceIP, "auth.logout", sessionObject(c.Session.ID), audit.ResultSuccess, nil)
	return s.store.RevokeSession(ctx, c.Session.ID, RevokeLogout, s.clock(), rec)
}

// ChangePassword меняет свой пароль (ИАФ.2, ИАФ.3): текущий пароль,
// политика, история. Остальные сессии пользователя завершаются, текущая
// получает полный доступ. Неверный текущий пароль считается неудачной
// попыткой (ИАФ.4): при блокировке завершаются все сессии. Пока запись
// заблокирована, пароль не меняется и текущий не проверяется (ErrLocked):
// иначе держатель чужой сессии перебирал бы пароль и во время блокировки.
func (s *Service) ChangePassword(ctx context.Context, c Caller, current, next string) error {
	if c.User.External() {
		return ErrExternalUser
	}
	now := s.clock()
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return err
	}
	if c.User.Locked(now) {
		return ErrLocked
	}
	ok, err := s.verify(ctx, current, c.User.PasswordHash)
	if err != nil {
		return err
	}
	if !ok {
		return s.wrongCurrentPassword(ctx, c, pol, now)
	}
	if err := pol.CheckPassword(next, c.User.Login); err != nil {
		return err
	}
	if err := s.checkHistory(ctx, c.User, next, pol); err != nil {
		return err
	}
	h, err := s.pw.Hash(ctx, []byte(next))
	if err != nil {
		return err
	}
	rec := s.entry(c.actor(), c.SourceIP, "auth.password_changed", userObject(c.User.ID), audit.ResultSuccess, nil)
	return s.store.SetPassword(ctx, PasswordChange{
		UserID: c.User.ID, NewHash: h, ExpectHash: c.User.PasswordHash, Now: now, Keep: pol.PasswordHistory,
		KeepSession: c.Session.ID, RevokeReason: RevokePasswordChanged,
	}, rec)
}

// verify — проверка пароля; недопустимая длина — просто несовпадение.
func (s *Service) verify(ctx context.Context, password, hash string) (bool, error) {
	if n := len(password); n < aisecCrypto.MinPasswordLen || n > aisecCrypto.MaxPasswordLen {
		return false, nil
	}
	ok, _, err := s.pw.Verify(ctx, []byte(password), hash)
	return ok, err
}

func (s *Service) wrongCurrentPassword(ctx context.Context, c Caller, pol Policy, now time.Time) error {
	return s.wrongPasswordFor(ctx, c, pol, now, "auth.password_changed")
}

// wrongPasswordFor — неверный текущий пароль перед действием action: запись
// неудачи action, счётчик ИАФ.4, на пороге — блокировка и завершение сессий.
func (s *Service) wrongPasswordFor(ctx context.Context, c Caller, pol Policy, now time.Time, action string) error {
	until, err := s.lockUntil(ctx, c.User, pol, now)
	if err != nil {
		return err
	}
	attempts, _, err := s.store.RecordFailure(ctx, c.User.ID, now, pol.LockoutThreshold, until,
		func(attempts int, lockedNow bool) []audit.Entry {
			recs := []audit.Entry{s.entry(c.actor(), c.SourceIP, action, userObject(c.User.ID),
				audit.ResultFailure, map[string]any{"reason": reasonWrongPassword, "attempts": attempts})}
			if lockedNow {
				recs = append(recs, s.entry(c.actor(), c.SourceIP, "auth.locked", userObject(c.User.ID), audit.ResultSuccess,
					map[string]any{"threshold": pol.LockoutThreshold, "lockout_minutes": lockMinutes(until, now)}))
			}
			return recs
		})
	if err != nil {
		return err
	}
	// На пороге и выше завершаются все сессии пользователя, в том числе эта.
	if attempts >= pol.LockoutThreshold {
		rec := s.entry(c.actor(), c.SourceIP, "auth.sessions_revoked", userObject(c.User.ID), audit.ResultSuccess,
			map[string]any{"reason": RevokeLocked})
		if _, err := s.store.RevokeUserSessions(ctx, c.User.ID, RevokeLocked, now, nil, rec); err != nil {
			return err
		}
	}
	return ErrWrongPassword
}

// checkHistory — новый пароль не совпадает с текущим и с последними
// pol.PasswordHistory прежними (ИАФ.2). Сравнение — проверкой по хешам.
func (s *Service) checkHistory(ctx context.Context, u User, next string, pol Policy) error {
	hashes := []string{u.PasswordHash}
	if pol.PasswordHistory > 0 {
		old, err := s.store.PasswordHistory(ctx, u.ID, pol.PasswordHistory)
		if err != nil {
			return err
		}
		hashes = append(hashes, old...)
	}
	for _, h := range hashes {
		ok, _, err := s.pw.Verify(ctx, []byte(next), h)
		if err != nil && !errors.Is(err, aisecCrypto.ErrInvalidPasswordHash) {
			return err
		}
		if ok {
			if pol.PasswordHistory == 0 {
				return &PasswordError{"Новый пароль совпадает с текущим."}
			}
			return &PasswordError{fmt.Sprintf("Новый пароль совпадает с текущим или с одним из %d предыдущих.", pol.PasswordHistory)}
		}
	}
	return nil
}

// ErrReauthentication — повторная проверка перед действием не пройдена:
// неверный пароль или код (неудача ИАФ.4 уже учтена).
var ErrReauthentication = errors.New("повторная проверка не пройдена")

// Reauthenticate — повторная проверка перед необратимым действием action
// вне internal/auth: сокращение сроков хранения событий (В13 ревью 2.r3a).
// Правила те же, что у выпуска токена (В8): ровно одно из password и code.
func (s *Service) Reauthenticate(ctx context.Context, c Caller, password, code, action string) error {
	return s.reauthenticate(ctx, c, password, code, action)
}

// reauthenticate — повторная проверка владельца полной сессии перед
// действием action (В8 ревью 2.r2): текущий пароль или код TOTP, ровно
// одно из двух. Неверное значение — неудачная попытка ИАФ.4 с общим
// счётчиком (на пороге — блокировка и завершение сессий), ответ —
// ErrReauthentication.
func (s *Service) reauthenticate(ctx context.Context, c Caller, password, code, action string) error {
	// У внешней записи нет пароля и TOTP консоли (ADR-0025, 3.10).
	if c.User.External() {
		return ErrExternalUser
	}
	if (password == "") == (code == "") {
		return &InputError{"password", "Введите текущий пароль или код из приложения-аутентификатора."}
	}
	if c.Session.State != SessionActive {
		return ErrSessionState
	}
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return err
	}
	now := s.clock()
	if c.User.Locked(now) {
		return ErrLocked
	}
	if password != "" {
		ok, err := s.verify(ctx, password, c.User.PasswordHash)
		if err != nil {
			return err
		}
		if !ok {
			if err := s.wrongPasswordFor(ctx, c, pol, now, action); !errors.Is(err, ErrWrongPassword) {
				return err
			}
			return ErrReauthentication
		}
		return nil
	}
	if s.box == nil {
		return ErrMFAUnavailable
	}
	st := MFAStep{Kind: MFAStepReauth, Now: now}
	st.Check = s.totpCheck(code, now)
	if err := s.prepare(ctx, &st, c, pol, "reauth"); err != nil {
		return err
	}
	err = s.store.MFAStep(ctx, st, audit.Entry{})
	switch {
	case errors.Is(err, ErrInvalidCode):
		return ErrReauthentication
	case errors.Is(err, ErrMFANotEnabled):
		return &InputError{"code", "Второй фактор не подключён: введите текущий пароль."}
	}
	return err
}
