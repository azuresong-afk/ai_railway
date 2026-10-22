package auth_test

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Второй фактор TOTP (ИАФ.5, задача 2.8).

const testKeyID = "01900000-0000-7000-8000-0000000000d1"

// testBox — ключ данных в памяти (без счётчика шифрований в БД).
func testBox(t testing.TB) *keyring.Box {
	t.Helper()
	p := provider(t)
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	k, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.NewAEAD(k)
	if err != nil {
		t.Fatal(err)
	}
	return keyring.NewStatic(testKeyID, a)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// mfaKeys — приложение-аутентификатор тестов: помнит выданные секреты и
// формирует коды на часах теста.
type mfaKeys struct {
	svc   *auth.Service
	st    auth.Store
	clock *clock

	mu      sync.Mutex
	secrets map[string][]byte
}

func newMFAKeys(svc *auth.Service, st auth.Store, c *clock) *mfaKeys {
	return &mfaKeys{svc: svc, st: st, clock: c, secrets: map[string][]byte{}}
}

// enroll выдаёт секрет и запоминает его.
func (k *mfaKeys) enroll(t *testing.T, c auth.Caller) auth.MFAEnrollment {
	t.Helper()
	en, err := k.svc.StartMFA(context.Background(), c, phrase)
	if err != nil {
		t.Fatalf("выдача секрета: %v", err)
	}
	secret, err := b32.DecodeString(en.Secret)
	if err != nil || len(secret) != aisecCrypto.TOTPSecretSize {
		t.Fatalf("секрет %q: %v", en.Secret, err)
	}
	k.mu.Lock()
	k.secrets[c.User.ID] = secret
	k.mu.Unlock()
	return en
}

// code — код, который сервер примет: часы сдвигаются, пока шаг текущего
// кода не станет больше последнего принятого (защита от повтора).
func (k *mfaKeys) code(t *testing.T, userID string) string {
	t.Helper()
	m, err := k.st.MFA(context.Background(), userID)
	if err != nil {
		t.Fatalf("второй фактор %s: %v", userID, err)
	}
	for k.clock.now().Unix()/30 <= m.LastStep {
		k.clock.add(30 * time.Second)
	}
	return k.codeAt(t, userID, k.clock.now())
}

func (k *mfaKeys) codeAt(t *testing.T, userID string, at time.Time) string {
	t.Helper()
	k.mu.Lock()
	secret := k.secrets[userID]
	k.mu.Unlock()
	c, err := cryptotest.TOTPCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// completeLogin доводит вход до конца: подключает второй фактор
// (mfa_setup) или вводит код (mfa_pending). Сессия до второго фактора
// заменяется полной — возвращаются её токены.
func (k *mfaKeys) completeLogin(t *testing.T, res auth.LoginResult) auth.LoginResult {
	t.Helper()
	ctx := context.Background()
	var (
		r   auth.MFAResult
		err error
	)
	switch res.Caller.Session.State {
	case auth.SessionMFASetup:
		k.enroll(t, res.Caller)
		r, err = k.svc.ConfirmMFA(ctx, res.Caller, k.code(t, res.Caller.User.ID))
		if err == nil && len(r.RecoveryCodes) != auth.RecoveryCodeCount {
			t.Fatalf("кодов восстановления: %d", len(r.RecoveryCodes))
		}
	case auth.SessionMFAPending:
		r, err = k.svc.VerifyMFA(ctx, res.Caller, k.code(t, res.Caller.User.ID), "")
	default:
		return res
	}
	if err != nil || r.Token == "" || r.CSRF == "" || r.Token == res.Token {
		t.Fatalf("второй фактор: %v", err)
	}
	// Прежний токен больше не действует, новый — полная сессия.
	if _, err := k.svc.Authenticate(ctx, res.Token, testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("токен до второго фактора: %v", err)
	}
	got, err := k.svc.Authenticate(ctx, r.Token, testIP)
	if err != nil || got.Session.State != r.Caller.Session.State || got.Session.ID != r.Caller.Session.ID {
		t.Fatalf("сессия после второго фактора: %v %s/%s", err, got.Session.State, r.Caller.Session.State)
	}
	return auth.LoginResult{Caller: got, Token: r.Token, CSRF: r.CSRF}
}

// complete — completeLogin, когда нужна только сессия.
func (k *mfaKeys) complete(t *testing.T, res auth.LoginResult) auth.Caller {
	t.Helper()
	return k.completeLogin(t, res).Caller
}

func TestMFARequiredForAdminRoles(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	res := e.mustLogin(t, "admin", phrase)
	c := res.Caller
	if c.Session.State != auth.SessionMFASetup {
		t.Fatalf("первый вход администратора: %s", c.Session.State)
	}
	// До второго фактора — только свои данные, выход и подключение фактора.
	if !allowed(t, e, c, auth.PermSession) || allowed(t, e, c, auth.PermSelf) || allowed(t, e, c, auth.PermUsersRead) {
		t.Fatal("сессия mfa_setup получила права роли")
	}
	info, err := e.svc.MFAStatus(ctx, c.User)
	if err != nil || info.Enabled || !info.Required {
		t.Fatalf("состояние: %+v %v", info, err)
	}
	en := e.mfa.enroll(t, c)
	if !strings.HasPrefix(en.URI, "otpauth://totp/AISec:admin?") || !strings.Contains(en.URI, "secret="+en.Secret) ||
		!strings.Contains(en.URI, "issuer=AISec") {
		t.Fatalf("ссылка: %s", en.URI)
	}
	if len(en.QR) < 21 || len(en.QR[0]) != len(en.QR) {
		t.Fatalf("QR %dx%d", len(en.QR), len(en.QR[0]))
	}
	// Секрет хранится шифротекстом ключа данных.
	m, err := e.mem.MFA(ctx, adminID)
	if err != nil || m.State != auth.MFAPending || m.KeyID != testKeyID || bytes.Contains(m.Secret, e.mfa.secrets[adminID]) {
		t.Fatalf("хранение секрета: %+v %v", m, err)
	}
	if _, err := e.svc.ConfirmMFA(ctx, c, "000000x"); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("неверный код: %v", err)
	}
	if rec := lastRecord(t, e.mem, "auth.mfa_failed"); rec.Result != audit.ResultFailure {
		t.Fatalf("аудит неудачи: %+v", rec)
	}
	r, err := e.svc.ConfirmMFA(ctx, c, e.mfa.code(t, adminID))
	if err != nil || r.Caller.Session.State != auth.SessionActive || len(r.RecoveryCodes) != auth.RecoveryCodeCount {
		t.Fatalf("подключение: %v %+v", err, r.Caller.Session)
	}
	for _, code := range r.RecoveryCodes {
		if len(code) != 19 || strings.Count(code, "-") != 3 {
			t.Fatalf("формат кода восстановления: %q", code)
		}
	}
	if n := e.mem.UnusedRecoveryCodes(adminID); n != auth.RecoveryCodeCount {
		t.Fatalf("кодов в хранилище: %d", n)
	}
	lastRecord(t, e.mem, "auth.mfa_setup_started")
	lastRecord(t, e.mem, "auth.mfa_enabled")
	// Сессия до второго фактора заменена полной с новыми токенами.
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("токен до второго фактора: %v", err)
	}
	if c := e.mustCaller(t, r.Token); c.Session.State != auth.SessionActive || !allowed(t, e, c, auth.PermUsersRead) {
		t.Fatalf("после подключения: %s", c.Session.State)
	}
	// Повторное подключение — только после сброса.
	if _, err := e.svc.StartMFA(ctx, e.mustCaller(t, r.Token), phrase); !errors.Is(err, auth.ErrMFAEnabled) {
		t.Fatalf("повторное подключение: %v", err)
	}
	// Следующий вход ждёт код.
	res2 := e.mustLogin(t, "admin", phrase)
	if res2.Caller.Session.State != auth.SessionMFAPending {
		t.Fatalf("второй вход: %s", res2.Caller.Session.State)
	}
	if allowed(t, e, res2.Caller, auth.PermSelf) {
		t.Fatal("сессия mfa_pending получила право self")
	}
	c2 := e.mfa.complete(t, res2)
	if c2.Session.State != auth.SessionActive {
		t.Fatalf("после кода: %s", c2.Session.State)
	}
	if rec := lastRecord(t, e.mem, "auth.mfa_verified"); rec.Object.ID != c2.Session.ID {
		t.Fatalf("аудит входа: %+v", rec)
	}
}

func TestMFAOptionalAndPolicyForAll(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	res := e.mustLogin(t, "ivanov", phrase)
	if res.Caller.Session.State != auth.SessionActive {
		t.Fatalf("аналитик без фактора: %s", res.Caller.Session.State)
	}
	// Аналитик может подключить фактор сам из полной сессии — с паролем.
	if _, err := e.svc.StartMFA(ctx, res.Caller, wrongPhrase); !errors.Is(err, auth.ErrWrongPassword) {
		t.Fatalf("выдача секрета без пароля: %v", err)
	}
	if rec := lastRecord(t, e.mem, "auth.password_changed"); rec.Result != audit.ResultFailure {
		t.Fatalf("неверный пароль не засчитан: %+v", rec)
	}
	e.mfa.enroll(t, res.Caller)
	r, err := e.svc.ConfirmMFA(ctx, res.Caller, e.mfa.code(t, userID))
	if err != nil || r.Token != "" || r.Caller.Session.ID != res.Caller.Session.ID {
		t.Fatalf("добровольное подключение: %v %+v", err, r)
	}
	e.mustCaller(t, res.Token)
	if r := e.mustLogin(t, "ivanov", phrase); r.Caller.Session.State != auth.SessionMFAPending {
		t.Fatalf("вход с фактором: %s", r.Caller.Session.State)
	}
	// Политика «для всех ролей»: новый аналитик без фактора — на подключение.
	p := auth.DefaultPolicy()
	p.MFARequiredAll = true
	if err := e.svc.SetPolicy(ctx, e.adminCaller(t), p, "", ""); err != nil {
		t.Fatal(err)
	}
	const other = "01900000-0000-7000-8000-00000000b002"
	e.mem.AddUser(e.user(other, "petrov", auth.RoleAuditor))
	if r := e.mustLogin(t, "petrov", phrase); r.Caller.Session.State != auth.SessionMFASetup {
		t.Fatalf("политика для всех: %s", r.Caller.Session.State)
	}
}

// Код одного шага принимается один раз (ADR-0006).
func TestMFAReplayRejected(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.adminCaller(t)
	res := e.mustLogin(t, "admin", phrase)
	code := e.mfa.code(t, adminID)
	if _, err := e.svc.VerifyMFA(ctx, res.Caller, code, ""); err != nil {
		t.Fatal(err)
	}
	res2 := e.mustLogin(t, "admin", phrase)
	if _, err := e.svc.VerifyMFA(ctx, res2.Caller, code, ""); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("повтор кода: %v", err)
	}
	// Код предыдущего шага (в окне рассинхронизации) — тоже повтор.
	prev := e.mfa.codeAt(t, adminID, e.clock.now().Add(-30*time.Second))
	if _, err := e.svc.VerifyMFA(ctx, res2.Caller, prev, ""); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("код прошлого шага: %v", err)
	}
}

// DM-39 для второго фактора: неверные коды считаются неудачами входа,
// повторный вход по паролю счётчик не сбрасывает.
func TestDM39_MFALockout(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.adminCaller(t)
	threshold := auth.DefaultPolicy().LockoutThreshold
	res := e.mustLogin(t, "admin", phrase)
	for range threshold - 1 {
		if _, err := e.svc.VerifyMFA(ctx, res.Caller, "000000", ""); !errors.Is(err, auth.ErrInvalidCode) {
			t.Fatal(err)
		}
	}
	// Пароль верный — но счётчик неудач до принятого кода не сбрасывается.
	res = e.mustLogin(t, "admin", phrase)
	c := e.mustCaller(t, res.Token)
	if _, err := e.svc.VerifyMFA(ctx, c, "000000", ""); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatal(err)
	}
	if u := e.userByID(t, adminID); !u.Locked(e.clock.now()) {
		t.Fatal("нет блокировки после неверных кодов")
	}
	lastRecord(t, e.mem, "auth.locked")
	if rec := lastRecord(t, e.mem, "auth.sessions_revoked"); rec.Object.ID != adminID {
		t.Fatalf("сессии: %+v", rec)
	}
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия после блокировки: %v", err)
	}
	if n := count(e.mem.Actions(), "auth.mfa_failed"); n != threshold {
		t.Fatalf("auth.mfa_failed: %d", n)
	}
	// Во время блокировки код не проверяется вовсе.
	if _, err := e.svc.VerifyMFA(ctx, c, e.mfa.code(t, adminID), ""); !errors.Is(err, auth.ErrLocked) {
		t.Fatalf("код во время блокировки: %v", err)
	}
}

// Верный код сбрасывает счётчик неудач.
func TestMFASuccessResetsFailures(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.adminCaller(t)
	res := e.mustLogin(t, "admin", phrase)
	if _, err := e.svc.VerifyMFA(ctx, res.Caller, "000000", ""); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatal(err)
	}
	e.mfa.complete(t, res)
	if u := e.userByID(t, adminID); u.FailedAttempts != 0 {
		t.Fatalf("неудач после верного кода: %d", u.FailedAttempts)
	}
}

func TestRecoveryCodes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	res := e.mustLogin(t, "admin", phrase)
	e.mfa.enroll(t, res.Caller)
	conf, err := e.svc.ConfirmMFA(ctx, res.Caller, e.mfa.code(t, adminID))
	if err != nil {
		t.Fatal(err)
	}
	codes := conf.RecoveryCodes
	// Регистр, дефисы и пробелы не важны.
	r := e.mustLogin(t, "admin", phrase)
	typed := " " + strings.ToLower(strings.ReplaceAll(codes[3], "-", " ")) + " "
	v, err := e.svc.VerifyMFA(ctx, r.Caller, "", typed)
	if err != nil || v.Caller.Session.State != auth.SessionActive {
		t.Fatalf("код восстановления: %v", err)
	}
	rec := lastRecord(t, e.mem, "auth.recovery_code_used")
	if d, _ := rec.Details.(map[string]any); d["recovery_codes_left"] != auth.RecoveryCodeCount-1 {
		t.Fatalf("осталось кодов: %+v", rec.Details)
	}
	// Код одноразовый.
	r = e.mustLogin(t, "admin", phrase)
	if _, err := e.svc.VerifyMFA(ctx, r.Caller, "", codes[3]); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("повтор кода восстановления: %v", err)
	}
	// Неразборчивый код — тоже неудача (разбор — TestNormalizeRecoveryCode).
	for _, bad := range []string{strings.Repeat("A", 65), "АААА-АААА-АААА-АААА"} {
		if _, err := e.svc.VerifyMFA(ctx, r.Caller, "", bad); !errors.Is(err, auth.ErrInvalidCode) {
			t.Fatalf("код %q: %v", bad, err)
		}
	}
	// Новые коды — по коду TOTP из полной сессии; прежние гасятся.
	full := e.mfa.complete(t, e.mustLogin(t, "admin", phrase))
	if _, err := e.svc.RegenerateRecoveryCodes(ctx, full, "000000"); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("неверный код при перевыпуске: %v", err)
	}
	fresh, err := e.svc.RegenerateRecoveryCodes(ctx, full, e.mfa.code(t, adminID))
	if err != nil || len(fresh) != auth.RecoveryCodeCount {
		t.Fatalf("перевыпуск: %v", err)
	}
	lastRecord(t, e.mem, "auth.recovery_codes_regenerated")
	if n := e.mem.UnusedRecoveryCodes(adminID); n != auth.RecoveryCodeCount {
		t.Fatalf("действующих кодов: %d", n)
	}
	r = e.mustLogin(t, "admin", phrase)
	if _, err := e.svc.VerifyMFA(ctx, r.Caller, "", codes[0]); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("старый код после перевыпуска: %v", err)
	}
	if _, err := e.svc.VerifyMFA(ctx, r.Caller, "", fresh[0]); err != nil {
		t.Fatalf("новый код: %v", err)
	}
}

// Действия второго фактора доступны только в своих состояниях сессии.
func TestMFAStateGating(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	full := e.adminCaller(t)
	if _, err := e.svc.VerifyMFA(ctx, full, e.mfa.code(t, adminID), ""); !errors.Is(err, auth.ErrSessionState) {
		t.Fatalf("код в полной сессии: %v", err)
	}
	pending := e.mustLogin(t, "admin", phrase).Caller
	if _, err := e.svc.StartMFA(ctx, pending, phrase); !errors.Is(err, auth.ErrSessionState) {
		t.Fatalf("выдача секрета до кода: %v", err)
	}
	if _, err := e.svc.ConfirmMFA(ctx, pending, "123456"); !errors.Is(err, auth.ErrSessionState) {
		t.Fatalf("подтверждение до кода: %v", err)
	}
	if _, err := e.svc.RegenerateRecoveryCodes(ctx, pending, "123456"); !errors.Is(err, auth.ErrSessionState) {
		t.Fatalf("перевыпуск до кода: %v", err)
	}
	// Подтверждение без выданного секрета.
	analyst := e.mustLogin(t, "ivanov", phrase).Caller
	if _, err := e.svc.ConfirmMFA(ctx, analyst, "123456"); !errors.Is(err, auth.ErrMFANotEnabled) {
		t.Fatalf("подтверждение без секрета: %v", err)
	}
	if _, err := e.svc.RegenerateRecoveryCodes(ctx, analyst, "123456"); !errors.Is(err, auth.ErrMFANotEnabled) {
		t.Fatalf("перевыпуск без фактора: %v", err)
	}
}

// Сессия до второго фактора живёт 5 минут, сессия подключения — 15.
func TestMFASessionTTL(t *testing.T) {
	e := newEnv(t)
	setup := e.mustLogin(t, "admin", phrase)
	e.clock.add(14 * time.Minute)
	e.mustCaller(t, setup.Token)
	e.clock.add(time.Minute)
	if _, err := e.caller(t, setup.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия mfa_setup через 15 минут: %v", err)
	}
	e.adminCaller(t)
	pending := e.mustLogin(t, "admin", phrase)
	e.clock.add(5 * time.Minute)
	if _, err := e.caller(t, pending.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия mfa_pending через 5 минут: %v", err)
	}
	lastRecord(t, e.mem, "auth.session_expired")
}

// Временный пароль меняется после второго фактора.
func TestMFAThenPasswordChange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.adminCaller(t)
	u := e.userByID(t, adminID)
	u.MustChangePassword = true
	e.mem.AddUser(u)
	c := e.mfa.complete(t, e.mustLogin(t, "admin", phrase))
	if c.Session.State != auth.SessionPasswordChange || !allowed(t, e, c, auth.PermSelf) {
		t.Fatalf("после кода с временным паролем: %s", c.Session.State)
	}
	if err := e.svc.ChangePassword(ctx, c, phrase, phrase2); err != nil {
		t.Fatal(err)
	}
	if r := e.mustLogin(t, "admin", phrase2); r.Caller.Session.State != auth.SessionMFAPending {
		t.Fatalf("вход с новым паролем: %s", r.Caller.Session.State)
	}
}

func TestResetMFA(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const second = "01900000-0000-7000-8000-00000000a002"
	e.mem.AddUser(e.user(second, "admin2", auth.RoleSecurityAdmin))
	admin := e.adminCaller(t)
	target := e.mfa.completeLogin(t, e.mustLogin(t, "admin2", phrase))
	if err := e.svc.ResetMFA(ctx, admin, adminID); !errors.Is(err, auth.ErrSelf) {
		t.Fatalf("сброс своего фактора: %v", err)
	}
	if err := e.svc.ResetMFA(ctx, admin, userID); !errors.Is(err, auth.ErrMFANotEnabled) {
		t.Fatalf("сброс без фактора: %v", err)
	}
	if err := e.svc.ResetMFA(ctx, admin, "01900000-0000-7000-8000-00000000ffff"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("сброс несуществующему: %v", err)
	}
	if err := e.svc.ResetMFA(ctx, admin, second); err != nil {
		t.Fatal(err)
	}
	rec := lastRecord(t, e.mem, "auth.mfa_reset")
	if d, _ := rec.Details.(map[string]any); rec.Object.ID != second || d["previous_state"] != "enabled" || d["revoked_sessions"] != 1 {
		t.Fatalf("аудит сброса: %+v", rec)
	}
	if _, err := e.caller(t, target.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия после сброса фактора: %v", err)
	}
	if n := e.mem.UnusedRecoveryCodes(second); n != 0 {
		t.Fatalf("коды после сброса: %d", n)
	}
	if r := e.mustLogin(t, "admin2", phrase); r.Caller.Session.State != auth.SessionMFASetup {
		t.Fatalf("вход после сброса: %s", r.Caller.Session.State)
	}
}

// Без ключа данных роли с обязательным фактором не входят, остальные — входят.
func TestMFAUnavailableWithoutKey(t *testing.T) {
	mem := authtest.NewMemory()
	svc, err := auth.NewService(context.Background(), mem, mem, provider(t), auth.WithPasswordHasher(&authtest.Hasher{}))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{svc: svc, mem: mem, clock: &clock{t: time.Now()}}
	mem.AddUser(e.user(adminID, "admin", auth.RoleSecurityAdmin))
	mem.AddUser(e.user(userID, "ivanov", auth.RoleAnalyst))
	if _, err := e.login(t, "admin", phrase); !errors.Is(err, auth.ErrMFAUnavailable) {
		t.Fatalf("вход администратора без ключа: %v", err)
	}
	res := e.mustLogin(t, "ivanov", phrase)
	if _, err := svc.StartMFA(context.Background(), res.Caller, phrase); !errors.Is(err, auth.ErrMFAUnavailable) {
		t.Fatalf("подключение без ключа: %v", err)
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	for in, want := range map[string]string{
		"ABCD-EFGH-IJKL-MNOP":       "ABCDEFGHIJKLMNOP",
		"abcd efgh ijkl mnop":       "ABCDEFGHIJKLMNOP",
		"  AB-CD-EF-GH-IJ-KL-MN-OP": "ABCDEFGHIJKLMNOP",
		"2345-6723-4567-2345":       "2345672345672345",
	} {
		if got, ok := auth.NormalizeRecoveryCode(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "ABCD-EFGH-IJKL-MNO", "ABCD-EFGH-IJKL-MNOPQ", "ABCD-EFGH-IJKL-MNO1",
		"ABCD-EFGH-IJKL-MNO0", "ABCD_EFGH_IJKL_MNOP", "ABCD-EFGH-IJKL-MNOÐ", strings.Repeat("-", 60) + "ABCDEFGHIJKLMNOP"} {
		if got, ok := auth.NormalizeRecoveryCode(in); ok {
			t.Errorf("принят %q → %q", in, got)
		}
	}
}

func FuzzNormalizeRecoveryCode(f *testing.F) {
	for _, s := range []string{"ABCD-EFGH-IJKL-MNOP", "abcd efgh ijkl mnop", "", "АБВГ", strings.Repeat("A", 70)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, ok := auth.NormalizeRecoveryCode(in)
		if !ok {
			return
		}
		if len(in) > 64 || len(got) != 16 {
			t.Fatalf("%q → %q", in, got)
		}
		for _, r := range got {
			if (r < 'A' || r > 'Z') && (r < '2' || r > '7') {
				t.Fatalf("%q → %q: символ %q", in, got, r)
			}
		}
		if again, ok := auth.NormalizeRecoveryCode(got); !ok || again != got {
			t.Fatalf("не идемпотентно: %q → %q → %q", in, got, again)
		}
	})
}

// УПД.4 (хранилище в памяти, как PGStore): входы по одному паролю
// вытесняют только сессии до второго фактора.
func TestPreMFASessionsDoNotEvictFull(t *testing.T) {
	e := newEnv(t)
	e.adminCaller(t)
	full := e.mfa.completeLogin(t, e.mustLogin(t, "admin", phrase))
	var tokens []string
	for range auth.DefaultPolicy().SessionMaxPerUser + 2 {
		e.clock.add(time.Second)
		tokens = append(tokens, e.mustLogin(t, "admin", phrase).Token)
	}
	e.mustCaller(t, full.Token)
	if _, err := e.caller(t, tokens[0]); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("старейшая сессия до второго фактора: %v", err)
	}
	e.mustCaller(t, tokens[len(tokens)-1])
}
