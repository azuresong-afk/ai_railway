package auth_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Учётные записи и пароли в тестах синтетические.
const (
	adminID     = "01900000-0000-7000-8000-00000000a001"
	userID      = "01900000-0000-7000-8000-00000000b001"
	phrase      = "Синтетический-Пароль-42"
	phrase2     = "Другой-Пароль-Для-Теста-7"
	wrongPhrase = "Неверный-Пароль-0"
)

var testIP = netip.MustParseAddr("192.0.2.10")

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	svc   *auth.Service
	mem   *authtest.Memory
	hash  *authtest.Hasher
	clock *clock
	mfa   *mfaKeys
}

func provider(t testing.TB) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{mem: authtest.NewMemory(), hash: &authtest.Hasher{}, clock: &clock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}}
	svc, err := auth.NewService(context.Background(), e.mem, e.mem, provider(t),
		auth.WithClock(e.clock.now), auth.WithPasswordHasher(e.hash), auth.WithSecretBox(testBox(t)), auth.WithRoleStore(e.mem), auth.WithAPITokenStore(e.mem))
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	e.mfa = newMFAKeys(svc, e.mem, e.clock)
	e.mem.AddUser(e.user(adminID, "admin", auth.RoleSecurityAdmin))
	e.mem.AddUser(e.user(userID, "ivanov", auth.RoleAnalyst))
	t.Cleanup(func() { checkRecords(t, e.mem.Records()) })
	return e
}

func (e *env) user(id, login string, role auth.Role) auth.User {
	now := e.clock.now()
	return auth.User{
		ID: id, OrgID: audit.DefaultOrgID, Login: login, DisplayName: "Тест " + login, Role: role,
		Status: auth.StatusActive, PasswordHash: authtest.HashOf(phrase), PasswordChangedAt: now,
		CreatedAt: now, CreatedBy: "test",
	}
}

// checkRecords — записи аудита годятся для настоящего журнала: код из
// перечня, подробности без ключей, похожих на секреты.
func checkRecords(t *testing.T, recs []audit.Entry) {
	t.Helper()
	for _, r := range recs {
		if _, ok := audit.Lookup(r.Action); !ok {
			t.Errorf("событие %q не из перечня аудита", r.Action)
		}
		if _, err := audit.CanonicalDetails(r.Details); err != nil {
			t.Errorf("%s: подробности отклонит журнал: %v", r.Action, err)
		}
		if r.Actor.ID == "" {
			t.Errorf("%s: субъект без ID", r.Action)
		}
	}
}

func (e *env) login(t *testing.T, login, password string) (auth.LoginResult, error) {
	t.Helper()
	return e.svc.Login(context.Background(), auth.LoginInput{Login: login, Password: password, SourceIP: testIP, UserAgent: "test"})
}

func (e *env) mustLogin(t *testing.T, login, password string) auth.LoginResult {
	t.Helper()
	res, err := e.login(t, login, password)
	if err != nil {
		t.Fatalf("вход %s: %v", login, err)
	}
	return res
}

// fail — попытка входа, которая должна получить отказ.
func (e *env) fail(t *testing.T, login, password string) {
	t.Helper()
	if _, err := e.login(t, login, password); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("вход %s: %v, ожидался отказ", login, err)
	}
}

func (e *env) userByID(t *testing.T, id string) auth.User {
	t.Helper()
	u, err := e.svc.User(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *env) mustCaller(t *testing.T, token string) auth.Caller {
	t.Helper()
	c, err := e.caller(t, token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) caller(t *testing.T, token string) (auth.Caller, error) {
	t.Helper()
	return e.svc.Authenticate(context.Background(), token, testIP)
}

func lastRecord(t *testing.T, m *authtest.Memory, action string) audit.Entry {
	t.Helper()
	recs := m.Records()
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].Action == action {
			return recs[i]
		}
	}
	t.Fatalf("нет записи %s в аудите: %v", action, m.Actions())
	return audit.Entry{}
}

func count(actions []string, a string) int {
	n := 0
	for _, x := range actions {
		if x == a {
			n++
		}
	}
	return n
}

func TestLoginSuccess(t *testing.T) {
	e := newEnv(t)
	res := e.mustLogin(t, "IVANOV", phrase) // логин без учёта регистра
	if res.Token == "" || res.CSRF == "" || res.Token == res.CSRF {
		t.Fatal("токены не выданы")
	}
	c, err := e.caller(t, res.Token)
	if err != nil {
		t.Fatal(err)
	}
	if c.User.ID != userID || c.Session.State != auth.SessionActive {
		t.Fatalf("сессия: %+v", c.Session)
	}
	rec := lastRecord(t, e.mem, "auth.login")
	if rec.Actor.ID != userID || rec.Result != audit.ResultSuccess || rec.SourceIP != testIP {
		t.Fatalf("запись аудита: %+v", rec)
	}
	if !e.svc.CheckCSRF(c, res.CSRF) {
		t.Fatal("CSRF-токен своей сессии не принят")
	}
}

// ADR-0006: неизвестный логин тоже проходит проверку пароля (с фиктивным
// хешем), и ответ совпадает с ответом на неверный пароль.
func TestLoginUnknownUserVerifiesDummyHash(t *testing.T) {
	e := newEnv(t)
	_, errUnknown := e.login(t, "nobody", phrase)
	verified := e.hash.Verified()
	if len(verified) != 1 {
		t.Fatalf("Verify вызван %d раз, ожидался 1", len(verified))
	}
	if verified[0] == authtest.HashOf(phrase) || !strings.HasPrefix(verified[0], "$fake$") {
		t.Fatalf("проверка шла не с фиктивным хешем: %q", verified[0])
	}
	_, errWrong := e.login(t, "ivanov", wrongPhrase)
	if !errors.Is(errUnknown, auth.ErrInvalidCredentials) || !errors.Is(errWrong, auth.ErrInvalidCredentials) ||
		errUnknown.Error() != errWrong.Error() {
		t.Fatalf("ответы различаются: %v / %v", errUnknown, errWrong)
	}
	rec := lastRecord(t, e.mem, "auth.login_failed")
	if rec.Actor.Name != "ivanov" {
		t.Fatalf("субъект: %+v", rec.Actor)
	}
	first := e.mem.Records()[0]
	// Строка из поля логина без учётной записи в журнал не попадает: это
	// может быть пароль, введённый не в то поле.
	if first.Action != "auth.login_failed" || first.Actor.Name != "(неизвестный логин)" || first.Actor.ID != "-" {
		t.Fatalf("неудача с неизвестным логином: %+v", first)
	}
}

// Строка, которая не может быть логином или не совпала ни с одной учётной
// записью (например, пароль, введённый в поле логина), не попадает в журнал.
func TestLoginInvalidLoginNotLogged(t *testing.T) {
	e := newEnv(t)
	for _, in := range []string{"P@ssw0rd!Секрет", "correcthorsebattery"} {
		if _, err := e.login(t, in, phrase); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatal(err)
		}
		rec := lastRecord(t, e.mem, "auth.login_failed")
		if rec.Actor.Name != "(неизвестный логин)" {
			t.Fatalf("в аудит попала введённая строка: %q", rec.Actor.Name)
		}
	}
	if n := len(e.hash.Verified()); n != 2 {
		t.Fatalf("Verify вызван %d раз", n)
	}
}

// DM-39 (ИАФ.4): после N неудач подряд учётная запись блокируется, это
// пишется в аудит; во время блокировки верный пароль не помогает, а ответ
// не отличается от неверного пароля.
func TestDM39_LockoutAfterFailures(t *testing.T) {
	e := newEnv(t)
	pol := auth.DefaultPolicy()
	for i := 1; i <= pol.LockoutThreshold; i++ {
		if _, err := e.login(t, "ivanov", wrongPhrase); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("попытка %d: %v", i, err)
		}
		locked := count(e.mem.Actions(), "auth.locked")
		if want := 0; i < pol.LockoutThreshold && locked != want {
			t.Fatalf("блокировка после %d неудач", i)
		}
	}
	if n := count(e.mem.Actions(), "auth.login_failed"); n != pol.LockoutThreshold {
		t.Fatalf("неудач в аудите: %d", n)
	}
	lock := lastRecord(t, e.mem, "auth.locked")
	if lock.Object.ID != userID || lock.SourceIP != testIP {
		t.Fatalf("запись о блокировке: %+v", lock)
	}
	_, err := e.login(t, "ivanov", phrase)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("вход во время блокировки: %v", err)
	}
	if rec := lastRecord(t, e.mem, "auth.login_failed"); rec.Details.(map[string]any)["reason"] != "locked" {
		t.Fatalf("причина: %v", rec.Details)
	}
	// Во время блокировки неудачи не продлевают её и не пишут повторный auth.locked.
	e.fail(t, "ivanov", wrongPhrase)
	if n := count(e.mem.Actions(), "auth.locked"); n != 1 {
		t.Fatalf("auth.locked записан %d раз", n)
	}
	e.clock.add(time.Duration(pol.LockoutMinutes) * time.Minute)
	e.mustLogin(t, "ivanov", phrase)
	// После успешного входа счёт неудач начинается заново.
	u := e.userByID(t, userID)
	if u.FailedAttempts != 0 || u.Locked(e.clock.now()) {
		t.Fatalf("после входа: %d неудач, блокировка %v", u.FailedAttempts, u.Locked(e.clock.now()))
	}
}

// Блокировка без срока снимается только администратором (активацией).
func TestLockoutUntilAdminUnlock(t *testing.T) {
	e := newEnv(t)
	pol := auth.DefaultPolicy()
	pol.LockoutMinutes = 0
	admin := e.adminCaller(t)
	if err := e.svc.SetPolicy(context.Background(), admin, pol, "", ""); err != nil {
		t.Fatal(err)
	}
	for range pol.LockoutThreshold {
		e.fail(t, "ivanov", wrongPhrase)
	}
	e.clock.add(30 * 24 * time.Hour)
	if _, err := e.login(t, "ivanov", phrase); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("бессрочная блокировка истекла сама: %v", err)
	}
	if err := e.svc.SetStatus(context.Background(), admin, userID, auth.StatusActive); err != nil {
		t.Fatal(err)
	}
	e.mustLogin(t, "ivanov", phrase)
}

// Неудачи после истечения блокировки считаются заново, а не блокируют сразу.
func TestLockoutExpiredResetsCounter(t *testing.T) {
	e := newEnv(t)
	pol := auth.DefaultPolicy()
	for range pol.LockoutThreshold {
		e.fail(t, "ivanov", wrongPhrase)
	}
	e.clock.add(time.Duration(pol.LockoutMinutes)*time.Minute + time.Second)
	e.fail(t, "ivanov", wrongPhrase)
	if n := count(e.mem.Actions(), "auth.locked"); n != 1 {
		t.Fatalf("одна неудача после истечения заблокировала снова: auth.locked = %d", n)
	}
	e.mustLogin(t, "ivanov", phrase)
}

// adminCaller — полный вход администратора безопасности: пароль и второй
// фактор (при первом входе — его подключение).
func (e *env) adminCaller(t *testing.T) auth.Caller {
	t.Helper()
	return e.mfa.complete(t, e.mustLogin(t, "admin", phrase))
}

func TestDeactivatedCannotLogin(t *testing.T) {
	e := newEnv(t)
	admin := e.adminCaller(t)
	res := e.mustLogin(t, "ivanov", phrase)
	if err := e.svc.SetStatus(context.Background(), admin, userID, auth.StatusDeactivated); err != nil {
		t.Fatal(err)
	}
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия деактивированного: %v", err)
	}
	_, err := e.login(t, "ivanov", phrase)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("вход деактивированного: %v", err)
	}
	// Хеш деактивированной записи не проверяется — только фиктивный.
	v := e.hash.Verified()
	if v[len(v)-1] == authtest.HashOf(phrase) {
		t.Fatal("для деактивированной записи проверялся её хеш")
	}
	if rec := lastRecord(t, e.mem, "auth.login_failed"); rec.Details.(map[string]any)["reason"] != "deactivated" {
		t.Fatalf("причина: %v", rec.Details)
	}
	if d := lastRecord(t, e.mem, "user.deactivate").Details.(map[string]any); d["previous_status"] != "active" {
		t.Fatalf("прежнее состояние: %v", d)
	}
	if d := lastRecord(t, e.mem, "user.deactivate").Details.(map[string]any); d["previous_status"] != "active" {
		t.Fatalf("прежнее состояние: %v", d)
	}
	if err := e.svc.SetStatus(context.Background(), admin, userID, auth.StatusActive); err != nil {
		t.Fatal(err)
	}
	e.mustLogin(t, "ivanov", phrase)
	if !slices.Contains(e.mem.Actions(), "user.deactivate") || !slices.Contains(e.mem.Actions(), "user.activate") {
		t.Fatalf("аудит: %v", e.mem.Actions())
	}
}

func TestSetStatusGuards(t *testing.T) {
	e := newEnv(t)
	admin := e.adminCaller(t)
	ctx := context.Background()
	if err := e.svc.SetStatus(ctx, admin, adminID, auth.StatusDeactivated); !errors.Is(err, auth.ErrSelf) {
		t.Fatalf("деактивация себя: %v", err)
	}
	// Последний активный администратор безопасности — даже другим администратором.
	other := admin
	other.User.ID = userID
	if err := e.svc.SetStatus(ctx, other, adminID, auth.StatusDeactivated); !errors.Is(err, auth.ErrLastAdmin) {
		t.Fatalf("деактивация последнего администратора: %v", err)
	}
	if err := e.svc.SetStatus(ctx, admin, "01900000-0000-7000-8000-0000000000ff", auth.StatusDeactivated); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("несуществующий: %v", err)
	}
}

// ИАФ.3: учётная запись создаётся с временным паролем; после входа доступна
// только смена пароля, затем — полный доступ, прочие сессии завершены.
func TestTemporaryPasswordFlow(t *testing.T) {
	e := newEnv(t)
	admin := e.adminCaller(t)
	ctx := context.Background()
	u, temp, err := e.svc.CreateUser(ctx, admin, auth.NewUser{Login: "Petrova", DisplayName: " Петрова А. ", Role: auth.RoleAuditor})
	if err != nil {
		t.Fatal(err)
	}
	if u.Login != "petrova" || u.DisplayName != "Петрова А." || !u.MustChangePassword {
		t.Fatalf("запись: %+v", u)
	}
	if err := auth.DefaultPolicy().CheckPassword(temp, u.Login); err != nil {
		t.Fatalf("временный пароль не проходит политику: %v", err)
	}
	if rec := lastRecord(t, e.mem, "user.create"); rec.Actor.ID != adminID || rec.Object.ID != u.ID {
		t.Fatalf("аудит: %+v", rec)
	}
	first := e.mustLogin(t, "petrova", temp)
	second := e.mustLogin(t, "petrova", temp)
	if first.Caller.Session.State != auth.SessionPasswordChange {
		t.Fatalf("состояние сессии: %s", first.Caller.Session.State)
	}
	c := e.mustCaller(t, second.Token)
	if allowed(t, e, c, auth.PermUsersRead) || !allowed(t, e, c, auth.PermSelf) {
		t.Fatal("сессия с временным паролем получила права роли")
	}
	if err := e.svc.ChangePassword(ctx, c, temp, temp); err == nil {
		t.Fatal("новый пароль совпадает с временным — принят")
	}
	if err := e.svc.ChangePassword(ctx, c, temp, phrase); err != nil {
		t.Fatal(err)
	}
	c, err = e.caller(t, second.Token)
	if err != nil || c.Session.State != auth.SessionActive || !allowed(t, e, c, auth.PermUsersRead) {
		t.Fatalf("после смены пароля: %v, %s", err, c.Session.State)
	}
	if _, err := e.caller(t, first.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("другая сессия не завершена: %v", err)
	}
	e.mustLogin(t, "petrova", phrase)
}

func TestTemporaryPasswordExpires(t *testing.T) {
	e := newEnv(t)
	admin := e.adminCaller(t)
	_, temp, err := e.svc.CreateUser(context.Background(), admin, auth.NewUser{Login: "sidorov", DisplayName: "Сидоров", Role: auth.RoleAnalyst})
	if err != nil {
		t.Fatal(err)
	}
	e.clock.add(time.Duration(auth.DefaultPolicy().TempPasswordHours) * time.Hour)
	if _, err := e.login(t, "sidorov", temp); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("истёкший временный пароль: %v", err)
	}
	if rec := lastRecord(t, e.mem, "auth.login_failed"); rec.Details.(map[string]any)["reason"] != "temp_password_expired" {
		t.Fatalf("причина: %v", rec.Details)
	}
}

// ИАФ.2: истёкший пароль переводит сессию в режим смены пароля, в том
// числе уже открытую.
func TestPasswordExpiry(t *testing.T) {
	e := newEnv(t)
	pol := auth.DefaultPolicy()
	ctx := context.Background()
	u := e.userByID(t, userID)
	if _, warn, err := e.svc.PasswordExpiresIn(ctx, u); err != nil || warn {
		t.Fatal("предупреждение о смене пароля слишком рано")
	}
	e.clock.add(time.Duration(pol.PasswordMaxAgeDays-pol.PasswordWarnDays)*24*time.Hour + time.Hour)
	res := e.mustLogin(t, "ivanov", phrase)
	left, warn, err := e.svc.PasswordExpiresIn(ctx, res.Caller.User)
	if err != nil || !warn || left <= 0 {
		t.Fatalf("предупреждение о смене пароля: %v %v %v", left, warn, err)
	}
	if res.Caller.Session.State != auth.SessionActive {
		t.Fatalf("до истечения: %s", res.Caller.Session.State)
	}
	// Пароль истекает во время открытой сессии: вход за час до истечения,
	// затем два часа активности.
	e.clock.add(time.Duration(pol.PasswordWarnDays)*24*time.Hour - 2*time.Hour)
	res = e.mustLogin(t, "ivanov", phrase)
	for range 12 {
		e.clock.add(10 * time.Minute)
		if _, err := e.caller(t, res.Token); err != nil {
			t.Fatal(err)
		}
	}
	c, err := e.caller(t, res.Token)
	if err != nil || c.Session.State != auth.SessionPasswordChange || allowed(t, e, c, auth.PermSystemRead) {
		t.Fatalf("открытая сессия после истечения пароля: %v %s", err, c.Session.State)
	}
	res = e.mustLogin(t, "ivanov", phrase)
	if res.Caller.Session.State != auth.SessionPasswordChange {
		t.Fatalf("вход с истёкшим паролем: состояние %s", res.Caller.Session.State)
	}
}

// УПД.4: бездействие и абсолютный срок сессии.
func TestSessionIdleAndLifetime(t *testing.T) {
	e := newEnv(t)
	res := e.mustLogin(t, "ivanov", phrase)
	for range 10 {
		e.clock.add(14 * time.Minute)
		if _, err := e.caller(t, res.Token); err != nil {
			t.Fatalf("активная сессия завершена: %v", err)
		}
	}
	e.clock.add(15 * time.Minute)
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("после 15 минут бездействия: %v", err)
	}
	res = e.mustLogin(t, "ivanov", phrase)
	for range 52 {
		e.clock.add(14 * time.Minute)
		if _, err := e.caller(t, res.Token); err != nil {
			break
		}
	}
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия старше 12 часов: %v", err)
	}
}

// УПД.4: лимит одновременных сессий — новая вытесняет самую старую.
func TestSessionLimit(t *testing.T) {
	e := newEnv(t)
	limit := auth.DefaultPolicy().SessionMaxPerUser
	var tokens []string
	for range limit + 1 {
		e.clock.add(time.Second)
		tokens = append(tokens, e.mustLogin(t, "ivanov", phrase).Token)
	}
	if _, err := e.caller(t, tokens[0]); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("самая старая сессия не вытеснена: %v", err)
	}
	for _, tok := range tokens[1:] {
		if _, err := e.caller(t, tok); err != nil {
			t.Fatal(err)
		}
	}
	list, err := e.svc.Sessions(context.Background(), userID)
	if err != nil || len(list) != limit {
		t.Fatalf("сессий %d, %v", len(list), err)
	}
}

func TestAuthenticateRejectsBadTokens(t *testing.T) {
	e := newEnv(t)
	res := e.mustLogin(t, "ivanov", phrase)
	for _, tok := range []string{"", "x", res.Token + "A", res.Token[:42] + "=", strings.ToUpper(res.Token), res.CSRF} {
		if _, err := e.caller(t, tok); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("токен %q принят: %v", tok, err)
		}
	}
	if err := e.svc.Logout(context.Background(), res.Caller); err != nil {
		t.Fatal(err)
	}
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия после выхода: %v", err)
	}
	if rec := lastRecord(t, e.mem, "auth.logout"); rec.Object.ID != res.Caller.Session.ID {
		t.Fatalf("аудит выхода: %+v", rec)
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	a := e.mustLogin(t, "ivanov", phrase)
	b := e.mustLogin(t, "ivanov", phrase)
	ca := e.mustCaller(t, a.Token)
	for _, h := range []string{"", b.CSRF, a.Token, a.CSRF + " ", "%%%"} {
		if e.svc.CheckCSRF(ca, h) {
			t.Errorf("CSRF-токен %q принят", h)
		}
	}
	if !e.svc.CheckCSRF(ca, a.CSRF) {
		t.Fatal("свой CSRF-токен отклонён")
	}
}

func TestChangePasswordRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.mustLogin(t, "ivanov", phrase).Caller
	var pe *auth.PasswordError
	if err := e.svc.ChangePassword(ctx, c, phrase, "короткий1A"); !errors.As(err, &pe) {
		t.Fatalf("короткий пароль: %v", err)
	}
	if err := e.svc.ChangePassword(ctx, c, phrase, "Ivanov-Длинный-Пароль-1"); !errors.As(err, &pe) {
		t.Fatalf("пароль с логином: %v", err)
	}
	if err := e.svc.ChangePassword(ctx, c, phrase, phrase); !errors.As(err, &pe) {
		t.Fatalf("тот же пароль: %v", err)
	}
	if err := e.svc.ChangePassword(ctx, c, wrongPhrase, phrase2); !errors.Is(err, auth.ErrWrongPassword) {
		t.Fatalf("неверный текущий: %v", err)
	}
	if rec := lastRecord(t, e.mem, "auth.password_changed"); rec.Result != audit.ResultFailure {
		t.Fatalf("неудача смены пароля не записана: %+v", rec)
	}
	// История: к прежним паролям вернуться нельзя.
	pass := []string{phrase, phrase2, "Третий-Пароль-Теста-3", "Четвёртый-Пароль-Теста-4"}
	for i := 1; i < len(pass); i++ {
		c = e.mustLogin(t, "ivanov", pass[i-1]).Caller
		if err := e.svc.ChangePassword(ctx, c, pass[i-1], pass[i]); err != nil {
			t.Fatalf("смена %d: %v", i, err)
		}
	}
	c = e.mustLogin(t, "ivanov", pass[3]).Caller
	if err := e.svc.ChangePassword(ctx, c, pass[3], phrase); !errors.As(err, &pe) {
		t.Fatalf("повтор пароля из истории: %v", err)
	}
}

// Неверный текущий пароль при смене считается неудачей (ИАФ.4): при
// блокировке завершаются все сессии.
func TestChangePasswordLockout(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	res := e.mustLogin(t, "ivanov", phrase)
	for range auth.DefaultPolicy().LockoutThreshold {
		if err := e.svc.ChangePassword(ctx, res.Caller, wrongPhrase, phrase2); !errors.Is(err, auth.ErrWrongPassword) {
			t.Fatal(err)
		}
	}
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия после блокировки: %v", err)
	}
	if !slices.Contains(e.mem.Actions(), "auth.locked") {
		t.Fatalf("аудит: %v", e.mem.Actions())
	}
}

func TestResetPassword(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	res := e.mustLogin(t, "ivanov", phrase)
	for range auth.DefaultPolicy().LockoutThreshold {
		e.fail(t, "ivanov", wrongPhrase)
	}
	temp, err := e.svc.ResetPassword(ctx, admin, userID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("сессии не завершены при сбросе пароля")
	}
	got := e.mustLogin(t, "ivanov", temp)
	if got.Caller.Session.State != auth.SessionPasswordChange {
		t.Fatalf("после сброса: %s", got.Caller.Session.State)
	}
	if _, err := e.svc.ResetPassword(ctx, admin, adminID); !errors.Is(err, auth.ErrSelf) {
		t.Fatalf("сброс своего пароля: %v", err)
	}
	if !slices.Contains(e.mem.Actions(), "user.password_reset") {
		t.Fatalf("аудит: %v", e.mem.Actions())
	}
}

func TestCreateUserValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	var ie *auth.InputError
	for _, nu := range []auth.NewUser{
		{Login: "", DisplayName: "Имя", Role: auth.RoleAnalyst},
		{Login: "-bad", DisplayName: "Имя", Role: auth.RoleAnalyst},
		{Login: "ok", DisplayName: "", Role: auth.RoleAnalyst},
		{Login: "ok", DisplayName: "Имя\x00", Role: auth.RoleAnalyst},
		{Login: "ok", DisplayName: "Имя", Role: "root"},
	} {
		if _, _, err := e.svc.CreateUser(ctx, admin, nu); !errors.As(err, &ie) {
			t.Errorf("%+v: %v", nu, err)
		}
	}
	if _, _, err := e.svc.CreateUser(ctx, admin, auth.NewUser{Login: "Ivanov", DisplayName: "Дубль", Role: auth.RoleAnalyst}); !errors.Is(err, auth.ErrLoginTaken) {
		t.Fatalf("занятый логин: %v", err)
	}
}

func TestRevokeSessionsByAdmin(t *testing.T) {
	e := newEnv(t)
	admin := e.adminCaller(t)
	a := e.mustLogin(t, "ivanov", phrase)
	e.mustLogin(t, "ivanov", phrase)
	n, err := e.svc.RevokeSessions(context.Background(), admin, userID, false)
	if err != nil || n != 2 {
		t.Fatalf("завершено %d, %v", n, err)
	}
	if _, err := e.caller(t, a.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("сессия не завершена")
	}
	if rec := lastRecord(t, e.mem, "auth.sessions_revoked"); rec.Object.ID != userID {
		t.Fatalf("аудит: %+v", rec)
	}
}

func TestSetPolicy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	bad := auth.DefaultPolicy()
	bad.PasswordMinLength = 4
	var ie *auth.InputError
	if err := e.svc.SetPolicy(ctx, admin, bad, "", ""); !errors.As(err, &ie) {
		t.Fatalf("длина 4: %v", err)
	}
	p := auth.DefaultPolicy()
	p.LockoutThreshold = 3
	if err := e.svc.SetPolicy(ctx, admin, p, "", ""); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.Policy(ctx); err != nil || got != p {
		t.Fatalf("политика: %+v", got)
	}
	rec := lastRecord(t, e.mem, "auth.policy_changed")
	d := rec.Details.(map[string]any)
	if d["before"].(map[string]any)["lockout_threshold"] != 5 || d["after"].(map[string]any)["lockout_threshold"] != 3 {
		t.Fatalf("до и после: %v", d)
	}
}

// Ослабление настроек входа — только с повторной проверкой и отметкой
// weakening (В24 ревью 2.r5): порог блокировки, обязательный TOTP и др.
func TestSetPolicyWeakeningNeedsReauth(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	stricter := auth.DefaultPolicy()
	stricter.MFARequiredAll = true
	if err := e.svc.SetPolicy(ctx, admin, stricter, "", ""); err != nil {
		t.Fatalf("ужесточение: %v", err)
	}
	if d := lastRecord(t, e.mem, "auth.policy_changed").Details.(map[string]any); d["weakening"] != false {
		t.Fatalf("ужесточение отмечено ослаблением: %v", d)
	}
	weaker := stricter
	weaker.LockoutThreshold = 20
	weaker.MFARequiredAll = false
	var ie *auth.InputError
	if err := e.svc.SetPolicy(ctx, admin, weaker, "", ""); !errors.As(err, &ie) {
		t.Fatalf("ослабление без пароля: %v", err)
	}
	if err := e.svc.SetPolicy(ctx, admin, weaker, wrongPhrase, ""); !errors.Is(err, auth.ErrReauthentication) {
		t.Fatalf("ослабление с неверным паролем: %v", err)
	}
	if got, _ := e.svc.Policy(ctx); got != stricter {
		t.Fatalf("настройки изменились после отказа: %+v", got)
	}
	if err := e.svc.SetPolicy(ctx, admin, weaker, phrase, ""); err != nil {
		t.Fatalf("ослабление с паролем: %v", err)
	}
	d := lastRecord(t, e.mem, "auth.policy_changed").Details.(map[string]any)
	if w, _ := d["weakened"].([]string); d["weakening"] != true || len(w) != 2 || w[0] != "lockout_threshold" || w[1] != "mfa_required_all" {
		t.Fatalf("аудит ослабления: %v", d)
	}
}

func TestWeakenedFields(t *testing.T) {
	base := auth.DefaultPolicy()
	for _, c := range []struct {
		name string
		mod  func(*auth.Policy)
		want string
	}{
		{"длина", func(p *auth.Policy) { p.PasswordMinLength = 10 }, "password_min_length"},
		{"классы", func(p *auth.Policy) { p.PasswordMinClasses = 2 }, "password_min_classes"},
		{"история", func(p *auth.Policy) { p.PasswordHistory = 0 }, "password_history"},
		{"бессрочный пароль", func(p *auth.Policy) { p.PasswordMaxAgeDays = 0 }, "password_max_age_days"},
		{"срок пароля дольше", func(p *auth.Policy) { p.PasswordMaxAgeDays = 180 }, "password_max_age_days"},
		{"порог", func(p *auth.Policy) { p.LockoutThreshold = 6 }, "lockout_threshold"},
		{"блокировка короче", func(p *auth.Policy) { p.LockoutMinutes = 1 }, "lockout_minutes"},
		{"бездействие", func(p *auth.Policy) { p.SessionIdleMinutes = 16 }, "session_idle_minutes"},
		{"сессии", func(p *auth.Policy) { p.SessionMaxPerUser = 6 }, "session_max_per_user"},
		{"временный пароль", func(p *auth.Policy) { p.TempPasswordHours = 73 }, "temp_password_hours"},
		{"бессрочная блокировка", func(p *auth.Policy) { p.LockoutMinutes = 0 }, ""},
		{"срок пароля короче", func(p *auth.Policy) { p.PasswordMaxAgeDays = 30 }, ""},
		{"предупреждение", func(p *auth.Policy) { p.PasswordWarnDays = 0 }, ""},
	} {
		after := base
		c.mod(&after)
		got := strings.Join(auth.WeakenedFields(base, after), ",")
		if got != c.want {
			t.Errorf("%s: %q, ожидалось %q", c.name, got, c.want)
		}
	}
	untimed := base
	untimed.LockoutMinutes = 0
	if got := auth.WeakenedFields(untimed, base); len(got) != 1 || got[0] != "lockout_minutes" {
		t.Errorf("бессрочная → 15 минут: %v", got)
	}
	never := base
	never.PasswordMaxAgeDays = 0
	if got := auth.WeakenedFields(never, base); len(got) != 0 {
		t.Errorf("бессрочный → 90 суток: %v", got)
	}
}

// Устаревшие параметры хеша пересчитываются после успешного входа.
func TestRehashOnLogin(t *testing.T) {
	e := newEnv(t)
	e.hash.Stale = "$fake$"
	e.mustLogin(t, "ivanov", phrase)
	e.hash.Stale = ""
	u := e.userByID(t, userID)
	if u.PasswordHash != authtest.HashOf(phrase) {
		t.Fatalf("хеш: %q", u.PasswordHash)
	}
}

// Сбой хранилища — ошибка, а не вход и не «неверный пароль».
func TestStoreFailure(t *testing.T) {
	e := newEnv(t)
	e.mem.Fail = errors.New("БД недоступна")
	_, err := e.login(t, "ivanov", phrase)
	if err == nil || errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("сбой хранилища: %v", err)
	}
	e.mem.Fail = nil
}

// Вход с настоящим Argon2id: фиктивный хеш вычисляется с рабочими параметрами.
func TestLoginRealArgon2(t *testing.T) {
	mem := authtest.NewMemory()
	p := provider(t)
	ph, err := p.PasswordHasher()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	h, err := ph.Hash(ctx, []byte(phrase))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mem.AddUser(auth.User{ID: userID, OrgID: audit.DefaultOrgID, Login: "ivanov", DisplayName: "Иванов",
		Role: auth.RoleAnalyst, Status: auth.StatusActive, PasswordHash: h, PasswordChangedAt: now, CreatedAt: now, CreatedBy: "test"})
	svc, err := auth.NewService(ctx, mem, mem, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, auth.LoginInput{Login: "nobody", Password: phrase}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, auth.LoginInput{Login: "ivanov", Password: phrase}); err != nil {
		t.Fatal(err)
	}
}

// Пока проверялся пароль, запись заблокировали, деактивировали или сменили
// ей пароль: вход не засчитывается, сессия не открывается (перепроверка в
// транзакции создания сессии).
func TestLoginRechecksAfterVerify(t *testing.T) {
	cases := map[string]struct {
		change func(e *env)
		reason string
	}{
		"блокировка": {func(e *env) {
			_, _, err := e.mem.RecordFailure(context.Background(), userID, e.clock.now(), 1, time.Time{}, nil)
			if err != nil {
				t.Fatal(err)
			}
		}, "locked"},
		"деактивация": {func(e *env) {
			u := e.userByID(t, userID)
			u.Status = auth.StatusDeactivated
			e.mem.AddUser(u)
		}, "changed_during_login"},
		"смена пароля": {func(e *env) {
			u := e.userByID(t, userID)
			u.PasswordHash = authtest.HashOf(phrase2)
			e.mem.AddUser(u)
		}, "changed_during_login"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			once := false
			e.hash.OnVerify = func() {
				if !once {
					once = true
					tc.change(e)
				}
			}
			e.fail(t, "ivanov", phrase)
			if rec := lastRecord(t, e.mem, "auth.login_failed"); rec.Details.(map[string]any)["reason"] != tc.reason {
				t.Fatalf("причина: %v", rec.Details)
			}
			if list, err := e.svc.Sessions(context.Background(), userID); err != nil || len(list) != 0 {
				t.Fatalf("открыта сессия: %d %v", len(list), err)
			}
		})
	}
}

// Вытесненные по лимиту сессии перечислены в записи входа (УПД.4).
func TestSessionLimitAudited(t *testing.T) {
	e := newEnv(t)
	limit := auth.DefaultPolicy().SessionMaxPerUser
	first := e.mustLogin(t, "ivanov", phrase)
	for range limit {
		e.clock.add(time.Second)
		e.mustLogin(t, "ivanov", phrase)
	}
	d := lastRecord(t, e.mem, "auth.login").Details.(map[string]any)
	if ids, _ := d["evicted_sessions"].([]string); !slices.Equal(ids, []string{first.Caller.Session.ID}) {
		t.Fatalf("вытеснены: %v", d)
	}
}

// Истечение сессии по бездействию пишется в аудит (УПД.4).
func TestSessionExpiryAudited(t *testing.T) {
	e := newEnv(t)
	res := e.mustLogin(t, "ivanov", phrase)
	e.clock.add(16 * time.Minute)
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal(err)
	}
	rec := lastRecord(t, e.mem, "auth.session_expired")
	if rec.Object.ID != res.Caller.Session.ID || rec.Details.(map[string]any)["reason"] != auth.RevokeIdle {
		t.Fatalf("аудит: %+v", rec)
	}
	// Повторное обращение с завершённой сессией новых записей не даёт.
	n := len(e.mem.Records())
	if _, err := e.caller(t, res.Token); !errors.Is(err, auth.ErrUnauthenticated) || len(e.mem.Records()) != n {
		t.Fatalf("повтор: %v, записей %d → %d", err, n, len(e.mem.Records()))
	}
}

// Пока запись заблокирована, пароль через открытую сессию не меняется и
// текущий пароль не проверяется: перебор не продолжается в обход блокировки.
func TestChangePasswordWhileLocked(t *testing.T) {
	e := newEnv(t)
	res := e.mustLogin(t, "ivanov", phrase)
	for range auth.DefaultPolicy().LockoutThreshold {
		e.fail(t, "ivanov", wrongPhrase)
	}
	c := e.mustCaller(t, res.Token)
	verified := len(e.hash.Verified())
	if err := e.svc.ChangePassword(context.Background(), c, phrase, phrase2); !errors.Is(err, auth.ErrLocked) {
		t.Fatalf("смена при блокировке: %v", err)
	}
	if len(e.hash.Verified()) != verified {
		t.Fatal("при блокировке проверялся текущий пароль")
	}
}

// Пароль сменили параллельно после проверки текущего: смена отклоняется.
func TestChangePasswordConcurrentChange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	res := e.mustLogin(t, "ivanov", phrase)
	c := e.mustCaller(t, res.Token)
	rec := audit.Entry{Actor: audit.Actor{Type: audit.ActorCLI, ID: "test"}, Action: "auth.password_changed",
		Object: audit.Object{Type: "user", ID: userID}, Result: audit.ResultSuccess}
	if err := e.mem.SetPassword(ctx, auth.PasswordChange{UserID: userID, NewHash: authtest.HashOf(phrase2),
		Now: e.clock.now(), KeepSession: c.Session.ID}, rec); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ChangePassword(ctx, c, phrase, "Третий-Пароль-Для-Теста-9"); !errors.Is(err, auth.ErrWrongPassword) {
		t.Fatalf("смена по устаревшему хешу: %v", err)
	}
	if e.userByID(t, userID).PasswordHash != authtest.HashOf(phrase2) {
		t.Fatal("пароль перезаписан")
	}
}

// Смена пароля из уже завершённой сессии отклоняется.
func TestChangePasswordRevokedSession(t *testing.T) {
	e := newEnv(t)
	res := e.mustLogin(t, "ivanov", phrase)
	c := e.mustCaller(t, res.Token)
	if err := e.svc.Logout(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ChangePassword(context.Background(), c, phrase, phrase2); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("смена из завершённой сессии: %v", err)
	}
}

// Сброс пароля не ложится на запись, которую деактивировали параллельно:
// хранилище перепроверяет состояние в своей транзакции.
func TestResetPasswordRequiresActive(t *testing.T) {
	e := newEnv(t)
	u := e.userByID(t, userID)
	u.Status = auth.StatusDeactivated
	e.mem.AddUser(u)
	rec := audit.Entry{Actor: audit.Actor{Type: audit.ActorCLI, ID: "test"}, Action: "user.password_reset",
		Object: audit.Object{Type: "user", ID: userID}, Result: audit.ResultSuccess}
	err := e.mem.SetPassword(context.Background(), auth.PasswordChange{UserID: userID, NewHash: authtest.HashOf(phrase2),
		Temporary: true, Now: e.clock.now(), RequireActive: true}, rec)
	if !errors.Is(err, auth.ErrDeactivated) {
		t.Fatalf("сброс деактивированной: %v", err)
	}
	if e.userByID(t, userID).PasswordHash != authtest.HashOf(phrase) {
		t.Fatal("пароль деактивированной записи изменён")
	}
	if _, err := e.svc.ResetPassword(context.Background(), e.adminCaller(t), userID); err == nil {
		t.Fatal("сброс деактивированной записи прошёл")
	}
}
