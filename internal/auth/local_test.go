package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

var cliActor = audit.Actor{Type: audit.ActorCLI, ID: "uid:1000", Name: "operator"}

// setPolicy задаёт настройки входа от имени администратора.
func (e *env) setPolicy(t *testing.T, admin auth.Caller, edit func(*auth.Policy)) {
	t.Helper()
	p := auth.DefaultPolicy()
	edit(&p)
	if err := e.svc.SetPolicy(context.Background(), admin, p, "", ""); err != nil {
		t.Fatal(err)
	}
}

// В7 ревью 2.r2: при бессрочной блокировке в настройках единственный
// администратор безопасности блокируется только на 15 минут — иначе подбор
// пароля по известному логину закрыл бы консоль навсегда.
func TestLastAdminLockoutCapped(t *testing.T) {
	e := newEnv(t)
	e.setPolicy(t, e.adminCaller(t), func(p *auth.Policy) { p.LockoutMinutes = 0 })
	for range auth.DefaultPolicy().LockoutThreshold {
		e.fail(t, "admin", wrongPhrase)
	}
	u := e.userByID(t, adminID)
	if u.LockedAt.IsZero() || u.LockedUntil.Sub(u.LockedAt) != 15*time.Minute {
		t.Fatalf("блокировка последнего администратора: %v — %v", u.LockedAt, u.LockedUntil)
	}
	if rec := lastRecord(t, e.mem, "auth.locked"); rec.Details.(map[string]any)["lockout_minutes"] != 15 {
		t.Fatalf("аудит: %v", rec.Details)
	}
	e.clock.add(16 * time.Minute)
	e.mfa.complete(t, e.mustLogin(t, "admin", phrase))
	// Обычного пользователя блокировка держит до разблокировки.
	for range auth.DefaultPolicy().LockoutThreshold {
		e.fail(t, "ivanov", wrongPhrase)
	}
	if u := e.userByID(t, userID); u.LockedAt.IsZero() || !u.LockedUntil.IsZero() {
		t.Fatalf("бессрочная блокировка: %v — %v", u.LockedAt, u.LockedUntil)
	}
}

// Есть другой незаблокированный администратор безопасности — настройка
// бессрочной блокировки действует и для администратора.
func TestAdminLockoutIndefiniteWithSecondAdmin(t *testing.T) {
	e := newEnv(t)
	e.setPolicy(t, e.adminCaller(t), func(p *auth.Policy) { p.LockoutMinutes = 0 })
	e.mem.AddUser(e.user(helperID, "admin2", auth.RoleSecurityAdmin))
	for range auth.DefaultPolicy().LockoutThreshold {
		e.fail(t, "admin", wrongPhrase)
	}
	if u := e.userByID(t, adminID); u.LockedAt.IsZero() || !u.LockedUntil.IsZero() {
		t.Fatalf("блокировка при втором администраторе: %v — %v", u.LockedAt, u.LockedUntil)
	}
	// Второй тоже заблокирован — разблокировать некому, ему 15 минут.
	for range auth.DefaultPolicy().LockoutThreshold {
		e.fail(t, "admin2", wrongPhrase)
	}
	if u := e.userByID(t, helperID); u.LockedUntil.IsZero() {
		t.Fatal("последний незаблокированный администратор заблокирован бессрочно")
	}
}

// В7: аварийные команды aisec-cli — снятие блокировки, сброс пароля и
// фактора без прав консоли, с записью от пользователя ОС.
func TestLocalRecovery(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.mfa.completeLogin(t, e.mustLogin(t, "admin", phrase))
	e.setPolicy(t, admin.Caller, func(p *auth.Policy) { p.LockoutMinutes = 0 })
	e.mem.AddUser(e.user(helperID, "admin2", auth.RoleSecurityAdmin))
	for range auth.DefaultPolicy().LockoutThreshold {
		e.fail(t, "admin", wrongPhrase)
	}
	if err := e.svc.LocalUnlock(ctx, cliActor, "Admin"); err != nil {
		t.Fatal(err)
	}
	rec := lastRecord(t, e.mem, "auth.unlocked")
	if rec.Actor != cliActor || rec.Object.ID != adminID || rec.Details.(map[string]any)["was_locked"] != true {
		t.Fatalf("запись: %+v", rec)
	}
	full := e.mfa.completeLogin(t, e.mustLogin(t, "admin", phrase))
	temp, err := e.svc.LocalResetPassword(ctx, cliActor, "admin")
	if err != nil || temp == "" {
		t.Fatalf("сброс пароля: %v", err)
	}
	if _, err := e.caller(t, full.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия после сброса пароля: %v", err)
	}
	if rec := lastRecord(t, e.mem, "user.password_reset"); rec.Actor != cliActor {
		t.Fatalf("сброс пароля от %+v", rec.Actor)
	}
	if err := e.svc.LocalResetMFA(ctx, cliActor, "admin"); err != nil {
		t.Fatal(err)
	}
	if r := e.mustLogin(t, "admin", temp); r.Caller.Session.State != auth.SessionMFASetup {
		t.Fatalf("вход после сброса фактора: %s", r.Caller.Session.State)
	}
	if err := e.svc.LocalResetMFA(ctx, cliActor, "admin"); !errors.Is(err, auth.ErrMFANotEnabled) {
		t.Fatalf("повторный сброс: %v", err)
	}
	// Отказы: не aisec-cli, неизвестный логин, деактивированная запись.
	if err := e.svc.LocalUnlock(ctx, audit.Actor{Type: audit.ActorUser, ID: adminID}, "admin"); err == nil {
		t.Fatal("аварийное действие от пользователя консоли")
	}
	if err := e.svc.LocalUnlock(ctx, cliActor, "nobody"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("неизвестный логин: %v", err)
	}
	if err := e.svc.SetStatus(ctx, e.adminCaller2(t), userID, auth.StatusDeactivated); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LocalUnlock(ctx, cliActor, "ivanov"); !errors.Is(err, auth.ErrDeactivated) {
		t.Fatalf("деактивированная запись: %v", err)
	}
}

// adminCaller2 — полный вход второго администратора безопасности admin2.
func (e *env) adminCaller2(t *testing.T) auth.Caller {
	t.Helper()
	return e.mfa.complete(t, e.mustLogin(t, "admin2", phrase))
}

// Н15 ревью 2.r2: в записи активации видно, снималась ли блокировка.
func TestActivateRecordsWasLocked(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	e.setPolicy(t, admin, func(p *auth.Policy) { p.LockoutMinutes = 0 })
	for range auth.DefaultPolicy().LockoutThreshold {
		e.fail(t, "ivanov", wrongPhrase)
	}
	if err := e.svc.SetStatus(ctx, admin, userID, auth.StatusActive); err != nil {
		t.Fatal(err)
	}
	if d := lastRecord(t, e.mem, "user.activate").Details.(map[string]any); d["was_locked"] != true || d["previous_status"] != "active" {
		t.Fatalf("подробности: %v", d)
	}
	if err := e.svc.SetStatus(ctx, admin, userID, auth.StatusActive); err != nil {
		t.Fatal(err)
	}
	if d := lastRecord(t, e.mem, "user.activate").Details.(map[string]any); d["was_locked"] != false {
		t.Fatalf("без блокировки: %v", d)
	}
}
