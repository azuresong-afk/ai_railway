package auth_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Второй фактор на PostgreSQL: секрет зашифрован ключом данных установки,
// записи аудита — в цепочке.
func TestPGMFAFlow(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	admin := e.mfa.complete(t, mustPGLogin(t, e, "admin"))
	var (
		keyID, state string
		secret       []byte
		sealed       int64
	)
	if err := e.owner.QueryRow(ctx, "SELECT data_key_id::text, state, secret FROM user_mfa WHERE user_id = $1", adminID).
		Scan(&keyID, &state, &secret); err != nil {
		t.Fatal(err)
	}
	if keyID != e.keyID || state != "enabled" || strings.Contains(string(secret), string(e.mfa.secrets[adminID])) {
		t.Fatalf("строка фактора: %s %s", keyID, state)
	}
	// Шифрование учтено в счётчике ключа данных (резерв пачкой, ADR-0007).
	if err := e.owner.QueryRow(ctx, "SELECT sealed FROM data_keys WHERE id = $1", e.keyID).Scan(&sealed); err != nil || sealed == 0 {
		t.Fatalf("счётчик ключа: %d %v", sealed, err)
	}
	// Шифротекст привязан к строке (AAD): чужой секрет, подставленный в
	// строку пользователя, не расшифровывается.
	user := e.mfa.complete(t, mustPGLogin(t, e, "ivanov"))
	e.mfa.enroll(t, user)
	if _, err := e.owner.Exec(ctx, "UPDATE user_mfa SET secret = $2 WHERE user_id = $1", userID, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ConfirmMFA(ctx, user, e.mfa.code(t, userID)); err == nil || errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("подменённый секрет: %v", err)
	}

	res := mustPGLogin(t, e, "admin")
	if res.Caller.Session.State != auth.SessionMFAPending {
		t.Fatalf("вход с фактором: %s", res.Caller.Session.State)
	}
	e.mfa.complete(t, res)
	if err := e.svc.ResetMFA(ctx, admin, userID); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"auth.mfa_enabled", "auth.mfa_verified", "auth.mfa_reset"} {
		if auditCount(t, e, a) == 0 {
			t.Errorf("нет записи %s в audit_log", a)
		}
	}
	v, err := audit.NewVerifier(e.log).Verify(ctx)
	if err != nil || !v.OK() {
		t.Fatalf("цепочка аудита: %v %+v", err, v.Break)
	}
}

func mustPGLogin(t *testing.T, e *pgEnv, login string) auth.LoginResult {
	t.Helper()
	res, err := e.login(t, login, phrase)
	if err != nil {
		t.Fatalf("вход %s: %v", login, err)
	}
	return res
}

// ADR-0006: один код TOTP (и один код восстановления) в параллельных
// запросах принимается ровно один раз — условием last_step < $шаг.
func TestPGMFAReplayConcurrent(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	res := mustPGLogin(t, e, "admin")
	e.mfa.enroll(t, res.Caller)
	conf, err := e.svc.ConfirmMFA(ctx, res.Caller, e.mfa.code(t, adminID))
	if err != nil {
		t.Fatal(err)
	}
	codes := conf.RecoveryCodes
	// Сессий не больше лимита и неудач меньше порога блокировки.
	const n = 4
	for _, tc := range []struct {
		name           string
		code, recovery string
	}{{"код TOTP", e.mfa.code(t, adminID), ""}, {"код восстановления", "", codes[0]}} {
		t.Run(tc.name, func(t *testing.T) {
			// Прежние сессии завершаются: вход с тем же временем вытеснял бы
			// по лимиту случайную из новых (порядок UUIDv7 внутри миллисекунды).
			if _, err := e.owner.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoke_reason = 'logout'
				WHERE user_id = $1 AND revoked_at IS NULL`, adminID); err != nil {
				t.Fatal(err)
			}
			callers := make([]auth.Caller, n)
			for i := range callers {
				callers[i] = mustPGLogin(t, e, "admin").Caller
			}
			var (
				wg sync.WaitGroup
				mu sync.Mutex
				ok int
			)
			for _, c := range callers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := e.svc.VerifyMFA(pgCtx(t), c, tc.code, tc.recovery)
					switch {
					case err == nil:
						mu.Lock()
						ok++
						mu.Unlock()
					case !errors.Is(err, auth.ErrInvalidCode):
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			if ok != 1 {
				t.Fatalf("код принят %d раз из %d", ok, n)
			}
			// Принятый код сбросил счётчик, остальные — неудачи после него или до.
			if _, err := e.owner.Exec(ctx, "UPDATE users SET failed_attempts = 0 WHERE id = $1", adminID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Триггеры и права роли приложения защищают строки фактора и кодов.
func TestPGMFAGuards(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.mfa.complete(t, mustPGLogin(t, e, "admin"))
	for name, q := range map[string]string{
		"шаг назад":         "UPDATE user_mfa SET last_step = 0 WHERE user_id = $1",
		"замена секрета":    "UPDATE user_mfa SET secret = secret || '\\x00'::bytea WHERE user_id = $1",
		"отключение":        "UPDATE user_mfa SET state = 'pending', enabled_at = NULL WHERE user_id = $1",
		"подмена хеша кода": "UPDATE recovery_codes SET code_hash = '\\x00000000000000000000000000000000'::bytea WHERE user_id = $1",
		"удаление кодов":    "DELETE FROM recovery_codes WHERE user_id = $1",
		"смена владельца":   "UPDATE user_mfa SET user_id = user_id WHERE user_id = $1",
	} {
		// 23514 — триггер, 42501 — у роли приложения нет такого права.
		if _, err := e.app.Exec(ctx, q, adminID); sqlState(err) != "23514" && sqlState(err) != "42501" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Код гасится один раз и обратно не возвращается.
	if _, err := e.app.Exec(ctx, "UPDATE recovery_codes SET used_at = now() WHERE user_id = $1", adminID); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"UPDATE recovery_codes SET used_at = now() WHERE user_id = $1",
		"UPDATE recovery_codes SET used_at = NULL WHERE user_id = $1"} {
		if _, err := e.app.Exec(ctx, q, adminID); sqlState(err) != "23514" {
			t.Errorf("%s: %v", q, err)
		}
	}
}

// ИАФ.4 и ADR-0006: параллельные неверные коды проверяются под блокировкой
// строки пользователя — неудач засчитывается ровно до порога, остальные
// запросы получают отказ блокировки, а не ещё одну проверку кода.
func TestPGMFALockoutConcurrent(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.mfa.complete(t, mustPGLogin(t, e, "admin"))
	threshold := auth.DefaultPolicy().LockoutThreshold
	callers := make([]auth.Caller, 4)
	for i := range callers {
		e.clock.add(time.Second)
		callers[i] = mustPGLogin(t, e, "admin").Caller
	}
	const perSession = 3
	var (
		wg              sync.WaitGroup
		mu              sync.Mutex
		invalid, locked int
	)
	for _, c := range callers {
		for range perSession {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := e.svc.VerifyMFA(pgCtx(t), c, "000000", "")
				mu.Lock()
				defer mu.Unlock()
				switch {
				case errors.Is(err, auth.ErrInvalidCode):
					invalid++
				case errors.Is(err, auth.ErrLocked):
					locked++
				default:
					t.Errorf("неожиданный ответ: %v", err)
				}
			}()
		}
	}
	wg.Wait()
	if invalid != threshold || locked != len(callers)*perSession-threshold {
		t.Fatalf("неверных %d, отказов блокировки %d (порог %d)", invalid, locked, threshold)
	}
	var attempts int
	if err := e.owner.QueryRow(ctx, "SELECT failed_attempts FROM users WHERE id = $1", adminID).Scan(&attempts); err != nil ||
		attempts != threshold {
		t.Fatalf("счётчик неудач: %d %v", attempts, err)
	}
	if n := auditCount(t, e, "auth.mfa_failed"); n != threshold {
		t.Fatalf("auth.mfa_failed: %d", n)
	}
	if n := auditCount(t, e, "auth.locked"); n != 1 {
		t.Fatalf("auth.locked: %d", n)
	}
}

// УПД.4: сессии до второго фактора вытесняют только друг друга — вход по
// одному паролю не завершает полную сессию владельца учётной записи.
func TestPGPreMFASessionsDoNotEvictFull(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	full := e.mfa.completeLogin(t, mustPGLogin(t, e, "admin"))
	limit := auth.DefaultPolicy().SessionMaxPerUser
	var tokens []string
	for range limit + 2 {
		e.clock.add(time.Second)
		tokens = append(tokens, mustPGLogin(t, e, "admin").Token)
	}
	if _, err := e.svc.Authenticate(ctx, full.Token, testIP); err != nil {
		t.Fatalf("полная сессия после входов по паролю: %v", err)
	}
	var pending, active int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'mfa_pending'), count(*) FILTER (WHERE state = 'active')
		FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, adminID).Scan(&pending, &active); err != nil {
		t.Fatal(err)
	}
	if pending != limit || active != 1 {
		t.Fatalf("сессий до второго фактора %d, полных %d", pending, active)
	}
	// Вытеснены самые старые сессии до второго фактора.
	if _, err := e.svc.Authenticate(ctx, tokens[0], testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("старейшая сессия до второго фактора: %v", err)
	}
	if _, err := e.svc.Authenticate(ctx, tokens[len(tokens)-1], testIP); err != nil {
		t.Fatalf("новая сессия: %v", err)
	}
}
