package auth_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
)

// Тесты токенов API на живой БД (AISEC_TEST_DATABASE_URL); без переменной
// пропускаются.

func TestPGAPITokensFlow(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.addUser(t, sysadmID, "sysadm", auth.RoleSystemAdmin)
	res, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	admin := e.mfa.complete(t, res)
	if res, err = e.login(t, "sysadm", phrase); err != nil {
		t.Fatal(err)
	}
	sys := e.mfa.complete(t, res)

	tok, raw, err := e.svc.CreateAPIToken(ctx, sys, auth.APITokenInput{Password: phrase, Name: "Мониторинг", ExpiresInDays: 30,
		Permissions: grants(auth.PermSystemRead)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.svc.AuthenticateAPIToken(ctx, raw, tokenIP)
	if err != nil || c.Token.ID != tok.ID || !c.Token.Grants.Full(auth.PermSystemRead) || c.User.ID != sysadmID {
		t.Fatalf("вход по токену: %+v %v", c, err)
	}
	if err := e.svc.APITokenUsed(ctx, c, "GET", "/api/v1/system/info", 200); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.APITokenByID(ctx, admin, tok.ID)
	if err != nil || got.LastUsedIP != tokenIP || got.LastUsedAt.IsZero() || got.Prefix != tok.Prefix ||
		!got.ExpiresAt.Equal(tok.ExpiresAt) || got.Name != "Мониторинг" {
		t.Fatalf("токен из БД: %+v %v", got, err)
	}
	if _, err := e.svc.AuthenticateAPIToken(ctx, raw[:len(raw)-43]+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", tokenIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("чужой секрет: %v", err)
	}
	if _, err := e.svc.AuthenticateAPIToken(ctx, "aisec_pat_00000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", tokenIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("неизвестный префикс: %v", err)
	}

	// Список: свои при own, все при all; курсор.
	tok2, _, err := e.svc.CreateAPIToken(ctx, admin, auth.APITokenInput{Password: phrase, Name: "Отчёты", Permissions: grants(auth.PermUsersRead)})
	if err != nil {
		t.Fatal(err)
	}
	if l, err := e.svc.APITokens(ctx, sys, nil, 10); err != nil || len(l) != 1 || l[0].ID != tok.ID {
		t.Fatalf("свои: %v %v", l, err)
	}
	first, err := e.svc.APITokens(ctx, admin, nil, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("первая страница: %v %v", first, err)
	}
	next, err := e.svc.APITokens(ctx, admin, &auth.UserCursor{CreatedAt: first[0].CreatedAt, ID: first[0].ID}, 10)
	if err != nil || len(next) != 1 || next[0].ID == first[0].ID {
		t.Fatalf("вторая страница: %v %v", next, err)
	}

	r, err := e.svc.RevokeAPIToken(ctx, admin, tok.ID)
	if err != nil || r.RevokeReason != auth.APITokenRevokedByAdmin {
		t.Fatalf("отзыв: %+v %v", r, err)
	}
	if _, err := e.svc.RevokeAPIToken(ctx, admin, tok.ID); !errors.Is(err, auth.ErrAPITokenRevoked) {
		t.Fatalf("повторный отзыв: %v", err)
	}
	if _, err := e.svc.AuthenticateAPIToken(ctx, raw, tokenIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("отозванный токен: %v", err)
	}
	if _, err := e.svc.RevokeAPIToken(ctx, admin, tok2.ID); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"api_token.create", "api_token.revoke", "api_token.used", "api_token.auth_failed"} {
		if auditCount(t, e, a) == 0 {
			t.Errorf("нет записи %s в журнале аудита", a)
		}
	}
}

// Права роли приложения и триггер: хеш, область и срок неизменны,
// отозванный токен не оживает, токены не удаляются — даже владельцем таблицы.
func TestPGAPITokensGuard(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	res, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	admin := e.mfa.complete(t, res)
	tok, _, err := e.svc.CreateAPIToken(ctx, admin, auth.APITokenInput{Password: phrase, Name: "x", Permissions: grants(auth.PermSystemRead)})
	if err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"хеш":      "UPDATE api_tokens SET token_hash = '\\x00000000000000000000000000000000' WHERE id = $1",
		"область":  "UPDATE api_tokens SET permissions = ARRAY['users.manage:all'] WHERE id = $1",
		"срок":     "UPDATE api_tokens SET expires_at = expires_at + interval '1 day' WHERE id = $1",
		"удаление": "DELETE FROM api_tokens WHERE id = $1",
	} {
		if _, err := e.app.Exec(ctx, q, tok.ID); sqlState(err) != "42501" {
			t.Errorf("роль приложения, %s: %v", name, err)
		}
		if _, err := e.owner.Exec(ctx, q, tok.ID); err == nil {
			t.Errorf("владелец таблицы, %s: изменение прошло", name)
		}
	}
	if _, err := e.svc.RevokeAPIToken(ctx, admin, tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, "UPDATE api_tokens SET revoked_at = NULL, revoked_by = NULL, revoke_reason = NULL WHERE id = $1", tok.ID); sqlState(err) != "23514" {
		t.Fatalf("оживление отозванного: %v", err)
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, hash_alg, permissions, expires_at, created_at)
		VALUES ('01900000-0000-7000-8000-0000000ab001', $1, $2, 'x', 'aisec_pat_aaaaaaaa', '\x00000000000000000000000000000000', 'sha256',
		ARRAY['system.read:all'], now() + interval '400 days', now())`, audit.DefaultOrgID, adminID); sqlState(err) != "23514" {
		t.Fatalf("срок больше года: %v", err)
	}
}

// Предел действующих токенов не обходится параллельными выпусками.
func TestPGAPITokensLimitConcurrent(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	res, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	admin := e.mfa.complete(t, res)
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok int
	)
	for range auth.MaxAPITokensPerUser + 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := e.svc.CreateAPIToken(ctx, admin, auth.APITokenInput{Password: phrase, Name: "x", Permissions: grants(auth.PermSystemRead)})
			switch {
			case err == nil:
				mu.Lock()
				ok++
				mu.Unlock()
			case !errors.Is(err, auth.ErrTooManyAPITokens):
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != auth.MaxAPITokensPerUser {
		t.Fatalf("выпущено %d токенов", ok)
	}
}

// В8 ревью 2.r2 на PostgreSQL: отзыв токенов при сбросе пароля и
// завершении сессий — в той же транзакции; сброс через aisec-cli — без
// revoked_by. Без причины password_reset пустой revoked_by отвергает CHECK.
func TestPGTokensRevokedWithAdminActions(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.addUser(t, helperID, "admin2", auth.RoleSecurityAdmin)
	admin := e.mfa.complete(t, mustPGLogin(t, e, "admin"))
	issue := func() string {
		t.Helper()
		second := e.mfa.complete(t, mustPGLogin(t, e, "admin2"))
		tok, _, err := e.svc.CreateAPIToken(ctx, second, auth.APITokenInput{Password: phrase, Name: "x", Permissions: grants(auth.PermSystemRead)})
		if err != nil {
			t.Fatal(err)
		}
		return tok.ID
	}
	row := func(id string) (reason string, by *string) {
		t.Helper()
		var r *string
		if err := e.owner.QueryRow(ctx, "SELECT revoke_reason, revoked_by::text FROM api_tokens WHERE id = $1", id).Scan(&r, &by); err != nil {
			t.Fatal(err)
		}
		if r != nil {
			reason = *r
		}
		return reason, by
	}
	t1 := issue()
	if _, err := e.svc.RevokeSessions(ctx, admin, helperID, false); err != nil {
		t.Fatal(err)
	}
	if r, _ := row(t1); r != "" {
		t.Fatalf("отозван без запроса: %s", r)
	}
	if _, err := e.svc.RevokeSessions(ctx, admin, helperID, true); err != nil {
		t.Fatal(err)
	}
	if r, by := row(t1); r != auth.APITokenRevokedBySessions || by == nil || *by != adminID {
		t.Fatalf("завершение сессий: %s %v", r, by)
	}
	t2 := issue()
	if _, err := e.svc.ResetPassword(ctx, admin, helperID); err != nil {
		t.Fatal(err)
	}
	if r, by := row(t2); r != auth.APITokenRevokedByPasswordReset || by == nil || *by != adminID {
		t.Fatalf("сброс пароля: %s %v", r, by)
	}
	restore := func() {
		t.Helper()
		if _, err := e.owner.Exec(ctx, `UPDATE users SET must_change_password = false, temp_password_expires_at = NULL,
			password_hash = $2 WHERE id = $1`, helperID, authtest.HashOf(phrase)); err != nil {
			t.Fatal(err)
		}
	}
	restore()
	t3 := issue()
	cli := audit.Actor{Type: audit.ActorCLI, ID: "uid:0", Name: "root"}
	if _, err := e.svc.LocalResetPassword(ctx, cli, "admin2"); err != nil {
		t.Fatal(err)
	}
	if r, by := row(t3); r != auth.APITokenRevokedByPasswordReset || by != nil {
		t.Fatalf("сброс через aisec-cli: %s %v", r, by)
	}
	var dbUser string
	if err := e.owner.QueryRow(ctx, `SELECT details->>'db_user' FROM audit_log WHERE action = 'user.password_reset'
		AND actor_type = 'cli' ORDER BY seq DESC LIMIT 1`).Scan(&dbUser); err != nil || dbUser == "" {
		t.Fatalf("логин СУБД в записи aisec-cli: %q %v", dbUser, err)
	}
	restore()
	if _, err := e.owner.Exec(ctx, `UPDATE api_tokens SET revoked_at = now(), revoke_reason = 'admin' WHERE id = $1`, issue()); sqlState(err) != "23514" {
		t.Fatalf("отзыв без revoked_by: %v", err)
	}
}
