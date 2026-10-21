package auth_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
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

	tok, raw, err := e.svc.CreateAPIToken(ctx, sys, auth.APITokenInput{Name: "Мониторинг", ExpiresInDays: 30,
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
	tok2, _, err := e.svc.CreateAPIToken(ctx, admin, auth.APITokenInput{Name: "Отчёты", Permissions: grants(auth.PermUsersRead)})
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
	tok, _, err := e.svc.CreateAPIToken(ctx, admin, auth.APITokenInput{Name: "x", Permissions: grants(auth.PermSystemRead)})
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
			_, _, err := e.svc.CreateAPIToken(ctx, admin, auth.APITokenInput{Name: "x", Permissions: grants(auth.PermSystemRead)})
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
