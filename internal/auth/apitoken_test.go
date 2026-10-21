package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Синтетическая учётная запись администратора системы для проверок токенов.
const sysadmID = "01900000-0000-7000-8000-00000000f101"

var tokenIP = netip.MustParseAddr("198.51.100.7")

// sysadmCaller — полный вход администратора системы (у роли обязателен второй фактор).
func (e *env) sysadmCaller(t *testing.T) auth.Caller {
	t.Helper()
	e.mem.AddUser(e.user(sysadmID, "sysadm", auth.RoleSystemAdmin))
	return e.mfa.complete(t, e.mustLogin(t, "sysadm", phrase))
}

func (e *env) issue(t *testing.T, by auth.Caller, perms ...string) (auth.APIToken, string) {
	t.Helper()
	tok, raw, err := e.svc.CreateAPIToken(context.Background(), by, auth.APITokenInput{Name: "Выгрузка", Permissions: grants(perms...)})
	if err != nil {
		t.Fatalf("выпуск токена: %v", err)
	}
	return tok, raw
}

// noSecret — секрета токена нет ни в одной записи аудита.
func noSecret(t *testing.T, e *env, raw string) {
	t.Helper()
	secret := raw[strings.LastIndex(raw, "_")+1:]
	for _, r := range e.mem.Records() {
		if s := fmt.Sprintf("%+v", r); strings.Contains(s, secret) {
			t.Fatalf("секрет токена в записи %s", r.Action)
		}
	}
}

func TestParseAPIToken(t *testing.T) {
	e := newEnv(t)
	_, raw := e.issue(t, e.adminCaller(t), auth.PermSystemRead)
	prefix, err := auth.ParseAPIToken(raw)
	if err != nil || !strings.HasPrefix(raw, prefix+"_") || len(prefix) != len("aisec_pat_")+8 {
		t.Fatalf("разбор выпущенного токена: %q %v", prefix, err)
	}
	// Последний символ base64url 32 байт несёт 4 значащих бита из 6: символ с
	// ненулевыми лишними битами — неканоничная запись того же секрета.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alt := alphabet[strings.IndexByte(alphabet, raw[len(raw)-1])|1]
	for name, s := range map[string]string{
		"пусто":           "",
		"ключ приложения": "aisec_abcd1234_" + strings.Repeat("A", 43),
		"короткий секрет": raw[:len(raw)-1],
		"длинный секрет":  raw + "A",
		"заглавные в ID":  raw[:10] + "ABCDEFGH" + raw[18:],
		"неканоничный":    raw[:len(raw)-1] + string(alt),
		"пробел":          " " + raw,
		"перевод строки":  raw + "\n",
		"слишком длинный": raw + strings.Repeat("A", auth.MaxKeyLen),
		"чужая схема":     strings.Replace(raw, "aisec_pat_", "aisec_tok_", 1),
		"недопустимый ID": raw[:10] + "-" + raw[11:],
		"не base64url":    raw[:len(raw)-2] + "+/",
		"только префикс":  prefix,
	} {
		if s == raw {
			continue
		}
		if _, err := auth.ParseAPIToken(s); !errors.Is(err, auth.ErrMalformedAPIToken) {
			t.Errorf("%s: %q принят", name, s)
		}
	}
}

// ИАФ.9: токену не выдаются функции безопасности и права на токены;
// права токена — пересечение с ролью владельца, с меньшей областью.
func TestTokenGrants(t *testing.T) {
	for _, p := range auth.Permissions() {
		want := !p.Security && !strings.HasPrefix(p.Name, "api_tokens.")
		if auth.TokenGrantable(p.Name) != want {
			t.Errorf("%s: TokenGrantable = %v", p.Name, !want)
		}
	}
	for _, p := range []string{auth.PermSelf, auth.PermSession, "unknown.read", ""} {
		if auth.TokenGrantable(p) {
			t.Errorf("%q доступно токену", p)
		}
	}
	tok := auth.Grants{auth.PermSystemRead: auth.ScopeAll, auth.PermUsersRead: auth.ScopeAll, auth.PermAPITokensRead: auth.ScopeOwn,
		auth.PermUsersManage: auth.ScopeAll, auth.PermSessionsRead: auth.ScopeAll, "self": auth.ScopeAll}
	role := auth.Grants{auth.PermSystemRead: auth.ScopeAll, auth.PermUsersRead: auth.ScopeOwn, auth.PermAPITokensRead: auth.ScopeAll,
		auth.PermUsersManage: auth.ScopeAll}
	got := auth.TokenGrants(tok, role)
	want := auth.Grants{auth.PermSystemRead: auth.ScopeAll, auth.PermUsersRead: auth.ScopeOwn}
	if len(got) != len(want) || !got.Covers(want) || !want.Covers(got) {
		t.Fatalf("пересечение %v, ожидалось %v", got, want)
	}
	c := auth.Caller{Session: auth.Session{State: auth.SessionActive}, Token: &auth.APIToken{Grants: tok}}
	if g := auth.SessionGrants(c, role); g.Allows(auth.PermSelf) || g.Allows(auth.PermSession) || g.Allows(auth.PermUsersManage) {
		t.Fatalf("у токена права сессии или безопасности: %v", g)
	}
}

func TestCreateAPITokenValidation(t *testing.T) {
	e := newEnv(t)
	admin := e.adminCaller(t)
	ctx := context.Background()
	for name, in := range map[string]auth.APITokenInput{
		"без названия":      {Name: " ", Permissions: grants(auth.PermSystemRead)},
		"без разрешений":    {Name: "x"},
		"срок 0 дней":       {Name: "x", ExpiresInDays: -1, Permissions: grants(auth.PermSystemRead)},
		"срок 366 дней":     {Name: "x", ExpiresInDays: 366, Permissions: grants(auth.PermSystemRead)},
		"безопасность":      {Name: "x", Permissions: grants(auth.PermUsersManage)},
		"роли":              {Name: "x", Permissions: grants(auth.PermRolesManage)},
		"проверка целостн.": {Name: "x", Permissions: grants(auth.PermIntegrityVerify)},
		"токены":            {Name: "x", Permissions: grants(auth.PermAPITokensRead)},
		"своё self":         {Name: "x", Permissions: grants(auth.PermSelf)},
		"неизвестное":       {Name: "x", Permissions: grants("unknown.read")},
		"повтор":            {Name: "x", Permissions: grants(auth.PermSystemRead, auth.PermSystemRead)},
		"own у не Ownable":  {Name: "x", Permissions: []auth.GrantInput{{Permission: auth.PermSystemRead, Scope: "own"}}},
		"неизвестная обл.":  {Name: "x", Permissions: []auth.GrantInput{{Permission: auth.PermSystemRead, Scope: "any"}}},
	} {
		var ie *auth.InputError
		if _, _, err := e.svc.CreateAPIToken(ctx, admin, in); !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
	tok, raw := e.issue(t, admin, auth.PermSystemRead, auth.PermUsersRead)
	if d := tok.ExpiresAt.Sub(tok.CreatedAt); d != auth.APITokenDefaultDays*24*time.Hour {
		t.Errorf("срок по умолчанию %v", d)
	}
	if strings.Contains(string(tok.Hash), raw) || len(tok.Hash) == 0 {
		t.Fatal("в БД должен быть только хеш")
	}
	rec := lastRecord(t, e.mem, "api_token.create")
	if rec.Actor.Type != audit.ActorUser || rec.Object.ID != tok.ID || rec.Result != audit.ResultSuccess {
		t.Fatalf("запись выпуска: %+v", rec)
	}
	noSecret(t, e, raw)
}

// УПД.2: токен не шире прав владельца; аналитик не выпускает токены; токен
// не выпускает токены; предел действующих токенов.
func TestCreateAPITokenEscalation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	sys := e.sysadmCaller(t)
	if _, _, err := e.svc.CreateAPIToken(ctx, sys, auth.APITokenInput{Name: "x", Permissions: grants(auth.PermUsersRead)}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("разрешение сверх роли: %v", err)
	}
	if deniedRecords(e.mem, "api_token.create") != 1 {
		t.Fatal("отказ не записан в аудит")
	}
	analyst := e.mustCaller(t, e.mustLogin(t, "ivanov", phrase).Token)
	if _, _, err := e.svc.CreateAPIToken(ctx, analyst, auth.APITokenInput{Name: "x", Permissions: grants(auth.PermSystemRead)}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("аналитик выпустил токен: %v", err)
	}
	_, raw := e.issue(t, sys, auth.PermSystemRead)
	viaToken, err := e.svc.AuthenticateAPIToken(ctx, raw, tokenIP)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.CreateAPIToken(ctx, viaToken, auth.APITokenInput{Name: "x", Permissions: grants(auth.PermSystemRead)}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("токен выпустил токен: %v", err)
	}
	for i := 1; i < auth.MaxAPITokensPerUser; i++ {
		e.issue(t, sys, auth.PermSystemRead)
	}
	if _, _, err := e.svc.CreateAPIToken(ctx, sys, auth.APITokenInput{Name: "x", Permissions: grants(auth.PermSystemRead)}); !errors.Is(err, auth.ErrTooManyAPITokens) {
		t.Fatalf("предел: %v", err)
	}
}

func authFailed(t *testing.T, e *env) audit.Entry {
	t.Helper()
	return lastRecord(t, e.mem, "api_token.auth_failed")
}

func TestAuthenticateAPIToken(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	tok, raw := e.issue(t, admin, auth.PermSystemRead, auth.PermUsersRead)
	c, err := e.svc.AuthenticateAPIToken(ctx, raw, tokenIP)
	if err != nil || c.Token == nil || c.Token.ID != tok.ID || c.User.ID != adminID || c.SourceIP != tokenIP {
		t.Fatalf("вход по токену: %+v %v", c, err)
	}
	if !allowed(t, e, c, auth.PermUsersRead) || allowed(t, e, c, auth.PermUsersManage) || allowed(t, e, c, auth.PermSelf) {
		t.Fatal("права токена не совпадают с областью")
	}
	if err := e.svc.APITokenUsed(ctx, c, "GET", "/api/v1/users", 200); err != nil {
		t.Fatal(err)
	}
	used := lastRecord(t, e.mem, "api_token.used")
	if used.Actor.Type != audit.ActorAPIToken || used.Actor.ID != tok.ID || !strings.Contains(used.Actor.Name, tok.Prefix) {
		t.Fatalf("субъект запроса по токену: %+v", used.Actor)
	}
	stored, err := e.svc.APITokenByID(ctx, admin, tok.ID)
	if err != nil || stored.LastUsedIP != tokenIP || stored.LastUsedAt.IsZero() {
		t.Fatalf("отметка использования: %+v %v", stored, err)
	}

	// Другой секрет с тем же префиксом: отказ без указания на токен.
	forged := raw[:len(raw)-43] + strings.Repeat("A", 43)
	if _, err := e.svc.AuthenticateAPIToken(ctx, forged, tokenIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("чужой секрет: %v", err)
	}
	if r := authFailed(t, e); r.Actor.ID == tok.ID || r.Details.(map[string]any)["reason"] != auth.ReasonInvalid {
		t.Fatalf("отказ по секрету: %+v", r)
	}
	// Тот же токен, но хеш другого алгоритма или подменённый — не принимается.
	e.mem.SetAPITokenHash(tok.ID, make([]byte, len(tok.Hash)))
	if _, err := e.svc.AuthenticateAPIToken(ctx, raw, tokenIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("подменённый хеш: %v", err)
	}
	e.mem.SetAPITokenHash(tok.ID, tok.Hash)

	for name, s := range map[string]string{"формат": "Basic xyz", "префикс": "aisec_pat_zzzzzzzz_" + strings.Repeat("A", 43)} {
		if _, err := e.svc.AuthenticateAPIToken(ctx, s, tokenIP); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("%s: %v", name, err)
		}
		r := authFailed(t, e)
		if r.Actor.Type != audit.ActorAPIToken || r.Actor.ID == tok.ID || strings.Contains(fmt.Sprint(r), "xyz") {
			t.Fatalf("%s: запись отказа %+v", name, r)
		}
	}

	// Понижение роли владельца сразу сужает токен.
	e.mem.AddUser(e.user(admin2ID, "admin2", auth.RoleSecurityAdmin))
	admin2 := e.mfa.complete(t, e.mustLogin(t, "admin2", phrase))
	if _, err := e.svc.AssignRole(ctx, admin2, adminID, auth.RoleAuditor); err != nil {
		t.Fatal(err)
	}
	c, err = e.svc.AuthenticateAPIToken(ctx, raw, tokenIP)
	if err != nil || !allowed(t, e, c, auth.PermUsersRead) {
		t.Fatalf("аудитор читает пользователей: %v", err)
	}
	if _, err := e.svc.AssignRole(ctx, admin2, adminID, auth.RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	if c, err = e.svc.AuthenticateAPIToken(ctx, raw, tokenIP); err != nil || allowed(t, e, c, auth.PermUsersRead) || !allowed(t, e, c, auth.PermSystemRead) {
		t.Fatal("права роли не сузили токен")
	}

	// Деактивированный владелец: токен не работает.
	if err := e.svc.SetStatus(ctx, admin2, adminID, auth.StatusDeactivated); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AuthenticateAPIToken(ctx, raw, tokenIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("токен деактивированного: %v", err)
	}
	if r := authFailed(t, e); r.Actor.ID != tok.ID || r.Details.(map[string]any)["reason"] != "owner_inactive" {
		t.Fatalf("отказ деактивированному: %+v", r)
	}
	if err := e.svc.SetStatus(ctx, admin2, adminID, auth.StatusActive); err != nil {
		t.Fatal(err)
	}

	// Истёкший токен.
	e.mem.ExpireAPIToken(tok.ID, e.clock.now())
	if _, err := e.svc.AuthenticateAPIToken(ctx, raw, tokenIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("истёкший токен: %v", err)
	}
	if r := authFailed(t, e); r.Details.(map[string]any)["reason"] != auth.ReasonExpired {
		t.Fatalf("отказ по сроку: %+v", r)
	}
	noSecret(t, e, raw)
}

// УПД.8: при области own видны и отзываются только свои токены; чужой
// токен отзывает только тот, чьи права шире прав владельца (УПД.2).
func TestAPITokenScopeAndRevoke(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	sys := e.sysadmCaller(t)
	adminTok, adminRaw := e.issue(t, admin, auth.PermUsersRead)
	sysTok, _ := e.issue(t, sys, auth.PermSystemRead)

	list, err := e.svc.APITokens(ctx, sys, nil, 100)
	if err != nil || len(list) != 1 || list[0].ID != sysTok.ID {
		t.Fatalf("свои токены администратора системы: %v %v", list, err)
	}
	if list, err = e.svc.APITokens(ctx, admin, nil, 100); err != nil || len(list) != 2 {
		t.Fatalf("все токены администратора безопасности: %v %v", list, err)
	}
	if _, err := e.svc.APITokenByID(ctx, sys, adminTok.ID); !errors.Is(err, auth.ErrAPITokenNotFound) {
		t.Fatalf("чужой токен при own: %v", err)
	}
	if _, err := e.svc.RevokeAPIToken(ctx, sys, adminTok.ID); !errors.Is(err, auth.ErrAPITokenNotFound) {
		t.Fatalf("отзыв чужого при own: %v", err)
	}

	// Своя роль с api_tokens.manage на все токены, но без прав администратора
	// безопасности: чужой токен более сильной учётной записи не отзывает.
	e.createRole(t, "token_admin", auth.PermAPITokensManage, auth.PermAPITokensRead)
	e.mem.AddUser(e.user(helperID, "helper", "token_admin"))
	helper := e.mfa.complete(t, e.mustLogin(t, "helper", phrase))
	if _, err := e.svc.RevokeAPIToken(ctx, helper, adminTok.ID); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("отзыв токена сильнее себя: %v", err)
	}
	if deniedRecords(e.mem, "api_token.revoke") != 1 {
		t.Fatal("отказ в отзыве не записан")
	}

	r, err := e.svc.RevokeAPIToken(ctx, admin, sysTok.ID)
	if err != nil || r.RevokeReason != auth.APITokenRevokedByAdmin || r.RevokedBy != adminID || !r.Revoked() {
		t.Fatalf("отзыв администратором: %+v %v", r, err)
	}
	if _, err := e.svc.RevokeAPIToken(ctx, admin, sysTok.ID); !errors.Is(err, auth.ErrAPITokenRevoked) {
		t.Fatalf("повторный отзыв: %v", err)
	}
	if r, err = e.svc.RevokeAPIToken(ctx, admin, adminTok.ID); err != nil || r.RevokeReason != auth.APITokenRevokedByOwner {
		t.Fatalf("отзыв своего: %+v %v", r, err)
	}
	if _, err := e.svc.AuthenticateAPIToken(ctx, adminRaw, tokenIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("отозванный токен принят: %v", err)
	}
	if rec := authFailed(t, e); rec.Details.(map[string]any)["reason"] != auth.ReasonRevoked {
		t.Fatalf("причина отказа: %+v", rec)
	}
	if rec := lastRecord(t, e.mem, "api_token.revoke"); rec.Result != audit.ResultSuccess || rec.Object.ID != adminTok.ID {
		t.Fatalf("запись отзыва: %+v", rec)
	}
}

// Сбой хранилища при проверке токена — не отказ по токену.
func TestAuthenticateAPITokenStoreFailure(t *testing.T) {
	e := newEnv(t)
	_, raw := e.issue(t, e.adminCaller(t), auth.PermSystemRead)
	e.mem.Fail = errors.New("сбой")
	_, err := e.svc.AuthenticateAPIToken(context.Background(), raw, tokenIP)
	e.mem.Fail = nil
	if err == nil || errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сбой хранилища: %v", err)
	}
}
