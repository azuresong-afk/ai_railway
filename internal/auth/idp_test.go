package auth_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Настройки входа через IdP на хранилище в памяти (ADR-0025, задача 4.17).

type idpEnv struct {
	*env
	idp   *cryptotest.IdP
	admin auth.Caller
	box   *keyring.Box
}

func newIdPEnv(t *testing.T) *idpEnv {
	t.Helper()
	e := newEnv(t)
	c, err := oidc.New(provider(t))
	if err != nil {
		t.Fatal(err)
	}
	c.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	box := testBox(t)
	if e.svc, err = auth.NewService(context.Background(), e.mem, e.mem, provider(t), auth.WithClock(e.clock.now),
		auth.WithPasswordHasher(e.hash), auth.WithSecretBox(box), auth.WithRoleStore(e.mem),
		auth.WithAPITokenStore(e.mem), auth.WithOIDC(e.mem, c)); err != nil {
		t.Fatal(err)
	}
	e.mfa = newMFAKeys(e.svc, e.mem, e.clock)
	idp, err := cryptotest.NewIdP(idpClientID, idpClientSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	return &idpEnv{env: e, idp: idp, box: box, admin: e.mfa.complete(t, e.mustLogin(t, "admin", phrase))}
}

func (e *idpEnv) input() auth.IdPInput {
	return auth.IdPInput{Enabled: true, DisplayName: "Вход через Keycloak", Issuer: e.idp.Issuer, ClientID: idpClientID,
		ClientSecret: idpClientSecret, ConsoleURL: idpConsoleURL, CAPEM: string(e.idp.RootPEM),
		GroupRoles: []auth.GroupRole{{Group: "aisec-analysts", Role: auth.RoleAnalyst}}}
}

// oidcLogin — полный вход через синтетический IdP.
func (e *idpEnv) oidcLogin(t *testing.T) auth.LoginResult {
	t.Helper()
	ctx := context.Background()
	start, err := e.svc.StartOIDC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	back, err := e.idp.Authorize(ctx, start.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.FinishOIDC(ctx, auth.OIDCCallbackInput{Cookie: start.Cookie, State: back.Get("state"),
		Code: back.Get("code"), SourceIP: testIP})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestIdPSettingsValidation(t *testing.T) {
	e := newIdPEnv(t)
	long := strings.Repeat("a", 257)
	cases := []struct {
		name, field string
		edit        func(in *auth.IdPInput)
	}{
		{"пустое название", "display_name", func(in *auth.IdPInput) { in.DisplayName = " " }},
		{"длинное название", "display_name", func(in *auth.IdPInput) { in.DisplayName = strings.Repeat("я", 65) }},
		{"издатель http", "issuer", func(in *auth.IdPInput) { in.Issuer = "http://idp.example.test/realms/aisec" }},
		{"издатель с параметрами", "issuer", func(in *auth.IdPInput) { in.Issuer = e.idp.Issuer + "?x=1" }},
		{"издатель с учётными данными", "issuer", func(in *auth.IdPInput) { in.Issuer = "https://u:p@idp.example.test/" }},
		{"пустой клиент", "client_id", func(in *auth.IdPInput) { in.ClientID = "" }},
		{"клиент не ASCII", "client_id", func(in *auth.IdPInput) { in.ClientID = "клиент" }},
		{"секрет с переводом строки", "client_secret", func(in *auth.IdPInput) { in.ClientSecret = "a\nb" }},
		{"консоль с путём", "console_url", func(in *auth.IdPInput) { in.ConsoleURL = idpConsoleURL + "/console" }},
		{"консоль http", "console_url", func(in *auth.IdPInput) { in.ConsoleURL = "http://console.example.test" }},
		{"консоль с параметрами", "console_url", func(in *auth.IdPInput) { in.ConsoleURL = idpConsoleURL + "/?a=1" }},
		{"нет корней", "ca_pem", func(in *auth.IdPInput) { in.CAPEM = "" }},
		{"корни не PEM", "ca_pem", func(in *auth.IdPInput) { in.CAPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" }},
		{"область с пробелом", "scopes", func(in *auth.IdPInput) { in.Scopes = []string{"a b"} }},
		{"много областей", "scopes", func(in *auth.IdPInput) { in.Scopes = slices.Repeat([]string{"x"}, 17) }},
		{"утверждение групп с пробелом", "groups_claim", func(in *auth.IdPInput) { in.GroupsClaim = "my groups" }},
		{"длинный acr", "required_acr", func(in *auth.IdPInput) { in.RequiredACR = []string{long} }},
		{"amr с управляющим", "required_amr", func(in *auth.IdPInput) { in.RequiredAMR = []string{"otp\x00"} }},
		// 4Н18 ревью 4.r2: однофакторные значения RFC 8176 не второй фактор.
		{"amr pwd", "required_amr", func(in *auth.IdPInput) { in.RequiredAMR = []string{"otp", "pwd"} }},
		{"amr kba", "required_amr", func(in *auth.IdPInput) { in.RequiredAMR = []string{"kba"} }},
		{"нет групп при включении", "group_roles", func(in *auth.IdPInput) { in.GroupRoles = nil }},
		{"пустая группа", "group_roles", func(in *auth.IdPInput) { in.GroupRoles = []auth.GroupRole{{Role: auth.RoleAnalyst}} }},
		{"группа с управляющим", "group_roles", func(in *auth.IdPInput) {
			in.GroupRoles = []auth.GroupRole{{Group: "a\u202eb", Role: auth.RoleAnalyst}}
		}},
		{"группа дважды", "group_roles", func(in *auth.IdPInput) {
			in.GroupRoles = []auth.GroupRole{{Group: "g", Role: auth.RoleAnalyst}, {Group: "g", Role: auth.RoleAuditor}}
		}},
		{"нет роли", "group_roles", func(in *auth.IdPInput) {
			in.GroupRoles = []auth.GroupRole{{Group: "g", Role: "no_such_role"}}
		}},
		{"много групп", "group_roles", func(in *auth.IdPInput) {
			in.GroupRoles = make([]auth.GroupRole, 201)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := e.input()
			c.edit(&in)
			_, err := e.svc.SetIdP(context.Background(), e.admin, in, phrase, "")
			var ie *auth.InputError
			if !errors.As(err, &ie) || ie.Field != c.field {
				t.Fatalf("ожидалась ошибка поля %s: %v", c.field, err)
			}
		})
	}
	// Отказ проверки не тратит повторную проверку впустую: настройки не сохранены.
	if _, err := e.svc.IdP(context.Background()); !errors.Is(err, auth.ErrIdPNotConfigured) {
		t.Fatalf("сохранено при ошибке: %v", err)
	}
	// Первое сохранение без секрета клиента — ошибка.
	in := e.input()
	in.ClientSecret = ""
	if _, err := e.svc.SetIdP(context.Background(), e.admin, in, phrase, ""); err == nil {
		t.Fatal("сохранено без секрета клиента")
	}
}

// Нормализация: адрес консоли без «/», openid в областях не хранится,
// повторы удаляются, утверждение групп по умолчанию — groups.
func TestIdPSettingsNormalized(t *testing.T) {
	e := newIdPEnv(t)
	in := e.input()
	in.ConsoleURL = idpConsoleURL + "/"
	in.Scopes = []string{"openid", "profile", "profile", "email"}
	st, err := e.svc.SetIdP(context.Background(), e.admin, in, phrase, "")
	if err != nil {
		t.Fatal(err)
	}
	if st.ConsoleURL != idpConsoleURL || !slices.Equal(st.Scopes, []string{"profile", "email"}) || st.GroupsClaim != "groups" {
		t.Fatalf("нормализация: %+v", st)
	}
	got, err := e.svc.IdP(context.Background())
	if err != nil || got.Secret != nil || got.SecretKeyID != "" {
		t.Fatalf("секрет в ответе: %+v %v", got, err)
	}
}

// Расширение доступа отмечается weakening (DM-40): включение, новые
// группы с ролью, ослабление второго фактора, смена издателя.
func TestIdPWeakeningFlags(t *testing.T) {
	e := newIdPEnv(t)
	ctx := context.Background()
	save := func(in auth.IdPInput) []string {
		t.Helper()
		if _, err := e.svc.SetIdP(ctx, e.admin, in, phrase, ""); err != nil {
			t.Fatal(err)
		}
		rec := lastRecord(t, e.mem, "auth.idp_changed")
		if d, err := audit.CanonicalDetails(rec.Details); err != nil || strings.Contains(string(d), idpClientSecret) {
			t.Fatal("секрет клиента в журнале аудита")
		}
		return weakReasons(rec)
	}
	in := e.input()
	in.RequiredACR = []string{"urn:aisec:mfa"}
	if got := save(in); !slices.Equal(got, []string{"idp_enabled", "idp_group_roles_added"}) {
		t.Fatalf("первое сохранение: %v", got)
	}
	in.ClientSecret = ""
	if got := save(in); got != nil {
		t.Fatalf("без изменений: %v", got)
	}
	in.RequiredAMR = []string{"otp"}
	if got := save(in); !slices.Equal(got, []string{"idp_mfa_relaxed"}) {
		t.Fatalf("новый способ подтверждения: %v", got)
	}
	in.GroupRoles = []auth.GroupRole{{Group: "aisec-analysts", Role: auth.RoleSecurityAdmin}}
	if got := save(in); !slices.Equal(got, []string{"idp_group_roles_added"}) {
		t.Fatalf("смена роли группы: %v", got)
	}
	in.GroupRoles = nil
	in.Enabled = false
	if got := save(in); got != nil {
		t.Fatalf("отключение: %v", got)
	}
	in.Enabled = true
	in.GroupRoles = []auth.GroupRole{{Group: "aisec-analysts", Role: auth.RoleAnalyst}}
	in.RequiredACR, in.RequiredAMR = nil, nil
	if got := save(in); !slices.Equal(got, []string{"idp_enabled", "idp_mfa_relaxed", "idp_group_roles_added"}) {
		t.Fatalf("включение без второго фактора: %v", got)
	}
	in.ClientID = "other-client"
	in.ClientSecret = idpClientSecret
	if _, err := e.svc.SetIdP(ctx, e.admin, in, phrase, ""); err != nil {
		t.Fatal(err)
	}
	if rs := weakReasons(lastRecord(t, e.mem, "auth.idp_changed")); !slices.Contains(rs, "idp_issuer_changed") {
		t.Fatalf("смена клиента: %v", rs)
	}
}

// weakReasons — признаки ослабления из подробностей записи аудита.
func weakReasons(rec audit.Entry) []string {
	d, _ := rec.Details.(map[string]any)
	rs, _ := d["weakening_reasons"].([]any)
	var out []string
	for _, r := range rs {
		if s, ok := r.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Внешняя запись не меняет настройки IdP, а без клиента IdP на сервере
// настройки недоступны.
func TestIdPSettingsAccess(t *testing.T) {
	e := newIdPEnv(t)
	ctx := context.Background()
	if _, err := e.svc.SetIdP(ctx, e.admin, e.input(), phrase, ""); err != nil {
		t.Fatal(err)
	}
	res := e.oidcLogin(t)
	if _, err := e.svc.SetIdP(ctx, res.Caller, e.input(), phrase, ""); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("изменение внешней записью: %v", err)
	}
	if err := e.svc.DeleteIdP(ctx, res.Caller, phrase, ""); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("удаление внешней записью: %v", err)
	}
	if _, err := e.svc.StartMFA(ctx, res.Caller, ""); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("TOTP внешней записи: %v", err)
	}
	if _, err := e.svc.ResetPassword(ctx, e.admin, res.Caller.User.ID); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("сброс пароля внешней записи: %v", err)
	}
	if err := e.svc.DeleteIdP(ctx, e.admin, phrase, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, res.Token, testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия внешней записи после удаления настроек: %v", err)
	}
	// Без клиента IdP на сервере (профиль без JWT) — недоступно.
	if _, err := e.svc.IdP(ctx); err != nil && !errors.Is(err, auth.ErrIdPNotConfigured) {
		t.Fatal(err)
	}
	plain := newEnv(t)
	if _, err := plain.svc.IdP(ctx); !errors.Is(err, auth.ErrIdPUnavailable) {
		t.Fatalf("без клиента IdP: %v", err)
	}
	if opt, err := plain.svc.IdPLoginOption(ctx); err != nil || opt.Enabled {
		t.Fatalf("кнопка без клиента IdP: %+v %v", opt, err)
	}
	if _, err := plain.svc.StartOIDC(ctx); !errors.Is(err, auth.ErrIdPUnavailable) {
		t.Fatalf("вход без клиента IdP: %v", err)
	}
}

// Таблица групп не шире прав того, кто её сохраняет (УПД.2): держатель
// своей роли с auth_idp.manage не выдаёт через IdP роль администратора
// безопасности.
func TestIdPGroupRolesEscalation(t *testing.T) {
	e := newIdPEnv(t)
	ctx := context.Background()
	if _, err := e.svc.CreateRole(ctx, e.admin, auth.RoleInput{ID: "idp_operator", DisplayName: "Оператор входа",
		Permissions: grants(auth.PermAuthIdPRead, auth.PermAuthIdPManage)}); err != nil {
		t.Fatal(err)
	}
	e.mem.AddUser(e.user("01900000-0000-7000-8000-00000000d001", "operator", "idp_operator"))
	op := e.mfa.complete(t, e.mustLogin(t, "operator", phrase))
	in := e.input()
	in.GroupRoles = []auth.GroupRole{{Group: "aisec-admins", Role: auth.RoleSecurityAdmin}}
	if _, err := e.svc.SetIdP(ctx, op, in, phrase, ""); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("роль шире своих прав: %v", err)
	}
	if rec := lastRecord(t, e.mem, "auth.idp_changed"); rec.Result != audit.ResultDenied {
		t.Fatalf("отказ не записан: %+v", rec)
	}
	if _, err := e.svc.IdP(ctx); !errors.Is(err, auth.ErrIdPNotConfigured) {
		t.Fatalf("сохранено: %v", err)
	}
	in.GroupRoles = []auth.GroupRole{{Group: "aisec-ops", Role: "idp_operator"}}
	if _, err := e.svc.SetIdP(ctx, op, in, phrase, ""); err != nil {
		t.Fatalf("роль в пределах своих прав: %v", err)
	}
}

// Учётная запись IdP с ролью администратора безопасности не получает
// локального входа: не заводит записи, не сбрасывает пароль и фактор
// (ADR-0025, 1.6) — иначе IdP переписал бы свои же настройки.
func TestIdPExternalAdminNoLocalCredentials(t *testing.T) {
	e := newIdPEnv(t)
	ctx := context.Background()
	in := e.input()
	in.GroupRoles = []auth.GroupRole{{Group: "aisec-admins", Role: auth.RoleSecurityAdmin}}
	in.RequiredAMR = []string{"otp"}
	if _, err := e.svc.SetIdP(ctx, e.admin, in, phrase, ""); err != nil {
		t.Fatal(err)
	}
	e.idp.SetClaims(map[string]any{"sub": "idp-admin", "groups": []string{"aisec-admins"}, "amr": []string{"otp"}})
	ext := e.oidcLogin(t).Caller
	if ext.User.Role != auth.RoleSecurityAdmin || !ext.User.External() {
		t.Fatalf("внешний администратор: %+v", ext.User)
	}
	if _, _, err := e.svc.CreateUser(ctx, ext, auth.NewUser{Login: "backdoor", DisplayName: "Вход", Role: auth.RoleSecurityAdmin}); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("создание локальной записи: %v", err)
	}
	if _, err := e.svc.ResetPassword(ctx, ext, adminID); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("сброс пароля локального администратора: %v", err)
	}
	if err := e.svc.ResetMFA(ctx, ext, adminID); !errors.Is(err, auth.ErrExternalUser) {
		t.Fatalf("сброс фактора: %v", err)
	}
}

// changingStore меняет настройки IdP в момент записи входа: вход,
// проверенный по прежней версии настроек, отклоняется.
type changingStore struct {
	*authtest.Memory
	change func()
}

func (c *changingStore) ExternalLogin(ctx context.Context, in auth.ExternalLoginTx) (auth.User, error) {
	c.change()
	return c.Memory.ExternalLogin(ctx, in)
}

func TestIdPChangedDuringLogin(t *testing.T) {
	e := newIdPEnv(t)
	ctx := context.Background()
	if _, err := e.svc.SetIdP(ctx, e.admin, e.input(), phrase, ""); err != nil {
		t.Fatal(err)
	}
	c, err := oidc.New(provider(t))
	if err != nil {
		t.Fatal(err)
	}
	c.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	st := &changingStore{Memory: e.mem}
	svc, err := auth.NewService(ctx, e.mem, e.mem, provider(t), auth.WithClock(e.clock.now), auth.WithPasswordHasher(e.hash),
		auth.WithSecretBox(e.box), auth.WithRoleStore(e.mem), auth.WithOIDC(st, c))
	if err != nil {
		t.Fatal(err)
	}
	st.change = func() {
		in := e.input()
		in.ClientSecret, in.GroupRoles = "", []auth.GroupRole{{Group: "other", Role: auth.RoleAnalyst}}
		if _, err := e.svc.SetIdP(ctx, e.admin, in, phrase, ""); err != nil {
			t.Error(err)
		}
	}
	start, err := svc.StartOIDC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	back, err := e.idp.Authorize(ctx, start.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.FinishOIDC(ctx, auth.OIDCCallbackInput{Cookie: start.Cookie, State: back.Get("state"), Code: back.Get("code"), SourceIP: testIP})
	var oe *auth.OIDCError
	if !errors.As(err, &oe) || oe.Code != auth.OIDCFailed || oe.Reason != "idp_changed" {
		t.Fatalf("вход по устаревшим настройкам: %v", err)
	}
}

// Замена корней доверия к IdP и утверждения с группами — ослабление и
// видна в записи аудита (хеш PEM).
func TestIdPTrustChangeAudited(t *testing.T) {
	e := newIdPEnv(t)
	ctx := context.Background()
	if _, err := e.svc.SetIdP(ctx, e.admin, e.input(), phrase, ""); err != nil {
		t.Fatal(err)
	}
	other, err := cryptotest.NewIdP(idpClientID, idpClientSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	in := e.input()
	in.ClientSecret, in.Enabled = "", false
	in.CAPEM = string(other.RootPEM)
	in.GroupsClaim = "roles"
	// Сохранённый секрет не уходит к другим корням доверия: его вводят заново.
	var ie *auth.InputError
	if _, err := e.svc.SetIdP(ctx, e.admin, in, phrase, ""); !errors.As(err, &ie) || ie.Field != "client_secret" {
		t.Fatalf("смена корней без секрета: %v", err)
	}
	in.ClientSecret = idpClientSecret
	if _, err := e.svc.SetIdP(ctx, e.admin, in, phrase, ""); err != nil {
		t.Fatal(err)
	}
	rec := lastRecord(t, e.mem, "auth.idp_changed")
	rs := weakReasons(rec)
	if !slices.Contains(rs, "idp_trust_changed") || !slices.Contains(rs, "idp_groups_claim_changed") {
		t.Fatalf("причины: %v", rs)
	}
	d, _ := rec.Details.(map[string]any)
	before, _ := d["before"].(map[string]any)
	after, _ := d["after"].(map[string]any)
	if d["ca_pem_changed"] != true || before["ca_pem_digest"] == after["ca_pem_digest"] || after["ca_pem_digest"] == "" {
		t.Fatalf("смена корней в аудите: %v", d)
	}
}
