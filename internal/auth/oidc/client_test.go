package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

const (
	clientID     = "aisec-console"
	clientSecret = "synthetic-client-credential-1"
	redirectURI  = "https://console.example.test/api/v1/auth/oidc/callback"
)

type env struct {
	idp *cryptotest.IdP
	c   *oidc.Client
	cfg oidc.Config
}

func newEnv(t *testing.T, opts ...oidc.Option) *env {
	t.Helper()
	idp, err := cryptotest.NewIdP(clientID, clientSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	c, err := oidc.New(p, opts...)
	if err != nil {
		t.Fatal(err)
	}
	// IdP теста — на 127.0.0.1: loopback разрешается явно.
	c.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	return &env{idp: idp, c: c, cfg: oidc.Config{Issuer: idp.Issuer, ClientID: clientID, ClientSecret: clientSecret,
		RootsPEM: idp.RootPEM, RedirectURI: redirectURI, Scopes: []string{"profile"}}}
}

// browser проходит авторизацию у IdP как браузер: адрес IdP → 303 на
// адрес возврата с кодом.
func (e *env) browser(t *testing.T, authURL string) url.Values {
	t.Helper()
	hc := &http.Client{Transport: mustTransport(t, e.idp.RootPEM),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close() //nolint:gosec // G104: тело ответа не нужно
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("IdP: %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), redirectURI) {
		t.Fatalf("возврат: %v %s", err, loc)
	}
	return loc.Query()
}

func mustTransport(t *testing.T, roots []byte) *http.Transport {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tp.ClientConfig(roots)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Transport{TLSClientConfig: cfg}
}

// Полный обмен: адрес авторизации с PKCE, код, ID-токен, проверка.
func TestCodeFlow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	verifier := strings.Repeat("v", 43)
	u, err := e.c.AuthURL(ctx, e.cfg, oidc.AuthParams{State: "st", Nonce: "nn", Challenge: aisecCrypto.PKCEChallengeS256(verifier)})
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u) //nolint:gosec // G104: адрес собран клиентом, неверный не пройдёт проверки ниже
	q := pu.Query()
	if q.Get("scope") != "openid profile" || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != redirectURI {
		t.Fatalf("параметры авторизации: %v", q)
	}
	back := e.browser(t, u)
	if back.Get("state") != "st" {
		t.Fatalf("state: %v", back)
	}
	tok, err := e.c.Exchange(ctx, e.cfg, back.Get("code"), verifier)
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.c.VerifyIDToken(ctx, e.cfg, tok, "nn")
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "idp-user-1" {
		t.Fatalf("sub %q", c.Subject)
	}
	// Повтор кода — отказ IdP с кодом ошибки, без описания из ответа.
	_, err = e.c.Exchange(ctx, e.cfg, back.Get("code"), verifier)
	if oidc.ErrorCode(err) != oidc.CodeGrant || strings.Contains(err.Error(), "script") {
		t.Fatalf("повтор кода: %v", err)
	}
	// Чужой code_verifier.
	back = e.browser(t, u)
	if _, err := e.c.Exchange(ctx, e.cfg, back.Get("code"), strings.Repeat("w", 43)); oidc.ErrorCode(err) != oidc.CodeGrant {
		t.Fatalf("чужой verifier: %v", err)
	}
	// Чужой секрет клиента.
	bad := e.cfg
	bad.ClientSecret = "wrong"
	back = e.browser(t, u)
	if _, err := e.c.Exchange(ctx, bad, back.Get("code"), verifier); oidc.ErrorCode(err) != oidc.CodeGrant {
		t.Fatalf("чужой секрет: %v", err)
	}
	// acr_values — когда требование задано.
	e.cfg.ACRValues = []string{"urn:mfa"}
	u, _ = e.c.AuthURL(ctx, e.cfg, oidc.AuthParams{State: "s", Nonce: "n", Challenge: "c"}) //nolint:gosec // G104: ошибка AuthURL проверена в TestCodeFlow
	if pu, _ := url.Parse(u); pu.Query().Get("acr_values") != "urn:mfa" {                   //nolint:gosec // G104: адрес собран клиентом, неверный не пройдёт проверку
		t.Fatalf("acr_values: %s", u)
	}
}

// Discovery: издатель побайтно, конечные точки — https на узле издателя.
func TestDiscoveryRules(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"чужой issuer":                  func(m map[string]any) { m["issuer"] = "https://evil.example.test/realms/aisec" },
		"issuer со слешем":              func(m map[string]any) { m["issuer"] = m["issuer"].(string) + "/" },
		"token_endpoint на другом узле": func(m map[string]any) { m["token_endpoint"] = "https://evil.example.test/token" },
		"jwks по http": func(m map[string]any) {
			m["jwks_uri"] = strings.Replace(m["jwks_uri"].(string), "https://", "http://", 1)
		},
		"auth на другом порту": func(m map[string]any) {
			m["authorization_endpoint"] = "https://127.0.0.1:1/auth"
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.idp.OnDiscovery(mod)
			err := e.c.Check(context.Background(), e.cfg)
			if oidc.ErrorCode(err) != oidc.CodeResponse {
				t.Fatalf("принято: %v", err)
			}
		})
	}
}

func TestNetworkRules(t *testing.T) {
	ctx := context.Background()
	// Без явного разрешения loopback запрещён.
	idp, err := cryptotest.NewIdP(clientID, clientSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Close()
	p, _ := aisecCrypto.New(aisecCrypto.ProfileStandard) //nolint:gosec // G104: стандартный профиль создаётся всегда
	c, err := oidc.New(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg := oidc.Config{Issuer: idp.Issuer, ClientID: clientID, ClientSecret: clientSecret, RootsPEM: idp.RootPEM, RedirectURI: redirectURI}
	if err := c.Check(ctx, cfg); oidc.ErrorCode(err) != oidc.CodeBlocked {
		t.Fatalf("loopback: %v", err)
	}
	for _, iss := range []string{"https://169.254.169.254/x", "https://[::1]/x", "https://[fd00:ec2::254]/x", "https://100.100.100.200/x"} {
		cfg.Issuer = iss
		if err := c.Check(ctx, cfg); oidc.ErrorCode(err) != oidc.CodeBlocked {
			t.Fatalf("%s: %v", iss, err)
		}
	}
	// Чужие корневые сертификаты — отказ TLS.
	e := newEnv(t)
	other, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	e.cfg.RootsPEM = other.Root
	if err := e.c.Check(ctx, e.cfg); oidc.ErrorCode(err) != oidc.CodeTLS {
		t.Fatalf("чужой корень: %v", err)
	}
	e.cfg.RootsPEM = []byte("not pem")
	if err := e.c.Check(ctx, e.cfg); oidc.ErrorCode(err) != oidc.CodeConfig {
		t.Fatalf("неверный PEM: %v", err)
	}
}

func TestValidateIssuer(t *testing.T) {
	for _, bad := range []string{"", "http://idp.example.test", "https://", "https://u:p@idp.example.test",
		"https://idp.example.test/#x", "https://idp.example.test/?a=1", "ftp://idp", "https://" + strings.Repeat("a", 600)} {
		if oidc.ValidateIssuer(bad) == nil {
			t.Errorf("принят %q", bad)
		}
	}
	if err := oidc.ValidateIssuer("https://idp.example.test:8443/realms/x"); err != nil {
		t.Fatal(err)
	}
}

// Ответы IdP: слишком большие, не JSON, перенаправление, нет id_token.
func TestResponseLimits(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.idp.SetJWKS([]byte(`{"keys":[` + strings.Repeat(`{"kty":"oct"},`, 6000) + `{"kty":"oct"}]}`))
	if err := e.c.Check(ctx, e.cfg); oidc.ErrorCode(err) != oidc.CodeTooLarge {
		t.Fatalf("JWKS больше предела: %v", err)
	}
	e.idp.SetJWKS([]byte(`{"keys":[{"kty":"oct","k":"AA"}]}`))
	if err := e.c.Check(ctx, e.cfg); oidc.ErrorCode(err) != oidc.CodeJWKS {
		t.Fatalf("JWKS без ключей подписи: %v", err)
	}
	e.idp.SetJWKS(nil)
	verifier := strings.Repeat("v", 43)
	u, err := e.c.AuthURL(ctx, e.cfg, oidc.AuthParams{State: "s", Nonce: "n", Challenge: aisecCrypto.PKCEChallengeS256(verifier)})
	if err != nil {
		t.Fatal(err)
	}
	for body, code := range map[string]string{
		`{"token_type":"Bearer"}`:                 oidc.CodeResponse,
		`{"id_token":"a.b.c","token_type":"MAC"}`: oidc.CodeResponse,
		`not json`: oidc.CodeResponse,
	} {
		e.idp.SetTokenBody([]byte(body))
		back := e.browser(t, u)
		if _, err := e.c.Exchange(ctx, e.cfg, back.Get("code"), verifier); oidc.ErrorCode(err) != code {
			t.Fatalf("%s: %v", body, err)
		}
	}
	e.idp.SetTokenBody(nil)
	if _, err := e.c.Exchange(ctx, e.cfg, "", verifier); oidc.ErrorCode(err) != oidc.CodeResponse {
		t.Fatalf("пустой код: %v", err)
	}
	if _, err := e.c.Exchange(ctx, e.cfg, strings.Repeat("c", 3000), verifier); oidc.ErrorCode(err) != oidc.CodeResponse {
		t.Fatalf("длинный код: %v", err)
	}
}

// Неизвестный kid: одно внеочередное обновление JWKS, не чаще раза в минуту.
func TestJWKSRefresh(t *testing.T) {
	now := time.Now()
	e := newEnv(t, oidc.WithClock(func() time.Time { return now }))
	e.idp.SetClock(func() time.Time { return now })
	ctx := context.Background()
	login := func(nonce string) (aisecCrypto.IDTokenClaims, error) {
		verifier := strings.Repeat("v", 43)
		u, err := e.c.AuthURL(ctx, e.cfg, oidc.AuthParams{State: "s", Nonce: nonce, Challenge: aisecCrypto.PKCEChallengeS256(verifier)})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := e.c.Exchange(ctx, e.cfg, e.browser(t, u).Get("code"), verifier)
		if err != nil {
			t.Fatal(err)
		}
		return e.c.VerifyIDToken(ctx, e.cfg, tok, nonce)
	}
	if _, err := login("n1"); err != nil {
		t.Fatal(err)
	}
	if e.idp.JWKSHits() != 1 {
		t.Fatalf("запросов JWKS: %d", e.idp.JWKSHits())
	}
	// IdP сменил ключ: первый же вход обновляет набор и проходит.
	next, err := cryptotest.NewJWTSigner("RS256", "k2", 0)
	if err != nil {
		t.Fatal(err)
	}
	e.idp.SetSigner(next)
	if _, err := login("n2"); err != nil {
		t.Fatalf("после смены ключа: %v", err)
	}
	if e.idp.JWKSHits() != 2 {
		t.Fatalf("запросов JWKS: %d", e.idp.JWKSHits())
	}
	// Токены с чужим kid подряд — без новых запросов до истечения минуты.
	rogue, err := cryptotest.NewJWTSigner("ES256", "rogue", 0)
	if err != nil {
		t.Fatal(err)
	}
	e.idp.SetSigner(rogue)
	for range 5 {
		_, err := login("n3")
		var oe *oidc.Error
		if !errors.As(err, &oe) || oe.Code != oidc.CodeIDToken {
			t.Fatalf("чужой kid: %v", err)
		}
	}
	// Внеочередное обновление было при смене ключа — в ту же минуту новых нет.
	if e.idp.JWKSHits() != 2 {
		t.Fatalf("запросов JWKS за минуту: %d", e.idp.JWKSHits())
	}
	// Через минуту — ещё одно обновление: IdP уже публикует этот ключ.
	now = now.Add(oidc.RefreshInterval + time.Second)
	for range 3 {
		if _, err := login("n4"); err != nil {
			t.Fatalf("ключ после обновления: %v", err)
		}
	}
	if e.idp.JWKSHits() != 3 {
		t.Fatalf("запросов JWKS через минуту: %d", e.idp.JWKSHits())
	}
}

// Подмена утверждений: чужой aud, iss, nonce.
func TestIDTokenClaims(t *testing.T) {
	ctx := context.Background()
	for name, mod := range map[string]func(c map[string]any){
		"чужой aud": func(c map[string]any) { c["aud"] = "other" },
		"чужой iss": func(c map[string]any) { c["iss"] = "https://evil.example.test" },
		"без nonce": func(c map[string]any) { delete(c, "nonce") },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.idp.OnToken(mod)
			verifier := strings.Repeat("v", 43)
			u, _ := e.c.AuthURL(ctx, e.cfg, oidc.AuthParams{State: "s", Nonce: "nn", Challenge: aisecCrypto.PKCEChallengeS256(verifier)}) //nolint:gosec // G104: ошибка AuthURL проверена в TestCodeFlow
			tok, err := e.c.Exchange(ctx, e.cfg, e.browser(t, u).Get("code"), verifier)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.c.VerifyIDToken(ctx, e.cfg, tok, "nn"); oidc.ErrorCode(err) != oidc.CodeIDToken {
				t.Fatalf("принят: %v", err)
			}
		})
	}
}

func TestSafeCode(t *testing.T) {
	for s, ok := range map[string]bool{"invalid_grant": true, "": false, "Invalid": false, "a b": false,
		strings.Repeat("a", 65): false} {
		if oidc.SafeCode(s) != ok {
			t.Errorf("%q", s)
		}
	}
}

// Сетевой отказ IdP запоминается на FailBackoff: входы не встают в очередь
// к недоступному IdP; другой IdP и проверка настроек (Check) не затронуты.
func TestNetworkFailureBackoff(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	e := newEnv(t, oidc.WithClock(func() time.Time { return now }))
	good := newEnv(t)
	e.idp.Close()
	_, err1 := e.c.Discover(ctx, e.cfg)
	if oidc.ErrorCode(err1) != oidc.CodeNetwork {
		t.Fatalf("недоступный IdP: %v", err1)
	}
	if _, err2 := e.c.Discover(ctx, e.cfg); err2 != err1 { //nolint:errorlint // сравнивается тот же самый запомненный отказ
		t.Fatalf("отказ не запомнен: %v", err2)
	}
	if err := e.c.Check(ctx, e.cfg); err == err1 || oidc.ErrorCode(err) != oidc.CodeNetwork { //nolint:errorlint // проверка идёт в сеть заново
		t.Fatalf("проверка настроек: %v", err)
	}
	// Другой издатель на том же клиенте не затронут.
	good.cfg.RedirectURI = e.cfg.RedirectURI
	if _, err := e.c.Discover(ctx, good.cfg); err != nil {
		t.Fatalf("другой IdP: %v", err)
	}
	now = now.Add(oidc.FailBackoff + time.Second)
	if _, err := e.c.Discover(ctx, e.cfg); err == err1 || oidc.ErrorCode(err) != oidc.CodeNetwork { //nolint:errorlint // после паузы — новый запрос
		t.Fatalf("после паузы: %v", err)
	}
}
