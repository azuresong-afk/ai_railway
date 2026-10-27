package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// JWT пользователя приложения и доступ к моделям по группам (задача 4.21
// этапа 4, ADR-0025, раздел 4).

const (
	tokIssuer   = "https://idp.example.test/realms/aisec"
	tokAudience = "aisec-gateway"
)

type tokenEnv struct {
	g      http.Handler
	log    *eventLog
	up     *upstreamRecord
	signer *cryptotest.JWTSigner
}

func tokenVerifier(t testing.TB) aisecCrypto.JWTVerifier {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.JWT()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// canonJWKS — каноничный JWKS ключей s, как его кладёт в пакет сервер.
func canonJWKS(t testing.TB, v aisecCrypto.JWTVerifier, s ...*cryptotest.JWTSigner) []byte {
	t.Helper()
	k, err := v.ParseJWKS(cryptotest.JWKS(s...))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := v.MarshalJWKS(k)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// tokenGateway — шлюз, где приложение app проверяет JWT в режиме mode;
// модель m доступна группе analysts, псевдоним default (→ m) — им же,
// mock-echo — всем. keys = false — ключей издателя в пакете нет.
func tokenGateway(t *testing.T, mode string, keys bool) *tokenEnv {
	t.Helper()
	return tokenGatewayGroups(t, mode, keys, map[string][]string{"m": {"analysts", "admins"}})
}

// tokenGatewayGroups — то же, но с группами моделей mg.
func tokenGatewayGroups(t *testing.T, mode string, keys bool, mg map[string][]string) *tokenEnv {
	t.Helper()
	up, rec := newUpstream(t, nil)
	v := tokenVerifier(t)
	s, err := cryptotest.NewJWTSigner("ES256", "k1", 0)
	if err != nil {
		t.Fatal(err)
	}
	env := &tokenEnv{up: rec, signer: s}
	env.g = newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.UserFrom = "header" }
		o.userMAC, o.jwt, env.log = testMAC(t), v, o.events
		o.tokenKeys = map[string][]byte{}
		if keys {
			o.tokenKeys[tokIssuer] = canonJWKS(t, v, s)
		}
		o.tokens = map[string]UserToken{"app": {Mode: mode, Issuer: tokIssuer, Audience: tokAudience, GroupsClaim: "groups",
			Leeway: time.Minute, ModelGroups: mg}}
	})
	return env
}

func tokClaims(groups ...string) map[string]any {
	now := time.Now()
	return map[string]any{"iss": tokIssuer, "sub": "u-0001", "aud": []string{"account", tokAudience}, "azp": "portal",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Add(-time.Hour).Unix(), "groups": groups}
}

func (e *tokenEnv) post(t *testing.T, model, token string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	h := map[string]string{}
	for k, v := range hdr {
		h[k] = v
	}
	if token != "" {
		h[HeaderUserToken] = token
	}
	return postChat(t, e.g, `{"model":"`+model+`","messages":[{"role":"user","content":"привет"}]}`, h)
}

// lastAuthFailure — последнее событие auth_failure.
func lastAuthFailure(t *testing.T, log *eventLog) events.Event {
	t.Helper()
	evs := log.all()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Type == events.TypeAuthFailure {
			return evs[i]
		}
	}
	t.Fatal("нет события auth_failure")
	return events.Event{}
}

// Покрывает: DM-33
// Модель, закрытая группами, без нужной группы в JWT — 403 без списка
// групп, событие с правилом model_group_denied; до провайдера запрос не
// доходит. Псевдоним той же модели закрыт так же.
func TestDM33_GroupDeniedModel(t *testing.T) {
	e := tokenGateway(t, UserTokenRequired, true)
	for _, model := range []string{"m", "default"} {
		resp := e.post(t, model, e.signer.Sign(tokClaims("sales")), nil)
		if resp.Code != http.StatusForbidden || errCode(t, resp) != "model_access_denied" {
			t.Fatalf("%s: %d %s", model, resp.Code, resp.Body.String())
		}
		if body := resp.Body.String(); strings.Contains(body, "analysts") || strings.Contains(body, "admins") || strings.Contains(body, "sales") {
			t.Fatalf("%s: ответ раскрывает группы: %s", model, body)
		}
		ev := lastEvent(t, e.log, resp)
		if ev.Decision.Rule != ruleModelGroup || ev.Decision.Action != "block" || len(ev.Threats) == 0 || ev.Threats[0] != "DM-33" ||
			ev.Model != "m" || len(ev.User) != 32 {
			t.Fatalf("%s: событие %+v", model, ev)
		}
	}
	// Без групп в токене — тоже отказ.
	if resp := e.post(t, "m", e.signer.Sign(tokClaims()), nil); resp.Code != http.StatusForbidden {
		t.Fatalf("без групп: %d", resp.Code)
	}
	if _, _, _, calls := e.up.get(); calls != 0 {
		t.Fatalf("до провайдера дошло %d запросов", calls)
	}
}

// Покрывает: DM-33
// Группы заданы только у псевдонима: прямое имя модели закрыто так же, и
// в /v1/embeddings тоже.
func TestDM33_GroupDeniedAliasModel(t *testing.T) {
	e := tokenGatewayGroups(t, UserTokenRequired, true, map[string][]string{"default": {"analysts"}})
	for _, model := range []string{"default", "m"} {
		if resp := e.post(t, model, e.signer.Sign(tokClaims("sales")), nil); resp.Code != http.StatusForbidden ||
			errCode(t, resp) != "model_access_denied" {
			t.Fatalf("%s: %d %s", model, resp.Code, resp.Body.String())
		}
		resp := postJSON(t, e.g, "/v1/embeddings", `{"model":"`+model+`","input":"привет"}`,
			map[string]string{HeaderUserToken: e.signer.Sign(tokClaims("sales"))})
		if resp.Code != http.StatusForbidden || errCode(t, resp) != "model_access_denied" {
			t.Fatalf("embeddings %s: %d %s", model, resp.Code, resp.Body.String())
		}
	}
	if resp := e.post(t, "m", e.signer.Sign(tokClaims("analysts")), nil); resp.Code != http.StatusOK {
		t.Fatalf("с группой псевдонима: %d", resp.Code)
	}
	if resp := e.post(t, "mock-echo", e.signer.Sign(tokClaims("sales")), nil); resp.Code != http.StatusOK {
		t.Fatalf("модель без групп: %d", resp.Code)
	}
}

// Покрывает: DM-33
// Пользователь с одной из групп модели получает ответ; модель без
// ограничения доступна любому пользователю с действительным JWT.
func TestDM33_GroupAllowedModel(t *testing.T) {
	e := tokenGateway(t, UserTokenRequired, true)
	for _, c := range []struct {
		model  string
		groups []string
	}{{"m", []string{"sales", "admins"}}, {"default", []string{"analysts"}}, {"mock-echo", nil}} {
		resp := e.post(t, c.model, e.signer.Sign(tokClaims(c.groups...)), nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", c.model, resp.Code, resp.Body.String())
		}
	}
	// Одна группа строкой, а не массивом, — тоже группа.
	c := tokClaims()
	c["groups"] = "analysts"
	if resp := e.post(t, "m", e.signer.Sign(c), nil); resp.Code != http.StatusOK {
		t.Fatalf("группа строкой: %d", resp.Code)
	}
	if _, _, _, calls := e.up.get(); calls != 4 {
		t.Fatalf("до провайдера дошло %d запросов", calls)
	}
}

// Недействительный JWT — 401 до провайдера и событие auth_failure с
// причиной; адрес не блокируется.
func TestUserTokenRejected(t *testing.T) {
	e := tokenGateway(t, UserTokenRequired, true)
	with := func(k string, v any) string {
		c := tokClaims("analysts")
		c[k] = v
		return e.signer.Sign(c)
	}
	rogue, err := cryptotest.NewJWTSigner("ES256", "k2", 0)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := cryptotest.NewJWTSigner("RS256", "k1", 0)
	if err != nil {
		t.Fatal(err)
	}
	none := func() string {
		h, _ := json.Marshal(map[string]any{"alg": "none", "kid": "k1"}) //nolint:gosec // G104: тест, данные заведомо корректны
		c, _ := json.Marshal(tokClaims("analysts"))                      //nolint:gosec // G104: тест, данные заведомо корректны
		enc := base64.RawURLEncoding
		return enc.EncodeToString(h) + "." + enc.EncodeToString(c) + "."
	}()
	cases := map[string]struct{ token, reason string }{
		"просрочен":       {with("exp", time.Now().Add(-2*time.Minute).Unix()), "user_token_expired"},
		"чужой издатель":  {with("iss", "https://evil.example.test/realms/aisec"), "user_token_issuer"},
		"чужая аудитория": {with("aud", "other-app"), "user_token_audience"},
		"неизвестный kid": {rogue.Sign(tokClaims("analysts")), "user_token_unknown_kid"},
		"alg=none":        {none, "user_token_malformed"},
		"HS256 открытым ключом": {cryptotest.HMACToken(map[string]any{"alg": "HS256", "kid": "k1"}, tokClaims("analysts"), rs.RSAModulus()),
			"user_token_alg"},
		"группы не строки": {with("groups", []int{1}), "user_token_groups"},
		"не JWT":           {"abc", "user_token_malformed"},
		"слишком длинный":  {strings.Repeat("a", aisecCrypto.MaxJWTSize+1), "user_token_malformed"},
	}
	for name, c := range cases {
		resp := e.post(t, "m", c.token, nil)
		if resp.Code != http.StatusUnauthorized || errCode(t, resp) != "invalid_user_token" {
			t.Fatalf("%s: %d %s", name, resp.Code, resp.Body.String())
		}
		ev := lastAuthFailure(t, e.log)
		if ev.AuthFailure.Reason != c.reason || ev.App != "app" || ev.AuthFailure.KeyPrefix == "" || ev.Threats[0] != "DM-38" {
			t.Fatalf("%s: событие %+v %+v", name, ev, ev.AuthFailure)
		}
	}
	if _, _, _, calls := e.up.get(); calls != 0 {
		t.Fatalf("до провайдера дошло %d запросов", calls)
	}
	// Отказы JWT не блокируют адрес: действительный токен проходит.
	if resp := e.post(t, "m", e.signer.Sign(tokClaims("analysts")), nil); resp.Code != http.StatusOK {
		t.Fatalf("после отказов: %d", resp.Code)
	}
}

// Режимы: required без токена и с двумя заголовками — 401; optional без
// токена — пользователь по X-AISec-User, но закрытая группами модель
// недоступна; ключа издателя в пакете нет — 401 no_keys.
func TestUserTokenModes(t *testing.T) {
	req := tokenGateway(t, UserTokenRequired, true)
	if resp := req.post(t, "mock-echo", "", map[string]string{HeaderUser: "ivanov"}); resp.Code != http.StatusUnauthorized ||
		lastAuthFailure(t, req.log).AuthFailure.Reason != "user_token_missing" {
		t.Fatalf("required без токена: %d", resp.Code)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"mock-echo","messages":[{"role":"user","content":"x"}]}`))
	r.Header.Set("Content-Type", "application/json")
	tok := req.signer.Sign(tokClaims("analysts"))
	r.Header.Add(HeaderUserToken, tok)
	r.Header.Add(HeaderUserToken, tok)
	if resp := httptest.NewRecorder(); func() bool { req.g.ServeHTTP(resp, r); return true }() && resp.Code != http.StatusUnauthorized || lastAuthFailure(t, req.log).AuthFailure.Reason != "user_token_duplicate" {
		t.Fatalf("два заголовка: %d", resp.Code)
	}

	opt := tokenGateway(t, UserTokenOptional, true)
	resp := opt.post(t, "mock-echo", "", map[string]string{HeaderUser: "u-0001"})
	if resp.Code != http.StatusOK {
		t.Fatalf("optional без токена: %d %s", resp.Code, resp.Body.String())
	}
	header := lastEvent(t, opt.log, resp).User
	if resp := opt.post(t, "m", "", map[string]string{HeaderUser: "u-0001"}); resp.Code != http.StatusForbidden {
		t.Fatalf("optional без токена, закрытая модель: %d", resp.Code)
	}
	// JWT важнее X-AISec-User; псевдоним sub не совпадает с псевдонимом
	// X-AISec-User с тем же значением.
	resp = opt.post(t, "m", opt.signer.Sign(tokClaims("analysts")), map[string]string{HeaderUser: "u-0001"})
	if resp.Code != http.StatusOK {
		t.Fatalf("optional с токеном: %d", resp.Code)
	}
	if u := lastEvent(t, opt.log, resp).User; len(u) != 32 || u == header {
		t.Fatalf("псевдоним из JWT %q, из заголовка %q", u, header)
	}
	// Недействительный токен в режиме optional — отказ, а не X-AISec-User.
	c := tokClaims("analysts")
	c["aud"] = "other"
	if resp := opt.post(t, "mock-echo", opt.signer.Sign(c), map[string]string{HeaderUser: "u-0001"}); resp.Code != http.StatusUnauthorized {
		t.Fatalf("optional с чужим токеном: %d", resp.Code)
	}

	// /v1/embeddings и /guard/v1/check в режиме required: без токена и с
	// недействительным токеном — 401.
	for _, rq := range [][2]string{{"/v1/embeddings", `{"model":"mock-echo","input":"x"}`},
		{"/guard/v1/check", `{"direction":"input","text":"x"}`}} {
		if resp := postJSON(t, req.g, rq[0], rq[1], map[string]string{HeaderUser: "ivanov"}); resp.Code != http.StatusUnauthorized ||
			errCode(t, resp) != "invalid_user_token" {
			t.Fatalf("%s без токена: %d %s", rq[0], resp.Code, resp.Body.String())
		}
		if resp := postJSON(t, req.g, rq[0], rq[1], map[string]string{HeaderUserToken: "a.b.c"}); resp.Code != http.StatusUnauthorized ||
			lastAuthFailure(t, req.log).AuthFailure.Reason != "user_token_malformed" {
			t.Fatalf("%s с плохим токеном: %d", rq[0], resp.Code)
		}
	}
	if resp := postJSON(t, req.g, "/guard/v1/check", `{"direction":"input","text":"x"}`,
		map[string]string{HeaderUserToken: req.signer.Sign(tokClaims())}); resp.Code != http.StatusOK {
		t.Fatalf("/guard/v1/check с токеном: %d %s", resp.Code, resp.Body.String())
	}

	stale := tokenGateway(t, UserTokenRequired, false)
	if resp := stale.post(t, "mock-echo", stale.signer.Sign(tokClaims("analysts")), nil); resp.Code != http.StatusUnauthorized ||
		lastAuthFailure(t, stale.log).AuthFailure.Reason != "user_token_no_keys" {
		t.Fatalf("без ключей в пакете: %d", resp.Code)
	}
}

// Неверный JWKS или режим в пакете — пакет не применяется.
func TestSetUserTokensRejects(t *testing.T) {
	v := tokenVerifier(t)
	rt := &Router{apps: map[string]*App{"app": {ID: "app"}}}
	if err := rt.SetUserTokens(v, map[string][]byte{tokIssuer: []byte(`{"keys":[]}`)}, nil); err == nil {
		t.Fatal("пустой JWKS принят")
	}
	good := UserToken{Mode: UserTokenRequired, Issuer: tokIssuer, Audience: tokAudience, GroupsClaim: "groups"}
	for name, mod := range map[string]func(u *UserToken){
		"режим off":       func(u *UserToken) { u.Mode = "off" },
		"нет аудитории":   func(u *UserToken) { u.Audience = "" },
		"допуск > 5 мин":  func(u *UserToken) { u.Leeway = 6 * time.Minute },
		"нет утверждения": func(u *UserToken) { u.GroupsClaim = "" },
	} {
		u := good
		mod(&u)
		if err := rt.SetUserTokens(v, nil, map[string]UserToken{"app": u}); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	// Профиль без проверки JWT: настройка принимается, JWT отклоняются.
	if err := rt.SetUserTokens(nil, map[string][]byte{tokIssuer: []byte(`{}`)}, map[string]UserToken{"app": good}); err != nil {
		t.Fatal(err)
	}
	if _, _, reason := rt.apps["app"].userToken.verify("a.b.c", time.Now()); reason != userTokenUnavailable {
		t.Fatalf("без проверки JWT: %q", reason)
	}
}

// FuzzUserTokenGroups — извлечение групп из утверждений подписанного JWT:
// любой объект утверждений не роняет шлюз, групп не больше предела.
func FuzzUserTokenGroups(f *testing.F) {
	v := tokenVerifier(f)
	s, err := cryptotest.NewJWTSigner("EdDSA", "k1", 0)
	if err != nil {
		f.Fatal(err)
	}
	keys, err := v.ParseJWKS(cryptotest.JWKS(s))
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now()
	c := &userTokenCheck{UserToken: UserToken{Mode: UserTokenRequired, Issuer: tokIssuer, Audience: tokAudience,
		GroupsClaim: "groups", Leeway: time.Minute}, keys: keys, jwt: v}
	base := func(groups string) []byte {
		return []byte(`{"iss":"` + tokIssuer + `","sub":"u","aud":"` + tokAudience + `","exp":` +
			jsonNum(now.Add(time.Hour).Unix()) + `,"groups":` + groups + `}`)
	}
	f.Add(base(`["a","b"]`))
	f.Add(base(`"a"`))
	f.Add(base(`[1,2]`))
	f.Add(base(`[` + strings.Repeat(`"g",`, 300) + `"g"]`))
	f.Add(base(`{"a":["b"]}`))
	f.Add(base(`null`))
	f.Fuzz(func(t *testing.T, claims []byte) {
		hdr, _ := json.Marshal(s.Header()) //nolint:gosec // G104: тест, данные заведомо корректны
		sub, groups, reason := c.verify(s.SignRaw(hdr, claims), now)
		if reason != "" && (sub != "" || groups != nil) {
			t.Fatalf("отказ %q с данными", reason)
		}
		if len(groups) > maxUserGroups {
			t.Fatalf("групп %d", len(groups))
		}
		for _, g := range groups {
			if g == "" || len(g) > maxUserGroupLen {
				t.Fatalf("группа %q", g)
			}
		}
	})
}

func jsonNum(n int64) string {
	b, _ := json.Marshal(n) //nolint:gosec // G104: число всегда кодируется
	return string(b)
}
