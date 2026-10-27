package crypto_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

const (
	testIssuer = "https://idp.example.test/realms/aisec"
	testClient = "aisec-console"
	testNonce  = "nonce-0123456789abcdef"
)

var testNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func jwtVerifier(t testing.TB) aisecCrypto.JWTVerifier {
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

func signer(t testing.TB, alg, kid string) *cryptotest.JWTSigner {
	t.Helper()
	s, err := cryptotest.NewJWTSigner(alg, kid, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func claims() map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "f3c1a2b4-0000-4000-8000-000000000001", "aud": testClient,
		"exp": testNow.Add(5 * time.Minute).Unix(), "iat": testNow.Add(-10 * time.Second).Unix(),
		"nonce": testNonce, "groups": []string{"aisec-analysts"}, "amr": []string{"pwd", "otp"},
	}
}

func want() aisecCrypto.IDTokenExpect {
	return aisecCrypto.IDTokenExpect{Issuer: testIssuer, Audience: testClient, Nonce: testNonce, Now: testNow}
}

func mustJWKS(t testing.TB, v aisecCrypto.JWTVerifier, signers ...*cryptotest.JWTSigner) *aisecCrypto.JWKS {
	t.Helper()
	k, err := v.ParseJWKS(cryptotest.JWKS(signers...))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if got := aisecCrypto.JWTReason(err); got != reason {
		t.Fatalf("причина отказа %q (%v), ожидалась %q", got, err, reason)
	}
}

// Подпись каждым допустимым алгоритмом принимается, утверждения доступны.
func TestVerifyIDTokenAlgorithms(t *testing.T) {
	v := jwtVerifier(t)
	for _, alg := range []string{"RS256", "ES256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			s := signer(t, alg, "k-"+alg)
			c, err := v.VerifyIDToken(s.Sign(claims()), mustJWKS(t, v, s), want())
			if err != nil {
				t.Fatal(err)
			}
			if c.Subject != "f3c1a2b4-0000-4000-8000-000000000001" || c.Issuer != testIssuer {
				t.Fatalf("утверждения %+v", c)
			}
			g, err := c.Strings("groups", 10, 100)
			if err != nil || len(g) != 1 || g[0] != "aisec-analysts" {
				t.Fatalf("groups %v, %v", g, err)
			}
		})
	}
}

func TestVerifyIDTokenRSA4096(t *testing.T) {
	v := jwtVerifier(t)
	s, err := cryptotest.NewJWTSigner("RS256", "big", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyIDToken(s.Sign(claims()), mustJWKS(t, v, s), want()); err != nil {
		t.Fatal(err)
	}
}

// Подмена алгоритма: none, HS256 с открытым ключом как секретом, alg,
// не совпавший с типом ключа, неизвестный alg.
func TestVerifyIDTokenRejectsAlgorithms(t *testing.T) {
	v := jwtVerifier(t)
	rs := signer(t, "RS256", "rsa")
	keys := mustJWKS(t, v, rs)
	none := func() string {
		h, _ := json.Marshal(map[string]any{"alg": "none", "kid": "rsa"}) //nolint:gosec // G104: тест, данные заведомо корректны
		c, _ := json.Marshal(claims())                                    //nolint:gosec // G104: тест, данные заведомо корректны
		e := base64.RawURLEncoding
		return e.EncodeToString(h) + "." + e.EncodeToString(c) + "."
	}()
	noneSig := strings.TrimSuffix(none, ".") + ".AA"
	cases := map[string]struct {
		token  string
		reason string
	}{
		"none без подписи": {none, aisecCrypto.JWTReasonMalformed},
		"none с подписью":  {noneSig, aisecCrypto.JWTReasonAlg},
		"HS256 открытым ключом": {cryptotest.HMACToken(map[string]any{"alg": "HS256", "kid": "rsa"}, claims(), rs.RSAModulus()),
			aisecCrypto.JWTReasonAlg},
		"ES256 с ключом RSA": {rs.SignWith(map[string]any{"alg": "ES256", "kid": "rsa"}, claims()), aisecCrypto.JWTReasonAlg},
		"PS256":              {rs.SignWith(map[string]any{"alg": "PS256", "kid": "rsa"}, claims()), aisecCrypto.JWTReasonAlg},
		"RS512":              {rs.SignWith(map[string]any{"alg": "RS512", "kid": "rsa"}, claims()), aisecCrypto.JWTReasonAlg},
		"без alg":            {rs.SignWith(map[string]any{"kid": "rsa"}, claims()), aisecCrypto.JWTReasonAlg},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyIDToken(tc.token, keys, want())
			wantReason(t, err, tc.reason)
		})
	}
}

// Ключ из набора с alg, отличным от заголовка, не используется.
func TestVerifyIDTokenKeyAlgMismatch(t *testing.T) {
	v := jwtVerifier(t)
	ed := signer(t, "EdDSA", "k1")
	jwk := ed.JWK()
	jwk["alg"] = "RS256"                                        // набор утверждает, что ключ для RS256
	data, _ := json.Marshal(map[string]any{"keys": []any{jwk}}) //nolint:gosec // G104: тест, данные заведомо корректны
	// Ключ OKP с alg RS256 не подходит ни одному алгоритму — пропускается.
	if _, err := v.ParseJWKS(data); !errors.Is(err, aisecCrypto.ErrJWKS) {
		t.Fatalf("набор без годных ключей принят: %v", err)
	}
}

func TestVerifyIDTokenKeySelection(t *testing.T) {
	v := jwtVerifier(t)
	a := signer(t, "ES256", "a")
	b := signer(t, "ES256", "b")
	other := signer(t, "ES256", "a")
	keys := mustJWKS(t, v, a, b)
	if _, err := v.VerifyIDToken(b.Sign(claims()), keys, want()); err != nil {
		t.Fatalf("ключ b по kid: %v", err)
	}
	// Чужой kid — повод обновить JWKS.
	_, err := v.VerifyIDToken(signer(t, "ES256", "c").Sign(claims()), keys, want())
	wantReason(t, err, aisecCrypto.JWTReasonUnknownKey)
	// Тот же kid, другой ключ — подпись неверна.
	_, err = v.VerifyIDToken(other.Sign(claims()), keys, want())
	wantReason(t, err, aisecCrypto.JWTReasonSignature)
	// Без kid при двух ключах нужного типа — неоднозначно.
	h := a.Header()
	delete(h, "kid")
	_, err = v.VerifyIDToken(a.SignWith(h, claims()), keys, want())
	wantReason(t, err, aisecCrypto.JWTReasonUnknownKey)
	// Без kid при одном ключе — принимается.
	if _, err := v.VerifyIDToken(a.SignWith(h, claims()), mustJWKS(t, v, a), want()); err != nil {
		t.Fatalf("единственный ключ без kid: %v", err)
	}
	// Нет набора ключей.
	_, err = v.VerifyIDToken(a.Sign(claims()), nil, want())
	wantReason(t, err, aisecCrypto.JWTReasonUnknownKey)
}

func TestVerifyIDTokenClaims(t *testing.T) {
	v := jwtVerifier(t)
	s := signer(t, "ES256", "k")
	keys := mustJWKS(t, v, s)
	mod := func(f func(c map[string]any)) string {
		c := claims()
		f(c)
		return s.Sign(c)
	}
	cases := map[string]struct {
		token  string
		reason string
	}{
		"истёк":                 {mod(func(c map[string]any) { c["exp"] = testNow.Add(-2 * time.Minute).Unix() }), aisecCrypto.JWTReasonExpired},
		"нет exp":               {mod(func(c map[string]any) { delete(c, "exp") }), aisecCrypto.JWTReasonExpired},
		"exp строкой":           {mod(func(c map[string]any) { c["exp"] = "2030-01-01" }), aisecCrypto.JWTReasonExpired},
		"exp больше 2^53":       {mod(func(c map[string]any) { c["exp"] = 1e300 }), aisecCrypto.JWTReasonExpired},
		"iat в будущем":         {mod(func(c map[string]any) { c["iat"] = testNow.Add(5 * time.Minute).Unix() }), aisecCrypto.JWTReasonIssuedAt},
		"iat старый":            {mod(func(c map[string]any) { c["iat"] = testNow.Add(-11 * time.Minute).Unix() }), aisecCrypto.JWTReasonIssuedAt},
		"нет iat":               {mod(func(c map[string]any) { delete(c, "iat") }), aisecCrypto.JWTReasonIssuedAt},
		"nbf в будущем":         {mod(func(c map[string]any) { c["nbf"] = testNow.Add(5 * time.Minute).Unix() }), aisecCrypto.JWTReasonNotBefore},
		"чужой aud":             {mod(func(c map[string]any) { c["aud"] = "other" }), aisecCrypto.JWTReasonAudience},
		"aud числом":            {mod(func(c map[string]any) { c["aud"] = 1 }), aisecCrypto.JWTReasonAudience},
		"пустой aud":            {mod(func(c map[string]any) { c["aud"] = []string{} }), aisecCrypto.JWTReasonAudience},
		"несколько aud без azp": {mod(func(c map[string]any) { c["aud"] = []string{testClient, "other"} }), aisecCrypto.JWTReasonAZP},
		"чужой azp":             {mod(func(c map[string]any) { c["azp"] = "other" }), aisecCrypto.JWTReasonAZP},
		"azp числом":            {mod(func(c map[string]any) { c["azp"] = 5 }), aisecCrypto.JWTReasonAZP},
		"чужой iss":             {mod(func(c map[string]any) { c["iss"] = testIssuer + "/" }), aisecCrypto.JWTReasonIssuer},
		"нет nonce":             {mod(func(c map[string]any) { delete(c, "nonce") }), aisecCrypto.JWTReasonNonce},
		"чужой nonce":           {mod(func(c map[string]any) { c["nonce"] = "x" }), aisecCrypto.JWTReasonNonce},
		"пустой sub":            {mod(func(c map[string]any) { c["sub"] = "" }), aisecCrypto.JWTReasonSubject},
		"длинный sub":           {mod(func(c map[string]any) { c["sub"] = strings.Repeat("a", 256) }), aisecCrypto.JWTReasonSubject},
		"sub с NUL":             {mod(func(c map[string]any) { c["sub"] = "a\x00b" }), aisecCrypto.JWTReasonSubject},
		"sub с C1":              {mod(func(c map[string]any) { c["sub"] = "a\u0085b" }), aisecCrypto.JWTReasonSubject},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyIDToken(tc.token, keys, want())
			wantReason(t, err, tc.reason)
		})
	}
	// Граница допуска часов: exp = now — ещё принимается в пределах минуты.
	ok := mod(func(c map[string]any) {
		c["exp"] = testNow.Add(-30 * time.Second).Unix()
		c["aud"] = []string{testClient, "other"}
		c["azp"] = testClient
	})
	if _, err := v.VerifyIDToken(ok, keys, want()); err != nil {
		t.Fatalf("exp в пределах допуска, несколько aud с azp: %v", err)
	}
}

func TestVerifyIDTokenMalformed(t *testing.T) {
	v := jwtVerifier(t)
	s := signer(t, "EdDSA", "k")
	keys := mustJWKS(t, v, s)
	good := s.Sign(claims())
	parts := strings.Split(good, ".")
	cases := map[string]string{
		"пусто":                  "",
		"две части":              parts[0] + "." + parts[1],
		"четыре части":           good + ".x",
		"пустая подпись":         parts[0] + "." + parts[1] + ".",
		"дополнение base64":      parts[0] + "=." + parts[1] + "." + parts[2],
		"слишком длинный":        strings.Repeat("a", aisecCrypto.MaxJWTSize+1),
		"повтор ключа заголовка": s.SignRaw([]byte(`{"alg":"EdDSA","kid":"k","kid":"k"}`), mustJSON(claims())),
		"повтор утверждения":     s.SignRaw(mustJSON(s.Header()), []byte(`{"iss":"`+testIssuer+`","iss":"x"}`)),
		"crit":                   s.SignWith(map[string]any{"alg": "EdDSA", "kid": "k", "crit": []string{"exp"}}, claims()),
		"typ at+jwt":             s.SignWith(map[string]any{"alg": "EdDSA", "kid": "k", "typ": "at+jwt"}, claims()),
		"заголовок не объект":    s.SignRaw([]byte(`["EdDSA"]`), mustJSON(claims())),
		"утверждения не объект":  s.SignRaw(mustJSON(s.Header()), []byte(`"x"`)),
		"данные после объекта":   s.SignRaw(mustJSON(s.Header()), append(mustJSON(claims()), []byte(` {}`)...)),
		"глубокая вложенность":   s.SignRaw(mustJSON(s.Header()), []byte(`{"a":`+strings.Repeat("[", 40)+strings.Repeat("]", 40)+`}`)),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyIDToken(tok, keys, want())
			if r := aisecCrypto.JWTReason(err); r != aisecCrypto.JWTReasonMalformed {
				t.Fatalf("причина %q (%v)", r, err)
			}
		})
	}
	// Подпись, изменённая в одном бите.
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2]) //nolint:gosec // G104: тест, данные заведомо корректны
	sig[0] ^= 1
	_, err := v.VerifyIDToken(parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(sig), keys, want())
	wantReason(t, err, aisecCrypto.JWTReasonSignature)
	// Без ожиданий проверка не выполняется вовсе.
	if _, err := v.VerifyIDToken(good, keys, aisecCrypto.IDTokenExpect{}); err == nil {
		t.Fatal("проверка без издателя прошла")
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseJWKS(t *testing.T) {
	v := jwtVerifier(t)
	rs := signer(t, "RS256", "r")
	es := signer(t, "ES256", "e")
	ed := signer(t, "EdDSA", "d")
	k, err := v.ParseJWKS(cryptotest.JWKS(rs, es, ed))
	if err != nil || k.Len() != 3 || !k.Has("e") || k.Has("x") {
		t.Fatalf("набор из трёх: %v, %d", err, k.Len())
	}
	enc := rs.JWK()
	enc["use"] = "enc"
	oct := map[string]any{"kty": "oct", "k": "c2VjcmV0", "kid": "h"}
	p384 := map[string]any{"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA", "kid": "p"}
	k, err = v.ParseJWKS(mustJSON(map[string]any{"keys": []any{enc, oct, p384, es.JWK()}}))
	if err != nil || k.Len() != 1 || !k.Has("e") {
		t.Fatalf("ключи не для подписи, oct и P-384 должны пропускаться: %v, %d", err, k.Len())
	}
	badE := rs.JWK()
	badE["e"] = "AQ" // e = 1
	short := es.JWK()
	short["x"] = "AAAA"
	offCurve := es.JWK()
	offCurve["y"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tooMany := make([]any, aisecCrypto.MaxJWKSKeys+1)
	for i := range tooMany {
		tooMany[i] = es.JWK()
	}
	dupKID := []any{es.JWK(), signer(t, "ES256", "e").JWK()}
	cases := map[string][]byte{
		"пусто":              nil,
		"не объект":          []byte(`[]`),
		"нет keys":           []byte(`{}`),
		"keys не массив":     []byte(`{"keys":{}}`),
		"нет ключей":         []byte(`{"keys":[]}`),
		"только enc":         mustJSON(map[string]any{"keys": []any{enc}}),
		"e = 1":              mustJSON(map[string]any{"keys": []any{badE}}),
		"короткая x":         mustJSON(map[string]any{"keys": []any{short}}),
		"точка не на кривой": mustJSON(map[string]any{"keys": []any{offCurve}}),
		"больше 32 ключей":   mustJSON(map[string]any{"keys": tooMany}),
		"повтор kid":         mustJSON(map[string]any{"keys": dupKID}),
		"повтор поля":        []byte(`{"keys":[],"keys":[]}`),
		"больше предела":     append([]byte(`{"keys":[],"x":"`), append([]byte(strings.Repeat("a", aisecCrypto.MaxJWKSSize)), '"', '}')...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.ParseJWKS(data); !errors.Is(err, aisecCrypto.ErrJWKS) {
				t.Fatalf("принят неверный набор: %v", err)
			}
		})
	}
	// RSA короче 2 048 бит.
	weak, err := cryptotest.NewJWTSigner("RS256", "w", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ParseJWKS(cryptotest.JWKS(weak)); !errors.Is(err, aisecCrypto.ErrJWKS) {
		t.Fatalf("ключ RSA 1024 принят: %v", err)
	}
}

func TestJWTUnavailableInGOST(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileGOST)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.JWT(); !errors.Is(err, aisecCrypto.ErrNotImplemented) {
		t.Fatalf("gost: %v", err)
	}
}

func FuzzParseJWT(f *testing.F) {
	v := jwtVerifier(f)
	s := signer(f, "ES256", "k")
	keys := mustJWKS(f, v, s)
	f.Add(s.Sign(claims()))
	f.Add(s.SignRaw([]byte(`{"alg":"ES256","kid":"k","kid":"x"}`), []byte(`{}`)))
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, token string) {
		c, err := v.VerifyIDToken(token, keys, want())
		if err == nil {
			// Принятый токен обязан нести наши издателя, клиента и nonce.
			if c.Issuer != testIssuer || c.Subject == "" {
				t.Fatalf("принят токен с утверждениями %+v", c)
			}
			return
		}
		if aisecCrypto.JWTReason(err) == "" {
			t.Fatalf("ошибка без причины: %v", err)
		}
	})
}

func FuzzParseJWKS(f *testing.F) {
	v := jwtVerifier(f)
	f.Add(cryptotest.JWKS(signer(f, "RS256", "r"), signer(f, "ES256", "e"), signer(f, "EdDSA", "d")))
	f.Add([]byte(`{"keys":[{"kty":"oct","k":"AA"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := v.ParseJWKS(data)
		if err != nil {
			if !errors.Is(err, aisecCrypto.ErrJWKS) {
				t.Fatalf("ошибка не ErrJWKS: %v", err)
			}
			return
		}
		if k.Len() == 0 || k.Len() > aisecCrypto.MaxJWKSKeys {
			t.Fatalf("принят набор из %d ключей", k.Len())
		}
	})
}
