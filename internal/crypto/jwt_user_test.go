package crypto_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

// JWT пользователя приложения на шлюзе (задача 4.21 этапа 4, ADR-0025, 4).

const testAudience = "aisec-gateway"

func userClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "u-0001", "aud": []string{"account", testAudience}, "azp": "portal",
		"exp": testNow.Add(5 * time.Minute).Unix(), "iat": testNow.Add(-2 * time.Hour).Unix(),
		"groups": []string{"analysts"},
	}
}

func userWant() aisecCrypto.UserTokenExpect {
	return aisecCrypto.UserTokenExpect{Issuer: testIssuer, Audience: testAudience, Now: testNow, Leeway: time.Minute}
}

// Токен доступа принимается: несколько aud с чужим azp, typ at+jwt, iat
// старше срока ID-токена.
func TestVerifyUserTokenAccepts(t *testing.T) {
	v := jwtVerifier(t)
	for _, alg := range []string{"RS256", "ES256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			s := signer(t, alg, "k-"+alg)
			h := s.Header()
			h["typ"] = "at+jwt"
			c, err := v.VerifyUserToken(s.SignWith(h, userClaims()), mustJWKS(t, v, s), userWant())
			if err != nil {
				t.Fatal(err)
			}
			groups, err := c.Strings("groups", 10, 64)
			if err != nil || len(groups) != 1 || groups[0] != "analysts" || c.Subject != "u-0001" {
				t.Fatalf("утверждения: %v %v %q", groups, err, c.Subject)
			}
		})
	}
}

// Отказы: просроченный токен, nbf в будущем, чужой издатель, чужая
// аудитория, неизвестный kid, none, HS256 с открытым ключом в роли секрета.
func TestVerifyUserTokenRejects(t *testing.T) {
	v := jwtVerifier(t)
	rs := signer(t, "RS256", "rsa")
	keys := mustJWKS(t, v, rs)
	with := func(k string, val any) map[string]any {
		c := userClaims()
		if val == nil {
			delete(c, k)
		} else {
			c[k] = val
		}
		return c
	}
	none := func() string {
		h, _ := json.Marshal(map[string]any{"alg": "none", "kid": "rsa"}) //nolint:gosec // G104: тест, данные заведомо корректны
		c, _ := json.Marshal(userClaims())                                //nolint:gosec // G104: тест, данные заведомо корректны
		e := base64.RawURLEncoding
		return e.EncodeToString(h) + "." + e.EncodeToString(c) + ".AA"
	}()
	cases := map[string]struct {
		token, reason string
	}{
		"просрочен":             {rs.Sign(with("exp", testNow.Add(-2*time.Minute).Unix())), aisecCrypto.JWTReasonExpired},
		"без exp":               {rs.Sign(with("exp", nil)), aisecCrypto.JWTReasonExpired},
		"nbf в будущем":         {rs.Sign(with("nbf", testNow.Add(2*time.Minute).Unix())), aisecCrypto.JWTReasonNotBefore},
		"iat в будущем":         {rs.Sign(with("iat", testNow.Add(2*time.Minute).Unix())), aisecCrypto.JWTReasonIssuedAt},
		"чужой издатель":        {rs.Sign(with("iss", "https://evil.example.test/realms/aisec")), aisecCrypto.JWTReasonIssuer},
		"издатель со слешем":    {rs.Sign(with("iss", testIssuer+"/")), aisecCrypto.JWTReasonIssuer},
		"чужая аудитория":       {rs.Sign(with("aud", "other")), aisecCrypto.JWTReasonAudience},
		"аудитория по регистру": {rs.Sign(with("aud", "AISEC-GATEWAY")), aisecCrypto.JWTReasonAudience},
		"без sub":               {rs.Sign(with("sub", nil)), aisecCrypto.JWTReasonSubject},
		"неизвестный kid":       {rs.SignWith(map[string]any{"alg": "RS256", "kid": "other"}, userClaims()), aisecCrypto.JWTReasonUnknownKey},
		"alg=none":              {none, aisecCrypto.JWTReasonAlg},
		"HS256 открытым ключом": {cryptotest.HMACToken(map[string]any{"alg": "HS256", "kid": "rsa"}, userClaims(), rs.RSAModulus()),
			aisecCrypto.JWTReasonAlg},
		"typ id-токена другой": {rs.SignWith(map[string]any{"alg": "RS256", "kid": "rsa", "typ": "logout+jwt"}, userClaims()),
			aisecCrypto.JWTReasonMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyUserToken(tc.token, keys, userWant())
			wantReason(t, err, tc.reason)
		})
	}
}

// Допуск часов берётся из настроек: просроченный на 30 с проходит с
// допуском 60 с и не проходит без допуска; допуск больше предела — ошибка.
func TestVerifyUserTokenLeeway(t *testing.T) {
	v := jwtVerifier(t)
	rs := signer(t, "RS256", "rsa")
	keys := mustJWKS(t, v, rs)
	c := userClaims()
	c["exp"] = testNow.Add(-30 * time.Second).Unix()
	tok := rs.Sign(c)
	if _, err := v.VerifyUserToken(tok, keys, userWant()); err != nil {
		t.Fatalf("в пределах допуска: %v", err)
	}
	w := userWant()
	w.Leeway = 0
	_, err := v.VerifyUserToken(tok, keys, w)
	wantReason(t, err, aisecCrypto.JWTReasonExpired)
	w.Leeway = aisecCrypto.MaxUserTokenLeeway + time.Second
	if _, err := v.VerifyUserToken(tok, keys, w); err == nil || aisecCrypto.JWTReason(err) != "" {
		t.Fatalf("допуск вне предела принят: %v", err)
	}
}

// Каноничный JWKS: тот же набор в другом порядке и с лишними полями даёт
// те же байты, и его снова разбирает ParseJWKS.
func TestMarshalJWKSCanonical(t *testing.T) {
	v := jwtVerifier(t)
	a, b, c := signer(t, "RS256", "b"), signer(t, "ES256", "a"), signer(t, "EdDSA", "c")
	one, err := v.MarshalJWKS(mustJWKS(t, v, a, b, c))
	if err != nil {
		t.Fatal(err)
	}
	extra := a.JWK()
	extra["x5c"] = []string{"MIIB"}
	raw, _ := json.Marshal(map[string]any{"keys": []any{c.JWK(), extra, b.JWK()}}) //nolint:gosec // G104: тест
	set, err := v.ParseJWKS(raw)
	if err != nil {
		t.Fatal(err)
	}
	two, err := v.MarshalJWKS(set)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one, two) {
		t.Fatalf("байты различаются:\n%s\n%s", one, two)
	}
	back, err := v.ParseJWKS(one)
	if err != nil || back.Len() != 3 {
		t.Fatalf("повторный разбор: %v", err)
	}
	if _, err := v.VerifyUserToken(b.Sign(userClaims()), back, userWant()); err != nil {
		t.Fatalf("ключ после кодирования не проверяет подпись: %v", err)
	}
	if _, err := v.MarshalJWKS(nil); err == nil {
		t.Fatal("пустой набор закодирован")
	}
}
