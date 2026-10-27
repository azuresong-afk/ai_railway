package cryptotest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWTSigner — ключ синтетического IdP для тестов OIDC (ADR-0025): выпускает
// ID-токены и описывает свой открытый ключ в JWKS. Независимая от
// internal/crypto реализация подписи: тест проверяет проверку, а не
// сравнивает код с самим собой.
type JWTSigner struct {
	Alg string // RS256, ES256 или EdDSA
	KID string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
	ed  ed25519.PrivateKey
}

// NewJWTSigner создаёт ключ для алгоритма alg; rsaBits — длина ключа RSA
// (0 — 2 048).
func NewJWTSigner(alg, kid string, rsaBits int) (*JWTSigner, error) {
	s := &JWTSigner{Alg: alg, KID: kid}
	var err error
	switch alg {
	case "RS256":
		if rsaBits == 0 {
			rsaBits = 2048
		}
		s.rsa, err = rsa.GenerateKey(rand.Reader, rsaBits)
	case "ES256":
		s.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EdDSA":
		_, s.ed, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("cryptotest: алгоритм %q не поддерживается", alg)
	}
	return s, err
}

var enc = base64.RawURLEncoding

// JWK — открытый ключ в JWKS (RFC 7517) с полями use и alg.
func (s *JWTSigner) JWK() map[string]any {
	k := map[string]any{"use": "sig", "alg": s.Alg}
	if s.KID != "" {
		k["kid"] = s.KID
	}
	switch {
	case s.rsa != nil:
		k["kty"] = "RSA"
		k["n"] = enc.EncodeToString(s.rsa.N.Bytes())
		k["e"] = enc.EncodeToString(big.NewInt(int64(s.rsa.E)).Bytes())
	case s.ec != nil:
		b, err := s.ec.PublicKey.Bytes()
		if err != nil {
			panic(err) // ключ P-256 из GenerateKey всегда кодируется
		}
		k["kty"], k["crv"] = "EC", "P-256"
		k["x"], k["y"] = enc.EncodeToString(b[1:33]), enc.EncodeToString(b[33:])
	default:
		pub, _ := s.ed.Public().(ed25519.PublicKey)
		k["kty"], k["crv"] = "OKP", "Ed25519"
		k["x"] = enc.EncodeToString(pub)
	}
	return k
}

// JWKS — набор {"keys": [...]} из ключей signers в JSON.
func JWKS(signers ...*JWTSigner) []byte {
	keys := make([]map[string]any, 0, len(signers))
	for _, s := range signers {
		keys = append(keys, s.JWK())
	}
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		panic(err)
	}
	return b
}

// Header — заголовок по умолчанию: alg, typ JWT и kid ключа.
func (s *JWTSigner) Header() map[string]any {
	h := map[string]any{"alg": s.Alg, "typ": "JWT"}
	if s.KID != "" {
		h["kid"] = s.KID
	}
	return h
}

// Sign выпускает токен с заголовком Header и утверждениями claims.
func (s *JWTSigner) Sign(claims map[string]any) string {
	return s.SignWith(s.Header(), claims)
}

// SignWith — токен с произвольным заголовком (подмена alg, kid, crit).
func (s *JWTSigner) SignWith(header, claims map[string]any) string {
	h, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	return s.SignRaw(h, c)
}

// SignRaw подписывает заголовок и утверждения как есть (повторяющиеся
// ключи, неверный JSON).
func (s *JWTSigner) SignRaw(header, claims []byte) string {
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	return input + "." + enc.EncodeToString(s.sign([]byte(input)))
}

func (s *JWTSigner) sign(msg []byte) []byte {
	switch {
	case s.rsa != nil:
		h := sha256.Sum256(msg)
		sig, err := rsa.SignPKCS1v15(rand.Reader, s.rsa, crypto.SHA256, h[:])
		if err != nil {
			panic(err)
		}
		return sig
	case s.ec != nil:
		h := sha256.Sum256(msg)
		r, sv, err := ecdsa.Sign(rand.Reader, s.ec, h[:])
		if err != nil {
			panic(err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		sv.FillBytes(out[32:])
		return out
	default:
		return ed25519.Sign(s.ed, msg)
	}
}

// HMACToken — токен HS256, подписанный строкой key (атака «открытый ключ
// как секрет HMAC»): проверка его обязана отклонить.
func HMACToken(header, claims map[string]any, key []byte) string {
	h, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(input))
	return input + "." + enc.EncodeToString(m.Sum(nil))
}

// RSAModulus — модуль открытого ключа RSA (байты n): им атакующий
// подписал бы HS256, выдавая открытый ключ за секрет.
func (s *JWTSigner) RSAModulus() []byte {
	if s.rsa == nil {
		return nil
	}
	return s.rsa.N.Bytes()
}
