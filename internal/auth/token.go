package auth

import (
	"encoding/base64"
	"errors"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// tokenBytes — случайная часть токена сессии и CSRF-токена (решение Р6).
const tokenBytes = 32

// TokenLen — длина токена в base64url без дополнения.
var TokenLen = base64.RawURLEncoding.EncodedLen(tokenBytes)

var errBadToken = errors.New("неверный формат токена")

// newToken возвращает токен для клиента и его хеш для БД.
func newToken(r aisecCrypto.Random, h aisecCrypto.Hasher) (token string, hash []byte, err error) {
	b, err := aisecCrypto.RandomBytes(r, tokenBytes)
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(b), h.Sum(b), nil
}

// parseToken строго разбирает токен из cookie или заголовка: точная длина,
// base64url без дополнения, каноническая форма (без лишних битов и
// переводов строк). Хешируются исходные байты.
func parseToken(s string) ([]byte, error) {
	if len(s) != TokenLen {
		return nil, errBadToken
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != tokenBytes || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errBadToken
	}
	return b, nil
}

// hashToken разбирает токен и возвращает его хеш.
func hashToken(h aisecCrypto.Hasher, s string) ([]byte, error) {
	b, err := parseToken(s)
	if err != nil {
		return nil, err
	}
	return h.Sum(b), nil
}
