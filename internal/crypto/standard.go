package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
)

// standard — профиль для коммерческих заказчиков: стандартная библиотека Go.
type standard struct{}

func (standard) Name() string { return ProfileStandard }

func (standard) Hasher() (Hasher, error) { return sha256Hasher{}, nil }

func (standard) NewMAC(key []byte) (MAC, error) {
	if len(key) < MinMACKeySize {
		return nil, fmt.Errorf("ключ имитовставки короче %d байт", MinMACKeySize)
	}
	k := make([]byte, len(key))
	copy(k, key)
	return hmacSHA256{key: k}, nil
}

func (standard) Random() (Random, error) { return systemRandom{}, nil }

func (standard) TLS() (TLSProvider, error) { return standardTLS{}, nil }

type sha256Hasher struct{}

func (sha256Hasher) Name() string   { return "SHA-256" }
func (sha256Hasher) New() hash.Hash { return sha256.New() }
func (sha256Hasher) Sum(data []byte) []byte {
	s := sha256.Sum256(data)
	return s[:]
}

type hmacSHA256 struct{ key []byte }

func (hmacSHA256) Name() string { return "HMAC-SHA-256" }

func (m hmacSHA256) Sum(msg []byte) []byte {
	h := hmac.New(sha256.New, m.key)
	h.Write(msg) // запись в hash.Hash не возвращает ошибок
	return h.Sum(nil)
}

func (m hmacSHA256) Verify(msg, tag []byte) bool {
	return hmac.Equal(m.Sum(msg), tag)
}

type systemRandom struct{}

func (systemRandom) Read(b []byte) error {
	// crypto/rand.Read всегда заполняет буфер целиком или завершает процесс.
	_, err := rand.Read(b)
	return err
}
