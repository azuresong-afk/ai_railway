package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// Пределы выведения ключей.
const (
	// MinKDFKeySize — минимальная длина исходного секрета, байт.
	MinKDFKeySize = 32
	// MaxKDFInfo — предел контекста выведения, байт.
	MaxKDFInfo = 1024
	minDerived = 16
	maxDerived = 64
)

// KDF — выведение ключей из секрета: производные ключи ключа данных по
// назначению и суткам (ADR-0007, п. 8). Хранит только псевдослучайный ключ
// после извлечения, исходный секрет не сохраняет.
type KDF interface {
	Name() string
	// Derive выводит ключ длины n (16–64 байт) для контекста info: разные
	// info дают независимые ключи.
	Derive(info []byte, n int) ([]byte, error)
}

// hkdfSHA256 — HKDF-SHA-256 (RFC 5869) без соли: исходный секрет — уже
// равномерно случайный ключ данных.
type hkdfSHA256 struct {
	redacted
	prk []byte
}

func newHKDF(secret []byte) (KDF, error) {
	if len(secret) < MinKDFKeySize {
		return nil, fmt.Errorf("секрет для выведения ключей короче %d байт", MinKDFKeySize)
	}
	prk, err := hkdf.Extract(sha256.New, secret, nil)
	if err != nil {
		return nil, err
	}
	return hkdfSHA256{redacted: redacted{"HKDF-SHA-256"}, prk: prk}, nil
}

func (k hkdfSHA256) Derive(info []byte, n int) ([]byte, error) {
	if n < minDerived || n > maxDerived {
		return nil, fmt.Errorf("длина производного ключа — от %d до %d байт", minDerived, maxDerived)
	}
	if len(info) == 0 || len(info) > MaxKDFInfo {
		return nil, fmt.Errorf("контекст выведения — от 1 до %d байт", MaxKDFInfo)
	}
	return hkdf.Expand(sha256.New, k.prk, string(info), n)
}
