package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// Размеры Ed25519 (RFC 8032), байт.
const (
	SigningSeedSize = ed25519.SeedSize
	PublicKeySize   = ed25519.PublicKeySize
	SignatureSize   = ed25519.SignatureSize
)

// Signer — электронная подпись: пакет конфигурации шлюза (Р7), манифест
// целостности (ОЦЛ.1), контрольные точки журнала аудита (Р5).
type Signer interface {
	Name() string
	Sign(msg []byte) ([]byte, error)
	// PublicKey — копия открытого ключа для Verifier.
	PublicKey() []byte
	// Seed — копия закрытого ключа для сохранения (только в зашифрованном
	// виде или в файле 0400, ТЗ 10.4). Не логируется и не передаётся по сети.
	Seed() []byte
}

// Verifier проверяет подпись открытым ключом.
type Verifier interface {
	Name() string
	Verify(msg, sig []byte) bool
	PublicKey() []byte
}

const ed25519Name = "Ed25519"

type ed25519Signer struct {
	redacted
	key ed25519.PrivateKey
}

type ed25519Verifier struct {
	redacted
	key ed25519.PublicKey
}

func newEd25519Signer(seed []byte) (Signer, error) {
	if len(seed) != SigningSeedSize {
		return nil, fmt.Errorf("закрытый ключ Ed25519 должен быть %d байт", SigningSeedSize)
	}
	// NewKeyFromSeed копирует seed: исходный буфер вызывающий может затереть.
	return ed25519Signer{redacted: redacted{ed25519Name}, key: ed25519.NewKeyFromSeed(seed)}, nil
}

func (s ed25519Signer) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.key, msg), nil
}

func (s ed25519Signer) PublicKey() []byte {
	pub, _ := s.key.Public().(ed25519.PublicKey) // тип гарантирован ed25519.PrivateKey.Public
	return append([]byte(nil), pub...)
}

func (s ed25519Signer) Seed() []byte { return s.key.Seed() }

func newEd25519Verifier(pub []byte) (Verifier, error) {
	if len(pub) != PublicKeySize {
		return nil, fmt.Errorf("открытый ключ Ed25519 должен быть %d байт", PublicKeySize)
	}
	return ed25519Verifier{redacted: redacted{ed25519Name}, key: append(ed25519.PublicKey(nil), pub...)}, nil
}

func (v ed25519Verifier) Verify(msg, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(v.key, msg, sig)
}

func (v ed25519Verifier) PublicKey() []byte { return append([]byte(nil), v.key...) }
