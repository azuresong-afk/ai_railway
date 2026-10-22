package crypto

import (
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"fmt"
)

// Шифрование для получателя по открытому ключу: секреты провайдеров в
// пакете конфигурации шифруются для конкретного шлюза (решение Р7, задача
// 2.13, ADR-0009). Профиль standard — HPKE (RFC 9180) стандартной
// библиотеки: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, режим
// base. Ключ получателя отдельный от ключа mTLS шлюза: у сертификата
// назначение только подпись.

// Размеры ключей получателя X25519, байт.
const (
	RecipientKeySize       = 32
	RecipientPublicKeySize = 32
)

// Пределы одного вызова SealTo и Open, байт.
const (
	MaxSealToPlaintext = 4 << 20
	// MaxSealToInfo: info — короткая привязка к месту (формат, шлюз, версия).
	MaxSealToInfo = 1 << 10
)

const hpkeName = "HPKE DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM"

// Recipient — закрытый ключ получателя. Форматируется только именем
// алгоритма; сам ключ не логируется и не передаётся по сети.
type Recipient interface {
	Name() string
	// PublicKey — открытый ключ для отправителя (SealTo).
	PublicKey() []byte
	// PrivateKey — копия закрытого ключа для сохранения в файле 0600.
	PrivateKey() ([]byte, error)
	// Open расшифровывает результат SealTo с тем же info; при любом
	// несоответствии — ErrDecrypt.
	Open(sealed, info []byte) ([]byte, error)
}

type hpkeRecipient struct {
	redacted
	key hpke.PrivateKey
}

func hpkeSuite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()
}

func generateHPKERecipient() (Recipient, error) {
	kem, _, _ := hpkeSuite()
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return hpkeRecipient{redacted: redacted{hpkeName}, key: k}, nil
}

func newHPKERecipient(priv []byte) (Recipient, error) {
	if len(priv) != RecipientKeySize {
		return nil, fmt.Errorf("закрытый ключ получателя должен быть %d байт", RecipientKeySize)
	}
	kem, _, _ := hpkeSuite()
	k, err := kem.NewPrivateKey(priv)
	if err != nil {
		return nil, errors.New("закрытый ключ получателя не принят")
	}
	return hpkeRecipient{redacted: redacted{hpkeName}, key: k}, nil
}

func (r hpkeRecipient) PublicKey() []byte { return r.key.PublicKey().Bytes() }

func (r hpkeRecipient) PrivateKey() ([]byte, error) { return r.key.Bytes() }

func (r hpkeRecipient) Open(sealed, info []byte) ([]byte, error) {
	if len(info) > MaxSealToInfo || len(sealed) > MaxSealToPlaintext+RecipientPublicKeySize+64 {
		return nil, ErrDecrypt
	}
	_, kdf, aead := hpkeSuite()
	pt, err := hpke.Open(r.key, kdf, aead, info, sealed)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func hpkeSealTo(publicKey, info, plaintext []byte) ([]byte, error) {
	if len(publicKey) != RecipientPublicKeySize {
		return nil, fmt.Errorf("открытый ключ получателя должен быть %d байт", RecipientPublicKeySize)
	}
	if len(info) > MaxSealToInfo {
		return nil, fmt.Errorf("info больше %d байт", MaxSealToInfo)
	}
	if len(plaintext) > MaxSealToPlaintext {
		return nil, fmt.Errorf("данные больше %d байт", MaxSealToPlaintext)
	}
	kem, kdf, aead := hpkeSuite()
	pk, err := kem.NewPublicKey(publicKey)
	if err != nil {
		return nil, errors.New("открытый ключ получателя не принят")
	}
	return hpke.Seal(pk, kdf, aead, info, plaintext)
}
