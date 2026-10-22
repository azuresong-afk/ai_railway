package crypto

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
)

// Имена криптопрофилей.
const (
	ProfileStandard = "standard"
	ProfileGOST     = "gost"
)

// ErrNotImplemented возвращает профиль, в котором операция ещё не реализована.
var ErrNotImplemented = errors.New("криптопрофиль: операция не реализована")

// MinMACKeySize — минимальная длина ключа имитовставки, байт.
const MinMACKeySize = 32

// Hasher — хеш-функция профиля.
type Hasher interface {
	// Name — имя алгоритма для отчётов и SBOM, например «SHA-256».
	Name() string
	// New возвращает потоковый хеш.
	New() hash.Hash
	// Sum считает хеш данных целиком.
	Sum(data []byte) []byte
}

// MAC — имитовставка на секретном ключе: псевдоним пользователя в событиях,
// подпись webhook, TOTP (ТЗ, 10.2).
type MAC interface {
	Name() string
	Sum(msg []byte) []byte
	// Verify сравнивает имитовставку за постоянное время.
	Verify(msg, tag []byte) bool
}

// Random — криптографически стойкий источник случайности.
type Random interface {
	// Read заполняет b случайными байтами целиком или возвращает ошибку.
	Read(b []byte) error
}

// Provider — криптопрофиль.
type Provider interface {
	Name() string
	Hasher() (Hasher, error)
	NewMAC(key []byte) (MAC, error)
	Random() (Random, error)
	TLS() (TLSProvider, error)
	// PasswordHasher — хеширование паролей учётных записей.
	PasswordHasher() (PasswordHasher, error)
	// PassphraseKDF — ключ шифрования из парольной фразы (резервная копия, ADR-0017).
	PassphraseKDF() (PassphraseKDF, error)
	// NewAEAD — шифрование ключом длины AEADKeySize.
	NewAEAD(key []byte) (AEAD, error)
	// GenerateSigner создаёт новую пару ключей подписи из источника профиля.
	GenerateSigner() (Signer, error)
	// NewSigner восстанавливает ключ подписи из сохранённого Signer.Seed.
	NewSigner(seed []byte) (Signer, error)
	NewVerifier(publicKey []byte) (Verifier, error)
	// NewTOTP — проверка кодов второго фактора по секрету длины TOTPSecretSize.
	NewTOTP(secret []byte) (TOTP, error)
	// NewKDF — выведение ключей из секрета не короче MinKDFKeySize.
	NewKDF(secret []byte) (KDF, error)
	// GenerateRecipient создаёт ключ получателя для шифрования по открытому
	// ключу (секреты в пакете конфигурации шлюза, Р7).
	GenerateRecipient() (Recipient, error)
	// NewRecipient восстанавливает ключ получателя из Recipient.PrivateKey.
	NewRecipient(privateKey []byte) (Recipient, error)
	// SealTo шифрует plaintext для владельца открытого ключа; info
	// привязывает шифротекст к месту, Open с другим info не расшифрует.
	SealTo(publicKey, info, plaintext []byte) ([]byte, error)
}

// New возвращает криптопрофиль по имени.
func New(profile string) (Provider, error) {
	switch profile {
	case ProfileStandard:
		return standard{}, nil
	case ProfileGOST:
		return gost{}, nil
	}
	return nil, fmt.Errorf("неизвестный криптопрофиль %q: допустимы %s и %s", profile, ProfileStandard, ProfileGOST)
}

// Equal сравнивает секреты за постоянное время (время зависит только от длины).
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RandomBytes возвращает n случайных байт из источника профиля.
func RandomBytes(r Random, n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("отрицательная длина")
	}
	b := make([]byte, n)
	if err := r.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
