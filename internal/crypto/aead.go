package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// AEADKeySize — длина ключа AES-256-GCM, байт.
const AEADKeySize = 32

// Пределы одного вызова Seal и Open, байт.
const (
	MaxAEADPlaintext = 64 << 20
	// MaxAEADAAD: присоединённые данные — короткая привязка к месту хранения (Р4).
	MaxAEADAAD = 4 << 10
)

// ErrDecrypt — шифротекст повреждён, подменён, зашифрован другим ключом или
// с другими присоединёнными данными. Подробности намеренно не различаются.
var ErrDecrypt = errors.New("расшифрование: данные повреждены или подменены")

// AEAD — аутентифицированное шифрование с присоединёнными данными: ключ данных
// и содержимое событий (ТЗ, 10.4, ЗИ.1). Присоединённые данные (AAD) не
// шифруются, но привязывают шифротекст к месту хранения: таблица, столбец,
// ID строки (решение Р4 этапа 2).
type AEAD interface {
	Name() string
	// Seal шифрует plaintext со случайным nonce и возвращает nonce, шифротекст и тег одним срезом.
	Seal(plaintext, aad []byte) ([]byte, error)
	// Open проверяет тег и расшифровывает результат Seal; при любом несоответствии — ErrDecrypt.
	Open(sealed, aad []byte) ([]byte, error)
}

// aesGCM — AES-256-GCM со случайным 96-битным nonce перед шифротекстом
// (cipher.NewGCMWithRandomNonce). Предел — 2^32 сообщений на ключ (ADR-0006).
type aesGCM struct {
	redacted
	aead cipher.AEAD
}

func newAESGCM(key []byte) (AEAD, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("ключ AES-256-GCM должен быть %d байт", AEADKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	// Ключ не хранится: развёрнутое расписание ключа живёт только внутри block.
	return aesGCM{redacted: redacted{"AES-256-GCM"}, aead: a}, nil
}

func (g aesGCM) Seal(plaintext, aad []byte) ([]byte, error) {
	if len(plaintext) > MaxAEADPlaintext {
		return nil, fmt.Errorf("открытый текст длиннее %d байт", MaxAEADPlaintext)
	}
	if len(aad) > MaxAEADAAD {
		return nil, fmt.Errorf("присоединённые данные длиннее %d байт", MaxAEADAAD)
	}
	return g.aead.Seal(nil, nil, plaintext, aad), nil //nolint:gosec // G407: NewGCMWithRandomNonce требует пустой nonce и сам берёт случайный из crypto/rand
}

func (g aesGCM) Open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < g.aead.Overhead() || len(sealed) > MaxAEADPlaintext+g.aead.Overhead() || len(aad) > MaxAEADAAD {
		return nil, ErrDecrypt
	}
	out, err := g.aead.Open(nil, nil, sealed, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}
