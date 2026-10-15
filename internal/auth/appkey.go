package auth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Ключ приложения (ТЗ, 5.4, ИАФ.8): aisec_<id>_<секрет>, где id — 8 символов
// [a-z0-9], секрет — 32 случайных байта в base64url без выравнивания.
// Префикс aisec_<id> позволяет понять, к чему относится ключ, не раскрывая
// секрет; он попадает в события auth_failure. Хранится только SHA-256 всего
// ключа: ключ высокоэнтропийный, медленный хеш паролей ему не нужен.
const (
	keyScheme     = "aisec_"
	keyIDLen      = 8
	keySecretSize = 32
	keyIDAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	// MaxKeyLen — предел длины предъявленного ключа: длиннее не разбираем.
	MaxKeyLen = 128
)

var (
	keyRe    = regexp.MustCompile(`^aisec_([a-z0-9]{8})_([A-Za-z0-9_-]{43})$`)
	prefixRe = regexp.MustCompile(`^aisec_[a-z0-9]{8}$`)
	hashRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErrMalformedKey — предъявленная строка не похожа на ключ приложения.
var ErrMalformedKey = errors.New("ключ приложения: неверный формат")

// NewAppKey выпускает ключ. Возвращает сам ключ (показывается один раз),
// префикс и SHA-256 для хранения.
func NewAppKey(rnd aisecCrypto.Random, h aisecCrypto.Hasher) (key, prefix, hash string, err error) {
	idRaw, err := aisecCrypto.RandomBytes(rnd, keyIDLen)
	if err != nil {
		return "", "", "", err
	}
	var id strings.Builder
	for _, b := range idRaw {
		// Смещение при взятии остатка (256 mod 36) для идентификатора
		// несущественно: он не секрет, секрет — отдельные 32 байта.
		id.WriteByte(keyIDAlphabet[int(b)%len(keyIDAlphabet)])
	}
	secret, err := aisecCrypto.RandomBytes(rnd, keySecretSize)
	if err != nil {
		return "", "", "", err
	}
	prefix = keyScheme + id.String()
	key = prefix + "_" + base64.RawURLEncoding.EncodeToString(secret)
	return key, prefix, HashAppKey(h, key), nil
}

// HashAppKey — SHA-256 ключа в hex.
func HashAppKey(h aisecCrypto.Hasher, key string) string {
	return hex.EncodeToString(h.Sum([]byte(key)))
}

// ParseAppKey проверяет формат предъявленного ключа и возвращает его префикс.
// Секрет не возвращается и не попадает в ошибки.
func ParseAppKey(key string) (prefix string, err error) {
	if len(key) > MaxKeyLen {
		return "", ErrMalformedKey
	}
	m := keyRe.FindStringSubmatch(key)
	if m == nil {
		return "", ErrMalformedKey
	}
	return keyScheme + m[1], nil
}

// ValidPrefix сообщает, что строка — префикс ключа aisec_<id>.
func ValidPrefix(p string) bool { return prefixRe.MatchString(p) }

// ValidHash сообщает, что строка — SHA-256 в hex.
func ValidHash(h string) bool { return hashRe.MatchString(h) }

// KeyMatches сравнивает хеш предъявленного ключа с сохранённым за
// постоянное время.
func KeyMatches(h aisecCrypto.Hasher, key, storedHash string) bool {
	want, err := hex.DecodeString(storedHash)
	if err != nil {
		return false
	}
	return aisecCrypto.Equal(h.Sum([]byte(key)), want)
}

// FormatKeyEntry — фрагмент YAML для файла конфигурации шлюза.
func FormatKeyEntry(prefix, hash, expires string) string {
	s := fmt.Sprintf("      - prefix: %s\n        sha256: %s\n", prefix, hash)
	if expires != "" {
		s += fmt.Sprintf("        expires: %s\n", expires)
	}
	return s
}
