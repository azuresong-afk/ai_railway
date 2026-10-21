// Пакет cryptotest — вспомогательные функции тестов, которым нужна
// криптография вне internal/crypto (depguard запрещает её импорт в других
// пакетах). В рабочие бинарники не входит: его импортируют только тесты.
package cryptotest

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // G505: HMAC-SHA-1 — алгоритм TOTP (RFC 6238), как в internal/crypto/totp.go (ADR-0006)
	"encoding/binary"
	"fmt"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// TOTPCode — код TOTP (RFC 6238: HMAC-SHA-1, шаг 30 с, 6 цифр) на момент
// at — то, что показало бы приложение-аутентификатор. Реализация отдельная
// от internal/crypto: тесты сверяют с ней проверку кодов сервера.
func TOTPCode(secret []byte, at time.Time) (string, error) {
	if len(secret) != aisecCrypto.TOTPSecretSize {
		return "", fmt.Errorf("секрет TOTP должен быть %d байт", aisecCrypto.TOTPSecretSize)
	}
	unix := at.Unix()
	if unix < 0 {
		return "", fmt.Errorf("время до 1970 года")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(unix)/uint64(aisecCrypto.TOTPPeriod/time.Second))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:]) // запись в hash.Hash не возвращает ошибок
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000), nil
}
