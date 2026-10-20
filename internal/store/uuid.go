package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// UUID — идентификатор в текстовой форме xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx.
type UUID string

// NewUUIDv7 создаёт UUID версии 7 (RFC 9562): 48 бит времени в миллисекундах,
// остальное — случайные байты из источника криптопрофиля. Идентификаторы
// растут со временем, поэтому индексы по ним не фрагментируются.
func NewUUIDv7(now time.Time, r crypto.Random) (UUID, error) {
	ms := now.UnixMilli()
	if ms < 0 || ms >= 1<<48 {
		return "", errors.New("время вне диапазона UUIDv7")
	}
	b, err := crypto.RandomBytes(r, 10)
	if err != nil {
		return "", fmt.Errorf("случайные байты для UUIDv7: %w", err)
	}
	var u [16]byte
	for i := 0; i < 6; i++ {
		u[i] = byte(ms >> (8 * (5 - i)))
	}
	copy(u[6:], b)
	u[6] = u[6]&0x0f | 0x70 // версия 7
	u[8] = u[8]&0x3f | 0x80 // вариант RFC 9562
	return UUID(fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])), nil
}

// ParseUUID проверяет текстовую форму UUID (нижний регистр, 36 символов).
func ParseUUID(s string) (UUID, error) {
	if len(s) != 36 {
		return "", errors.New("UUID: длина не 36 символов")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "", errors.New("UUID: неверный разделитель")
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return "", errors.New("UUID: допустимы цифры и a–f нижнего регистра")
			}
		}
	}
	return UUID(s), nil
}
