// Пакет ids — идентификаторы UUIDv7 (RFC 9562): 48 бит времени в
// миллисекундах, затем случайные биты. Идентификаторы упорядочены по времени
// создания, что удобно для секционированной по дням таблицы событий
// (ТЗ, 5.5, 12). Случайная часть берётся из Random криптопрофиля.
package ids

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// UUID — 16 байт идентификатора.
type UUID [16]byte

// Generator выпускает UUIDv7.
type Generator struct {
	rnd aisecCrypto.Random
	now func() time.Time
}

// NewGenerator создаёт генератор на источнике случайности криптопрофиля.
func NewGenerator(rnd aisecCrypto.Random) *Generator {
	return &Generator{rnd: rnd, now: time.Now}
}

// New возвращает новый UUIDv7.
func (g *Generator) New() (UUID, error) {
	var u UUID
	if err := g.rnd.Read(u[6:]); err != nil {
		return UUID{}, err
	}
	ms := g.now().UnixMilli()
	if ms < 0 || ms >= 1<<48 {
		return UUID{}, errors.New("идентификатор: время вне диапазона UUIDv7")
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(ms))
	copy(u[0:6], ts[2:8])       // младшие 48 бит времени
	u[6] = (u[6] & 0x0f) | 0x70 // версия 7
	u[8] = (u[8] & 0x3f) | 0x80 // вариант RFC 9562
	return u, nil
}

// String — каноническая запись 8-4-4-4-12 строчными шестнадцатеричными цифрами.
func (u UUID) String() string {
	var b [36]byte
	hex.Encode(b[0:8], u[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], u[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], u[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], u[8:10])
	b[23] = '-'
	hex.Encode(b[24:36], u[10:16])
	return string(b[:])
}

// Time — момент создания с точностью до миллисекунды.
func (u UUID) Time() time.Time {
	ms := int64(u[0])<<40 | int64(u[1])<<32 | int64(u[2])<<24 | int64(u[3])<<16 | int64(u[4])<<8 | int64(u[5])
	return time.UnixMilli(ms).UTC()
}

// ErrInvalid — строка не является UUIDv7 в канонической записи.
var ErrInvalid = errors.New("идентификатор: ожидается UUIDv7 в виде 8-4-4-4-12")

// Parse разбирает UUIDv7 в канонической записи (строчные или прописные цифры).
// Другие версии и варианты отвергаются: внешний ввод (например, ID события в
// пакете от шлюза) должен быть именно UUIDv7.
func Parse(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return UUID{}, ErrInvalid
	}
	parts := [][2]int{{0, 8}, {9, 13}, {14, 18}, {19, 23}, {24, 36}}
	pos := 0
	for _, p := range parts {
		n, err := hex.Decode(u[pos:], []byte(s[p[0]:p[1]]))
		if err != nil {
			return UUID{}, ErrInvalid
		}
		pos += n
	}
	if u[6]>>4 != 7 || u[8]>>6 != 2 {
		return UUID{}, ErrInvalid
	}
	return u, nil
}
