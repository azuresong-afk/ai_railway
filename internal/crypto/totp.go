package crypto

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // G505: HMAC-SHA-1 только для TOTP (RFC 6238) — исключение из профиля по ТЗ 10.2 и ADR-0006
	"encoding/binary"
	"fmt"
	"time"
)

// Параметры TOTP (решение Р1 этапа 2, ADR-0006): их понимают все
// распространённые приложения-аутентификаторы.
const (
	TOTPSecretSize = 20
	TOTPDigits     = 6
	TOTPPeriod     = 30 * time.Second
	// TOTPSkew — сколько шагов до и после текущего принимается (рассинхронизация часов).
	TOTPSkew = 1
)

// TOTP — одноразовые пароли второго фактора (ТЗ, ИАФ.5). HMAC-SHA-1 здесь —
// исключение из профиля (ТЗ, 10.2): используется только этим типом и ни для
// чего другого.
type TOTP interface {
	Name() string
	// Verify проверяет код на момент now в окне ±TOTPSkew шагов. lastStep — шаг
	// последнего принятого кода этого пользователя (0, если кодов не было):
	// код того же или более раннего шага отвергается как повтор. При успехе
	// возвращается шаг принятого кода — его вызывающий сохраняет как новый lastStep.
	//
	// Контракт вызывающего (задачи 2.7, 2.8): lastStep обновляется атомарно,
	// условием в той же записи (UPDATE … SET last_step = $шаг WHERE last_step < $шаг),
	// и вход засчитывается, только если запись изменилась, — иначе два
	// параллельных запроса с одним кодом пройдут оба. Число попыток ввода
	// кода ограничивает вызывающий: 10^6 кодов перебираются быстро.
	Verify(code string, now time.Time, lastStep int64) (step int64, ok bool)
}

type totpSHA1 struct {
	redacted
	secret []byte
}

func newTOTP(secret []byte) (TOTP, error) {
	if len(secret) != TOTPSecretSize {
		return nil, fmt.Errorf("секрет TOTP должен быть %d байт", TOTPSecretSize)
	}
	return totpSHA1{redacted: redacted{"TOTP (RFC 6238, HMAC-SHA-1)"}, secret: append([]byte(nil), secret...)}, nil
}

func (t totpSHA1) Verify(code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != TOTPDigits {
		return 0, false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	unix := now.Unix()
	if unix < 0 {
		return 0, false
	}
	cur := unix / int64(TOTPPeriod/time.Second)
	var found int64
	// Все кандидаты окна сравниваются за постоянное время, без раннего выхода.
	for s := cur - TOTPSkew; s <= cur+TOTPSkew; s++ {
		if s <= lastStep || s <= 0 {
			continue
		}
		if Equal([]byte(hotp(t.secret, uint64(s), TOTPDigits)), []byte(code)) && found == 0 {
			found = s
		}
	}
	return found, found != 0
}

// hotp — HOTP по RFC 4226, раздел 5.3: динамическое усечение HMAC-SHA-1.
func hotp(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:]) // запись в hash.Hash не возвращает ошибок
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}
