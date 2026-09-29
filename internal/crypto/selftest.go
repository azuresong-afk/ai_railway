package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

// Эталонные значения (known answer tests) профиля standard.
var (
	// SHA-256("abc") — FIPS 180-2, приложение B.1.
	katSHA256In  = []byte("abc")
	katSHA256Out = mustHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	// HMAC-SHA-256 — RFC 4231, тест 2 (ключ короче минимального для продукта,
	// поэтому проверяется напрямую, а не через NewMAC).
	katHMACKey = []byte("Jefe")
	katHMACIn  = []byte("what do ya want for nothing?")
	katHMACOut = mustHex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err) // константа в коде: ошибка возможна только при правке исходника
	}
	return b
}

// SelfTest проверяет работоспособность криптопрофиля на эталонных значениях
// (ТЗ, ОЦЛ.4). Вызывается при запуске компонентов; ошибка — повод не стартовать.
func SelfTest(p Provider) error {
	if p.Name() != ProfileStandard {
		// Для gost эталоны появятся вместе с реализацией (этап 6).
		return fmt.Errorf("самотест профиля %s: %w", p.Name(), ErrNotImplemented)
	}
	h, err := p.Hasher()
	if err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(katSHA256In), katSHA256Out) {
		return errors.New("самотест: SHA-256 не совпал с эталоном")
	}
	if !bytes.Equal(hmacSHA256{key: katHMACKey}.Sum(katHMACIn), katHMACOut) {
		return errors.New("самотест: HMAC-SHA-256 не совпал с эталоном")
	}
	r, err := p.Random()
	if err != nil {
		return err
	}
	a, err := RandomBytes(r, 32)
	if err != nil {
		return err
	}
	b, err := RandomBytes(r, 32)
	if err != nil {
		return err
	}
	if bytes.Equal(a, b) || bytes.Equal(a, make([]byte, 32)) {
		return errors.New("самотест: источник случайности выдаёт повторяющиеся значения")
	}
	return nil
}
