package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

// Эталонные значения (known answer tests) профиля standard.
var (
	// SHA-256("abc") — FIPS 180-2, приложение B.1.
	katSHA256In  = []byte("abc")
	katSHA256Out = mustHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	// HMAC-SHA-256 — RFC 4231, тест 6: ключ 131 байт 0xaa, длиннее блока —
	// проверяется через тот же NewMAC и Verify, что используют компоненты.
	katHMACKey = bytes.Repeat([]byte{0xaa}, 131)
	katHMACIn  = []byte("Test Using Larger Than Block-Size Key - Hash Key First")
	katHMACOut = mustHex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
	// AES-256-GCM — McGrew, Viega «The Galois/Counter Mode of Operation», тест 14:
	// нулевые ключ, nonce и 16 байт открытого текста.
	katGCMOut = mustHex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
	// Ed25519 — RFC 8032, раздел 7.1, тест 1 (пустое сообщение).
	katEd25519Seed = mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	katEd25519Pub  = mustHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	katEd25519Sig  = mustHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	// TOTP — RFC 6238, приложение B: секрет ASCII «12345678901234567890», T = 59 с,
	// код 94287082 (последние 6 цифр — 287082).
	katTOTPSecret = []byte("12345678901234567890")
	// Argon2id версии 19 без секрета и AD (их нет в x/crypto, поэтому векторы
	// RFC 9106 не подходят) — вектор эталонной реализации phc-winner-argon2
	// (src/test.c): пароль «password», соль «somesalt», t = 2, m = 256 КиБ,
	// p = 1, 32 байта; совпадает и с OpenSSL 4.0.
	katArgon2Out = mustHex("9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe")
	// Строка PHC с параметрами по умолчанию (соль и хеш — произвольные байты):
	// проверяет разбор и кодирование, которыми пользуется PasswordHasher.
	katArgon2PHC = "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHRzb21lc2FsdA$" +
		"CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
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
	m, err := p.NewMAC(katHMACKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(m.Sum(katHMACIn), katHMACOut) || !m.Verify(katHMACIn, katHMACOut) {
		return errors.New("самотест: HMAC-SHA-256 не совпал с эталоном")
	}
	if m.Verify(katHMACIn[1:], katHMACOut) {
		return errors.New("самотест: HMAC-SHA-256 принял чужое сообщение")
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
	if err := selfTestAEAD(p); err != nil {
		return err
	}
	if err := selfTestSign(p); err != nil {
		return err
	}
	if err := selfTestTOTP(p); err != nil {
		return err
	}
	if err := selfTestHPKE(p); err != nil {
		return err
	}
	return selfTestArgon2id()
}

// selfTestHPKE — шифрование для получателя: эталона с фиксированным
// эфемерным ключом стандартная библиотека не допускает, поэтому проверяются
// расшифрование своего шифротекста и отказ при другом info.
func selfTestHPKE(p Provider) error {
	r, err := p.GenerateRecipient()
	if err != nil {
		return err
	}
	sealed, err := p.SealTo(r.PublicKey(), katHMACIn, katSHA256In)
	if err != nil {
		return err
	}
	got, err := r.Open(sealed, katHMACIn)
	if err != nil || !bytes.Equal(got, katSHA256In) {
		return errors.New("самотест: HPKE не расшифровал свой шифротекст")
	}
	if _, err := r.Open(sealed, katHMACIn[1:]); err == nil {
		return errors.New("самотест: HPKE расшифровал шифротекст с чужим info")
	}
	return nil
}

func selfTestArgon2id() error {
	// Малые параметры: самотест при запуске не должен занимать 64 МиБ.
	if !bytes.Equal(argon2.IDKey([]byte("password"), []byte("somesalt"), 2, 256, 1, 32), katArgon2Out) {
		return errors.New("самотест: Argon2id не совпал с эталоном")
	}
	p, salt, key, err := parseArgon2id(katArgon2PHC)
	if err != nil || p != argon2Default || encodeArgon2id(p, salt, key) != katArgon2PHC {
		return errors.New("самотест: кодирование хеша пароля работает неверно")
	}
	return nil
}

func selfTestAEAD(p Provider) error {
	// Эталон проверяет сам AES-GCM с фиксированным nonce; рабочий AEAD профиля
	// берёт nonce случайно, поэтому для него — расшифрование и отказ при подмене.
	block, err := aes.NewCipher(make([]byte, AEADKeySize))
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	kat := gcm.Seal(nil, make([]byte, gcm.NonceSize()), make([]byte, 16), nil) //nolint:gosec // G407: нулевой nonce задан эталоном McGrew–Viega; этот объект шифрует только эталон
	if !bytes.Equal(kat, katGCMOut) {
		return errors.New("самотест: AES-256-GCM не совпал с эталоном")
	}
	a, err := p.NewAEAD(make([]byte, AEADKeySize))
	if err != nil {
		return err
	}
	sealed, err := a.Seal(katSHA256In, katHMACIn)
	if err != nil {
		return err
	}
	if out, err := a.Open(sealed, katHMACIn); err != nil || !bytes.Equal(out, katSHA256In) {
		return errors.New("самотест: AES-256-GCM не расшифровал свой шифротекст")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := a.Open(sealed, katHMACIn); err == nil {
		return errors.New("самотест: AES-256-GCM принял подменённый шифротекст")
	}
	return nil
}

func selfTestSign(p Provider) error {
	s, err := p.NewSigner(katEd25519Seed)
	if err != nil {
		return err
	}
	sig, err := s.Sign(nil)
	if err != nil {
		return err
	}
	if !bytes.Equal(sig, katEd25519Sig) || !bytes.Equal(s.PublicKey(), katEd25519Pub) {
		return errors.New("самотест: Ed25519 не совпал с эталоном")
	}
	v, err := p.NewVerifier(katEd25519Pub)
	if err != nil {
		return err
	}
	if !v.Verify(nil, katEd25519Sig) || v.Verify([]byte{0}, katEd25519Sig) {
		return errors.New("самотест: проверка подписи Ed25519 работает неверно")
	}
	return nil
}

func selfTestTOTP(p Provider) error {
	t, err := p.NewTOTP(katTOTPSecret)
	if err != nil {
		return err
	}
	now := time.Unix(59, 0)
	if step, ok := t.Verify("287082", now, 0); !ok || step != 1 {
		return errors.New("самотест: TOTP не совпал с эталоном")
	}
	if _, ok := t.Verify("287082", now, 1); ok {
		return errors.New("самотест: TOTP принял повтор кода")
	}
	return nil
}
