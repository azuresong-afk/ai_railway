package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func mustStandard(t *testing.T) Provider {
	t.Helper()
	p, err := New(ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewProfiles(t *testing.T) {
	for _, name := range []string{ProfileStandard, ProfileGOST} {
		p, err := New(name)
		if err != nil || p.Name() != name {
			t.Fatalf("New(%q) = %v, %v", name, p, err)
		}
	}
	for _, bad := range []string{"", "STANDARD", "gost2012", "none"} {
		if _, err := New(bad); err == nil {
			t.Errorf("New(%q): ожидалась ошибка", bad)
		}
	}
}

// Контрактные тесты: одинаковые требования к обоим профилям. Профиль gost
// пока обязан честно отвечать ErrNotImplemented, а не делать вид, что работает.
func TestProfileContract(t *testing.T) {
	for _, name := range []string{ProfileStandard, ProfileGOST} {
		t.Run(name, func(t *testing.T) {
			p, err := New(name)
			if err != nil {
				t.Fatal(err)
			}
			h, err := p.Hasher()
			if errors.Is(err, ErrNotImplemented) {
				assertAllNotImplemented(t, p)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if h.Name() == "" {
				t.Fatal("у хеш-функции нет имени")
			}
			sum := h.Sum([]byte("данные"))
			stream := h.New()
			for _, part := range []string{"дан", "ные"} {
				if _, err := stream.Write([]byte(part)); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(sum, stream.Sum(nil)) {
				t.Fatal("потоковый и разовый хеш различаются")
			}
			if bytes.Equal(sum, h.Sum([]byte("данныЕ"))) {
				t.Fatal("хеш не зависит от данных")
			}

			key := bytes.Repeat([]byte{7}, MinMACKeySize)
			m, err := p.NewMAC(key)
			if err != nil {
				t.Fatal(err)
			}
			tag := m.Sum([]byte("сообщение"))
			if !m.Verify([]byte("сообщение"), tag) {
				t.Fatal("имитовставка не прошла проверку")
			}
			if m.Verify([]byte("сообщениЕ"), tag) || m.Verify([]byte("сообщение"), tag[:len(tag)-1]) {
				t.Fatal("проверка приняла чужое сообщение или обрезанную имитовставку")
			}
			key[0] = 8 // ключ скопирован: изменение исходного буфера не влияет
			if !m.Verify([]byte("сообщение"), tag) {
				t.Fatal("MAC зависит от буфера ключа после создания")
			}
			if _, err := p.NewMAC(make([]byte, MinMACKeySize-1)); err == nil {
				t.Fatal("принят слишком короткий ключ")
			}

			r, err := p.Random()
			if err != nil {
				t.Fatal(err)
			}
			a, err := RandomBytes(r, 32)
			if err != nil || len(a) != 32 {
				t.Fatalf("RandomBytes: %v %v", a, err)
			}
			if _, err := RandomBytes(r, -1); err == nil {
				t.Fatal("принята отрицательная длина")
			}
			if _, err := p.TLS(); err != nil {
				t.Fatal(err)
			}
			assertPrimitivesContract(t, p)
		})
	}
}

// assertPrimitivesContract — общие требования к паролям, AEAD, подписи и TOTP:
// круговая проверка, отказ на чужих данных и на ключах неверной длины.
func assertPrimitivesContract(t *testing.T, p Provider) {
	t.Helper()
	ph, err := p.PasswordHasher()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ph.Hash(context.Background(), []byte("пароль"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := ph.Verify(context.Background(), []byte("пароль"), enc); !ok || err != nil {
		t.Fatalf("PasswordHasher: %v %v", ok, err)
	}
	if ok, _, err := ph.Verify(context.Background(), []byte("парол"), enc); ok || err != nil {
		t.Fatalf("PasswordHasher, чужой пароль: %v %v", ok, err)
	}

	a, err := p.NewAEAD(make([]byte, AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.Seal([]byte("данные"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := a.Open(sealed, []byte("aad")); err != nil || string(out) != "данные" {
		t.Fatalf("AEAD: %q %v", out, err)
	}
	if _, err := a.Open(sealed, []byte("aaD")); err == nil {
		t.Fatal("AEAD принял чужие AAD")
	}
	if _, err := p.NewAEAD(make([]byte, AEADKeySize-1)); err == nil {
		t.Fatal("AEAD принял короткий ключ")
	}

	s, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.NewVerifier(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign([]byte("пакет"))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Verify([]byte("пакет"), sig) || v.Verify([]byte("пакеТ"), sig) {
		t.Fatal("Signer/Verifier: подпись проверяется неверно")
	}

	tp, err := p.NewTOTP(make([]byte, TOTPSecretSize))
	if err != nil {
		t.Fatal(err)
	}
	if tp.Name() == "" {
		t.Fatal("у TOTP нет имени")
	}
	if _, err := p.NewTOTP(make([]byte, TOTPSecretSize-1)); err == nil {
		t.Fatal("TOTP принял короткий секрет")
	}
}

func assertAllNotImplemented(t *testing.T, p Provider) {
	t.Helper()
	if _, err := p.NewMAC(make([]byte, 64)); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("NewMAC: %v", err)
	}
	if _, err := p.Random(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Random: %v", err)
	}
	if _, err := p.TLS(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("TLS: %v", err)
	}
	if _, err := p.PasswordHasher(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("PasswordHasher: %v", err)
	}
	if _, err := p.NewAEAD(make([]byte, AEADKeySize)); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("NewAEAD: %v", err)
	}
	if _, err := p.GenerateSigner(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("GenerateSigner: %v", err)
	}
	if _, err := p.NewSigner(make([]byte, SigningSeedSize)); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("NewSigner: %v", err)
	}
	if _, err := p.NewVerifier(make([]byte, PublicKeySize)); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("NewVerifier: %v", err)
	}
	if _, err := p.NewTOTP(make([]byte, TOTPSecretSize)); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("NewTOTP: %v", err)
	}
	if err := SelfTest(p); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("SelfTest: %v", err)
	}
}

func TestKnownAnswers(t *testing.T) {
	p := mustStandard(t)
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(h.Sum([]byte("abc"))); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("SHA-256: %s", got)
	}
	// RFC 4231, тест 1: ключ 20 байт 0x0b — через NewMAC нельзя (короче 32), проверяем тип напрямую.
	m := hmacSHA256{key: bytes.Repeat([]byte{0x0b}, 20)}
	if got := hex.EncodeToString(m.Sum([]byte("Hi There"))); got != "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" {
		t.Fatalf("HMAC-SHA-256: %s", got)
	}
	if err := SelfTest(p); err != nil {
		t.Fatal(err)
	}
}

func TestSelfTestDetectsBrokenRandom(t *testing.T) {
	err := SelfTest(brokenRandomProvider{standard{}})
	if err == nil || !strings.Contains(err.Error(), "случайност") {
		t.Fatalf("ожидался отказ самотеста, получено %v", err)
	}
}

// Самотест ловит неверный KDF профиля (Н19 ревью 2.r3a): ключ, не
// совпадающий с HKDF-SHA-256 по RFC 5869, останавливает запуск.
func TestSelfTestDetectsBrokenKDF(t *testing.T) {
	err := SelfTest(brokenKDFProvider{standard{}})
	if err == nil || !strings.Contains(err.Error(), "выведение ключей") {
		t.Fatalf("ожидался отказ самотеста, получено %v", err)
	}
}

type brokenKDFProvider struct{ standard }

func (brokenKDFProvider) NewKDF([]byte) (KDF, error) { return constKDF{}, nil }

// constKDF выдаёт один и тот же ключ для любого контекста.
type constKDF struct{}

func (constKDF) Name() string { return "broken" }

func (constKDF) Derive(_ []byte, n int) ([]byte, error) { return make([]byte, n), nil }

type brokenRandomProvider struct{ standard }

func (brokenRandomProvider) Random() (Random, error) { return zeroRandom{}, nil }

type zeroRandom struct{}

func (zeroRandom) Read(b []byte) error {
	clear(b)
	return nil
}

func TestEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"секрет", "секрет", true},
		{"секрет", "секреТ", false},
		{"секрет", "секре", false},
		{"", "", true},
	}
	for _, c := range cases {
		if got := Equal([]byte(c.a), []byte(c.b)); got != c.want {
			t.Errorf("Equal(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestMACDoesNotLeakKey(t *testing.T) {
	key := bytes.Repeat([]byte("K"), MinMACKeySize)
	m, err := mustStandard(t).NewMAC(key)
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("проверка", "mac", m)
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("проверка", "mac", m)
	outputs := []string{
		fmt.Sprintf("%v %+v %#v %s %x %X %q %d", m, m, m, m, m, m, m, m),
		fmt.Sprint(m), fmt.Sprintf("%v", []MAC{m}), logBuf.String(),
	}
	hexKey := hex.EncodeToString(key)
	for _, out := range outputs {
		if strings.Contains(out, "KKKK") || strings.Contains(strings.ToLower(out), hexKey[:16]) || strings.Contains(out, "75 75") {
			t.Fatalf("ключ попал в вывод: %s", out)
		}
		if !strings.Contains(out, "HMAC-SHA-256") {
			t.Fatalf("в выводе нет имени алгоритма: %s", out)
		}
	}
}
