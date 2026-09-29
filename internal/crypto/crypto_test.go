package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
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
		})
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
