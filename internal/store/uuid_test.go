package store

import (
	"errors"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

type fixedRandom byte

func (r fixedRandom) Read(b []byte) error {
	for i := range b {
		b[i] = byte(r)
	}
	return nil
}

type failRandom struct{}

func (failRandom) Read([]byte) error { return errors.New("нет энтропии") }

func TestUUIDv7Format(t *testing.T) {
	now := time.UnixMilli(0x018f_1234_5678)
	u, err := NewUUIDv7(now, fixedRandom(0xff))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(u), "018f1234-5678-7fff-bfff-ffffffffffff"; got != want {
		t.Fatalf("UUID = %s, ожидалось %s", u, want)
	}
	if _, err := ParseUUID(string(u)); err != nil {
		t.Fatal(err)
	}
}

func TestUUIDv7Ordering(t *testing.T) {
	r := mustRandom(t)
	a, errA := NewUUIDv7(time.UnixMilli(1000), r)
	b, errB := NewUUIDv7(time.UnixMilli(1001), r)
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if a >= b {
		t.Fatalf("%s не меньше %s", a, b)
	}
}

func mustRandom(t *testing.T) crypto.Random {
	t.Helper()
	p, err := crypto.New(crypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUUIDv7Errors(t *testing.T) {
	if _, err := NewUUIDv7(time.UnixMilli(-1), fixedRandom(0)); err == nil {
		t.Error("отрицательное время принято")
	}
	if _, err := NewUUIDv7(time.UnixMilli(1<<48), fixedRandom(0)); err == nil {
		t.Error("время за пределом принято")
	}
	if _, err := NewUUIDv7(time.UnixMilli(1), failRandom{}); err == nil {
		t.Error("ошибка источника проглочена")
	}
}

func TestParseUUID(t *testing.T) {
	for _, s := range []string{"", "018f1234-5678-7fff-bfff-fffffffffff", "018F1234-5678-7fff-bfff-ffffffffffff", "018f12345678-7fff-bfff-ffffffffffff-", "018f1234-5678-7fff-bfff-fffffffffffg"} {
		if _, err := ParseUUID(s); err == nil {
			t.Errorf("%q принято", s)
		}
	}
}

func FuzzParseUUID(f *testing.F) {
	f.Add("018f1234-5678-7fff-bfff-ffffffffffff")
	f.Fuzz(func(t *testing.T, s string) {
		if u, err := ParseUUID(s); err == nil && string(u) != s {
			t.Fatalf("%q → %q", s, u)
		}
	})
}
