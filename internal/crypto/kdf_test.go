package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// KAT HKDF-SHA-256 без соли (RFC 5869, соль по умолчанию — нули длины хеша):
// посчитан независимой реализацией HMAC.
func TestKDFKnownAnswer(t *testing.T) {
	p := mustStandard(t)
	k, err := p.NewKDF(seq(32))
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Derive([]byte("aisec-test"), 32)
	if err != nil {
		t.Fatal(err)
	}
	want := "82425682601c88c09e78aea2e0d57989b05d277d9cdcaebd671ca487ca532358"
	if hex.EncodeToString(got) != want {
		t.Fatalf("HKDF: %x", got)
	}
	if k.Name() != "HKDF-SHA-256" {
		t.Fatalf("имя: %s", k.Name())
	}
}

func TestKDFContextSeparation(t *testing.T) {
	p := mustStandard(t)
	k, err := p.NewKDF(seq(32))
	if err != nil {
		t.Fatal(err)
	}
	a, err := k.Derive([]byte("events|2026-10-21"), AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.Derive([]byte("events|2026-10-22"), AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := k.Derive([]byte("events|2026-10-21"), AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) || !bytes.Equal(a, a2) {
		t.Fatal("производные ключи: разные контексты должны давать разные ключи, один контекст — один ключ")
	}
	other, err := p.NewKDF(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c, err := other.Derive([]byte("events|2026-10-21"), AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("разные секреты дали один ключ")
	}
}

func TestKDFLimits(t *testing.T) {
	p := mustStandard(t)
	if _, err := p.NewKDF(seq(MinKDFKeySize - 1)); err == nil {
		t.Fatal("принят короткий секрет")
	}
	k, err := p.NewKDF(seq(MinKDFKeySize))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		info []byte
		n    int
	}{
		{nil, 32}, {[]byte("x"), 15}, {[]byte("x"), 65}, {bytes.Repeat([]byte("x"), MaxKDFInfo+1), 32},
	} {
		if _, err := k.Derive(tc.info, tc.n); err == nil {
			t.Errorf("Derive(%d байт, %d) без ошибки", len(tc.info), tc.n)
		}
	}
	for _, n := range []int{16, 64} {
		if out, err := k.Derive(bytes.Repeat([]byte("x"), MaxKDFInfo), n); err != nil || len(out) != n {
			t.Errorf("Derive(граница, %d): %d %v", n, len(out), err)
		}
	}
}

// Секрет не попадает в форматирование и журнал.
func TestKDFRedacted(t *testing.T) {
	k, err := mustStandard(t).NewKDF(bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%x", "%s"} {
		if s := fmt.Sprintf(verb, k); s != "HKDF-SHA-256" {
			t.Errorf("%s: %q", verb, s)
		}
	}
}

func TestKDFGostNotImplemented(t *testing.T) {
	p, err := New(ProfileGOST)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.NewKDF(seq(32)); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("gost NewKDF: %v", err)
	}
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
