package crypto

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func mustPassphraseKDF(t *testing.T) PassphraseKDF {
	t.Helper()
	k, err := mustStandard(t).PassphraseKDF()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Ключ детерминирован по фразе, соли и параметрам; любая из них меняет ключ.
func TestPassphraseKDFDerive(t *testing.T) {
	k := mustPassphraseKDF(t)
	if k.Name() != "Argon2id" || k.Params() != "m=65536,t=3,p=2" {
		t.Fatalf("параметры по умолчанию: %s %s", k.Name(), k.Params())
	}
	ctx := context.Background()
	salt := bytes.Repeat([]byte{7}, PassphraseSaltSize)
	phrase := []byte("синтетическая фраза копии")
	a, err := k.Derive(ctx, phrase, salt, k.Params())
	if err != nil || len(a) != AEADKeySize {
		t.Fatalf("%d %v", len(a), err)
	}
	b, err := k.Derive(ctx, phrase, salt, k.Params())
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("не детерминирован: %v", err)
	}
	salt2 := bytes.Repeat([]byte{8}, PassphraseSaltSize)
	for name, args := range map[string]struct {
		phrase, salt []byte
		params       string
	}{
		"фраза":     {[]byte("синтетическая фраза копии!"), salt, k.Params()},
		"соль":      {phrase, salt2, k.Params()},
		"параметры": {phrase, salt, "m=19456,t=2,p=1"},
	} {
		c, err := k.Derive(ctx, args.phrase, args.salt, args.params)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(a, c) {
			t.Errorf("%s не влияет на ключ", name)
		}
	}
}

// Параметры и соль приходят из файла: разбор строгий, границы — как у
// хешей паролей (память не выше параметров по умолчанию).
func TestPassphraseKDFRejects(t *testing.T) {
	k := mustPassphraseKDF(t)
	ctx := context.Background()
	salt := make([]byte, PassphraseSaltSize)
	phrase := []byte("синтетическая фраза копии")
	for _, params := range []string{
		"", "m=65536,t=3", "m=65536,t=3,p=2,x=1", "t=3,m=65536,p=2", "m=065536,t=3,p=2",
		"m=131072,t=3,p=2", "m=1024,t=3,p=2", "m=19456,t=1,p=1", "m=65536,t=17,p=2",
		"m=65536,t=3,p=0", "m=65536,t=3,p=17", "m=65536,t=+3,p=2", "m=65536, t=3,p=2",
		strings.Repeat("m=1,", 40),
	} {
		if _, err := k.Derive(ctx, phrase, salt, params); err == nil {
			t.Errorf("параметры %q приняты", params)
		}
	}
	for _, n := range []int{0, 15, 65} {
		if _, err := k.Derive(ctx, phrase, make([]byte, n), k.Params()); err == nil {
			t.Errorf("соль %d байт принята", n)
		}
	}
	for _, p := range [][]byte{nil, bytes.Repeat([]byte("я"), MaxPasswordLen)} {
		if _, err := k.Derive(ctx, p, salt, k.Params()); err == nil {
			t.Errorf("фраза %d байт принята", len(p))
		}
	}
}

// Истёкший контекст при занятых слотах — отказ, а не ожидание.
func TestPassphraseKDFContext(t *testing.T) {
	k := mustPassphraseKDF(t)
	slots := argon2Slots()
	for range cap(slots) {
		slots <- struct{}{}
	}
	defer func() {
		for range cap(slots) {
			<-slots
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := k.Derive(ctx, []byte("синтетическая фраза копии"), make([]byte, PassphraseSaltSize), k.Params()); err == nil {
		t.Fatal("вычисление без свободного слота")
	}
}

func FuzzParseKDFParams(f *testing.F) {
	for _, s := range []string{"m=65536,t=3,p=2", "m=19456,t=2,p=1", "m=0,t=0,p=0", "", ",,", "m=65536,t=3,p=2,"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := parseKDFParams(s)
		if err != nil {
			return
		}
		if p.memory < argon2MinMemory || p.memory > argon2MaxMemory || p.time < 1 || p.time > argon2MaxTime ||
			p.threads < 1 || p.threads > argon2MaxThreads {
			t.Fatalf("параметры вне границ приняты: %q → %+v", s, p)
		}
		// Разбор однозначен: каноническая запись совпадает со входом.
		if got := (argon2idKDF{params: p}).Params(); got != s {
			t.Fatalf("неоднозначный разбор: %q → %q", s, got)
		}
	})
}
