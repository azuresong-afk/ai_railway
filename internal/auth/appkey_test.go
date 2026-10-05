package auth

import (
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func prims(t *testing.T) (aisecCrypto.Random, aisecCrypto.Hasher) {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return r, h
}

func TestNewAppKey(t *testing.T) {
	r, h := prims(t)
	seen := map[string]bool{}
	for range 1000 {
		key, prefix, hash, err := NewAppKey(r, h)
		if err != nil {
			t.Fatal(err)
		}
		if seen[key] {
			t.Fatal("повтор ключа")
		}
		seen[key] = true
		got, err := ParseAppKey(key)
		if err != nil || got != prefix || !ValidPrefix(prefix) || !ValidHash(hash) {
			t.Fatalf("ключ %q: префикс %q/%q, хеш %q, %v", key, got, prefix, hash, err)
		}
		if !strings.HasPrefix(key, prefix+"_") || strings.Contains(hash, key) {
			t.Fatal("неверная структура ключа")
		}
		if !KeyMatches(h, key, hash) {
			t.Fatal("ключ не совпал со своим хешем")
		}
		if KeyMatches(h, key+"x", hash) || KeyMatches(h, key, strings.Repeat("0", 64)) || KeyMatches(h, key, "не hex") {
			t.Fatal("совпадение с чужим ключом или хешем")
		}
	}
}

func TestParseAppKeyRejects(t *testing.T) {
	for _, k := range []string{
		"", "Bearer aisec_abcd1234_" + strings.Repeat("A", 43),
		"aisec_abcd1234_" + strings.Repeat("A", 42),
		"aisec_ABCD1234_" + strings.Repeat("A", 43),
		"aisec_abcd123_" + strings.Repeat("A", 44),
		"sk-" + strings.Repeat("a", 48),
		"aisec_abcd1234_" + strings.Repeat("A", 42) + "=",
		strings.Repeat("a", MaxKeyLen+1),
	} {
		if _, err := ParseAppKey(k); err == nil {
			t.Errorf("ParseAppKey(%q): ожидалась ошибка", k)
		}
	}
}

func TestErrorDoesNotLeakKey(t *testing.T) {
	_, err := ParseAppKey("aisec_abcd1234_" + strings.Repeat("S", 42) + "!")
	if err == nil || strings.Contains(err.Error(), "SSSS") {
		t.Fatalf("ошибка раскрывает ключ: %v", err)
	}
}

func FuzzParseAppKey(f *testing.F) {
	f.Add("aisec_abcd1234_" + strings.Repeat("A", 43))
	f.Add("aisec_")
	f.Fuzz(func(t *testing.T, k string) {
		p, err := ParseAppKey(k)
		if err != nil {
			return
		}
		if !ValidPrefix(p) || !strings.HasPrefix(k, p+"_") || len(k) != len(p)+1+43 {
			t.Fatalf("принят ключ %q с префиксом %q", k, p)
		}
	})
}
