package main

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

var now = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

func TestAppKey(t *testing.T) {
	var out, errOut strings.Builder
	if code := run([]string{"app-key", "-expires", "2027-01-01"}, &out, &errOut, now); code != 0 {
		t.Fatalf("код %d: %s", code, errOut.String())
	}
	key := regexp.MustCompile(`aisec_[a-z0-9]{8}_[A-Za-z0-9_-]{43}`).FindString(out.String())
	hash := regexp.MustCompile(`sha256: ([0-9a-f]{64})`).FindStringSubmatch(out.String())
	if key == "" || hash == nil || !strings.Contains(out.String(), "expires: 2027-01-01") {
		t.Fatalf("вывод: %s", out.String())
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if !auth.KeyMatches(h, key, hash[1]) {
		t.Fatal("хеш во фрагменте не соответствует выпущенному ключу")
	}
	if strings.Contains(errOut.String(), key) {
		t.Fatal("ключ попал в поток ошибок")
	}
}

func TestAppKeyErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"дата":        {"app-key", "-expires", "01.01.2027"},
		"прошлое":     {"app-key", "-expires", "2020-01-01"},
		"лишнее":      {"app-key", "x"},
		"флаг":        {"app-key", "-debug"},
		"команда":     {"nope"},
		"без команды": {},
	} {
		var out, errOut strings.Builder
		if code := run(args, &out, &errOut, now); code == 0 {
			t.Errorf("%s: ожидался ненулевой код", name)
		}
		if strings.Contains(out.String(), "aisec_") {
			t.Errorf("%s: при ошибке ключ не выпускается", name)
		}
	}
	var out, errOut strings.Builder
	if code := run([]string{"app-key", "-h"}, &out, &errOut, now); code != 0 {
		t.Errorf("-h: код %d", code)
	}
}
