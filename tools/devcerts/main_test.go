package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func TestRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := run(dir, []string{"localhost", "127.0.0.1"}, time.Hour, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	perms := map[string]os.FileMode{CAFile: publicPerm, CertFile: publicPerm, KeyFile: secretPerm, AppKeyFile: secretPerm, ConfigFile: publicPerm}
	for f, want := range perms {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s: права %o, ожидалось %o", f, info.Mode().Perm(), want)
		}
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != dirPerm {
		t.Errorf("каталог: права %o", info.Mode().Perm())
	}
	// Выпущенная пара работает с профилем standard.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	read := func(name string) []byte {
		t.Helper()
		b, err := root.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cert, key, ca := read(CertFile), read(KeyFile), read(CAFile)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tp.ServerConfig(cert, key); err != nil {
		t.Fatal(err)
	}
	if _, err := tp.ClientConfig(ca); err != nil {
		t.Fatal(err)
	}
	// Без -force файлы не перезаписываются.
	if err := run(dir, []string{"localhost"}, time.Hour, false, time.Now()); err == nil {
		t.Fatal("ожидалась ошибка без -force")
	}
	if err := run(dir, []string{"localhost"}, time.Hour, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Временных файлов не осталось.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Конфигурация принимается шлюзом и содержит хеш выпущенного ключа.
	gw, err := config.LoadGatewayFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	appKey := strings.TrimSpace(string(read(AppKeyFile)))
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if k := gw.Applications[0].Keys[0]; !auth.KeyMatches(h, appKey, k.SHA256) || k.Expires == "" {
		t.Fatalf("ключ приложения не соответствует конфигурации: %+v", k)
	}
	if len(entries) != 5 {
		t.Fatalf("в каталоге лишние файлы: %v", entries)
	}
}

func TestRunErrors(t *testing.T) {
	if err := run(t.TempDir(), nil, time.Hour, false, time.Now()); err == nil {
		t.Error("принят пустой список имён")
	}
	if err := run(t.TempDir(), []string{"a"}, 0, false, time.Now()); err == nil {
		t.Error("принят нулевой срок")
	}
}

func TestSplitHosts(t *testing.T) {
	got := splitHosts(" a, ,b ,")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("splitHosts: %q", got)
	}
}
