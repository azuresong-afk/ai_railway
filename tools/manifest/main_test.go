package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

func TestBuildWithTestKey(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "aisec-cli"), []byte("cli"), 0o600); err != nil {
		t.Fatal(err)
	}
	static := filepath.Join(dir, "dist")
	if err := os.MkdirAll(static, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, ".gitkeep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out", "aisec-manifest.json")
	args := []string{"build", "-out", out, "-version", "v1", "-created", "2026-10-21T00:00:00Z",
		"-bin", bin, "-cmds", "aisec-cli", "-static", static, "-migrations", "../../migrations"}
	var stdout, stderr strings.Builder
	if err := run(append(args, "-test-key", "../../testdata/integrity/manifest-test.signkey"), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "НЕ ДЛЯ ПОСТАВКИ") {
		t.Fatal(stderr.String())
	}
	for _, f := range []string{out, out + ".sig"} {
		if _, err := os.Stat(f); err != nil {
			t.Fatal(err)
		}
	}

	// Чужой ключ как тестовый не принимается: манифест не принял бы ни один компонент.
	other := filepath.Join(dir, "other.signkey")
	if err := run([]string{"gen-key", "-test", "-key", other, "-pub", filepath.Join(dir, "other.pub")}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(other)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("права закрытого ключа: %v %v", info, err)
	}
	if err := run(append(args, "-test-key", other), io.Discard, io.Discard); err == nil {
		t.Fatal("чужой тестовый ключ принят")
	}
	// Повторная генерация не перезаписывает ключ.
	if err := run([]string{"gen-key", "-test", "-key", other, "-pub", filepath.Join(dir, "other2.pub")}, io.Discard, io.Discard); err == nil {
		t.Fatal("ключ перезаписан")
	}
	for name, a := range map[string][]string{
		// Ключ производителя на сборочной машине не используется (ADR-0022).
		"ключ производителя в build": append(args, "-key", other),
		"тестовый и без подписи":     append(args, "-test-key", other, "-unsigned"),
		"нет ключа":                  args,
		"неверное время":             {"build", "-out", out, "-version", "v1", "-created", "вчера", "-bin", bin, "-cmds", "aisec-cli", "-static", static, "-migrations", "../../migrations", "-unsigned"},
		"нет команды":                {"verify"},
		"sign без ключа":             {"sign", "-manifest", out},
		"fingerprint без ключа":      {"fingerprint"},
	} {
		if err := run(a, io.Discard, io.Discard); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// offline подменяет список сетевых интерфейсов: только петлевой и
// выключенный Wi-Fi.
func offline(t *testing.T) {
	t.Helper()
	saved := netInterfaces
	t.Cleanup(func() { netInterfaces = saved })
	netInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "lo", Flags: net.FlagUp | net.FlagLoopback | net.FlagRunning},
			{Name: "wlan0", Flags: net.FlagUp | net.FlagBroadcast},
			{Name: "eth0"},
		}, nil
	}
}

// unsignedRelease — манифест поставки без подписи (make release-dir RELEASE=1).
func unsignedRelease(t *testing.T) (manifest, sum string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	static := filepath.Join(dir, "dist")
	for _, d := range []string{bin, static} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "aisec-cli"), []byte("cli"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, "index.html"), []byte("<!doctype html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest = filepath.Join(dir, "release", "aisec-manifest.json")
	// Подпись прежней сборки удаляется вместе с новым манифестом.
	if err := os.MkdirAll(filepath.Dir(manifest), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest+".sig", []byte("старая\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout strings.Builder
	if err := run([]string{"build", "-unsigned", "-out", manifest, "-version", "1.2.3", "-created", "2026-10-27T00:00:00Z",
		"-bin", bin, "-cmds", "aisec-cli", "-static", static, "-migrations", "../../migrations"}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manifest + ".sig"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("подпись прежней сборки осталась: %v", err)
	}
	_, after, ok := strings.Cut(stdout.String(), "SHA-256 манифеста: ")
	if !ok || len(after) < 64 {
		t.Fatal(stdout.String())
	}
	return manifest, after[:64]
}

func vendorKey(t *testing.T) (key, pub string) {
	t.Helper()
	dir := t.TempDir()
	key, pub = filepath.Join(dir, "vendor.signkey"), filepath.Join(dir, "vendor.pub")
	if err := run([]string{"gen-key", "-key", key, "-pub", pub}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	return key, pub
}

// ADR-0022: манифест поставки подписывается отдельным шагом на машине без
// сети; подпись проверяется открытым ключом производителя.
func TestSignOffline(t *testing.T) {
	offline(t)
	manifest, sum := unsignedRelease(t)
	key, pub := vendorKey(t)
	var stdout, stderr strings.Builder
	if err := run([]string{"sign", "-key", key, "-manifest", manifest, "-expect-sha256", strings.ToUpper(sum)}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var fp strings.Builder
	if err := run([]string{"fingerprint", "-pub", pub}, &fp, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"версия 1.2.3", "SHA-256 манифеста: " + sum, "Отпечаток ключа производителя: " + strings.TrimSpace(fp.String())} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("нет %q в %q", want, stdout.String())
		}
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := os.ReadFile(pub) //nolint:gosec // G304: путь — от t.TempDir() или testdata, внешнего ввода в тесте нет
	if err != nil {
		t.Fatal(err)
	}
	v, err := aisecCrypto.ParseVerifierPEM(p, pub, pubPEM, aisecCrypto.KeyKindManifestSigningPublic)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(manifest) //nolint:gosec // G304: путь — от t.TempDir() или testdata, внешнего ввода в тесте нет
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(manifest + ".sig") //nolint:gosec // G304: путь — от t.TempDir() или testdata, внешнего ввода в тесте нет
	if err != nil {
		t.Fatal(err)
	}
	if err := integrity.VerifySignature(v, data, sig); err != nil {
		t.Fatal(err)
	}
	// Готовая подпись не перезаписывается.
	if err := run([]string{"sign", "-key", key, "-manifest", manifest}, io.Discard, io.Discard); err == nil {
		t.Fatal("подпись перезаписана")
	}
	// Без -expect-sha256 подпись есть, но с напоминанием сверить хеш.
	manifest2, _ := unsignedRelease(t)
	stderr.Reset()
	if err := run([]string{"sign", "-key", key, "-manifest", manifest2}, io.Discard, &stderr); err != nil || !strings.Contains(stderr.String(), "хеш не сверен") {
		t.Fatalf("%v %q", err, stderr.String())
	}
}

// ADR-0022: отказы подписи — сеть, подмена манифеста, ключи из
// репозитория, ключ с открытыми правами, испорченный манифест.
func TestSignRejects(t *testing.T) {
	offline(t)
	key, _ := vendorKey(t)
	repoKey := func(name string) string {
		data, err := os.ReadFile("../../testdata/integrity/" + name) //nolint:gosec // G304: путь — от t.TempDir() или testdata, внешнего ввода в тесте нет
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, data, 0o400); err != nil { //nolint:gosec // G703: путь — от t.TempDir() или testdata, внешнего ввода в тесте нет
			t.Fatal(err)
		}
		return path
	}
	openKey := filepath.Join(t.TempDir(), "open.signkey")
	data, err := os.ReadFile(key) //nolint:gosec // G304: путь — от t.TempDir() или testdata, внешнего ввода в тесте нет
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openKey, data, 0o644); err != nil { //nolint:gosec // G306: проверяется отказ на ключ с открытыми правами
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		key    string
		prep   func(t *testing.T, manifest string)
		expect bool
		want   string
	}{
		"манифест изменён после сборки": {key: key, expect: true, want: "не совпадает", prep: func(t *testing.T, m string) {
			data, err := os.ReadFile(m) //nolint:gosec // G304: путь — от t.TempDir() или testdata, внешнего ввода в тесте нет
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(m, []byte(strings.Replace(string(data), "1.2.3", "1.2.4", 1)), 0o600); err != nil { //nolint:gosec // G703: путь — от t.TempDir() или testdata, внешнего ввода в тесте нет
				t.Fatal(err)
			}
		}},
		"испорченный манифест": {key: key, prep: func(t *testing.T, m string) {
			if err := os.WriteFile(m, []byte(`{"format":"x"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		"манифест — ссылка": {key: key, prep: func(t *testing.T, m string) {
			target := m + ".real"
			if err := os.Rename(m, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, m); err != nil {
				t.Fatal(err)
			}
		}},
		"тестовый ключ репозитория":    {key: repoKey("manifest-test.signkey"), want: "ключ из репозитория"},
		"имитация ключа производителя": {key: repoKey("manifest-release-ci.signkey"), want: "ключ из репозитория"},
		"ключ с открытыми правами":     {key: openKey},
	} {
		t.Run(name, func(t *testing.T) {
			manifest, sum := unsignedRelease(t)
			if tc.prep != nil {
				tc.prep(t, manifest)
			}
			args := []string{"sign", "-key", tc.key, "-manifest", manifest}
			if tc.expect {
				args = append(args, "-expect-sha256", sum)
			}
			err := run(args, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ошибка %v, ожидается %q", err, tc.want)
			}
			if _, err := os.Lstat(manifest + ".sig"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("подпись создана: %v", err)
			}
		})
	}
	// Работающий сетевой интерфейс — отказ подписи и создания ключа.
	netInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "eth0", Flags: net.FlagUp | net.FlagRunning}}, nil
	}
	manifest, _ := unsignedRelease(t)
	if err := run([]string{"sign", "-key", key, "-manifest", manifest}, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "eth0") {
		t.Fatalf("подпись при работающей сети: %v", err)
	}
	dir := t.TempDir()
	if err := run([]string{"gen-key", "-key", filepath.Join(dir, "k"), "-pub", filepath.Join(dir, "p")}, io.Discard, io.Discard); err == nil {
		t.Fatal("ключ производителя создан при работающей сети")
	}
}

// Отпечаток ключа из репозитория печатается с предупреждением.
func TestFingerprintRepositoryKey(t *testing.T) {
	var stdout, stderr strings.Builder
	if err := run([]string{"fingerprint", "-pub", "../../internal/integrity/keys/manifest-test.pub"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "НЕ ДЛЯ ПОСТАВКИ") || len(strings.TrimSpace(stdout.String())) != 79 {
		t.Fatalf("%q %q", stdout.String(), stderr.String())
	}
	if err := run([]string{"fingerprint", "-pub", "../../testdata/integrity/manifest-test.signkey"}, io.Discard, io.Discard); err == nil {
		t.Fatal("закрытый ключ принят как открытый")
	}
}
