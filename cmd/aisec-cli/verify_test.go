package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// verifyInstall — установка во временном каталоге с манифестом, подписанным
// тестовым ключом репозитория (его принимает сборка без aisec_release).
func verifyInstall(t *testing.T) (root string) {
	t.Helper()
	return verifyInstallAt(t, time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), "test")
}

// verifyInstallAt — то же с заданными временем сборки и версией манифеста.
func verifyInstallAt(t *testing.T, created time.Time, version string) (root string) {
	t.Helper()
	root = signedRelease(t, created, version, "синтетический aisec-cli")
	prev := executable
	executable = func() (string, error) { return filepath.Join(root, "bin", "aisec-cli"), nil }
	t.Cleanup(func() { executable = prev })
	t.Setenv("AISEC_DATABASE_URL", "")
	return root
}

// signedRelease — каталог выпуска с подписанным тестовым ключом манифестом;
// cli — содержимое bin/aisec-cli (в настоящих выпусках в него вшита версия).
func signedRelease(t *testing.T, created time.Time, version, cli string) (root string) {
	t.Helper()
	root = t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"aisec-cli": cli, "aisec-server": "синтетический aisec-server"} {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	static := filepath.Join(t.TempDir(), "dist")
	if err := os.MkdirAll(static, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, "index.html"), []byte("<!doctype html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	m, err := integrity.Build(p, integrity.BuildInput{Version: version, Created: created, Sources: []integrity.Source{
		{Kind: integrity.KindBinary, Dir: filepath.Join(root, "bin"), Files: []string{"aisec-cli", "aisec-server"}},
		{Kind: integrity.KindStatic, Dir: static, Recursive: true},
		{Kind: integrity.KindMigration, Dir: "../../migrations", Glob: "*.sql"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := integrity.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile("../../testdata/integrity/manifest-test.signkey")
	if err != nil {
		t.Fatal(err)
	}
	_, seed, err := aisecCrypto.DecodeKeyPEM(keyPEM, aisecCrypto.KeyKindManifestSigning)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := integrity.Sign(s, data)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{integrity.ManifestFile: data, integrity.SignatureFile: sig} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestVerifyOK(t *testing.T) {
	verifyInstall(t)
	var out, errOut strings.Builder
	// Манифест по умолчанию — над каталогом bin/ с aisec-cli.
	if code := run([]string{"verify"}, &out, &errOut, now); code != 0 {
		t.Fatalf("код %d: %s %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Целостность не нарушена") || !strings.Contains(out.String(), "тестовым ключом") {
		t.Fatal(out.String())
	}
}

// Нарушение целостности — код 3 и список файлов (DM-42).
func TestVerifyViolation(t *testing.T) {
	root := verifyInstall(t)
	if err := os.WriteFile(filepath.Join(root, "bin", "aisec-server"), []byte("подменённый aisec-server!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	code := run([]string{"verify", "-manifest", filepath.Join(root, integrity.ManifestFile)}, &out, &errOut, now)
	if code != 3 || !strings.Contains(out.String(), "bin/aisec-server — размер не совпадает") {
		t.Fatalf("код %d: %s %s", code, out.String(), errOut.String())
	}
}

func TestVerifyBadSignature(t *testing.T) {
	root := verifyInstall(t)
	if err := os.WriteFile(filepath.Join(root, integrity.SignatureFile), []byte("AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run([]string{"verify"}, &out, &errOut, now); code != 3 || !strings.Contains(out.String(), "подпись манифеста неверна") {
		t.Fatalf("код %d: %s", code, out.String())
	}
}

func TestVerifyArgs(t *testing.T) {
	verifyInstall(t)
	var out, errOut strings.Builder
	for _, args := range [][]string{
		{"verify", "лишний"},
		{"verify", "-accept-rollback"},                  // без БД откат не принять
		{"verify", "-gateway", "gw-1"},                  // -gateway только с -accept-rollback
		{"verify", "-accept-rollback", "-gateway", "Ш"}, // без БД и с неверным именем
	} {
		if code := run(args, &out, &errOut, now); code != 1 {
			t.Fatalf("%v: код %d", args, code)
		}
	}
}

// ОБН.1, A2-В1: установленный aisec-cli проверяет выпуск другой версии.
// -manifest сверяет с новым манифестом и сам aisec-cli и потому отвергает
// любое обновление; -release проверяет подпись и файлы каталога, но не себя.
func TestVerifyReleaseOtherVersion(t *testing.T) {
	verifyInstall(t)
	next := signedRelease(t, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), "2", "синтетический aisec-cli версии 2")
	var out, errOut strings.Builder
	if code := run([]string{"verify", "-manifest", filepath.Join(next, integrity.ManifestFile)}, &out, &errOut, now); code != 3 || !strings.Contains(out.String(), "bin/aisec-cli") {
		t.Fatalf("-manifest: ожидалось нарушение bin/aisec-cli, код %d: %s", code, out.String())
	}
	// Режим выпуска не обращается к БД, даже если она задана.
	t.Setenv("AISEC_DATABASE_URL", "postgres://нет-такого-хоста.invalid/aisec")
	out.Reset()
	if code := run([]string{"verify", "-release", next}, &out, &errOut, now); code != 0 || !strings.Contains(out.String(), "Выпуск 2 проверен") {
		t.Fatalf("-release: код %d: %s %s", code, out.String(), errOut.String())
	}
}

func TestVerifyReleaseRejects(t *testing.T) {
	for name, edit := range map[string]func(t *testing.T, dir string){
		"подменён бинарник": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "bin", "aisec-server"), []byte("подменённый aisec-server!!"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"подменён aisec-cli": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "bin", "aisec-cli"), []byte("подменённый aisec-cli версии 2"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"нет файла": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "bin", "aisec-server")); err != nil {
				t.Fatal(err)
			}
		},
		"ссылка вместо файла": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "bin", "aisec-server")
			if err := os.Rename(p, p+".orig"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("aisec-server.orig", p); err != nil {
				t.Fatal(err)
			}
		},
		"неверная подпись": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, integrity.SignatureFile), []byte("AAAA\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"нет манифеста": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, integrity.ManifestFile)); err != nil {
				t.Fatal(err)
			}
		},
		// A2-В6: манифест и подпись по ссылке (например, на подписанный
		// манифест установки) не читаются.
		"манифест — ссылка": func(t *testing.T, dir string) { linkTo(t, dir, integrity.ManifestFile) },
		"подпись — ссылка":  func(t *testing.T, dir string) { linkTo(t, dir, integrity.SignatureFile) },
	} {
		t.Run(name, func(t *testing.T) {
			verifyInstall(t)
			next := signedRelease(t, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), "2", "синтетический aisec-cli версии 2")
			edit(t, next)
			var out, errOut strings.Builder
			if code := run([]string{"verify", "-release", next}, &out, &errOut, now); code != 3 || !strings.Contains(out.String(), "Выпуск не прошёл проверку") {
				t.Fatalf("код %d: %s %s", code, out.String(), errOut.String())
			}
		})
	}
}

// linkTo заменяет файл каталога ссылкой на его копию рядом.
func linkTo(t *testing.T, dir, name string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.Rename(p, p+".orig"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(name+".orig", p); err != nil {
		t.Fatal(err)
	}
}

// A2-В7: выпуск, собранный раньше установленного, — откат: отвергается, с
// -allow-older принимается.
func TestVerifyReleaseOlder(t *testing.T) {
	verifyInstall(t)
	old := signedRelease(t, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), "0.9", "синтетический aisec-cli версии 0.9")
	var out, errOut strings.Builder
	if code := run([]string{"verify", "-release", old}, &out, &errOut, now); code != 3 || !strings.Contains(out.String(), "откат") {
		t.Fatalf("старый выпуск: код %d: %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"verify", "-release", old, "-allow-older"}, &out, &errOut, now); code != 0 || !strings.Contains(out.String(), "Выпуск 0.9 проверен") {
		t.Fatalf("-allow-older: код %d: %s %s", code, out.String(), errOut.String())
	}
}

// Без подписанного манифеста установки откат не определить: ошибка, не «проверен».
func TestVerifyReleaseNoInstalledManifest(t *testing.T) {
	root := verifyInstall(t)
	if err := os.Remove(filepath.Join(root, integrity.ManifestFile)); err != nil {
		t.Fatal(err)
	}
	next := signedRelease(t, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), "2", "синтетический aisec-cli версии 2")
	var out, errOut strings.Builder
	if code := run([]string{"verify", "-release", next}, &out, &errOut, now); code != 1 || !strings.Contains(errOut.String(), "-allow-older") {
		t.Fatalf("код %d: %s %s", code, out.String(), errOut.String())
	}
}

func TestVerifyReleaseArgs(t *testing.T) {
	root := verifyInstall(t)
	var out, errOut strings.Builder
	for _, args := range [][]string{
		{"verify", "-release", root, "-manifest", filepath.Join(root, integrity.ManifestFile)},
		{"verify", "-release", root, "-accept-rollback"},
		{"verify", "-release", root, "-gateway", "gw-1"},
		{"verify", "-allow-older"}, // только с -release
	} {
		if code := run(args, &out, &errOut, now); code != 1 {
			t.Fatalf("%v: код %d", args, code)
		}
	}
}

// DM-42, В20 ревью 2.r4 (на живой БД, поэтому без префикса TestDM42_):
// выпуск старше уже проверенного — код 3 и «откат»; -accept-rollback
// принимает его, дальше проверка проходит; принять нечего — ошибка.
func TestVerifyRollbackOnRealDB(t *testing.T) {
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	const schema = "cli_verify_rollback_test"
	reset := func(create bool) {
		t.Helper()
		if _, err := admin.Pool().Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			t.Fatal(err)
		}
		if create {
			if _, err := admin.Pool().Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
				t.Fatal(err)
			}
		}
	}
	reset(true)
	defer reset(false)
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	sdsn := dsn + sep + "search_path=" + schema
	var out, errOut strings.Builder
	if err := migrate(nil, sdsn, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	verify := func(args ...string) (int, string) {
		t.Helper()
		out.Reset()
		errOut.Reset()
		t.Setenv("AISEC_DATABASE_URL", sdsn)
		code := run(append([]string{"verify"}, args...), &out, &errOut, now)
		return code, out.String() + errOut.String()
	}
	verifyInstallAt(t, time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), "1.1.0")
	if code, msg := verify(); code != 0 {
		t.Fatalf("выпуск 1.1.0: код %d: %s", code, msg)
	}
	if code, msg := verify("-accept-rollback"); code != 1 || !strings.Contains(msg, "откат не обнаружен") {
		t.Fatalf("принят откат без отката: код %d: %s", code, msg)
	}
	verifyInstallAt(t, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), "1.0.0")
	if code, msg := verify(); code != 3 || !strings.Contains(msg, "откат") {
		t.Fatalf("откат не обнаружен: код %d: %s", code, msg)
	}
	if code, msg := verify("-accept-rollback"); code != 0 || !strings.Contains(msg, "Откат на выпуск 1.0.0 принят") {
		t.Fatalf("откат не принят: код %d: %s", code, msg)
	}
	if code, msg := verify(); code != 0 {
		t.Fatalf("после принятия: код %d: %s", code, msg)
	}
	// Откат шлюза: шлюза нет — ошибка.
	if code, _ := verify("-accept-rollback", "-gateway", "gw-1"); code != 1 {
		t.Fatalf("неизвестный шлюз: код %d", code)
	}
	var n int
	if err := admin.Pool().QueryRow(ctx, "SELECT count(*) FROM "+schema+".audit_log WHERE action = 'integrity.rollback_accepted'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
}
