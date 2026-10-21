package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// verifyInstall — установка во временном каталоге с манифестом, подписанным
// тестовым ключом репозитория (его принимает сборка без aisec_release).
func verifyInstall(t *testing.T) (root string) {
	t.Helper()
	root = t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"aisec-cli": "синтетический aisec-cli", "aisec-server": "синтетический aisec-server"} {
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
	m, err := integrity.Build(p, integrity.BuildInput{Version: "test", Created: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), Sources: []integrity.Source{
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
	prev := executable
	executable = func() (string, error) { return filepath.Join(root, "bin", "aisec-cli"), nil }
	t.Cleanup(func() { executable = prev })
	t.Setenv("AISEC_DATABASE_URL", "")
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
	if code := run([]string{"verify", "лишний"}, &out, &errOut, now); code != 1 {
		t.Fatalf("код %d", code)
	}
}
