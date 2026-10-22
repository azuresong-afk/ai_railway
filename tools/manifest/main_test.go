package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if err := run([]string{"gen-key", "-key", other, "-pub", filepath.Join(dir, "other.pub")}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(other)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("права закрытого ключа: %v %v", info, err)
	}
	if err := run(append(args, "-test-key", other), io.Discard, io.Discard); err == nil {
		t.Fatal("чужой тестовый ключ принят")
	}
	// Ключ производителя (-key) с правами 0400 подходит.
	if err := run(append(args, "-key", other), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	// Тестовый ключ репозитория как ключ производителя — отказ (Н35 ревью 2.r4).
	testSign, err := os.ReadFile("../../testdata/integrity/manifest-test.signkey")
	if err != nil {
		t.Fatal(err)
	}
	asVendor := filepath.Join(dir, "vendor.signkey")
	if err := os.WriteFile(asVendor, testSign, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := run(append(args, "-key", asVendor), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "тестовый ключ") {
		t.Fatalf("тестовый ключ через -key: %v", err)
	}
	// Повторная генерация не перезаписывает ключ.
	if err := run([]string{"gen-key", "-key", other, "-pub", filepath.Join(dir, "other2.pub")}, io.Discard, io.Discard); err == nil {
		t.Fatal("ключ перезаписан")
	}
	for name, a := range map[string][]string{
		"оба ключа":      append(args, "-key", other, "-test-key", other),
		"нет ключа":      args,
		"неверное время": {"build", "-out", out, "-version", "v1", "-created", "вчера", "-bin", bin, "-cmds", "aisec-cli", "-static", static, "-migrations", "../../migrations", "-key", other},
		"нет команды":    {"sign"},
	} {
		if err := run(a, io.Discard, io.Discard); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}
