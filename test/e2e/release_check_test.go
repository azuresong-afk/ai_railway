//go:build e2e

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Ревью 4.r1, 4В11: make images RELEASE=1 собирает поставочные образы только
// из каталога, подписанного ключом производителя (make release-signed-check).
// Вместо aisec-cli выпуска — заглушка, печатающая заданный вывод проверки:
// тестовый ключ, чужой отпечаток и другая версия манифеста — отказ.
func TestE2EReleaseSignedCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pub := filepath.Join("internal", "integrity", "keys", "manifest-test.pub")
	root := filepath.Join("..", "..")
	fc := exec.CommandContext(ctx, "go", "run", "./tools/manifest", "fingerprint", "-pub", pub) //nolint:gosec // G204: инструмент репозитория
	fc.Dir = root
	fpOut, err := fc.Output()
	if err != nil {
		t.Fatalf("отпечаток: %v", err)
	}
	fp := strings.TrimSpace(string(fpOut))
	if fp == "" {
		t.Fatal("пустой отпечаток")
	}
	ok := "Выпуск 1.2.3 проверен ключом установленной версии 1.2.3: подпись верна, файлов: 3.\nОтпечаток ключа производителя: " + fp + "\n"
	cases := []struct {
		name, out, version, want string
	}{
		{"тестовый ключ", "ВНИМАНИЕ: сборка с тестовым ключом манифеста — не для поставки.\n" + ok, "1.2.3", "тестовым ключом"},
		{"чужой отпечаток", strings.Replace(ok, fp, "0000:1111", 1), "1.2.3", "проверяют подпись ключом 0000:1111"},
		{"нет отпечатка", "Выпуск 1.2.3 проверен\n", "1.2.3", "проверяют подпись ключом"},
		{"другая версия", ok, "1.2.4", "версия манифеста 1.2.3"},
		{"подписан ключом производителя", ok, "1.2.3", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			rel := filepath.Join(dir, "release")
			if err := os.MkdirAll(filepath.Join(rel, "bin"), 0o700); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(rel, "aisec-manifest.json"), []byte("{\n  \"version\": \"1.2.3\",\n  \"files\": []\n}\n"))
			mustWrite(t, filepath.Join(dir, "out"), []byte(c.out))
			s2Copy(t, writeTemp(t, "#!/bin/sh\ncat '"+filepath.Join(dir, "out")+"'\n"), filepath.Join(rel, "bin", "aisec-cli"), 0o755)
			cmd := exec.CommandContext(ctx, "make", "--no-print-directory", "-C", root, "release-signed-check", //nolint:gosec // G204: цель Makefile репозитория
				"RELEASE_DIR="+rel, "BUILD="+filepath.Join(dir, "build"), "VERSION="+c.version, "VENDOR_PUB="+pub)
			out, err := cmd.CombinedOutput()
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("подписанный каталог отвергнут: %v\n%s", err, out)
			case c.want != "" && (err == nil || !strings.Contains(string(out), c.want)):
				t.Fatalf("ожидался отказ «%s»: %v\n%s", c.want, err, out)
			}
		})
	}
}
