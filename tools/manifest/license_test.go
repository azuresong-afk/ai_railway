package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const licenseSource = "../../testdata/license/license-test.json"

// ADR-0026, п. 9: лицензия подписывается рабочим ключом с назначением
// license офлайн и проверяется так же, как её проверит сервер.
func TestLicenseFlow(t *testing.T) {
	offline(t)
	vkey, vpub := vendorKey(t)
	dir := t.TempDir()
	sk, spub := subkey(t, dir, "lic")
	endorsement := filepath.Join(dir, "lic.endorsement")
	if err := run(endorseArgs(vkey, spub, "license", endorsement), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "license.aiseclic")
	var out bytes.Buffer
	if err := run([]string{"sign-license", "-key", sk, "-endorsement", endorsement, "-vendor-pub", vpub, "-in", licenseSource, "-out", file},
		&out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "Лицензия № 1 (commercial)") || !strings.Contains(s, "ИНН 0012345673") ||
		!strings.Contains(s, "Шлюзов: 10, приложений: 50") || !strings.Contains(s, "Хеш файла:") {
		t.Fatalf("вывод sign-license: %s", s)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("файл лицензии: %v %v", info, err)
	}
	if err := run([]string{"sign-license", "-key", sk, "-endorsement", endorsement, "-vendor-pub", vpub, "-in", licenseSource, "-out", file},
		io.Discard, io.Discard); err == nil {
		t.Fatal("файл лицензии перезаписан")
	}
	out.Reset()
	if err := run([]string{"inspect-license", "-in", file, "-vendor-pub", vpub}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "Заверение: license, номер 7") || !strings.Contains(s, "Подпись и заверение проверены") {
		t.Fatalf("вывод inspect-license: %s", s)
	}
	out.Reset()
	if err := run([]string{"inspect-license", "-in", file}, &out, io.Discard); err != nil || !strings.Contains(out.String(), "не проверялась") {
		t.Fatalf("inspect-license без ключа: %v %s", err, out.String())
	}
	_, otherPub := vendorKey(t)
	if err := run([]string{"inspect-license", "-in", file, "-vendor-pub", otherPub}, io.Discard, io.Discard); err == nil {
		t.Fatal("подпись проверена чужим ключом производителя")
	}
}

func TestLicenseSignRejects(t *testing.T) {
	offline(t)
	vkey, vpub := vendorKey(t)
	dir := t.TempDir()
	sk, spub := subkey(t, dir, "lic")
	sk2, _ := subkey(t, dir, "lic2")
	good := filepath.Join(dir, "good.endorsement")
	if err := run(endorseArgs(vkey, spub, "license", good), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "db.endorsement")
	if err := run(endorseArgs(vkey, spub, "service_db", db), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(licenseSource)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, from, to string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(strings.Replace(string(src), from, to, 1)), 0o600); err != nil { //nolint:gosec // G703: файл во временном каталоге теста
			t.Fatal(err)
		}
		return p
	}
	// Заверение действует с 01.10.2026: выданная раньше лицензия не подписывается.
	early := write("early.json", `"issued_at":"2026-10-28T00:00:00Z"`, `"issued_at":"2026-09-01T00:00:00Z"`)
	badINN := write("inn.json", `"inn":"0012345673"`, `"inn":"0012345674"`)
	unknown := write("unknown.json", `"type":"commercial"`, `"type":"commercial","extra":1`)
	i := 0
	sign := func(key, endorsement, vendorPub, in string) error {
		i++
		args := []string{"sign-license", "-key", key, "-endorsement", endorsement, "-in", in, "-out", filepath.Join(dir, "l"+strconv.Itoa(i))}
		if vendorPub != "" {
			args = append(args, "-vendor-pub", vendorPub)
		}
		return run(args, io.Discard, io.Discard)
	}
	for name, err := range map[string]error{
		"заверение служебных баз": sign(sk, db, vpub, licenseSource),
		"чужой рабочий ключ":      sign(sk2, good, vpub, licenseSource),
		"ключ из репозитория":     sign(sk, good, "../../internal/integrity/keys/manifest-test.pub", licenseSource),
		"нет ключа производителя": sign(sk, good, "", licenseSource),
		"выдана до заверения":     sign(sk, good, vpub, early),
		"неверный ИНН":            sign(sk, good, vpub, badINN),
		"неизвестное поле":        sign(sk, good, vpub, unknown),
		"не лицензия":             sign(sk, good, vpub, catalogSource),
		"inspect не лицензии":     run([]string{"inspect-license", "-in", good}, io.Discard, io.Discard),
	} {
		if err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	netInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "eth0", Flags: net.FlagUp | net.FlagRunning}}, nil
	}
	if err := sign(sk, good, vpub, licenseSource); err == nil || !strings.Contains(err.Error(), "eth0") {
		t.Errorf("sign-license при работающей сети: %v", err)
	}
}

// Тестовая лицензия testdata/license воспроизводится командой с -test байт в
// байт: Ed25519 детерминирован, содержимое подписывается как есть.
func TestLicenseTestFiles(t *testing.T) {
	file := filepath.Join(t.TempDir(), "license.aiseclic")
	if err := run([]string{"sign-license", "-test", "-key", "../../testdata/license/subkey-test.signkey",
		"-endorsement", "../../testdata/license/subkey-test.endorsement", "-in", licenseSource, "-out", file}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file) //nolint:gosec // G304: файл теста во временном каталоге
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../testdata/license/license-test.aiseclic")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/license/license-test.aiseclic не совпадает с подписью license-test.json: пересоздайте его (testdata/license/README.md)")
	}
}
