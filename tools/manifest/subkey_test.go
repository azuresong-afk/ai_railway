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

const catalogSource = "../../internal/shadowai/catalog/catalog.yaml"

// subkey создаёт рабочую пару в каталоге dir.
func subkey(t *testing.T, dir, name string) (key, pub string) {
	t.Helper()
	key, pub = filepath.Join(dir, name+".signkey"), filepath.Join(dir, name+".pub")
	var out bytes.Buffer
	if err := run([]string{"gen-subkey", "-key", key, "-pub", pub}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Отпечаток:") {
		t.Fatalf("вывод gen-subkey: %s", out.String())
	}
	return key, pub
}

func endorseArgs(vendorKey, subPub, purpose, out string) []string {
	return []string{"endorse", "-key", vendorKey, "-subkey-pub", subPub, "-purpose", purpose, "-serial", "7",
		"-not-before", "2026-10-01", "-not-after", "2031-09-30", "-comment", "тест", "-out", out}
}

// ADR-0022, п. 2; ADR-0027, пп. 2–3: рабочий ключ заверяется ключом
// производителя офлайн, база подписывается рабочим ключом и проверяется
// так же, как её проверит сервер.
func TestServiceDBFlow(t *testing.T) {
	offline(t)
	vkey, vpub := vendorKey(t)
	dir := t.TempDir()
	sk, spub := subkey(t, dir, "sub")
	if err := run([]string{"gen-subkey", "-key", sk, "-pub", filepath.Join(dir, "x.pub")}, io.Discard, io.Discard); err == nil {
		t.Fatal("рабочий ключ перезаписан")
	}
	endorsement := filepath.Join(dir, "sub.endorsement")
	var out bytes.Buffer
	if err := run(endorseArgs(vkey, spub, "service_db", endorsement), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "service_db, номер 7") {
		t.Fatalf("вывод endorse: %s", out.String())
	}
	db := filepath.Join(dir, "catalog.aisecdb")
	out.Reset()
	if err := run([]string{"sign-db", "-key", sk, "-endorsement", endorsement, "-vendor-pub", vpub, "-in", catalogSource, "-out", db},
		&out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Каталог ИИ-сервисов: версия 1 от 2026-10-28, записей: 28") || !strings.Contains(out.String(), "SHA-256 файла:") {
		t.Fatalf("вывод sign-db: %s", out.String())
	}
	if info, err := os.Stat(db); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("файл базы: %v %v", info, err)
	}
	out.Reset()
	if err := run([]string{"inspect-db", "-in", db, "-vendor-pub", vpub}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "Вид: shadow_ai_catalog") || !strings.Contains(s, "Подпись и заверение проверены") {
		t.Fatalf("вывод inspect-db: %s", s)
	}
	out.Reset()
	if err := run([]string{"inspect-db", "-in", db}, &out, io.Discard); err != nil || !strings.Contains(out.String(), "не проверялась") {
		t.Fatalf("inspect-db без ключа: %v %s", err, out.String())
	}
	// Чужой ключ производителя — подпись заверения не сходится.
	_, otherPub := vendorKey(t)
	if err := run([]string{"inspect-db", "-in", db, "-vendor-pub", otherPub}, io.Discard, io.Discard); err == nil {
		t.Fatal("подпись проверена чужим ключом производителя")
	}
}

func TestServiceDBRejects(t *testing.T) {
	offline(t)
	vkey, vpub := vendorKey(t)
	dir := t.TempDir()
	sk, spub := subkey(t, dir, "sub")
	sk2, _ := subkey(t, dir, "sub2")
	good := filepath.Join(dir, "good.endorsement")
	if err := run(endorseArgs(vkey, spub, "service_db", good), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	license := filepath.Join(dir, "license.endorsement")
	if err := run(endorseArgs(vkey, spub, "license", license), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	badYAML := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badYAML, []byte("format: aisec-shadow-ai-catalog-v1\nversion: 1\nunknown: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	i := 0
	signDB := func(key, endorsement, vendorPub, in string) error {
		i++
		args := []string{"sign-db", "-key", key, "-endorsement", endorsement, "-in", in, "-out", filepath.Join(dir, "db"+strconv.Itoa(i))}
		if vendorPub != "" {
			args = append(args, "-vendor-pub", vendorPub)
		}
		return run(args, io.Discard, io.Discard)
	}
	for name, err := range map[string]error{
		"заверение для лицензий":  signDB(sk, license, vpub, catalogSource),
		"чужой рабочий ключ":      signDB(sk2, good, vpub, catalogSource),
		"ключ из репозитория":     signDB(sk, good, "../../internal/integrity/keys/manifest-test.pub", catalogSource),
		"нет ключа производителя": signDB(sk, good, "", catalogSource),
		"неверный каталог":        signDB(sk, good, vpub, badYAML),
		"заверение вместо базы":   signDB(sk, catalogSource, vpub, catalogSource),
		"неизвестный вид базы":    run([]string{"sign-db", "-kind", "x", "-key", sk, "-endorsement", good, "-in", catalogSource, "-out", filepath.Join(dir, "k")}, io.Discard, io.Discard),
		"каталог видом базы требований": run([]string{"sign-db", "-kind", "compliance_requirements", "-key", sk, "-endorsement", good, "-vendor-pub", vpub,
			"-in", catalogSource, "-out", filepath.Join(dir, "k2")}, io.Discard, io.Discard),
		"заверение длиннее 5 лет": run([]string{"endorse", "-key", vkey, "-subkey-pub", spub, "-purpose", "service_db", "-serial", "8", "-not-before", "2026-10-01", "-not-after", "2032-10-01", "-out", filepath.Join(dir, "e1")}, io.Discard, io.Discard),
		"неизвестное назначение":  run(endorseArgs(vkey, spub, "firmware", filepath.Join(dir, "e2")), io.Discard, io.Discard),
		"номер 0": run([]string{"endorse", "-key", vkey, "-subkey-pub", spub, "-purpose", "service_db", "-serial", "0", "-not-after", "2027-10-01", "-out", filepath.Join(dir, "e3")}, io.Discard, io.Discard),
		"закрытый ключ вместо откр.": run(endorseArgs(vkey, sk, "service_db", filepath.Join(dir, "e4")), io.Discard, io.Discard),
	} {
		if err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	// Работающая сеть — отказ всех команд с закрытыми ключами.
	netInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "eth0", Flags: net.FlagUp | net.FlagRunning}}, nil
	}
	for name, args := range map[string][]string{
		"gen-subkey": {"gen-subkey", "-key", filepath.Join(dir, "n.key"), "-pub", filepath.Join(dir, "n.pub")},
		"endorse":    endorseArgs(vkey, spub, "service_db", filepath.Join(dir, "n.endorsement")),
		"sign-db":    {"sign-db", "-key", sk, "-endorsement", good, "-vendor-pub", vpub, "-in", catalogSource, "-out", filepath.Join(dir, "n.aisecdb")},
	} {
		if err := run(args, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "eth0") {
			t.Errorf("%s при работающей сети: %v", name, err)
		}
	}
}

// Тестовые файлы testdata/shadowai воспроизводятся командами с -test (сеть
// не проверяется): заверение тестовым ключом производителя и подпись
// тестовым рабочим ключом.
func TestServiceDBTestKeys(t *testing.T) {
	dir := t.TempDir()
	endorsement := filepath.Join(dir, "test.endorsement")
	if err := run([]string{"endorse", "-test", "-key", "../../testdata/integrity/manifest-test.signkey",
		"-subkey-pub", "../../testdata/shadowai/subkey-test.pub", "-purpose", "service_db", "-serial", "1",
		"-not-before", "2026-10-01", "-not-after", "2031-09-30", "-out", endorsement}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "catalog.aisecdb")
	if err := run([]string{"sign-db", "-test", "-key", "../../testdata/shadowai/subkey-test.signkey",
		"-endorsement", "../../testdata/shadowai/subkey-test.endorsement", "-in", catalogSource, "-out", db}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"inspect-db", "-in", db, "-vendor-pub", "../../internal/integrity/keys/manifest-test.pub"}, &out, io.Discard); err != nil ||
		!strings.Contains(out.String(), "service_db, номер 1") {
		t.Fatalf("inspect-db: %v %s", err, out.String())
	}
}
