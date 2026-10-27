package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// tlsDir — пустой каталог 0700, как его создаёт lab-install.sh.
func tlsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runTLS(t *testing.T, now time.Time, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(append([]string{"tls"}, args...), &out, &errOut, now)
	return code, out.String(), errOut.String()
}

func TestTLSInitIssuesCertsForHosts(t *testing.T) {
	now := time.Now()
	dir := tlsDir(t)
	code, out, errOut := runTLS(t, now, "init", "-out", dir, "-hosts", " aisec-console, 192.168.10.5,Lab.Example.RU,aisec-console,")
	if code != 0 {
		t.Fatalf("код %d: %s", code, errOut)
	}
	perms := map[string]os.FileMode{
		tlsCAFile: 0o444, tlsConsoleCertFile: 0o444, tlsGatewayCertFile: 0o444,
		tlsConsoleKeyFile: 0o400, tlsGatewayKeyFile: 0o400,
	}
	for name, want := range perms {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s: права %04o, ожидались %04o", name, info.Mode().Perm(), want)
		}
	}
	caPEM := mustReadFile(t, filepath.Join(dir, tlsCAFile))
	// Оба сертификата — пара своему ключу, имя есть в SAN, цепочка строится
	// до выпущенного корня и годится для TLS-сервера (как при загрузке
	// сертификата заказчика в консоли).
	for _, pair := range [][2]string{{tlsConsoleCertFile, tlsConsoleKeyFile}, {tlsGatewayCertFile, tlsGatewayKeyFile}} {
		chain := append(mustReadFile(t, filepath.Join(dir, pair[0])), caPEM...)
		for _, host := range []string{"aisec-console", "192.168.10.5", "lab.example.ru"} {
			sc, key, err := aisecCrypto.ParseServerCert(chain, mustReadFile(t, filepath.Join(dir, pair[1])), host, now)
			if err != nil {
				t.Fatalf("%s для %s: %v", pair[0], host, err)
			}
			clear(key)
			if sc.ChainLen != 2 {
				t.Errorf("%s: цепочка из %d сертификатов", pair[0], sc.ChainLen)
			}
			if !slices.Equal(sc.DNSNames, []string{"aisec-console", "lab.example.ru"}) || !slices.Equal(sc.IPAddresses, []string{"192.168.10.5"}) {
				t.Errorf("%s: имена %v, адреса %v", pair[0], sc.DNSNames, sc.IPAddresses)
			}
			if d := sc.NotAfter.Sub(now) - tlsDefaultDays*24*time.Hour; d < -time.Minute || d > time.Minute {
				t.Errorf("%s: срок до %v", pair[0], sc.NotAfter)
			}
		}
	}
	if bytes.Equal(mustReadFile(t, filepath.Join(dir, tlsConsoleKeyFile)), mustReadFile(t, filepath.Join(dir, tlsGatewayKeyFile))) {
		t.Error("у консоли и шлюза один ключ")
	}
	for _, want := range []string{"aisec-console, 192.168.10.5, lab.example.ru", "SHA-256", tlsCAFile} {
		if !strings.Contains(out, want) {
			t.Errorf("в выводе нет %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Error("закрытый ключ в выводе")
	}
	// Ключ УЦ не сохраняется: в каталоге только пять файлов, закрытых ключей два.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(tlsFileNames) {
		t.Errorf("в каталоге %d файлов", len(entries))
	}
	if strings.Contains(string(caPEM), "PRIVATE KEY") {
		t.Error("ключ УЦ в ca.crt")
	}
}

func TestTLSInitDoesNotOverwrite(t *testing.T) {
	dir := tlsDir(t)
	existing := filepath.Join(dir, tlsGatewayKeyFile)
	if err := os.WriteFile(existing, []byte("прежний ключ"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runTLS(t, time.Now(), "init", "-out", dir, "-hosts", "aisec-console")
	if code == 0 || !strings.Contains(errOut, "не перезаписывает") {
		t.Fatalf("код %d: %s", code, errOut)
	}
	if got := string(mustReadFile(t, existing)); got != "прежний ключ" {
		t.Errorf("файл изменён: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("созданы файлы: %d", len(entries)-1)
	}
	// Повторный запуск в каталог с готовыми сертификатами тоже отказ.
	dir2 := tlsDir(t)
	if code, _, errOut := runTLS(t, time.Now(), "init", "-out", dir2, "-hosts", "a"); code != 0 {
		t.Fatalf("код %d: %s", code, errOut)
	}
	before := mustReadFile(t, filepath.Join(dir2, tlsCAFile))
	if code, _, _ := runTLS(t, time.Now(), "init", "-out", dir2, "-hosts", "a"); code == 0 {
		t.Error("повторный выпуск в тот же каталог принят")
	}
	if !bytes.Equal(before, mustReadFile(t, filepath.Join(dir2, tlsCAFile))) {
		t.Error("ca.crt перезаписан")
	}
}

func TestTLSInitRejectsBadInput(t *testing.T) {
	now := time.Now()
	dir := tlsDir(t)
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o755); err != nil { //nolint:gosec // G301: каталог, доступный остальным, — проверяемый отказ
		t.Fatal(err)
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("h%d", i)
	}
	for name, args := range map[string][]string{
		"без подкоманды":       {},
		"неизвестная":          {"issue"},
		"без -out":             {"init", "-hosts", "a"},
		"без -hosts":           {"init", "-out", dir},
		"только запятые":       {"init", "-out", dir, "-hosts", " , ,"},
		"шаблон":               {"init", "-out", dir, "-hosts", "*.example.ru"},
		"подчёркивание":        {"init", "-out", dir, "-hosts", "aisec_console"},
		"IPv6 с зоной":         {"init", "-out", dir, "-hosts", "fe80::1%eth0"},
		"срок 0":               {"init", "-out", dir, "-hosts", "a", "-days", "0"},
		"срок 826":             {"init", "-out", dir, "-hosts", "a", "-days", "826"},
		"срок с переполнением": {"init", "-out", dir, "-hosts", "a", "-days", "281474976710657"},
		"отрицательный срок":   {"init", "-out", dir, "-hosts", "a", "-days", "-1"},
		"33 имени":             {"init", "-out", dir, "-hosts", strings.Join(many, ",")},
		"каталог открыт":       {"init", "-out", open, "-hosts", "a"},
		"каталога нет":         {"init", "-out", filepath.Join(dir, "нет"), "-hosts", "a"},
		"лишний аргумент":      {"init", "-out", dir, "-hosts", "a", "лишнее"},
		"длинный список имён":  {"init", "-out", dir, "-hosts", strings.Repeat("a,", tlsMaxHostsArg)},
	} {
		if code, _, _ := runTLS(t, now, args...); code == 0 {
			t.Errorf("%s: принято", name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("после отказов в каталоге %d файлов", len(entries))
	}
}

func TestTLSInitBoundaries(t *testing.T) {
	now := time.Now()
	hosts := make([]string, 32)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.lab", i)
	}
	dir := tlsDir(t)
	if code, _, errOut := runTLS(t, now, "init", "-out", dir, "-hosts", strings.Join(hosts, ","), "-days", "825"); code != 0 {
		t.Fatalf("32 имени и 825 суток: код %d: %s", code, errOut)
	}
	chain := append(mustReadFile(t, filepath.Join(dir, tlsConsoleCertFile)), mustReadFile(t, filepath.Join(dir, tlsCAFile))...)
	sc, key, err := aisecCrypto.ParseServerCert(chain, mustReadFile(t, filepath.Join(dir, tlsConsoleKeyFile)), "h31.lab", now)
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if len(sc.DNSNames) != 32 || sc.NotAfter.Before(now.Add(824*24*time.Hour)) {
		t.Errorf("имён %d, срок до %v", len(sc.DNSNames), sc.NotAfter)
	}
	dir1 := tlsDir(t)
	if code, _, errOut := runTLS(t, now, "init", "-out", dir1, "-hosts", "10.0.0.1", "-days", "1"); code != 0 {
		t.Fatalf("1 сутки: код %d: %s", code, errOut)
	}
}

func FuzzParseTLSHosts(f *testing.F) {
	for _, s := range []string{"", "a", "aisec-console, 192.168.1.5", "*.x", " , ,", "A.B.C", "::1,fe80::1%1", strings.Repeat("a,", 100)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		hosts, err := parseTLSHosts(s)
		if err != nil {
			return
		}
		if len(hosts) == 0 {
			t.Fatal("пустой список без ошибки")
		}
		seen := map[string]bool{}
		for _, h := range hosts {
			n, err := aisecCrypto.NormalizeHost(h)
			if err != nil || n != h {
				t.Fatalf("имя %q не нормализовано: %q, %v", h, n, err)
			}
			if seen[h] {
				t.Fatalf("повтор %q", h)
			}
			seen[h] = true
		}
	})
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: путь — временный каталог теста
	if err != nil {
		t.Fatal(err)
	}
	return b
}
