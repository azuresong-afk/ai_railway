package main

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

// Имена в синтетических сертификатах: имя консоли внутри установки, имя и
// адрес ВМ.
var tlsCheckHosts = []string{"aisec-console", "lab.example.ru", "192.168.10.5"}

func newTLSChain(t *testing.T, o cryptotest.ChainOptions) cryptotest.Chain {
	t.Helper()
	if o.Hosts == nil {
		o.Hosts = tlsCheckHosts
	}
	c, err := cryptotest.NewChain(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tlsCheckFiles — пять файлов каталога: у консоли и шлюза одна пара (две
// пары с общим корнем cryptotest не выпускает, а проверка у них одна).
func tlsCheckFiles(c cryptotest.Chain) map[string][]byte {
	cert := cat(c.Leaf, c.Intermediate)
	return map[string][]byte{
		tlsConsoleCertFile: cert, tlsConsoleKeyFile: c.Key,
		tlsGatewayCertFile: cert, tlsGatewayKeyFile: c.Key,
		tlsCAFile: c.Root,
	}
}

func writeTLSCheckDir(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := tlsDir(t)
	for name, data := range files {
		if data == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func checkArgs(dir string) []string {
	return []string{"check", "-dir", dir, "-hosts", "lab.example.ru, 192.168.10.5", "-console-name", "aisec-console"}
}

func TestTLSCheckAccepts(t *testing.T) {
	now := time.Now()
	ecdsa := newTLSChain(t, cryptotest.ChainOptions{})
	rsa := newTLSChain(t, cryptotest.ChainOptions{LeafRSABits: 2048})
	full := tlsCheckFiles(ecdsa)
	// «Полная цепочка» с корнем в файле сертификата тоже годится.
	full[tlsConsoleCertFile] = ecdsa.Full()
	for name, tc := range map[string]struct {
		files map[string][]byte
		want  []string
	}{
		"ECDSA с промежуточным":  {tlsCheckFiles(ecdsa), []string{"ECDSA P-256", "цепочка из 3"}},
		"RSA с промежуточным":    {tlsCheckFiles(rsa), []string{"RSA 2048", "цепочка из 3"}},
		"корень и в файле серт.": {full, []string{"цепочка из 3"}},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := runTLS(t, now, checkArgs(writeTLSCheckDir(t, tc.files))...)
			if code != 0 {
				t.Fatalf("код %d: %s\n%s", code, errOut, out)
			}
			if n := strings.Count(out, "[в порядке]"); n != 3 {
				t.Errorf("пунктов «в порядке» — %d:\n%s", n, out)
			}
			for _, w := range append(tc.want, "aisec-console, lab.example.ru, 192.168.10.5", "ошибок нет, предупреждений — 0") {
				if !strings.Contains(out, w) {
					t.Errorf("в выводе нет %q:\n%s", w, out)
				}
			}
			if strings.Contains(out+errOut, "PRIVATE KEY") {
				t.Error("ключевой материал в выводе")
			}
		})
	}
}

// Сертификаты tls init проходят tls check с теми же именами: lab-install.sh
// проверяет ими и повторный запуск.
func TestTLSCheckAcceptsTLSInit(t *testing.T) {
	now := time.Now()
	dir := tlsDir(t)
	if code, _, errOut := runTLS(t, now, "init", "-out", dir, "-hosts", "aisec-console,lab.example.ru,192.168.10.5"); code != 0 {
		t.Fatalf("init: код %d: %s", code, errOut)
	}
	code, out, errOut := runTLS(t, now, checkArgs(dir)...)
	if code != 0 {
		t.Fatalf("код %d: %s\n%s", code, errOut, out)
	}
	if !strings.Contains(out, "цепочка из 2") {
		t.Errorf("вывод:\n%s", out)
	}
	// Чужой адрес в -hosts — ошибка.
	code, out, _ = runTLS(t, now, "check", "-dir", dir, "-hosts", "10.0.0.1")
	if code == 0 || !strings.Contains(out, "не на имя 10.0.0.1") {
		t.Errorf("код %d:\n%s", code, out)
	}
}

func TestTLSCheckWarnsNearExpiry(t *testing.T) {
	now := time.Now()
	soon := newTLSChain(t, cryptotest.ChainOptions{NotAfter: now.Add(10 * 24 * time.Hour)})
	code, out, errOut := runTLS(t, now, checkArgs(writeTLSCheckDir(t, tlsCheckFiles(soon)))...)
	if code != 0 {
		t.Fatalf("код %d: %s\n%s", code, errOut, out)
	}
	if n := strings.Count(out, "[внимание]"); n != 2 || !strings.Contains(out, "меньше 30 суток") {
		t.Errorf("предупреждений %d:\n%s", n, out)
	}
	// Граница: 31 сутки — без предупреждения.
	later := newTLSChain(t, cryptotest.ChainOptions{NotAfter: now.Add(31 * 24 * time.Hour)})
	if code, out, _ := runTLS(t, now, checkArgs(writeTLSCheckDir(t, tlsCheckFiles(later)))...); code != 0 || strings.Contains(out, "[внимание]") {
		t.Errorf("31 сутки: код %d:\n%s", code, out)
	}
}

func TestTLSCheckRejects(t *testing.T) {
	now := time.Now()
	good := newTLSChain(t, cryptotest.ChainOptions{})
	other := newTLSChain(t, cryptotest.ChainOptions{})
	expired := newTLSChain(t, cryptotest.ChainOptions{NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)})
	future := newTLSChain(t, cryptotest.ChainOptions{NotBefore: now.Add(time.Hour)})
	weak := newTLSChain(t, cryptotest.ChainOptions{LeafRSABits: 1024})
	client := newTLSChain(t, cryptotest.ChainOptions{ClientAuthOnly: true})
	wrongName := newTLSChain(t, cryptotest.ChainOptions{Hosts: []string{"other.example.ru"}})
	noConsole := newTLSChain(t, cryptotest.ChainOptions{Hosts: []string{"lab.example.ru", "192.168.10.5"}})
	noIP := newTLSChain(t, cryptotest.ChainOptions{Hosts: []string{"aisec-console", "lab.example.ru", "192.168.10.6"}})
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	legacyEncrypted := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})
	with := func(c cryptotest.Chain, name string, data []byte) map[string][]byte {
		f := tlsCheckFiles(c)
		f[name] = data
		return f
	}
	both := func(c cryptotest.Chain, suffix string, data []byte) map[string][]byte {
		f := tlsCheckFiles(c)
		f["console"+suffix] = data
		f["gateway"+suffix] = data
		return f
	}
	for name, tc := range map[string]struct {
		files map[string][]byte
		want  string
	}{
		"просроченный":                 {tlsCheckFiles(expired), "истёк"},
		"ещё не действует":             {tlsCheckFiles(future), "действует с"},
		"чужое имя":                    {tlsCheckFiles(wrongName), "не на имя lab.example.ru: имена в сертификате — other.example.ru"},
		"нет имени консоли":            {tlsCheckFiles(noConsole), "не на имя aisec-console"},
		"IP не в IP SAN":               {tlsCheckFiles(noIP), "не на имя 192.168.10.5"},
		"ключ не от сертификата":       {with(good, tlsGatewayKeyFile, other.Key), "не подходит ни к одному"},
		"слабый RSA":                   {tlsCheckFiles(weak), "слабый или слишком большой ключ RSA (1024 бит)"},
		"ключ с паролем PKCS#8":        {with(good, tlsConsoleKeyFile, encrypted), "зашифрован паролем"},
		"ключ с паролем PEM":           {with(good, tlsConsoleKeyFile, legacyEncrypted), "зашифрован паролем"},
		"два ключа в файле":            {with(good, tlsConsoleKeyFile, cat(good.Key, other.Key)), "ровно один блок"},
		"сертификат в файле ключа":     {with(good, tlsGatewayKeyFile, cat(good.Key, good.Leaf)), "ровно один блок"},
		"ключ в файле сертификата":     {with(good, tlsConsoleCertFile, cat(good.Leaf, good.Intermediate, good.Key)), "только сертификаты"},
		"лист не первым":               {with(good, tlsConsoleCertFile, cat(good.Intermediate, good.Leaf)), "первым в console.crt должен быть"},
		"корень перед листом":          {with(good, tlsGatewayCertFile, cat(good.Root, good.Leaf, good.Intermediate)), "первым в gateway.crt должен быть"},
		"нет промежуточного":           {both(good, ".crt", good.Leaf), "не хватает промежуточного"},
		"clientAuth вместо serverAuth": {tlsCheckFiles(client), "serverAuth"},
		"чужой корень в ca.crt":        {with(good, tlsCAFile, other.Root), "не хватает промежуточного"},
		"два сертификата в ca.crt":     {with(good, tlsCAFile, cat(good.Intermediate, good.Root)), "ровно один корневой"},
		"промежуточный вместо корня":   {with(good, tlsCAFile, good.Intermediate), "самоподписанный"},
		"лишний корень в сертификате":  {with(good, tlsConsoleCertFile, cat(good.Leaf, good.Intermediate, other.Root)), "не входящие в путь"},
		"нет файла ключа":              {with(good, tlsGatewayKeyFile, nil), "gateway.key: нет файла"},
		"нет ca.crt":                   {with(good, tlsCAFile, nil), "ca.crt: нет файла"},
		"пустой сертификат":            {with(good, tlsConsoleCertFile, []byte{}), "пустой файл"},
		"большой сертификат":           {with(good, tlsConsoleCertFile, make([]byte, aisecCrypto.MaxServerChainPEM+1)), "больше 64 КиБ"},
		"большой ключ":                 {with(good, tlsConsoleKeyFile, make([]byte, aisecCrypto.MaxServerKeyPEM+1)), "больше 16 КиБ"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTLSCheckDir(t, tc.files)
			code, out, errOut := runTLS(t, now, checkArgs(dir)...)
			if code == 0 {
				t.Fatalf("принято:\n%s", out)
			}
			if !strings.Contains(out, "[ошибка]") || !strings.Contains(errOut, "не прошли проверку") {
				t.Errorf("вывод:\n%s\n%s", out, errOut)
			}
			if tc.want != "" && !strings.Contains(out, tc.want) {
				t.Errorf("в выводе нет %q:\n%s", tc.want, out)
			}
			if strings.Contains(out+errOut, "PRIVATE KEY-----") {
				t.Error("ключевой материал в выводе")
			}
		})
	}
}

func TestTLSCheckRejectsLinks(t *testing.T) {
	good := newTLSChain(t, cryptotest.ChainOptions{})
	dir := writeTLSCheckDir(t, tlsCheckFiles(good))
	outside := filepath.Join(t.TempDir(), "gateway.key")
	if err := os.WriteFile(outside, good.Key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, tlsGatewayKeyFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, tlsGatewayKeyFile)); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runTLS(t, time.Now(), checkArgs(dir)...)
	if code == 0 || !strings.Contains(out, "gateway.key: не обычный файл") {
		t.Errorf("код %d:\n%s", code, out)
	}
	// Каталог вместо файла.
	files := tlsCheckFiles(good)
	delete(files, tlsCAFile)
	dir2 := writeTLSCheckDir(t, files)
	if err := os.Mkdir(filepath.Join(dir2, tlsCAFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runTLS(t, time.Now(), checkArgs(dir2)...); code == 0 || !strings.Contains(out, "ca.crt: не обычный файл") {
		t.Errorf("каталог: код %d:\n%s", code, out)
	}
}

func TestTLSCheckBadArgs(t *testing.T) {
	dir := writeTLSCheckDir(t, tlsCheckFiles(newTLSChain(t, cryptotest.ChainOptions{})))
	for name, args := range map[string][]string{
		"без -dir":             {"check", "-hosts", "a"},
		"без -hosts":           {"check", "-dir", dir},
		"шаблон в -hosts":      {"check", "-dir", dir, "-hosts", "*.example.ru"},
		"неверное имя консоли": {"check", "-dir", dir, "-hosts", "a", "-console-name", "aisec_console"},
		"каталога нет":         {"check", "-dir", filepath.Join(dir, "нет"), "-hosts", "a"},
		"лишний аргумент":      {"check", "-dir", dir, "-hosts", "a", "лишнее"},
	} {
		if code, _, _ := runTLS(t, time.Now(), args...); code == 0 {
			t.Errorf("%s: принято", name)
		}
	}
}

func FuzzPEMHasCert(f *testing.F) {
	c, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"a"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(c.Full(), []byte{})
	f.Add(c.Key, []byte{1})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"), []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, data, der []byte) {
		// Без паники на любых данных; блок с der, записанный первым,
		// находится всегда.
		_ = pemHasCert(data, der)
		if !pemHasCert(append(aisecCrypto.CertPEMFromDER(der), data...), der) {
			t.Fatal("не найден первый блок")
		}
	})
}
