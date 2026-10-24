package crypto_test

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

const testHost = "aisec-gw.example.ru"

func newChain(t testing.TB, o cryptotest.ChainOptions) cryptotest.Chain {
	t.Helper()
	if o.Hosts == nil {
		o.Hosts = []string{testHost, "10.0.0.5"}
	}
	c, err := cryptotest.NewChain(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseServerCertValid(t *testing.T) {
	for name, o := range map[string]cryptotest.ChainOptions{
		"ECDSA P-256": {},
		"ECDSA P-384": {LeafCurve: elliptic.P384()},
		"RSA 2048":    {LeafRSABits: 2048},
	} {
		t.Run(name, func(t *testing.T) {
			c := newChain(t, o)
			// Порядок в файле не важен: корень первым, лист последним.
			chain := append(append(append([]byte{}, c.Root...), c.Intermediate...), c.Leaf...)
			sc, key, err := aisecCrypto.ParseServerCert(chain, c.Key, "AISEC-GW.example.ru", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if sc.ChainLen != 3 || sc.KeyAlg != name || len(sc.Fingerprint) != 64 || sc.DNSNames[0] != testHost ||
				sc.IPAddresses[0] != "10.0.0.5" || !strings.Contains(sc.Issuer, "промежуточный") {
				t.Fatalf("сведения: %+v", sc)
			}
			// Канонический порядок: лист, промежуточный, корень.
			if want := c.Full(); string(sc.ChainPEM) != string(want) {
				t.Fatal("цепочка не в каноническом порядке")
			}
			if b, _ := pem.Decode(key); b == nil || b.Type != "PRIVATE KEY" {
				t.Fatal("ключ не в PKCS#8 PEM")
			}
			// По IP-адресу из SAN тоже проходит.
			if _, _, err := aisecCrypto.ParseServerCert(c.Full(), c.Key, "10.0.0.5", time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseServerCertRejects(t *testing.T) {
	now := time.Now()
	good := newChain(t, cryptotest.ChainOptions{})
	other := newChain(t, cryptotest.ChainOptions{})
	expired := newChain(t, cryptotest.ChainOptions{NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)})
	future := newChain(t, cryptotest.ChainOptions{NotBefore: now.Add(time.Hour)})
	weak := newChain(t, cryptotest.ChainOptions{LeafRSABits: 1024})
	p521 := newChain(t, cryptotest.ChainOptions{LeafCurve: elliptic.P521()})
	client := newChain(t, cryptotest.ChainOptions{ClientAuthOnly: true})
	encOnly := newChain(t, cryptotest.ChainOptions{LeafKeyUsage: x509.KeyUsageKeyEncipherment})
	longOrg := newChain(t, cryptotest.ChainOptions{LeafOrg: strings.Repeat("я", 2100)})
	bigSerial := newChain(t, cryptotest.ChainOptions{LeafSerial: new(big.Int).Lsh(big.NewInt(1), 300)})
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})
	cases := []struct {
		name       string
		chain, key []byte
		host       string
		want       string
		notValid   bool
	}{
		{"цепочка без корня", cat(good.Leaf, good.Intermediate), good.Key, testHost, "нет корневого", false},
		{"цепочка без промежуточного", cat(good.Leaf, good.Root), good.Key, testHost, "не хватает промежуточного", false},
		{"просроченный", expired.Full(), expired.Key, testHost, "истёк", true},
		{"ещё не действует", future.Full(), future.Key, testHost, "действует с", true},
		{"чужое имя", good.Full(), good.Key, "other.example.ru", "не на имя other.example.ru", false},
		{"ключ не от сертификата", good.Full(), other.Key, testHost, "не подходит", false},
		{"слабый ключ RSA", weak.Full(), weak.Key, testHost, "1024", false},
		{"ключ P-521", p521.Full(), p521.Key, testHost, "P-256 и P-384", false},
		{"только clientAuth", client.Full(), client.Key, testHost, "serverAuth", false},
		{"keyUsage без digitalSignature", encOnly.Full(), encOnly.Key, testHost, "digitalSignature", false},
		{"длинное имя владельца", longOrg.Full(), longOrg.Key, testHost, "длиннее 2048", false},
		{"длинный серийный номер", bigSerial.Full(), bigSerial.Key, testHost, "серийный номер", false},
		{"лишний сертификат", cat(good.Full(), other.Root), good.Key, testHost, "не входящие в путь", false},
		{"ключ в файле цепочки", cat(good.Full(), good.Key), good.Key, testHost, "только сертификаты", false},
		{"сертификат в файле ключа", good.Full(), cat(good.Key, good.Leaf), testHost, "ровно один блок", false},
		{"два ключа", good.Full(), cat(good.Key, other.Key), testHost, "ровно один блок", false},
		{"текст до ключа", good.Full(), cat([]byte("ключ:\n"), good.Key), testHost, "перед блоком", false},
		{"текст в цепочке", cat(good.Leaf, []byte("мусор\n"), good.Root), good.Key, testHost, "вне блоков", false},
		{"зашифрованный ключ", good.Full(), encrypted, testHost, "зашифрован паролем", false},
		{"сертификат вместо ключа", good.Full(), good.Leaf, testHost, "ожидается закрытый ключ", false},
		{"пустая цепочка", nil, good.Key, testHost, "цепочка сертификатов", false},
		{"большая цепочка", make([]byte, aisecCrypto.MaxServerChainPEM+1), good.Key, testHost, "цепочка сертификатов", false},
		{"большой ключ", good.Full(), make([]byte, aisecCrypto.MaxServerKeyPEM+1), testHost, "закрытый ключ", false},
		{"шаблон в имени", good.Full(), good.Key, "*.example.ru", "DNS-имя", false},
		{"пустое имя", good.Full(), good.Key, "", "имя адреса шлюза", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, key, err := aisecCrypto.ParseServerCert(tc.chain, tc.key, tc.host, now)
			if err == nil || key != nil {
				t.Fatal("ожидалась ошибка")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ошибка %q, ожидалось %q", err, tc.want)
			}
			if errors.Is(err, aisecCrypto.ErrCertNotValidNow) != tc.notValid {
				t.Fatalf("ErrCertNotValidNow: %v", err)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY-----") {
				t.Fatal("ключевой материал в тексте ошибки")
			}
		})
	}
}

func TestParseServerCertTooManyCerts(t *testing.T) {
	c := newChain(t, cryptotest.ChainOptions{})
	var chain []byte
	for range aisecCrypto.MaxServerChainCerts + 1 {
		chain = append(chain, c.Root...)
	}
	if _, _, err := aisecCrypto.ParseServerCert(chain, c.Key, testHost, time.Now()); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Fatalf("ошибка: %v", err)
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{"GW.Example.RU": "gw.example.ru", "10.0.0.1": "10.0.0.1", "::1": "::1", "gw-1": "gw-1"} {
		if got, err := aisecCrypto.NormalizeHost(in); err != nil || got != want {
			t.Fatalf("%s: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "gw.", ".gw", "-gw.ru", "gw_1.ru", "шлюз.рф", "fe80::1%eth0", strings.Repeat("a", 64) + ".ru",
		strings.Repeat("a.", 127) + "ru"} {
		if _, err := aisecCrypto.NormalizeHost(bad); err == nil {
			t.Fatalf("%q принят", bad)
		}
	}
}

// TestServerCertSwitch — переключение сертификата TLS-сервера без
// перезапуска и возврат к сертификату по умолчанию.
func TestServerCertSwitch(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := aisecCrypto.NewCA("Внутренний УЦ", 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	defCert, defKey, err := ca.IssueServer([]string{"localhost", "127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	sw, err := aisecCrypto.NewServerCertSwitch(defCert, defKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := aisecCrypto.SwitchServerConfig(tp, defCert, defKey, sw)
	if err != nil {
		t.Fatal(err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }() //nolint:gosec // G104: закрытие порта в конце теста
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c := aisecCrypto.ServerTLS(conn, cfg)
				_, _ = io.Copy(io.Discard, c) //nolint:gosec // G104: соединение тестового сервера, ошибка чтения не важна
				_ = c.Close()                 //nolint:gosec // G104: закрытие тестового соединения
			}()
		}
	}()
	dial := func(roots []byte) error {
		ccfg, err := tp.ClientConfig(roots)
		if err != nil {
			return err
		}
		ccfg.ServerName = testHost
		if roots == nil || string(roots) == string(ca.CertPEM()) {
			ccfg.ServerName = "localhost"
		}
		var d net.Dialer
		conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
		if err != nil {
			return err
		}
		c, err := aisecCrypto.ClientTLS(context.Background(), conn, ccfg)
		if err != nil {
			return err
		}
		return c.Close()
	}
	chain := newChain(t, cryptotest.ChainOptions{})
	if err := dial(ca.CertPEM()); err != nil {
		t.Fatalf("сертификат по умолчанию: %v", err)
	}
	sc, key, err := aisecCrypto.ParseServerCert(chain.Full(), chain.Key, testHost, now)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := aisecCrypto.NewServerPair(sc.ChainPEM, key)
	if err != nil {
		t.Fatal(err)
	}
	if pair.Fingerprint != sc.Fingerprint {
		t.Fatal("отпечаток пары не совпадает")
	}
	sw.Use(pair)
	if sw.Current() != sc.Fingerprint {
		t.Fatal("пара заказчика не включена")
	}
	if err := dial(chain.Root); err != nil {
		t.Fatalf("сертификат заказчика: %v", err)
	}
	if err := dial(ca.CertPEM()); err == nil {
		t.Fatal("после переключения клиент внутреннего УЦ не должен доверять серверу")
	}
	sw.Use(nil)
	if err := dial(ca.CertPEM()); err != nil {
		t.Fatalf("возврат к сертификату по умолчанию: %v", err)
	}
}

func FuzzParseServerCert(f *testing.F) {
	c := newChain(f, cryptotest.ChainOptions{})
	f.Add(c.Full(), c.Key, testHost)
	f.Add(c.Leaf, c.Key, "10.0.0.5")
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), []byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"), "a")
	now := time.Now()
	f.Fuzz(func(t *testing.T, chain, key []byte, host string) {
		sc, out, err := aisecCrypto.ParseServerCert(chain, key, host, now)
		if err != nil {
			if out != nil {
				t.Fatal("ключ при ошибке")
			}
			return
		}
		// Принятое должно собираться в пару TLS и разбираться повторно.
		if _, err := aisecCrypto.NewServerPair(sc.ChainPEM, out); err != nil {
			t.Fatalf("принятая цепочка не собирается в пару: %v", err)
		}
		if _, _, err := aisecCrypto.ParseServerCert(sc.ChainPEM, out, host, now); err != nil {
			t.Fatalf("каноническая форма не принимается: %v", err)
		}
	})
}
