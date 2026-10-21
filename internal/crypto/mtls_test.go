package crypto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func testCA(t *testing.T, now time.Time, validity time.Duration) *CA {
	t.Helper()
	ca, err := NewCA("AISec test CA", validity, now)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func parseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("нет блока PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// csrWithKey — CSR произвольного ключа и содержимого (для отрицательных тестов).
func csrWithKey(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestIssueClient(t *testing.T) {
	now := time.Now()
	ca := testCA(t, now, 30*24*time.Hour)
	keyPEM, csrPEM, err := NewClientCSR("gateway-asks-this-name")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(keyPEM, []byte("PRIVATE KEY")) {
		t.Fatal("ключ шлюза не в PKCS#8 PEM")
	}
	const id = "0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"
	certPEM, info, err := ca.IssueClient(csrPEM, id, ClientCertValidity, now)
	if err != nil {
		t.Fatal(err)
	}
	c := parseCertPEM(t, certPEM)
	if c.Subject.CommonName != id {
		t.Fatalf("CN %q: имя из CSR не должно попадать в сертификат", c.Subject.CommonName)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("назначение %v, ожидается только clientAuth", c.ExtKeyUsage)
	}
	if c.IsCA || len(c.DNSNames)+len(c.IPAddresses)+len(c.URIs)+len(c.EmailAddresses) != 0 {
		t.Fatal("клиентский сертификат не должен быть УЦ и иметь альтернативных имён")
	}
	if info.Serial != c.SerialNumber.Text(16) || !info.NotAfter.Equal(c.NotAfter) {
		t.Fatalf("CertInfo %+v не соответствует сертификату", info)
	}
	// Запрошено 365 дней, УЦ живёт 30: срок обрезан сроком УЦ.
	if c.NotAfter.After(ca.NotAfter()) || c.NotAfter.Before(now.Add(29*24*time.Hour)) {
		t.Fatal("срок сертификата не ограничен сроком УЦ")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	if _, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("цепочка до УЦ: %v", err)
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("клиентский сертификат принят как серверный")
	}
	got, err := ParseCertInfo(certPEM)
	if err != nil || got.CommonName != id || got.Serial != info.Serial {
		t.Fatalf("ParseCertInfo: %+v, %v", got, err)
	}
}

// Расширения и альтернативные имена из CSR не копируются в сертификат.
func TestIssueClientIgnoresRequestedExtensions(t *testing.T) {
	now := time.Now()
	ca := testCA(t, now, time.Hour)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := csrWithKey(t, key, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "server.example"},
		DNSNames:       []string{"server.example"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		EmailAddresses: []string{"a@example.org"},
	})
	certPEM, _, err := ca.IssueClient(csrPEM, "gw", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	c := parseCertPEM(t, certPEM)
	if len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses) != 0 || c.Subject.CommonName != "gw" {
		t.Fatalf("из CSR перенесены имена: %v %v %v %q", c.DNSNames, c.IPAddresses, c.EmailAddresses, c.Subject.CommonName)
	}
}

func TestIssueClientRejects(t *testing.T) {
	now := time.Now()
	ca := testCA(t, now, time.Hour)
	_, good, err := NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Подпись запроса испорчена: последний байт DER — часть подписи.
	block, _ := pem.Decode(good)
	broken := bytes.Clone(block.Bytes)
	broken[len(broken)-1] ^= 0xff
	badSig := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: broken})

	cases := map[string]struct {
		csr      []byte
		cn       string
		validity time.Duration
	}{
		"пустой":           {csr: nil, cn: "gw", validity: time.Hour},
		"мусор":            {csr: []byte("not a csr"), cn: "gw", validity: time.Hour},
		"данные до блока":  {csr: append([]byte("x\n"), good...), cn: "gw", validity: time.Hour},
		"два блока":        {csr: append(bytes.Clone(good), good...), cn: "gw", validity: time.Hour},
		"не тот тип блока": {csr: bytes.ReplaceAll(good, []byte("CERTIFICATE REQUEST"), []byte("CERTIFICATE")), cn: "gw", validity: time.Hour},
		"слишком большой":  {csr: append(bytes.Clone(good), bytes.Repeat([]byte(" "), maxCSR)...), cn: "gw", validity: time.Hour},
		"чужая подпись":    {csr: badSig, cn: "gw", validity: time.Hour},
		"ключ P-384":       {csr: csrWithKey(t, p384, &x509.CertificateRequest{}), cn: "gw", validity: time.Hour},
		"ключ RSA":         {csr: csrWithKey(t, rsaKey, &x509.CertificateRequest{}), cn: "gw", validity: time.Hour},
		"пустое имя":       {csr: good, cn: "", validity: time.Hour},
		"имя с пробелом":   {csr: good, cn: "g w", validity: time.Hour},
		"длинное имя":      {csr: good, cn: strings.Repeat("a", maxCNLength+1), validity: time.Hour},
		"нулевой срок":     {csr: good, cn: "gw", validity: 0},
		"срок больше":      {csr: good, cn: "gw", validity: MaxCertValidity + time.Hour},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ca.IssueClient(tc.csr, tc.cn, tc.validity, now); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
	if _, _, err := ca.IssueClient(good, "gw", time.Hour, now.Add(2*time.Hour)); err == nil {
		t.Fatal("истёкший УЦ выпустил сертификат")
	}
	if _, _, err := NewClientCSR("g w"); err == nil {
		t.Fatal("CSR с недопустимым именем")
	}
}

func FuzzIssueClient(f *testing.F) {
	now := time.Now()
	ca, err := NewCA("AISec fuzz CA", time.Hour, now)
	if err != nil {
		f.Fatal(err)
	}
	_, good, err := NewClientCSR("gw")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		certPEM, info, err := ca.IssueClient(data, "gw", time.Hour, now)
		if err != nil {
			return
		}
		// Выпущенный сертификат всегда клиентский, с нашим именем и P-256.
		c := parseCertPEM(t, certPEM)
		if c.Subject.CommonName != "gw" || info.Serial == "" {
			t.Fatalf("неожиданный сертификат: %q", c.Subject.CommonName)
		}
		if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
			t.Fatal("выпущен сертификат не на ключ P-256")
		}
	})
}

// mtlsPair — серверные и клиентские настройки mTLS. Клиентский сертификат
// выпускает clientCA (его можно подменить чужим УЦ).
func mtlsConfigs(t *testing.T, serverCA, clientCA *CA, clientCN string) (srv, cli *tls.Config) {
	t.Helper()
	tp := mustTLS(t)
	now := time.Now()
	certPEM, keyPEM, err := serverCA.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	srv, err = tp.MutualServerConfig(certPEM, keyPEM, serverCA.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	if clientCA == nil {
		cli, err = tp.ClientConfig(serverCA.CertPEM())
		if err != nil {
			t.Fatal(err)
		}
		return srv, cli
	}
	cKey, csr, err := NewClientCSR(clientCN)
	if err != nil {
		t.Fatal(err)
	}
	cCert, _, err := clientCA.IssueClient(csr, clientCN, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cli, err = tp.ClientCertConfig(serverCA.CertPEM(), cCert, cKey)
	if err != nil {
		t.Fatal(err)
	}
	return srv, cli
}

// mtlsHandshake: в TLS 1.3 клиент узнаёт об отказе в своём сертификате только
// при чтении, поэтому сервер после рукопожатия пишет байт, а клиент читает его.
func mtlsHandshake(t *testing.T, server, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() }) //nolint:gosec // G104: уборка тестового слушателя
	states := make(chan tls.ConnectionState, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(states)
			return
		}
		defer func() { _ = c.Close() }() //nolint:gosec // G104: уборка тестового соединения
		tc := c.(*tls.Conn)
		if err := tc.HandshakeContext(ctx); err != nil {
			close(states)
			return
		}
		states <- tc.ConnectionState()
		_, _ = tc.Write([]byte{1}) //nolint:gosec // G104: сбой записи клиент увидит как ошибку чтения
	}()
	d := tls.Dialer{NetDialer: &net.Dialer{}, Config: client}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }() //nolint:gosec // G104: уборка тестового соединения
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		return tls.ConnectionState{}, err
	}
	st, ok := <-states
	if !ok {
		t.Fatal("сервер не завершил рукопожатие")
	}
	return st, nil
}

func TestMutualTLS(t *testing.T) {
	now := time.Now()
	ours := testCA(t, now, time.Hour)
	srv, cli := mtlsConfigs(t, ours, ours, "gw-1")
	if srv.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v", srv.ClientAuth)
	}
	st, err := mtlsHandshake(t, srv, cli)
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := PeerFromTLS(&st)
	if !ok || peer.CommonName != "gw-1" || peer.Serial == "" {
		t.Fatalf("PeerFromTLS: %+v, %v", peer, ok)
	}
}

func TestMutualTLSRejectsClients(t *testing.T) {
	now := time.Now()
	ours := testCA(t, now, time.Hour)
	foreign := testCA(t, now, time.Hour)
	tp := mustTLS(t)

	t.Run("без сертификата", func(t *testing.T) {
		srv, cli := mtlsConfigs(t, ours, nil, "")
		if _, err := mtlsHandshake(t, srv, cli); err == nil {
			t.Fatal("клиент без сертификата принят")
		}
	})
	t.Run("чужой УЦ", func(t *testing.T) {
		srv, cli := mtlsConfigs(t, ours, foreign, "gw-1")
		if _, err := mtlsHandshake(t, srv, cli); err == nil {
			t.Fatal("клиент с сертификатом чужого УЦ принят")
		}
	})
	t.Run("серверный сертификат нашего УЦ", func(t *testing.T) {
		srv, _ := mtlsConfigs(t, ours, nil, "")
		certPEM, keyPEM, err := ours.IssueServer([]string{"gw.example"}, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		cli, err := tp.ClientCertConfig(ours.CertPEM(), certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mtlsHandshake(t, srv, cli); err == nil {
			t.Fatal("сертификат без назначения clientAuth принят")
		}
	})
}

func TestMutualTLSConfigErrors(t *testing.T) {
	tp := mustTLS(t)
	now := time.Now()
	ca := testCA(t, now, time.Hour)
	certPEM, keyPEM, err := ca.IssueServer([]string{"localhost"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tp.MutualServerConfig(certPEM, keyPEM, []byte("нет сертификатов")); err == nil {
		t.Fatal("сервер mTLS без корня клиентов")
	}
	if _, err := tp.MutualServerConfig([]byte("x"), keyPEM, ca.CertPEM()); err == nil {
		t.Fatal("сервер mTLS с неверным сертификатом")
	}
	if _, err := tp.ClientCertConfig(ca.CertPEM(), certPEM, []byte("x")); err == nil {
		t.Fatal("клиент mTLS с неверным ключом")
	}
	if _, err := tp.ClientCertConfig(nil, certPEM, keyPEM); err == nil {
		t.Fatal("клиент mTLS без корня")
	}
	if _, err := tp.ClientCertConfig(ca.CertPEM(), bytes.Repeat([]byte("a"), maxPEMFile+1), keyPEM); err == nil {
		t.Fatal("клиент mTLS со слишком большим сертификатом")
	}
}

func TestPeerFromTLS(t *testing.T) {
	if _, ok := PeerFromTLS(nil); ok {
		t.Fatal("нет соединения TLS — нет субъекта")
	}
	now := time.Now()
	ca := testCA(t, now, time.Hour)
	_, csr, err := NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.IssueClient(csr, "gw", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	// Сертификат предъявлен, но цепочка не проверена — субъекта нет.
	st := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parseCertPEM(t, certPEM)}}
	if _, ok := PeerFromTLS(st); ok {
		t.Fatal("непроверенный сертификат принят")
	}
}

func TestParseCertInfoRejects(t *testing.T) {
	for name, data := range map[string][]byte{
		"пусто":       nil,
		"мусор":       []byte("x"),
		"не та схема": []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
	} {
		if _, err := ParseCertInfo(data); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}
