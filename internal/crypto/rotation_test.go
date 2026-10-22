package crypto

import (
	"bytes"
	"testing"
	"time"
)

// Корни из заявления о доверии и проверка перевыпущенного сертификата
// (ADR-0018, п. 6).

func TestCheckRootDER(t *testing.T) {
	now := time.Now()
	ca, err := NewCA("AISec test CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	notAfter, err := CheckRootDER(ca.CertDER())
	if err != nil || !notAfter.Equal(ca.NotAfter()) {
		t.Fatalf("корень УЦ: %v %v", notAfter, err)
	}
	der, err := CertDER(ca.CertPEM())
	if err != nil || !bytes.Equal(der, ca.CertDER()) || !bytes.Equal(CertPEMFromDER(der), ca.CertPEM()) {
		t.Fatalf("PEM ↔ DER: %v", err)
	}
	// Сертификат сервера от того же УЦ — не корень.
	srvPEM, _, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	srvDER, err := CertDER(srvPEM)
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string][]byte{
		"пусто":          nil,
		"больше предела": bytes.Repeat([]byte{1}, MaxRootDER+1),
		"не сертификат":  []byte("not a certificate"),
		"не УЦ":          srvDER,
		"обрезанный":     ca.CertDER()[:len(ca.CertDER())-1],
	} {
		if _, err := CheckRootDER(d); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
	if _, err := CertDER(append(ca.CertPEM(), ca.CertPEM()...)); err == nil {
		t.Error("два сертификата приняты как один")
	}
}

func TestVerifyClientCert(t *testing.T) {
	now := time.Now()
	ca, err := NewCA("AISec test CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCA("other", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, csrPEM, err := NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.IssueClient(csrPEM, "gw-id", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyClientCert(certPEM, keyPEM, "gw-id", [][]byte{other.CertDER(), ca.CertDER()}, now); err != nil {
		t.Fatalf("сертификат от корня из набора: %v", err)
	}
	otherKey, _, err := NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"чужой корень":    VerifyClientCert(certPEM, keyPEM, "gw-id", [][]byte{other.CertDER()}, now),
		"чужое имя":       VerifyClientCert(certPEM, keyPEM, "gw-other", [][]byte{ca.CertDER()}, now),
		"чужой ключ":      VerifyClientCert(certPEM, otherKey, "gw-id", [][]byte{ca.CertDER()}, now),
		"истёк":           VerifyClientCert(certPEM, keyPEM, "gw-id", [][]byte{ca.CertDER()}, now.Add(2*time.Hour)),
		"неверный корень": VerifyClientCert(certPEM, keyPEM, "gw-id", [][]byte{[]byte("x")}, now),
	} {
		if err == nil {
			t.Errorf("%s: принят", name)
		}
	}
}

func TestClientCertSwitch(t *testing.T) {
	now := time.Now()
	ca, err := NewCA("AISec test CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	issue := func() ([]byte, []byte) {
		t.Helper()
		keyPEM, csrPEM, err := NewClientCSR("gw")
		if err != nil {
			t.Fatal(err)
		}
		certPEM, _, err := ca.IssueClient(csrPEM, "gw-id", time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		return certPEM, keyPEM
	}
	c1, k1 := issue()
	c2, k2 := issue()
	sw, err := NewClientCertSwitch(c1, k1)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := SwitchClientConfig(tp, ca.CertPEM(), sw)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func() []byte {
		t.Helper()
		c, err := cfg.GetClientCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		return c.Certificate[0]
	}
	d1, _ := CertDER(c1)
	d2, _ := CertDER(c2)
	if !bytes.Equal(leaf(), d1) {
		t.Fatal("начальная пара")
	}
	if err := sw.Set(c2, k1); err == nil {
		t.Fatal("непарные сертификат и ключ приняты")
	}
	if !bytes.Equal(leaf(), d1) {
		t.Fatal("после отказа пара сменилась")
	}
	if err := sw.Set(c2, k2); err != nil || !bytes.Equal(leaf(), d2) {
		t.Fatalf("переключение: %v", err)
	}
	if _, err := SwitchClientConfig(tp, ca.CertPEM(), &ClientCertSwitch{}); err == nil {
		t.Fatal("клиент без сертификата")
	}
	pool := RootPoolPEM([][]byte{ca.CertDER(), d2})
	if !bytes.Contains(pool, ca.CertPEM()) || bytes.Count(pool, []byte("BEGIN CERTIFICATE")) != 2 {
		t.Fatal("набор корней в PEM")
	}
}
