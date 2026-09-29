package crypto

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustTLS(t *testing.T) TLSProvider {
	t.Helper()
	tp, err := mustStandard(t).TLS()
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// configs возвращает настройки сервера и клиента для пары, выпущенной devPair.
func configs(t *testing.T, caPEM, certPEM, keyPEM []byte) (srv, cli *tls.Config) {
	t.Helper()
	tp := mustTLS(t)
	srv, err := tp.ServerConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cli, err = tp.ClientConfig(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	return srv, cli
}

func devPair(t *testing.T, hosts ...string) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	now := time.Now()
	ca, err := NewCA("AISec test CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err = ca.IssueServer(hosts, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	return ca.CertPEM(), certPEM, keyPEM
}

// pairConfigs выпускает пару для hosts и возвращает настройки сервера и клиента.
func pairConfigs(t *testing.T, hosts ...string) (srv, cli *tls.Config) {
	t.Helper()
	caPEM, certPEM, keyPEM := devPair(t, hosts...)
	return configs(t, caPEM, certPEM, keyPEM)
}

// handshake поднимает TLS-сервер и выполняет рукопожатие клиентом.
func handshake(t *testing.T, server, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
			t.Error(err)
		}
	})
	// Ошибки сервера ожидаемы в отрицательных тестах; они собираются, но не проверяются.
	serverErrs := make(chan error, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErrs <- err
			return
		}
		serverErrs <- c.(*tls.Conn).HandshakeContext(ctx)
		_, err = io.Copy(io.Discard, c)
		serverErrs <- err
		serverErrs <- c.Close()
	}()
	d := tls.Dialer{NetDialer: &net.Dialer{}, Config: client}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		return tls.ConnectionState{}, err
	}
	st := conn.(*tls.Conn).ConnectionState()
	return st, conn.Close()
}

func TestTLSHandshake(t *testing.T) {
	srv, cli := pairConfigs(t, "localhost", "127.0.0.1")
	st, err := handshake(t, srv, cli)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("ожидался TLS 1.3, получено %x", st.Version)
	}
}

func TestTLSConfigValues(t *testing.T) {
	srv, cli := pairConfigs(t, "localhost")
	for name, cfg := range map[string]*tls.Config{"сервер": srv, "клиент": cli} {
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("%s: MinVersion %x", name, cfg.MinVersion)
		}
		if cfg.InsecureSkipVerify {
			t.Errorf("%s: проверка сертификата отключена", name)
		}
		for _, id := range cfg.CipherSuites {
			n := tls.CipherSuiteName(id)
			aead := strings.Contains(n, "_GCM_") || strings.Contains(n, "CHACHA20_POLY1305")
			if !strings.HasPrefix(n, "TLS_ECDHE_") || !aead {
				t.Errorf("%s: набор без ECDHE или AEAD: %s", name, n)
			}
		}
	}
}

func TestTLSRejectsOldVersion(t *testing.T) {
	srv, cli := pairConfigs(t, "127.0.0.1")
	cli.MinVersion = tls.VersionTLS10
	cli.MaxVersion = tls.VersionTLS11
	if _, err := handshake(t, srv, cli); err == nil {
		t.Fatal("сервер принял TLS 1.1")
	}
}

func TestTLSRejectsWeakSuite(t *testing.T) {
	srv, cli := pairConfigs(t, "127.0.0.1")
	cli.MaxVersion = tls.VersionTLS12
	cli.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	if _, err := handshake(t, srv, cli); err == nil {
		t.Fatal("сервер принял набор без AEAD")
	}
	// TLS 1.2 с разрешённым набором проходит.
	cli.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	st, err := handshake(t, srv, cli)
	if err != nil || st.Version != tls.VersionTLS12 {
		t.Fatalf("TLS 1.2 с AEAD: %v %x", err, st.Version)
	}
}

func TestTLSRejectsUnknownCA(t *testing.T) {
	_, certPEM, keyPEM := devPair(t, "127.0.0.1")
	otherCA, _, _ := devPair(t, "127.0.0.1")
	srv, cli := configs(t, otherCA, certPEM, keyPEM)
	if _, err := handshake(t, srv, cli); err == nil {
		t.Fatal("клиент принял сертификат чужого УЦ")
	}
}

func TestTLSRejectsWrongHost(t *testing.T) {
	srv, cli := pairConfigs(t, "other.example")
	if _, err := handshake(t, srv, cli); err == nil {
		t.Fatal("клиент принял сертификат с чужим именем")
	}
}

func TestTLSConfigErrors(t *testing.T) {
	tp := mustTLS(t)
	caPEM, certPEM, keyPEM := devPair(t, "localhost")
	_, _, otherKey := devPair(t, "localhost")
	if _, err := tp.ServerConfig(certPEM, otherKey); err == nil {
		t.Error("принята пара с чужим ключом")
	}
	if _, err := tp.ServerConfig([]byte("мусор"), keyPEM); err == nil {
		t.Error("принят испорченный сертификат")
	}
	if _, err := tp.ServerConfig(make([]byte, maxPEMFile+1), keyPEM); err == nil {
		t.Error("принят слишком большой сертификат")
	}
	if _, err := tp.ClientConfig([]byte("нет сертификатов")); err == nil {
		t.Error("принят пустой список корневых")
	}
	if _, err := tp.ClientConfig(append(caPEM, make([]byte, maxPEMFile)...)); err == nil {
		t.Error("принят слишком большой файл корневых")
	}
	// Ошибка не раскрывает ключевой материал.
	_, err := tp.ServerConfig(certPEM, append([]byte("x"), otherKey...))
	if err != nil && strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatal("ошибка содержит ключ")
	}
}

func TestReadPEMFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.pem")
	if err := os.WriteFile(p, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadPEMFile(p); err != nil || string(b) != "pem" {
		t.Fatalf("ReadPEMFile: %q %v", b, err)
	}
	if _, err := ReadPEMFile(dir); err == nil {
		t.Error("принят каталог")
	}
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, make([]byte, maxPEMFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPEMFile(big); err == nil {
		t.Error("принят слишком большой файл")
	}
	if _, err := ReadPEMFile(filepath.Join(dir, "нет.pem")); err == nil {
		t.Error("принят несуществующий файл")
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !KeyFilePermsOK(info) {
		t.Error("0600 должны считаться допустимыми правами ключа")
	}
	if err := os.Chmod(p, 0o640); err != nil { //nolint:gosec // G302: тест проверяет, что слишком широкие права ключа обнаруживаются
		t.Fatal(err)
	}
	if info, err = os.Stat(p); err != nil {
		t.Fatal(err)
	}
	if KeyFilePermsOK(info) {
		t.Error("0640 не должны считаться допустимыми правами ключа")
	}
}

func TestPKIValidity(t *testing.T) {
	now := time.Now()
	if _, err := NewCA("x", 0, now); err == nil {
		t.Error("принят нулевой срок")
	}
	if _, err := NewCA("x", MaxCertValidity+time.Hour, now); err == nil {
		t.Error("принят слишком долгий срок")
	}
	ca, err := NewCA("x", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ca.IssueServer(nil, time.Hour, now); err == nil {
		t.Error("принят сертификат без имён")
	}
	if _, _, err := ca.IssueServer([]string{"a"}, -time.Hour, now); err == nil {
		t.Error("принят отрицательный срок")
	}
	// Истёкший сертификат клиент не принимает.
	past := now.Add(-2 * time.Hour)
	oldCA, err := NewCA("old", time.Hour, past)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := oldCA.IssueServer([]string{"127.0.0.1"}, time.Hour, past)
	if err != nil {
		t.Fatal(err)
	}
	srv, cli := configs(t, oldCA.CertPEM(), certPEM, keyPEM)
	if _, err := handshake(t, srv, cli); err == nil {
		t.Fatal("клиент принял истёкший сертификат")
	}
}
