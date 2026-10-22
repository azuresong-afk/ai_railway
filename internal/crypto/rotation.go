package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Ротация корня внутреннего УЦ и перевыпуск сертификатов шлюзов (ADR-0018,
// п. 6): корни передаются шлюзам в заявлении о доверии в DER, шлюз
// проверяет новый сертификат по ним и переключает клиент TLS без
// перезапуска.

// MaxRootDER — предел корневого сертификата в DER: P-256 — меньше 1 КиБ.
const MaxRootDER = 4 << 10

// CertDER — содержимое единственного блока CERTIFICATE.
func CertDER(certPEM []byte) ([]byte, error) {
	if len(certPEM) > maxPEMFile {
		return nil, fmt.Errorf("сертификат больше %d байт", maxPEMFile)
	}
	der, err := singlePEM(certPEM, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("сертификат: %w", err)
	}
	return der, nil
}

// CertPEMFromDER кодирует сертификат в PEM.
func CertPEMFromDER(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// CertDER — сертификат УЦ в DER.
func (ca *CA) CertDER() []byte { return append([]byte(nil), ca.der...) }

// CheckRootDER строго проверяет корень из заявления о доверии: размер,
// самоподписанный УЦ с правом подписи сертификатов. Возвращает срок
// действия сертификата.
func CheckRootDER(der []byte) (time.Time, error) {
	if len(der) == 0 || len(der) > MaxRootDER {
		return time.Time{}, fmt.Errorf("корень УЦ: от 1 до %d байт", MaxRootDER)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return time.Time{}, errors.New("корень УЦ: неверная структура")
	}
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return time.Time{}, errors.New("корень УЦ: не сертификат удостоверяющего центра")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return time.Time{}, errors.New("корень УЦ: не самоподписанный")
	}
	return cert.NotAfter, nil
}

// VerifyClientCert проверяет новый сертификат шлюза перед переключением:
// пара с ключом keyPEM, имя commonName, назначение clientAuth и, если
// rootsDER не пуст, цепочка к одному из корней на момент now.
func VerifyClientCert(certPEM, keyPEM []byte, commonName string, rootsDER [][]byte, now time.Time) error {
	if len(certPEM) > maxPEMFile || len(keyPEM) > maxPEMFile {
		return errors.New("сертификат или ключ слишком большой")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("сертификат не подходит к ключу: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("сертификат: неверная структура")
	}
	if cert.Subject.CommonName != commonName {
		return errors.New("сертификат выдан на другое имя")
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("сертификат ещё не действует или истёк")
	}
	if len(rootsDER) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, der := range rootsDER {
		root, err := x509.ParseCertificate(der)
		if err != nil {
			return errors.New("корень УЦ: неверная структура")
		}
		pool.AddCert(root)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("сертификат не выпущен корнем из заявления о доверии")
	}
	return nil
}

// ClientCertSwitch — клиентский сертификат mTLS, который можно заменить без
// пересоздания транспорта: новые рукопожатия берут текущую пару.
type ClientCertSwitch struct {
	cur atomic.Pointer[tls.Certificate]
}

// NewClientCertSwitch — переключатель с начальной парой.
func NewClientCertSwitch(certPEM, keyPEM []byte) (*ClientCertSwitch, error) {
	s := &ClientCertSwitch{}
	if err := s.Set(certPEM, keyPEM); err != nil {
		return nil, err
	}
	return s, nil
}

// Set заменяет пару; неверная пара — ошибка, прежняя остаётся.
func (s *ClientCertSwitch) Set(certPEM, keyPEM []byte) error {
	if len(certPEM) > maxPEMFile || len(keyPEM) > maxPEMFile {
		return errors.New("TLS: сертификат или ключ слишком большой")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("TLS: сертификат и ключ клиента: %w", err)
	}
	s.cur.Store(&pair)
	return nil
}

// SwitchClientConfig — клиент mTLS, доверяющий rootsPEM, с сертификатом из
// переключателя (шлюз после перевыпуска, ADR-0018, п. 6.3).
func SwitchClientConfig(tp TLSProvider, rootsPEM []byte, sw *ClientCertSwitch) (*tls.Config, error) {
	if sw == nil || sw.cur.Load() == nil {
		return nil, errors.New("TLS: нет сертификата клиента")
	}
	cfg, err := tp.ClientConfig(rootsPEM)
	if err != nil {
		return nil, err
	}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return sw.cur.Load(), nil
	}
	return cfg, nil
}

// RootPoolPEM — несколько корней одним PEM для MutualServerConfig.
func RootPoolPEM(rootsDER [][]byte) []byte {
	var out []byte
	for _, der := range rootsDER {
		out = append(out, CertPEMFromDER(der)...)
	}
	return out
}
