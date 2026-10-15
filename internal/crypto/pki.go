package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Внутренний УЦ: сертификаты для TLS и mTLS между компонентами (ТЗ, 4.2, 10.4).
// На этапе 0 используется для стенда разработки (tools/devcerts), на этапе 2 —
// в aisec-cli init. Ключи — ECDSA P-256 (профиль standard).

// MaxCertValidity ограничивает срок действия выпускаемых сертификатов.
const MaxCertValidity = 825 * 24 * time.Hour

// Ограничения на имена в сертификатах.
const (
	maxHosts    = 32
	maxHostLen  = 253 // длина DNS-имени (RFC 1035)
	maxCNLength = 64  // ub-common-name (RFC 5280)
)

// CA — удостоверяющий центр в памяти.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

// NewCA создаёт самоподписанный УЦ.
func NewCA(commonName string, validity time.Duration, now time.Time) (*CA, error) {
	if err := checkValidity(validity); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ключ УЦ: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("сертификат УЦ: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, der: der}, nil
}

// CertPEM — сертификат УЦ в PEM (для списка доверенных корневых).
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
}

// IssueServer выпускает серверный сертификат для указанных имён и адресов.
// Возвращает сертификат и закрытый ключ в PEM.
func (ca *CA) IssueServer(hosts []string, validity time.Duration, now time.Time) (certPEM, keyPEM []byte, err error) {
	if err := checkHosts(hosts); err != nil {
		return nil, nil, err
	}
	if err := checkValidity(validity); err != nil {
		return nil, nil, err
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.cert.NotAfter) {
		// Сертификат не может жить дольше УЦ, который его выпустил.
		notAfter = ca.cert.NotAfter
	}
	cn := hosts[0]
	if len(cn) > maxCNLength {
		cn = cn[:maxCNLength]
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ключ сервера: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("сертификат сервера: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// checkHosts проверяет имена и адреса для серверного сертификата.
func checkHosts(hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("не указано ни одного имени или адреса")
	}
	if len(hosts) > maxHosts {
		return fmt.Errorf("больше %d имён и адресов", maxHosts)
	}
	for _, h := range hosts {
		switch {
		case h == "" || strings.TrimSpace(h) != h:
			return fmt.Errorf("пустое имя или имя с пробелами: %q", h)
		case len(h) > maxHostLen:
			return fmt.Errorf("имя длиннее %d символов", maxHostLen)
		case strings.Contains(h, "*"):
			return fmt.Errorf("шаблонные имена запрещены: %q", h)
		}
	}
	return nil
}

func checkValidity(d time.Duration) error {
	if d <= 0 || d > MaxCertValidity {
		return fmt.Errorf("срок действия сертификата должен быть от 0 до %s", MaxCertValidity)
	}
	return nil
}

// newSerial — случайный 128-битный серийный номер (RFC 5280, не больше 20 байт).
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("серийный номер: %w", err)
	}
	return s.Add(s, big.NewInt(1)), nil
}
