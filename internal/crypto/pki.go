package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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

// CA — удостоверяющий центр в памяти. При выводе через fmt и slog
// показывается только имя алгоритма: закрытый ключ не попадёт в логи.
type CA struct {
	redacted
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
	return &CA{redacted: caName, cert: cert, key: key, der: der}, nil
}

var caName = redacted{"ECDSA P-256 CA"}

// LoadCA восстанавливает УЦ из файлов aisec-cli init (Р8): сертификат в PEM и
// закрытый ключ PKCS#8 в PEM. Проверяется, что сертификат — УЦ с правом
// подписи сертификатов, ключ — ECDSA P-256 и соответствует сертификату.
// Срок действия не проверяется здесь: его проверяет выпуск (IssueServer).
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	if len(certPEM) > maxPEMFile || len(keyPEM) > maxPEMFile {
		return nil, fmt.Errorf("УЦ: файл больше %d байт", maxPEMFile)
	}
	der, err := singlePEM(certPEM, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("сертификат УЦ: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("сертификат УЦ: %w", err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("сертификат УЦ: не сертификат удостоверяющего центра")
	}
	// Корневой УЦ подписан своим ключом: иначе это чужой сертификат с
	// подложенными расширениями.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, errors.New("сертификат УЦ: не самоподписанный")
	}
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || certKey.Curve != elliptic.P256() {
		return nil, errors.New("сертификат УЦ: ключ не ECDSA P-256")
	}
	keyDER, err := singlePEM(keyPEM, "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("ключ УЦ: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, errors.New("ключ УЦ: не PKCS#8") // подробности разбора ключа не выводятся
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("ключ УЦ: не ECDSA P-256")
	}
	if !key.PublicKey.Equal(certKey) {
		return nil, errors.New("ключ УЦ не соответствует сертификату")
	}
	return &CA{redacted: caName, cert: cert, key: key, der: cert.Raw}, nil
}

// singlePEM возвращает содержимое единственного блока PEM типа typ.
func singlePEM(data []byte, typ string) ([]byte, error) {
	if !startsWithPEM(data) {
		return nil, errors.New("данные перед блоком PEM или нет блока")
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("нет блока PEM")
	}
	if block.Type != typ || len(block.Headers) != 0 {
		return nil, fmt.Errorf("ожидается блок %s без заголовков", typ)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("данные после блока PEM")
	}
	return block.Bytes, nil
}

// KeyPEM — закрытый ключ УЦ в PKCS#8 PEM для файла 0400 (ТЗ, 10.4). Не
// логируется и не передаётся по сети.
func (ca *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// NotAfter — окончание срока действия сертификата УЦ.
func (ca *CA) NotAfter() time.Time { return ca.cert.NotAfter }

// CertPEM — сертификат УЦ в PEM (для списка доверенных корневых).
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
}

// Fingerprint — отпечаток SHA-256 сертификата УЦ в том виде, в каком его
// показывают браузеры и certutil: шестнадцатеричные байты в верхнем
// регистре через двоеточие. По нему администратор сверяет корень, который
// добавляет в доверенные.
func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
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
	if !now.Before(ca.cert.NotAfter) {
		return nil, nil, errors.New("срок действия сертификата УЦ истёк")
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
