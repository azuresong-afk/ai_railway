package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// mTLS «шлюз — сервер» (ИАФ.10, решение Р8, ADR-0009): шлюз сам создаёт ключ
// и запрос на сертификат (CSR), внутренний УЦ подписывает запрос. Закрытый
// ключ шлюза не покидает шлюз.

// ClientCertValidity — срок сертификата шлюза по умолчанию.
const ClientCertValidity = 365 * 24 * time.Hour

// maxCSR ограничивает размер CSR в PEM: запрос с ключом P-256 — меньше 1 КиБ.
const maxCSR = 16 << 10

// CertInfo — сведения о выпущенном сертификате для учёта в БД.
type CertInfo struct {
	// Serial — серийный номер в шестнадцатеричном виде, строчными буквами.
	Serial   string
	NotAfter time.Time
}

// PeerIdentity — проверенный клиентский сертификат соединения.
type PeerIdentity struct {
	CommonName string
	Serial     string
	NotAfter   time.Time
	// RootDER — корень проверенной цепочки (только из PeerFromTLS): по нему
	// сервер отказывает сертификатам корня с истёкшим перекрытием (ADR-0018).
	RootDER []byte
}

// NewClientCSR создаёт ключ ECDSA P-256 и CSR с именем commonName. Ключ —
// PKCS#8 PEM для файла 0600 на шлюзе.
func NewClientCSR(commonName string) (keyPEM, csrPEM []byte, err error) {
	if err := checkCommonName(commonName); err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ключ шлюза: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("запрос на сертификат: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return keyPEM, csrPEM, nil
}

// parseCSR — строгий разбор недоверенного CSR: один блок PEM без заголовков,
// верная подпись запроса (владение ключом), ключ только ECDSA P-256. Покрыт
// fuzz-тестом FuzzIssueClient.
func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	if len(csrPEM) > maxCSR {
		return nil, fmt.Errorf("CSR больше %d байт", maxCSR)
	}
	der, err := singlePEM(csrPEM, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, fmt.Errorf("CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errors.New("CSR: неверная структура")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("CSR: неверная подпись запроса")
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("CSR: ключ не ECDSA P-256")
	}
	return csr, nil
}

// CheckCSR проверяет CSR шлюза так же, как IssueClient, без выпуска: сервер
// отклоняет неверный запрос до того, как погасить токен регистрации.
func CheckCSR(csrPEM []byte) error {
	_, err := parseCSR(csrPEM)
	return err
}

// IssueClient подписывает CSR шлюза клиентским сертификатом с именем
// commonName (ID шлюза из БД). Из запроса берётся только открытый ключ:
// имя, альтернативные имена и расширения запроса игнорируются, поэтому
// шлюз не может выпросить себе чужое имя или серверное назначение.
func (ca *CA) IssueClient(csrPEM []byte, commonName string, validity time.Duration, now time.Time) ([]byte, CertInfo, error) {
	if err := checkCommonName(commonName); err != nil {
		return nil, CertInfo{}, err
	}
	if err := checkValidity(validity); err != nil {
		return nil, CertInfo{}, err
	}
	if !now.Before(ca.cert.NotAfter) {
		return nil, CertInfo{}, errors.New("срок действия сертификата УЦ истёк")
	}
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, CertInfo{}, err
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	serial, err := newSerial()
	if err != nil {
		return nil, CertInfo{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, CertInfo{}, fmt.Errorf("сертификат шлюза: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, CertInfo{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CertInfo{Serial: cert.SerialNumber.Text(16), NotAfter: cert.NotAfter}, nil
}

// ParseCertInfo разбирает сертификат в PEM (один блок): шлюз так узнаёт свой
// ID и срок сертификата.
func ParseCertInfo(certPEM []byte) (PeerIdentity, error) {
	if len(certPEM) > maxPEMFile {
		return PeerIdentity{}, fmt.Errorf("сертификат больше %d байт", maxPEMFile)
	}
	der, err := singlePEM(certPEM, "CERTIFICATE")
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("сертификат: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return PeerIdentity{}, errors.New("сертификат: неверная структура")
	}
	return identity(cert), nil
}

// PeerFromTLS возвращает клиентский сертификат соединения, если его цепочка
// проверена при рукопожатии (MutualServerConfig). Непроверенный сертификат
// (PeerCertificates без VerifiedChains) не принимается.
func PeerFromTLS(st *tls.ConnectionState) (PeerIdentity, bool) {
	if st == nil || len(st.VerifiedChains) == 0 || len(st.VerifiedChains[0]) == 0 {
		return PeerIdentity{}, false
	}
	chain := st.VerifiedChains[0]
	id := identity(chain[0])
	id.RootDER = chain[len(chain)-1].Raw
	return id, true
}

func identity(c *x509.Certificate) PeerIdentity {
	return PeerIdentity{CommonName: c.Subject.CommonName, Serial: c.SerialNumber.Text(16), NotAfter: c.NotAfter}
}

// checkCommonName: 1–64 печатных символа ASCII (ID шлюза — UUID).
func checkCommonName(cn string) error {
	if cn == "" || len(cn) > maxCNLength {
		return fmt.Errorf("имя в сертификате: от 1 до %d символов", maxCNLength)
	}
	for i := 0; i < len(cn); i++ {
		if cn[i] < 0x21 || cn[i] > 0x7e {
			return errors.New("имя в сертификате: только печатные символы ASCII без пробелов")
		}
	}
	return nil
}

// MutualServerConfig — настройки сервера внутреннего API: клиент обязан
// предъявить сертификат, выпущенный УЦ clientCAPEM (только им, системное
// хранилище не используется), с назначением clientAuth.
func (t standardTLS) MutualServerConfig(certPEM, keyPEM, clientCAPEM []byte) (*tls.Config, error) {
	cfg, err := t.ServerConfig(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pool, err := rootPool(clientCAPEM)
	if err != nil {
		return nil, err
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	return cfg, nil
}

// ClientCertConfig — настройки клиента с собственным сертификатом (шлюз при
// обращении к внутреннему API сервера).
func (t standardTLS) ClientCertConfig(rootsPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	if len(certPEM) > maxPEMFile || len(keyPEM) > maxPEMFile {
		return nil, errors.New("TLS: сертификат или ключ слишком большой")
	}
	cfg, err := t.ClientConfig(rootsPEM)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("TLS: сертификат и ключ клиента: %w", err)
	}
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}
