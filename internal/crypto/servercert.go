package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Сертификат заказчика для адреса шлюза (S1, ТЗ 5.4; решение Р9 этапа 3,
// задача 3.27): администратор загружает цепочку и закрытый ключ в PEM,
// сервер и шлюз проверяют их одной функцией ParseServerCert. Своих
// алгоритмов нет: разбор и проверка цепочки — crypto/x509.

// Пределы загружаемого PEM.
const (
	// MaxServerChainPEM — цепочка сертификатов: лист, промежуточные, корень.
	MaxServerChainPEM = 64 << 10
	// MaxServerKeyPEM — закрытый ключ: RSA 8192 в PKCS#1 — около 6,3 КиБ.
	MaxServerKeyPEM = 16 << 10
	// MaxServerChainCerts — сертификатов в цепочке.
	MaxServerChainCerts = 10
	// Пределы сведений о сертификате (те же — в CHECK таблицы gateway_tls).
	maxServerCertName  = 2048
	maxServerCertNames = 1000
	maxServerSerialHex = 64
	// minRSABits и maxRSABits — размер ключа RSA (ТЗ 10.3); верхний предел
	// ограничивает стоимость рукопожатия.
	minRSABits = 2048
	maxRSABits = 8192
)

// ErrCertNotValidNow — сертификат цепочки истёк или ещё не действует.
// Шлюз по нему не отклоняет пакет, а возвращается к своему сертификату:
// иначе после перезапуска без связи с сервером он остался бы без
// конфигурации.
var ErrCertNotValidNow = errors.New("сертификат истёк или ещё не действует")

// ServerCert — проверенный сертификат заказчика: сведения для консоли и
// цепочка в каноническом виде (лист, промежуточные, корень).
type ServerCert struct {
	Subject     string
	Issuer      string
	Serial      string
	NotBefore   time.Time
	NotAfter    time.Time
	DNSNames    []string
	IPAddresses []string
	// KeyAlg — «RSA 2048», «ECDSA P-256»…
	KeyAlg string
	// Fingerprint — SHA-256 листового сертификата в DER, hex.
	Fingerprint string
	// ChainLen — сертификатов в цепочке с корнем.
	ChainLen int
	ChainPEM []byte
}

// NormalizeHost проверяет имя адреса шлюза: DNS-имя из букв, цифр и «-»
// (метки до 63 символов, всего до 253, без шаблона «*» и точки в конце)
// или IP-адрес. Возвращает имя в нижнем регистре.
func NormalizeHost(host string) (string, error) {
	h := strings.ToLower(host)
	if h == "" || len(h) > maxHostLen {
		return "", fmt.Errorf("имя адреса шлюза — от 1 до %d символов", maxHostLen)
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("IP-адрес шлюза — без зоны")
		}
		return ip.String(), nil
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("имя адреса шлюза — DNS-имя (метки из латиницы, цифр и «-», без «*») или IP-адрес")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errors.New("имя адреса шлюза — DNS-имя (метки из латиницы, цифр и «-», без «*») или IP-адрес")
			}
		}
	}
	return h, nil
}

// ParseServerCert строго разбирает и проверяет недоверенные цепочку и ключ:
// размеры; в файле цепочки только блоки CERTIFICATE, в файле ключа ровно
// один незашифрованный ключ (PKCS#8, PKCS#1 или SEC 1); ключ — RSA от 2048
// бит или ECDSA P-256/P-384; один из сертификатов — пара ключу (лист);
// имя host есть в SAN листа; все сертификаты действуют на now; цепочка
// строится от листа до самоподписанного корня из загруженных и подходит
// для TLS-сервера; лишних сертификатов нет. Возвращает сведения и ключ в
// PKCS#8 PEM (вызывающий затирает его). Тексты ошибок — для пользователя,
// без ключевого материала. Покрыт fuzz-тестом FuzzParseServerCert.
func ParseServerCert(chainPEM, keyPEM []byte, host string, now time.Time) (ServerCert, []byte, error) {
	host, err := NormalizeHost(host)
	if err != nil {
		return ServerCert{}, nil, err
	}
	if len(chainPEM) == 0 || len(chainPEM) > MaxServerChainPEM {
		return ServerCert{}, nil, fmt.Errorf("цепочка сертификатов — от 1 байта до %d КиБ", MaxServerChainPEM>>10)
	}
	if len(keyPEM) == 0 || len(keyPEM) > MaxServerKeyPEM {
		return ServerCert{}, nil, fmt.Errorf("закрытый ключ — от 1 байта до %d КиБ", MaxServerKeyPEM>>10)
	}
	certs, err := parseCertBlocks(chainPEM)
	if err != nil {
		return ServerCert{}, nil, err
	}
	key, err := parseServerKey(keyPEM)
	if err != nil {
		return ServerCert{}, nil, err
	}
	leafIdx := -1
	for i, c := range certs {
		if publicKeyMatches(c.PublicKey, key) {
			leafIdx = i
			break
		}
	}
	if leafIdx < 0 {
		return ServerCert{}, nil, errors.New("закрытый ключ не подходит ни к одному сертификату цепочки")
	}
	leaf := certs[leafIdx]
	// x509.Verify проверяет только расширенное назначение (EKU): лист с
	// keyUsage без digitalSignature TLS-клиенты отвергнут (обмен ключами —
	// только ECDHE, ключ сервера подписывает).
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return ServerCert{}, nil, errors.New("в сертификате шлюза не разрешена цифровая подпись (keyUsage digitalSignature): для TLS-сервера он не подходит")
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return ServerCert{}, nil, fmt.Errorf("сертификат выдан не на имя %s: имена в сертификате — %s", host, namesOf(leaf))
	}
	for _, c := range certs {
		if now.Before(c.NotBefore) {
			return ServerCert{}, nil, fmt.Errorf("%w: «%s» действует с %s", ErrCertNotValidNow, certName(c), c.NotBefore.UTC().Format(time.DateOnly))
		}
		if !now.Before(c.NotAfter) {
			return ServerCert{}, nil, fmt.Errorf("%w: «%s» истёк %s", ErrCertNotValidNow, certName(c), c.NotAfter.UTC().Format(time.DateOnly))
		}
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	haveRoot := false
	for i, c := range certs {
		if i == leafIdx && len(certs) > 1 {
			continue
		}
		if selfSigned(c) {
			roots.AddCert(c)
			haveRoot = true
		} else {
			inter.AddCert(c)
		}
	}
	if !haveRoot {
		return ServerCert{}, nil, errors.New("в цепочке нет корневого (самоподписанного) сертификата: добавьте промежуточные и корневой сертификаты УЦ")
	}
	paths, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		var ua x509.UnknownAuthorityError
		var inv x509.CertificateInvalidError
		switch {
		case errors.As(err, &ua):
			return ServerCert{}, nil, errors.New("цепочка не доходит до корневого сертификата: не хватает промежуточного сертификата УЦ")
		case errors.As(err, &inv) && inv.Reason == x509.IncompatibleUsage:
			return ServerCert{}, nil, errors.New("сертификат не предназначен для TLS-сервера (нет назначения serverAuth)")
		}
		return ServerCert{}, nil, errors.New("цепочка сертификатов не проходит проверку: проверьте порядок выпуска и ограничения УЦ")
	}
	path := shortest(paths)
	if len(path) != len(certs) {
		return ServerCert{}, nil, errors.New("в цепочке есть сертификаты, не входящие в путь от сертификата шлюза до корня: удалите их")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ServerCert{}, nil, errors.New("закрытый ключ не кодируется в PKCS#8")
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	clear(keyDER)
	var chain []byte
	for _, c := range path {
		chain = append(chain, CertPEMFromDER(c.Raw)...)
	}
	sum := sha256.Sum256(leaf.Raw)
	sc := ServerCert{Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), Serial: leaf.SerialNumber.Text(16),
		NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(), DNSNames: append([]string{}, leaf.DNSNames...),
		IPAddresses: []string{}, KeyAlg: keyAlg(leaf.PublicKey), Fingerprint: hex.EncodeToString(sum[:]),
		ChainLen: len(path), ChainPEM: chain}
	for _, ip := range leaf.IPAddresses {
		sc.IPAddresses = append(sc.IPAddresses, ip.String())
	}
	// Срок цепочки — самый ранний из сроков её сертификатов.
	for _, c := range path {
		if c.NotAfter.Before(sc.NotAfter) {
			sc.NotAfter = c.NotAfter.UTC()
		}
	}
	if err := checkServerCertLimits(sc); err != nil {
		clear(keyOut)
		return ServerCert{}, nil, err
	}
	return sc, keyOut, nil
}

// checkServerCertLimits — пределы сведений о сертификате и канонической
// цепочки (перекодирование в PEM по 64 символа может увеличить её размер).
func checkServerCertLimits(sc ServerCert) error {
	switch {
	case len(sc.ChainPEM) > MaxServerChainPEM:
		return fmt.Errorf("цепочка сертификатов в стандартной записи PEM больше %d КиБ", MaxServerChainPEM>>10)
	case utf8.RuneCountInString(sc.Subject) > maxServerCertName || utf8.RuneCountInString(sc.Issuer) > maxServerCertName:
		return fmt.Errorf("имя владельца или издателя сертификата длиннее %d символов", maxServerCertName)
	case strings.HasPrefix(sc.Serial, "-") || len(sc.Serial) > maxServerSerialHex:
		return fmt.Errorf("серийный номер сертификата — положительное число не длиннее %d байт", maxServerSerialHex/2)
	case len(sc.DNSNames) > maxServerCertNames || len(sc.IPAddresses) > maxServerCertNames:
		return fmt.Errorf("в сертификате больше %d имён или адресов", maxServerCertNames)
	}
	return nil
}

// parseCertBlocks — только блоки CERTIFICATE без заголовков, от 1 до
// MaxServerChainCerts, без данных вне блоков; ключи сертификатов — не
// слабее minRSABits или ECDSA P-256.
func parseCertBlocks(data []byte) ([]*x509.Certificate, error) {
	rest := data
	var certs []*x509.Certificate
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !startsWithPEM(rest) {
			return nil, errors.New("цепочка: данные вне блоков PEM")
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("цепочка: повреждённый блок PEM")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("цепочка: блок %s — в файле цепочки только сертификаты (BEGIN CERTIFICATE)", truncate(block.Type, 40))
		}
		if len(certs) == MaxServerChainCerts {
			return nil, fmt.Errorf("цепочка: больше %d сертификатов", MaxServerChainCerts)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("цепочка: сертификат %d не разбирается (поддерживаются RSA и ECDSA)", len(certs)+1)
		}
		if err := checkCertKey(c.PublicKey, false); err != nil {
			return nil, fmt.Errorf("цепочка: сертификат «%s»: %w", certName(c), err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("цепочка: нет ни одного сертификата")
	}
	return certs, nil
}

// parseServerKey — ровно один блок незашифрованного закрытого ключа.
func parseServerKey(data []byte) (crypto.Signer, error) {
	if !startsWithPEM(data) {
		return nil, errors.New("ключ: данные перед блоком PEM или нет блока")
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("ключ: повреждённый блок PEM")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("ключ: в файле ключа должен быть ровно один блок PEM — уберите сертификаты и другие ключи")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "" {
		return nil, errors.New("ключ зашифрован паролем: выгрузите его без пароля (например, openssl pkey -in key.pem -out plain.pem)")
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("ключ: блок PEM с заголовками не поддерживается")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("ключ: блок %s — ожидается закрытый ключ (BEGIN PRIVATE KEY)", truncate(block.Type, 40))
	}
	clear(block.Bytes)
	if err != nil {
		return nil, errors.New("ключ: неверная структура закрытого ключа")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("ключ: поддерживаются только RSA и ECDSA")
	}
	if err := checkCertKey(signer.Public(), true); err != nil {
		return nil, fmt.Errorf("ключ: %w", err)
	}
	if k, ok := signer.(*rsa.PrivateKey); ok {
		if err := k.Validate(); err != nil {
			return nil, errors.New("ключ: неверный ключ RSA")
		}
	}
	return signer, nil
}

// checkCertKey — RSA от minRSABits до maxRSABits или ECDSA: у ключа
// шлюза — P-256 или P-384, у УЦ — ещё и P-521.
func checkCertKey(pub any, leaf bool) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if n := k.N.BitLen(); n < minRSABits || n > maxRSABits {
			return fmt.Errorf("слабый или слишком большой ключ RSA (%d бит): нужно от %d до %d", n, minRSABits, maxRSABits)
		}
		return nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384():
			return nil
		case elliptic.P521():
			if !leaf {
				return nil
			}
		}
		return errors.New("ключ ECDSA — только на кривых P-256 и P-384")
	}
	return errors.New("поддерживаются только ключи RSA и ECDSA")
}

func publicKeyMatches(pub any, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := key.Public().(equaler)
	return ok && e.Equal(pub)
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
}

// shortest — самый короткий из построенных путей.
func shortest(paths [][]*x509.Certificate) []*x509.Certificate {
	best := paths[0]
	for _, p := range paths[1:] {
		if len(p) < len(best) {
			best = p
		}
	}
	return best
}

func keyAlg(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	}
	return "неизвестный"
}

func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return truncate(c.Subject.CommonName, 64)
	}
	return truncate(c.Subject.String(), 64)
}

func namesOf(c *x509.Certificate) string {
	var names []string
	names = append(names, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		return "нет имён в SAN"
	}
	if len(names) > 10 {
		names = append(names[:10], fmt.Sprintf("и ещё %d", len(names)-10))
	}
	return truncate(strings.Join(names, ", "), 600)
}

// ServerPair — пара для TLS-сервера, готовая к переключению: лист и
// промежуточные сертификаты (корень клиенту не передаётся) и ключ.
type ServerPair struct {
	cert *tls.Certificate
	// Fingerprint — SHA-256 листового сертификата, hex.
	Fingerprint string
}

// NewServerPair готовит пару из проверенной ParseServerCert цепочки и
// ключа в PKCS#8 PEM.
func NewServerPair(chainPEM, keyPEM []byte) (*ServerPair, error) {
	if len(chainPEM) > MaxServerChainPEM || len(keyPEM) > MaxServerKeyPEM {
		return nil, errors.New("TLS: цепочка или ключ слишком большие")
	}
	pair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("TLS: цепочка и ключ: %w", err)
	}
	if n := len(pair.Certificate); n > 1 {
		if last, err := x509.ParseCertificate(pair.Certificate[n-1]); err == nil && selfSigned(last) {
			pair.Certificate = pair.Certificate[:n-1]
		}
	}
	sum := sha256.Sum256(pair.Certificate[0])
	return &ServerPair{cert: &pair, Fingerprint: hex.EncodeToString(sum[:])}, nil
}

// ServerCertSwitch — сертификат TLS-сервера, который меняется без
// перезапуска: новые рукопожатия берут текущую пару. Без пары заказчика —
// пара по умолчанию (файлы -tls-cert и -tls-key шлюза).
type ServerCertSwitch struct {
	def    *tls.Certificate
	custom atomic.Pointer[ServerPair]
}

// NewServerCertSwitch — переключатель с парой по умолчанию.
func NewServerCertSwitch(certPEM, keyPEM []byte) (*ServerCertSwitch, error) {
	if len(certPEM) > maxPEMFile || len(keyPEM) > maxPEMFile {
		return nil, errors.New("TLS: сертификат или ключ слишком большой")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("TLS: сертификат и ключ сервера: %w", err)
	}
	return &ServerCertSwitch{def: &pair}, nil
}

// Use включает пару заказчика; nil — возврат к паре по умолчанию.
func (s *ServerCertSwitch) Use(p *ServerPair) { s.custom.Store(p) }

// Current — отпечаток действующей пары заказчика; пусто — пара по умолчанию.
func (s *ServerCertSwitch) Current() string {
	if p := s.custom.Load(); p != nil {
		return p.Fingerprint
	}
	return ""
}

func (s *ServerCertSwitch) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p := s.custom.Load(); p != nil {
		return p.cert, nil
	}
	return s.def, nil
}

// SwitchServerConfig — настройки TLS-сервера профиля tp с сертификатом из
// переключателя sw.
func SwitchServerConfig(tp TLSProvider, certPEM, keyPEM []byte, sw *ServerCertSwitch) (*tls.Config, error) {
	if sw == nil {
		return nil, errors.New("TLS: нет переключателя сертификата")
	}
	cfg, err := tp.ServerConfig(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	cfg.Certificates = nil
	cfg.GetCertificate = sw.get
	return cfg, nil
}
