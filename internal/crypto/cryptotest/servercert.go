package cryptotest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// ChainOptions — параметры синтетической цепочки сертификата заказчика
// (задача 3.27): корень → промежуточный УЦ → сертификат шлюза.
type ChainOptions struct {
	// Hosts — имена и IP-адреса в SAN сертификата шлюза.
	Hosts []string
	// NotBefore и NotAfter сертификата шлюза; нулевые — сейчас ± 1 год.
	NotBefore, NotAfter time.Time
	// LeafRSABits — ключ шлюза RSA этого размера; 0 — ECDSA LeafCurve.
	LeafRSABits int
	// LeafCurve — кривая ключа шлюза; nil — P-256.
	LeafCurve elliptic.Curve
	// ClientAuthOnly — у сертификата шлюза назначение только clientAuth.
	ClientAuthOnly bool
	// LeafKeyUsage — keyUsage сертификата шлюза; 0 — digitalSignature и
	// keyEncipherment.
	LeafKeyUsage x509.KeyUsage
	// LeafOrg — поле O имени владельца (для проверки пределов).
	LeafOrg string
	// LeafSerial — серийный номер сертификата шлюза; nil — по счётчику.
	LeafSerial *big.Int
}

// Chain — синтетическая цепочка в PEM и ключ шлюза в PKCS#8 PEM.
type Chain struct {
	Root, Intermediate, Leaf []byte
	Key                      []byte
}

// Full — лист, промежуточный и корень одним файлом.
func (c Chain) Full() []byte {
	out := append([]byte{}, c.Leaf...)
	out = append(out, c.Intermediate...)
	return append(out, c.Root...)
}

// NewChain выпускает цепочку: корень и промежуточный УЦ — ECDSA P-256 на
// два года вокруг текущего момента.
func NewChain(o ChainOptions) (Chain, error) {
	now := time.Now()
	if o.NotBefore.IsZero() {
		o.NotBefore = now.Add(-24 * time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = now.Add(365 * 24 * time.Hour)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Chain{}, err
	}
	root, rootCert, err := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "Тестовый корневой УЦ"}, IsCA: true,
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(2 * 365 * 24 * time.Hour)}, nil, rootKey.Public(), rootKey)
	if err != nil {
		return Chain{}, err
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Chain{}, err
	}
	inter, interCert, err := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "Тестовый промежуточный УЦ"}, IsCA: true,
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(2 * 365 * 24 * time.Hour)}, rootCert, interKey.Public(), rootKey)
	if err != nil {
		return Chain{}, err
	}
	var leafKey crypto.Signer
	if o.LeafRSABits > 0 {
		leafKey, err = rsa.GenerateKey(rand.Reader, o.LeafRSABits)
	} else {
		curve := o.LeafCurve
		if curve == nil {
			curve = elliptic.P256()
		}
		leafKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	}
	if err != nil {
		return Chain{}, err
	}
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "шлюз"}, NotBefore: o.NotBefore, NotAfter: o.NotAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: o.LeafKeyUsage, SerialNumber: o.LeafSerial}
	if o.LeafOrg != "" {
		tmpl.Subject.Organization = []string{o.LeafOrg}
	}
	if o.ClientAuthOnly {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	for _, h := range o.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	leaf, _, err := issue(tmpl, interCert, leafKey.Public(), interKey)
	if err != nil {
		return Chain{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return Chain{}, err
	}
	return Chain{Root: root, Intermediate: inter, Leaf: leaf, Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}, nil
}

var serial int64

// issue подписывает tmpl ключом signer от имени parent (nil — самоподписанный).
func issue(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) ([]byte, *x509.Certificate, error) {
	serial++
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(serial)
	}
	switch {
	case tmpl.IsCA:
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	case tmpl.KeyUsage == 0:
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("тестовый сертификат: %w", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c, nil
}
