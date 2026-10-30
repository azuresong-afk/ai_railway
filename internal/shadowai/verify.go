package shadowai

import (
	"errors"
	"fmt"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// ErrCatalogDate — дата каталога вне срока заверения рабочего ключа.
var ErrCatalogDate = errors.New("каталог: дата выпуска вне срока заверения рабочего ключа")

// SignedCatalog — проверенный каталог и сведения о подписи.
type SignedCatalog struct {
	Catalog     *Catalog
	Endorsement aisecCrypto.Endorsement
	// Fingerprint — отпечаток рабочего ключа (как у ключа производителя).
	Fingerprint string
}

// VerifyCatalogFile проверяет подписанный файл каталога встроенным ключом
// производителя и разбирает содержимое (ADR-0027, п. 3). at — момент
// проверки срока заверения: время загрузки; нулевой — уже загруженный
// каталог (срок не проверяется, но дата каталога должна попадать в срок
// заверения).
func VerifyCatalogFile(p aisecCrypto.Provider, data []byte, at time.Time) (SignedCatalog, error) {
	vendor, _, err := integrity.EmbeddedVerifier(p)
	if err != nil {
		return SignedCatalog{}, err
	}
	return VerifyCatalog(p, vendor, data, at)
}

// VerifyCatalog — VerifyCatalogFile с заданным ключом производителя
// (инструмент подписи проверяет готовый файл ключом из -vendor-pub).
func VerifyCatalog(p aisecCrypto.Provider, vendor aisecCrypto.Verifier, data []byte, at time.Time) (SignedCatalog, error) {
	db, err := aisecCrypto.VerifyServiceDB(p, vendor, data, CatalogKind, aisecCrypto.EndorsementCheck{At: at, Revoked: integrity.RevokedServiceDB})
	if err != nil {
		return SignedCatalog{}, err
	}
	c, err := ParseCatalog(db.Payload)
	if err != nil {
		return SignedCatalog{}, err
	}
	// Дата каталога — сутки выпуска: заверение должно действовать хотя бы
	// в часть этих суток.
	e := db.Endorsement
	if c.Day().Add(24*time.Hour).Before(e.NotBefore) || c.Day().After(e.NotAfter) {
		return SignedCatalog{}, ErrCatalogDate
	}
	fp, err := integrity.Fingerprint(p, e.PublicKey)
	if err != nil {
		return SignedCatalog{}, fmt.Errorf("каталог: %w", err)
	}
	return SignedCatalog{Catalog: c, Endorsement: e, Fingerprint: fp}, nil
}

// vendorVerifier — встроенный ключ производителя: тестовый в сборке без
// тега aisec_release, ключ производителя в поставочной (ADR-0022, п. 7).
func vendorVerifier(p aisecCrypto.Provider) (aisecCrypto.Verifier, error) {
	v, _, err := integrity.EmbeddedVerifier(p)
	return v, err
}
