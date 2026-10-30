package shadowai

import (
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// ErrCatalogDate — дата каталога вне срока заверения рабочего ключа.
var ErrCatalogDate = servicedb.ErrDate

// DBKind — вид служебной базы «каталог ИИ-сервисов» (ADR-0028, п. 1):
// содержимое — YAML каталога, разбор — ParseCatalog.
func DBKind() servicedb.Kind {
	return servicedb.Kind{Name: CatalogKind, Title: "Каталог ИИ-сервисов", Parse: func(b []byte) (servicedb.Content, error) {
		c, err := ParseCatalog(b)
		if err != nil {
			return servicedb.Content{}, err
		}
		return servicedb.Content{Value: c, Version: c.Version, Date: c.Day(), Records: len(c.Services)}, nil
	}}
}

// SignedCatalog — проверенный каталог и сведения о подписи.
type SignedCatalog struct {
	Catalog     *Catalog
	Endorsement aisecCrypto.Endorsement
	// Fingerprint — отпечаток рабочего ключа (как у ключа производителя).
	Fingerprint string
}

func signedCatalog(v servicedb.Verified) SignedCatalog {
	c, _ := v.Content.Value.(*Catalog)
	return SignedCatalog{Catalog: c, Endorsement: v.Endorsement, Fingerprint: v.Fingerprint}
}

// VerifyCatalog проверяет подписанный файл каталога ключом производителя
// vendor и разбирает содержимое (ADR-0027, п. 3; ADR-0028). at — момент
// проверки срока заверения: время загрузки; нулевой — уже загруженный
// каталог (срок не проверяется, но дата каталога должна попадать в срок
// заверения).
func VerifyCatalog(p aisecCrypto.Provider, vendor aisecCrypto.Verifier, data []byte, at time.Time) (SignedCatalog, error) {
	v, err := servicedb.Verify(p, vendor, DBKind(), data, at)
	if err != nil {
		return SignedCatalog{}, err
	}
	return signedCatalog(v), nil
}

// VerifyCatalogFile — VerifyCatalog встроенным ключом производителя.
func VerifyCatalogFile(p aisecCrypto.Provider, data []byte, at time.Time) (SignedCatalog, error) {
	vendor, err := servicedb.EmbeddedVendor(p)
	if err != nil {
		return SignedCatalog{}, err
	}
	return VerifyCatalog(p, vendor, data, at)
}
