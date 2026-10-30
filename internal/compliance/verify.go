package compliance

import (
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// ErrBaseDate — дата базы вне срока заверения рабочего ключа.
var ErrBaseDate = servicedb.ErrDate

// DBKind — вид служебной базы «база требований» (ADR-0028, п. 1):
// содержимое — YAML базы, разбор — ParseBase. Отзыв ключа — общий список
// integrity.RevokedServiceDB (через servicedb.Verify).
func DBKind() servicedb.Kind {
	return servicedb.Kind{Name: BaseKind, Title: "База требований", Parse: func(b []byte) (servicedb.Content, error) {
		base, err := ParseBase(b)
		if err != nil {
			return servicedb.Content{}, err
		}
		return servicedb.Content{Value: base, Version: base.Version, Date: base.Day(), Records: len(base.Requirements)}, nil
	}}
}

// SignedBase — проверенная база и сведения о подписи.
type SignedBase struct {
	Base        *Base
	Endorsement aisecCrypto.Endorsement
	// Fingerprint — отпечаток рабочего ключа.
	Fingerprint string
}

func signedBase(v servicedb.Verified) SignedBase {
	b, _ := v.Content.Value.(*Base)
	return SignedBase{Base: b, Endorsement: v.Endorsement, Fingerprint: v.Fingerprint}
}

// VerifyBase проверяет подписанный файл базы ключом производителя vendor и
// разбирает содержимое (ADR-0027, п. 3; ADR-0028). at — момент проверки
// срока заверения: время загрузки; нулевой — уже загруженная база (срок не
// проверяется, но дата базы должна попадать в срок заверения).
func VerifyBase(p aisecCrypto.Provider, vendor aisecCrypto.Verifier, data []byte, at time.Time) (SignedBase, error) {
	v, err := servicedb.Verify(p, vendor, DBKind(), data, at)
	if err != nil {
		return SignedBase{}, err
	}
	return signedBase(v), nil
}

// VerifyBaseFile — VerifyBase встроенным ключом производителя.
func VerifyBaseFile(p aisecCrypto.Provider, data []byte, at time.Time) (SignedBase, error) {
	vendor, err := servicedb.EmbeddedVendor(p)
	if err != nil {
		return SignedBase{}, err
	}
	return VerifyBase(p, vendor, data, at)
}
