package compliance

import (
	"errors"
	"fmt"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// ErrBaseDate — дата базы вне срока заверения рабочего ключа.
var ErrBaseDate = errors.New("база требований: дата выпуска вне срока заверения рабочего ключа")

// SignedBase — проверенная база и сведения о подписи.
type SignedBase struct {
	Base        *Base
	Endorsement aisecCrypto.Endorsement
	// Fingerprint — отпечаток рабочего ключа.
	Fingerprint string
}

// VerifyBaseFile проверяет подписанный файл базы встроенным ключом
// производителя и разбирает содержимое (ADR-0027, п. 3). at — момент
// проверки срока заверения: время загрузки; нулевой — уже загруженная
// база (срок не проверяется, но дата базы должна попадать в срок заверения).
func VerifyBaseFile(p aisecCrypto.Provider, data []byte, at time.Time) (SignedBase, error) {
	vendor, _, err := integrity.EmbeddedVerifier(p)
	if err != nil {
		return SignedBase{}, err
	}
	return VerifyBase(p, vendor, data, at)
}

// VerifyBase — VerifyBaseFile с заданным ключом производителя (инструмент
// подписи проверяет готовый файл ключом из -vendor-pub). Подпись, заверение
// и вид проверяет только internal/crypto.
func VerifyBase(p aisecCrypto.Provider, vendor aisecCrypto.Verifier, data []byte, at time.Time) (SignedBase, error) {
	db, err := aisecCrypto.VerifyServiceDB(p, vendor, data, BaseKind, aisecCrypto.EndorsementCheck{At: at, Revoked: integrity.RevokedServiceDB})
	if err != nil {
		return SignedBase{}, err
	}
	b, err := ParseBase(db.Payload)
	if err != nil {
		return SignedBase{}, err
	}
	// Дата базы — сутки выпуска: заверение должно действовать хотя бы в
	// часть этих суток.
	e := db.Endorsement
	if b.Day().Add(24*time.Hour).Before(e.NotBefore) || b.Day().After(e.NotAfter) {
		return SignedBase{}, ErrBaseDate
	}
	fp, err := integrity.Fingerprint(p, e.PublicKey)
	if err != nil {
		return SignedBase{}, fmt.Errorf("база требований: %w", err)
	}
	return SignedBase{Base: b, Endorsement: e, Fingerprint: fp}, nil
}

func vendorVerifier(p aisecCrypto.Provider) (aisecCrypto.Verifier, error) {
	v, _, err := integrity.EmbeddedVerifier(p)
	return v, err
}
