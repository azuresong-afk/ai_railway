package license

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// revokedLicenseSerials — отозванные номера заверений рабочих ключей
// лицензий (ADR-0022, п. 2: отзыв — новым выпуском; ADR-0026, п. 2). Номер
// добавляется сюда, и выпуск с ним перестаёт принимать лицензии, подписанные
// этим ключом, в том числе уже загруженные (состояние invalid). Список свой,
// а не общий со служебными базами: отзыв ключа лицензий не задевает каталог
// теневого ИИ.
var revokedLicenseSerials = []uint64{}

func revokedSerial(serial uint64) bool { return slices.Contains(revokedLicenseSerials, serial) }

// ErrIssuedDate — дата выдачи лицензии вне срока заверения рабочего ключа.
var ErrIssuedDate = errors.New("лицензия: дата выдачи вне срока заверения рабочего ключа")

// Signed — проверенная лицензия и сведения о подписи.
type Signed struct {
	License     *License
	Endorsement aisecCrypto.Endorsement
	// Fingerprint — отпечаток рабочего ключа (как у ключа производителя).
	Fingerprint string
	// FileHash — хеш файла лицензии криптопрофилем установки, hex.
	FileHash string
}

// VendorVerifier — встроенный ключ производителя: тестовый в сборке без
// тега aisec_release, ключ производителя в поставочной (ADR-0022, п. 7).
func VendorVerifier(p aisecCrypto.Provider) (aisecCrypto.Verifier, error) {
	v, _, err := integrity.EmbeddedVerifier(p)
	return v, err
}

// Verify проверяет файл лицензии ключом производителя vendor и разбирает
// содержимое (ADR-0026, п. 2). at — момент проверки срока заверения
// рабочего ключа: время загрузки; нулевой — уже загруженная лицензия (срок
// заверения не проверяется, но дата выдачи должна попадать в него).
func Verify(p aisecCrypto.Provider, vendor aisecCrypto.Verifier, data []byte, at time.Time) (Signed, error) {
	sl, err := aisecCrypto.VerifyLicense(p, vendor, data, aisecCrypto.EndorsementCheck{At: at, Revoked: revokedSerial})
	if err != nil {
		return Signed{}, err
	}
	l, err := Parse(sl.Payload)
	if err != nil {
		return Signed{}, err
	}
	if !sl.Endorsement.ValidAt(l.IssuedAt) {
		return Signed{}, ErrIssuedDate
	}
	fp, err := integrity.Fingerprint(p, sl.Endorsement.PublicKey)
	if err != nil {
		return Signed{}, fmt.Errorf("лицензия: %w", err)
	}
	h, err := p.Hasher()
	if err != nil {
		return Signed{}, err
	}
	return Signed{License: l, Endorsement: sl.Endorsement, Fingerprint: fp, FileHash: hex.EncodeToString(h.Sum(data))}, nil
}
