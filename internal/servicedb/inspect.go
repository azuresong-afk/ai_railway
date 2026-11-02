package servicedb

import (
	"fmt"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// Report — итог проверки файла до загрузки (aisec-cli servicedb inspect,
// ADR-0028, п. 8). Поля содержимого заполнены только у прошедшего проверку
// файла; заверение без проверки показывается и у не прошедшего.
type Report struct {
	Kind  string
	Title string
	// Verified — подпись, заверение, отзыв, срок на момент проверки,
	// содержимое и дата прошли проверку.
	Verified    bool
	Version     uint64
	Date        time.Time
	Records     int
	Endorsement aisecCrypto.Endorsement
	Fingerprint string
	// Reason и Err — причина отказа (пусто у прошедшего проверку).
	Reason string
	Err    error
}

// Inspect проверяет файл базы так же, как его проверит загрузка на момент
// now (кроме сравнения версии с уже загруженной), ключом производителя
// vendor и видами kinds. Ошибка — только у файла, который вовсе не
// разбирается как служебная база.
func Inspect(p aisecCrypto.Provider, vendor aisecCrypto.Verifier, kinds []Kind, data []byte, now time.Time) (Report, error) {
	raw, err := aisecCrypto.InspectServiceDB(data)
	if err != nil {
		return Report{}, err
	}
	r := Report{Kind: raw.Kind, Endorsement: raw.Endorsement}
	if fp, err := integrity.Fingerprint(p, raw.Endorsement.PublicKey); err == nil {
		r.Fingerprint = fp
	}
	var k *Kind
	for i := range kinds {
		if kinds[i].Name == raw.Kind {
			k = &kinds[i]
			break
		}
	}
	if k == nil {
		r.Reason, r.Err = ReasonKind, ErrUnknownKind
		return r, nil
	}
	r.Title = k.Title
	v, err := Verify(p, vendor, *k, data, now)
	if err != nil {
		r.Reason, r.Err = Reason(err), err
		return r, nil
	}
	r.Verified, r.Version, r.Date, r.Records = true, v.Content.Version, v.Content.Date, v.Content.Records
	r.Endorsement, r.Fingerprint = v.Endorsement, v.Fingerprint
	return r, nil
}

// KindByName — вид из списка; нет — ErrUnknownKind.
func KindByName(kinds []Kind, name string) (Kind, error) {
	for _, k := range kinds {
		if k.Name == name {
			return k, nil
		}
	}
	return Kind{}, fmt.Errorf("%w: %q", ErrUnknownKind, name)
}
