package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Подпись лицензии рабочим ключом производителя (ADR-0026, п. 2). Формат
// повторяет служебную базу (endorsement.go): заверение рабочего ключа с
// назначением license внутри файла и подпись содержимого в своём
// контексте — подпись базы или манифеста нельзя выдать за лицензию.
// Содержимое разбирает internal/license после проверки подписи.

const licenseContext = "aisec-license-v1"

// Пределы файла лицензии.
const (
	// MaxLicenseSize — файл лицензии целиком; содержимое — до MaxLicensePayload.
	MaxLicenseSize    = 16 << 10
	MaxLicensePayload = 8 << 10
)

// Ошибки проверки лицензии. Текст не содержит байтов файла.
var (
	ErrLicenseFormat    = errors.New("лицензия: неверный формат файла")
	ErrLicenseSignature = errors.New("лицензия: подпись неверна")
)

// SignedLicense — содержимое лицензии с проверенной подписью.
type SignedLicense struct {
	Payload     []byte
	Endorsement Endorsement
}

type licenseJSON struct {
	Format      string          `json:"format"`
	Endorsement json.RawMessage `json:"endorsement"`
	License     string          `json:"license"`
	Signature   string          `json:"signature"`
}

func licenseMessage(payload []byte) []byte {
	msg := make([]byte, 0, len(licenseContext)+1+len(payload))
	msg = append(msg, licenseContext+"\n"...)
	return append(msg, payload...)
}

// SignLicense подписывает содержимое лицензии рабочим ключом sub и
// возвращает файл лицензии с заверением внутри (команда sign-license
// инструмента подписи, на машине без сети). Ключ должен совпадать с ключом
// из заверения, назначение заверения — license.
func SignLicense(sub Signer, endorsement, payload []byte) ([]byte, error) {
	if sub == nil {
		return nil, errors.New("лицензия: нет рабочего ключа")
	}
	if CheckLicensePayload(payload) != nil {
		return nil, fmt.Errorf("лицензия: содержимое — объект JSON без повторяющихся ключей, до %d байт", MaxLicensePayload)
	}
	e, err := InspectEndorsement(endorsement)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(e.PublicKey, sub.PublicKey()) {
		return nil, errors.New("лицензия: рабочий ключ не совпадает с ключом из заверения")
	}
	if e.Purpose != PurposeLicense {
		return nil, ErrEndorsementPurpose
	}
	sig, err := sub.Sign(licenseMessage(payload))
	if err != nil {
		return nil, fmt.Errorf("лицензия: %w", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, endorsement); err != nil {
		return nil, ErrEndorsementFormat
	}
	out, err := json.Marshal(licenseJSON{Format: licenseContext, Endorsement: compact.Bytes(),
		License: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		return nil, err
	}
	if len(out) >= MaxLicenseSize {
		return nil, fmt.Errorf("лицензия: файл больше %d байт", MaxLicenseSize)
	}
	return append(out, '\n'), nil
}

// CheckLicensePayload проверяет, что содержимое лицензии — объект JSON без
// повторяющихся ключей на любом уровне и без данных после него (jsonObject):
// разбор полей в internal/license видит то же, что подписал производитель.
func CheckLicensePayload(payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxLicensePayload {
		return ErrLicenseFormat
	}
	if _, err := jsonObject(payload); err != nil {
		return ErrLicenseFormat
	}
	return nil
}

// ParseLicenseFile — части файла лицензии без проверки подписей. Разбор
// строгий: объект без повторяющихся ключей и неизвестных полей.
func ParseLicenseFile(data []byte) (endorsement, payload, sig []byte, err error) {
	if len(data) > MaxLicenseSize {
		return nil, nil, nil, ErrLicenseFormat
	}
	m, err := strictFields(data, []string{"format", "endorsement", "license", "signature"}, nil)
	if err != nil {
		return nil, nil, nil, ErrLicenseFormat
	}
	var j licenseJSON
	for name, dst := range map[string]*string{"format": &j.Format, "license": &j.License, "signature": &j.Signature} {
		if *dst, err = rawStringField(m, name); err != nil {
			return nil, nil, nil, ErrLicenseFormat
		}
	}
	if j.Format != licenseContext {
		return nil, nil, nil, ErrLicenseFormat
	}
	endorsement = m["endorsement"]
	if len(endorsement) == 0 || endorsement[0] != '{' {
		return nil, nil, nil, ErrLicenseFormat
	}
	if payload, err = strictBase64(j.License); err != nil || CheckLicensePayload(payload) != nil {
		return nil, nil, nil, ErrLicenseFormat
	}
	if sig, err = strictBase64(j.Signature); err != nil {
		return nil, nil, nil, ErrLicenseFormat
	}
	return endorsement, payload, sig, nil
}

// VerifyLicense проверяет файл лицензии: заверение рабочего ключа ключом
// производителя vendor (назначение license, срок — на c.At, отзыв), затем
// подпись содержимого рабочим ключом. Содержимое разбирает
// internal/license и сверяет дату выдачи со сроком заверения.
func VerifyLicense(p Provider, vendor Verifier, data []byte, c EndorsementCheck) (SignedLicense, error) {
	c.Purpose = PurposeLicense
	endorsement, payload, sig, err := ParseLicenseFile(data)
	if err != nil {
		return SignedLicense{}, err
	}
	e, v, err := VerifyEndorsement(p, vendor, endorsement, c)
	if err != nil {
		return SignedLicense{}, err
	}
	if !v.Verify(licenseMessage(payload), sig) {
		return SignedLicense{}, ErrLicenseSignature
	}
	return SignedLicense{Payload: payload, Endorsement: e}, nil
}

// InspectLicense — содержимое и заявление без проверки подписей (для показа
// в inspect-license). Доверять результату нельзя.
func InspectLicense(data []byte) (SignedLicense, error) {
	endorsement, payload, _, err := ParseLicenseFile(data)
	if err != nil {
		return SignedLicense{}, err
	}
	e, err := InspectEndorsement(endorsement)
	if err != nil {
		return SignedLicense{}, err
	}
	return SignedLicense{Payload: payload, Endorsement: e}, nil
}
