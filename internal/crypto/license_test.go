package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

const licensePayload = `{"format":"aisec-license-data-v1","number":1}`

func TestLicenseRoundTrip(t *testing.T) {
	f := newEndorseFixture(t, PurposeLicense)
	file, err := SignLicense(f.sub, f.file, []byte(licensePayload))
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyLicense(f.p, f.vendorVerifier(t), file, EndorsementCheck{At: endorseNow})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != licensePayload || got.Endorsement.Serial != 7 || got.Endorsement.Purpose != PurposeLicense {
		t.Fatalf("лицензия: %+v", got)
	}
	ins, err := InspectLicense(file)
	if err != nil || string(ins.Payload) != licensePayload || ins.Endorsement.Serial != 7 {
		t.Fatalf("inspect: %+v %v", ins, err)
	}
}

func TestLicenseRejects(t *testing.T) {
	f := newEndorseFixture(t, PurposeLicense)
	file, err := SignLicense(f.sub, f.file, []byte(licensePayload))
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(file, &env); err != nil {
		t.Fatal(err)
	}
	mutated := func(fn func(map[string]any)) []byte {
		m := map[string]any{}
		for k, v := range env {
			m[k] = v
		}
		fn(m)
		return must(json.Marshal(m))(t)
	}
	// Заверение служебных баз с тем же рабочим ключом: подпись содержимого
	// верна, но назначение другое.
	db := newEndorseFixture(t, PurposeServiceDB)
	dbEndorsed := mutated(func(m map[string]any) {
		var e any
		if err := json.Unmarshal(db.file, &e); err != nil {
			t.Fatal(err)
		}
		m["endorsement"] = e
	})
	other := must(f.p.NewSigner(bytes.Repeat([]byte{9}, SigningSeedSize)))(t)
	foreignSig := must(other.Sign(licenseMessage([]byte(licensePayload))))(t)
	// Подпись рабочим ключом в контексте служебной базы — не подпись лицензии.
	dbCtxSig := must(f.sub.Sign(serviceDBMessage("license", []byte(licensePayload))))(t)
	ok := EndorsementCheck{At: endorseNow}
	for name, tc := range map[string]struct {
		data  []byte
		check EndorsementCheck
		want  error
	}{
		"содержимое подменено": {mutated(func(m map[string]any) {
			m["license"] = base64.StdEncoding.EncodeToString([]byte(`{"format":"aisec-license-data-v1","number":2}`))
		}), ok, ErrLicenseSignature},
		"содержимое не объект": {mutated(func(m map[string]any) { m["license"] = base64.StdEncoding.EncodeToString([]byte(`[1]`)) }),
			ok, ErrLicenseFormat},
		"повтор ключа в содержимом": {mutated(func(m map[string]any) {
			m["license"] = base64.StdEncoding.EncodeToString([]byte(`{"number":1,"number":2}`))
		}), ok, ErrLicenseFormat},
		"подпись чужим ключом": {mutated(func(m map[string]any) { m["signature"] = base64.StdEncoding.EncodeToString(foreignSig) }),
			ok, ErrLicenseSignature},
		"подпись в контексте базы": {mutated(func(m map[string]any) { m["signature"] = base64.StdEncoding.EncodeToString(dbCtxSig) }),
			ok, ErrLicenseSignature},
		"заверение служебных баз":    {dbEndorsed, ok, ErrEndorsementPurpose},
		"истёкшее заверение":         {file, EndorsementCheck{At: endorseEnd.AddDate(0, 0, 1)}, ErrEndorsementExpired},
		"заверение ещё не действует": {file, EndorsementCheck{At: endorseStart.AddDate(0, 0, -1)}, ErrEndorsementExpired},
		"отозванное":                 {file, EndorsementCheck{Revoked: func(uint64) bool { return true }}, ErrEndorsementRevoked},
		"формат":                     {mutated(func(m map[string]any) { m["format"] = "aisec-service-db-v1" }), ok, ErrLicenseFormat},
		"лишнее поле":                {mutated(func(m map[string]any) { m["kind"] = "license" }), ok, ErrLicenseFormat},
		"нет подписи":                {mutated(func(m map[string]any) { delete(m, "signature") }), ok, ErrLicenseFormat},
		"заверение строкой":          {mutated(func(m map[string]any) { m["endorsement"] = "x" }), ok, ErrLicenseFormat},
		"base64 с пробелом":          {mutated(func(m map[string]any) { m["license"] = " " + m["license"].(string) }), ok, ErrLicenseFormat},
		"повтор ключа":               {append([]byte(`{"format":"x",`), file[1:]...), ok, ErrLicenseFormat},
		"мусор":                      {[]byte{0xff, 0xfe, 0, 1}, ok, ErrLicenseFormat},
		"сверх размера":              {append(bytes.Repeat([]byte(" "), MaxLicenseSize), file...), ok, ErrLicenseFormat},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyLicense(f.p, f.vendorVerifier(t), tc.data, tc.check); !errors.Is(err, tc.want) {
				t.Fatalf("ожидалась %v, получено %v", tc.want, err)
			}
		})
	}
	// Ключ производителя другой — заверение не принимается.
	if _, err := VerifyLicense(f.p, must(f.p.NewVerifier(other.PublicKey()))(t), file, ok); !errors.Is(err, ErrEndorsementSignature) {
		t.Fatalf("чужой ключ производителя: %v", err)
	}
}

func TestSignLicenseChecksKey(t *testing.T) {
	f := newEndorseFixture(t, PurposeLicense)
	if _, err := SignLicense(f.vendor, f.file, []byte("{}")); err == nil {
		t.Fatal("подписано ключом не из заверения")
	}
	db := newEndorseFixture(t, PurposeServiceDB)
	if _, err := SignLicense(db.sub, db.file, []byte("{}")); !errors.Is(err, ErrEndorsementPurpose) {
		t.Fatalf("заверение служебных баз: %v", err)
	}
	if _, err := SignLicense(f.sub, f.file, nil); err == nil {
		t.Fatal("пустое содержимое подписано")
	}
	if _, err := SignLicense(f.sub, f.file, make([]byte, MaxLicensePayload+1)); err == nil {
		t.Fatal("содержимое сверх предела подписано")
	}
	if _, err := SignLicense(f.sub, f.file, []byte(`{"a":1}x`)); err == nil {
		t.Fatal("данные после объекта подписаны")
	}
	if _, err := SignLicense(nil, f.file, []byte("{}")); err == nil {
		t.Fatal("подписано без ключа")
	}
}

// FuzzParseLicenseFile: недоверенный файл лицензии (загрузка через API) не
// роняет разбор; принимается только содержимое, подписанное заверенным
// рабочим ключом с назначением license.
func FuzzParseLicenseFile(f *testing.F) {
	fx := newEndorseFixture(f, PurposeLicense)
	file, err := SignLicense(fx.sub, fx.file, []byte(licensePayload))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(file)
	f.Add([]byte(`{"format":"aisec-license-v1","endorsement":{},"license":"AA==","signature":"AA=="}`))
	f.Add([]byte(`{}`))
	vendor := fx.vendorVerifier(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = InspectLicense(data) //nolint:gosec // G104: проверяется только отсутствие паники
		got, err := VerifyLicense(fx.p, vendor, data, EndorsementCheck{})
		if err == nil && string(got.Payload) != licensePayload {
			t.Fatalf("принято чужое содержимое: %q", got.Payload)
		}
	})
}
