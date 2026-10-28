package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	endorseNow   = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	endorseStart = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	endorseEnd   = time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)
)

type endorseFixture struct {
	p       Provider
	vendor  Signer
	sub     Signer
	file    []byte
	statemt Endorsement
}

func newEndorseFixture(t testing.TB, purpose string) endorseFixture {
	t.Helper()
	p, err := New(ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	vendor, err := p.NewSigner(bytes.Repeat([]byte{1}, SigningSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := p.NewSigner(bytes.Repeat([]byte{2}, SigningSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	e := Endorsement{Purpose: purpose, Profile: ProfileStandard, Serial: 7, PublicKey: sub.PublicKey(),
		NotBefore: endorseStart, NotAfter: endorseEnd, Comment: "каталог теневого ИИ"}
	file, err := SignEndorsement(vendor, e)
	if err != nil {
		t.Fatal(err)
	}
	return endorseFixture{p: p, vendor: vendor, sub: sub, file: file, statemt: e}
}

func (f endorseFixture) vendorVerifier(t testing.TB) Verifier {
	t.Helper()
	v, err := f.p.NewVerifier(f.vendor.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEndorsementRoundTrip(t *testing.T) {
	f := newEndorseFixture(t, PurposeServiceDB)
	e, v, err := VerifyEndorsement(f.p, f.vendorVerifier(t), f.file, EndorsementCheck{Purpose: PurposeServiceDB, At: endorseNow})
	if err != nil {
		t.Fatal(err)
	}
	if e.Serial != 7 || e.Purpose != PurposeServiceDB || !e.NotBefore.Equal(endorseStart) || !e.NotAfter.Equal(endorseEnd) ||
		e.Comment != "каталог теневого ИИ" || !bytes.Equal(v.PublicKey(), f.sub.PublicKey()) {
		t.Fatalf("заявление: %+v", e)
	}
	// Границы срока включены.
	for _, at := range []time.Time{endorseStart, endorseEnd} {
		if _, _, err := VerifyEndorsement(f.p, f.vendorVerifier(t), f.file, EndorsementCheck{Purpose: PurposeServiceDB, At: at}); err != nil {
			t.Fatalf("%s: %v", at, err)
		}
	}
	// Без момента срок не проверяется (уже загруженная база).
	if _, _, err := VerifyEndorsement(f.p, f.vendorVerifier(t), f.file, EndorsementCheck{Purpose: PurposeServiceDB}); err != nil {
		t.Fatal(err)
	}
}

func TestEndorsementRejects(t *testing.T) {
	f := newEndorseFixture(t, PurposeServiceDB)
	other, err := f.p.NewSigner(bytes.Repeat([]byte{3}, SigningSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	otherV := must(f.p.NewVerifier(other.PublicKey()))(t)
	ok := EndorsementCheck{Purpose: PurposeServiceDB, At: endorseNow}
	for name, tc := range map[string]struct {
		vendor Verifier
		data   []byte
		check  EndorsementCheck
		want   error
	}{
		"чужой ключ производителя": {otherV, f.file, ok, ErrEndorsementSignature},
		"чужое назначение":         {f.vendorVerifier(t), f.file, EndorsementCheck{Purpose: PurposeLicense, At: endorseNow}, ErrEndorsementPurpose},
		"истекло":                  {f.vendorVerifier(t), f.file, EndorsementCheck{Purpose: PurposeServiceDB, At: endorseEnd.Add(time.Second)}, ErrEndorsementExpired},
		"ещё не началось":          {f.vendorVerifier(t), f.file, EndorsementCheck{Purpose: PurposeServiceDB, At: endorseStart.Add(-time.Second)}, ErrEndorsementExpired},
		"отозвано": {f.vendorVerifier(t), f.file, EndorsementCheck{Purpose: PurposeServiceDB, At: endorseNow,
			Revoked: func(s uint64) bool { return s == 7 }}, ErrEndorsementRevoked},
		"заявление подменено": {f.vendorVerifier(t), resign(t, f.file, func(m map[string]any) { m["serial"] = 8 }, nil), ok, ErrEndorsementSignature},
		"пусто":               {f.vendorVerifier(t), nil, ok, ErrEndorsementFormat},
		"не JSON":             {f.vendorVerifier(t), []byte("CEF:0|"), ok, ErrEndorsementFormat},
		"лишнее поле":         {f.vendorVerifier(t), addField(t, f.file, "extra", "1"), ok, ErrEndorsementFormat},
		"ключ в другом регистре": {f.vendorVerifier(t), bytes.Replace(f.file, []byte(`"signature"`), []byte(`"Signature"`), 1), ok,
			ErrEndorsementFormat},
		"повтор поля": {f.vendorVerifier(t), bytes.Replace(f.file, []byte(`{"statement"`), []byte(`{"signature":"AA==","statement"`), 1), ok,
			ErrEndorsementFormat},
		"сверх размера":        {f.vendorVerifier(t), append(bytes.Repeat([]byte(" "), MaxEndorsementSize), f.file...), ok, ErrEndorsementFormat},
		"данные после объекта": {f.vendorVerifier(t), append(bytes.Clone(f.file), "{}"...), ok, ErrEndorsementFormat},
	} {
		t.Run(name, func(t *testing.T) {
			_, v, err := VerifyEndorsement(f.p, tc.vendor, tc.data, tc.check)
			if !errors.Is(err, tc.want) || v != nil {
				t.Fatalf("ожидалась %v, получено %v", tc.want, err)
			}
		})
	}
}

// resign меняет заявление и подписывает его ключом vendor (nil — прежняя
// подпись остаётся, то есть заявление подменено).
func resign(t *testing.T, file []byte, mutate func(map[string]any), vendor Signer) []byte {
	t.Helper()
	var env signedJSON
	if err := json.Unmarshal(file, &env); err != nil {
		t.Fatal(err)
	}
	st := must(base64.StdEncoding.DecodeString(env.Statement))(t)
	var m map[string]any
	if err := json.Unmarshal(st, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	st = must(json.Marshal(m))(t)
	env.Statement = base64.StdEncoding.EncodeToString(st)
	if vendor != nil {
		sig := must(vendor.Sign(endorsementMessage(st)))(t)
		env.Signature = base64.StdEncoding.EncodeToString(sig)
	}
	return must(json.Marshal(env))(t)
}

func addField(t *testing.T, file []byte, k, v string) []byte {
	t.Helper()
	return bytes.Replace(file, []byte("{"), []byte(`{"`+k+`":"`+v+`",`), 1)
}

// Подписанное заявление с неверными полями отклоняется при разборе: ключ
// производителя не спасает ошибку в заявлении.
func TestEndorsementStatementStrict(t *testing.T) {
	f := newEndorseFixture(t, PurposeServiceDB)
	for name, mutate := range map[string]func(map[string]any){
		"формат":            func(m map[string]any) { m["format"] = "aisec-vendor-subkey-v2" },
		"назначение":        func(m map[string]any) { m["purpose"] = "manifest" },
		"номер 0":           func(m map[string]any) { m["serial"] = 0 },
		"номер дробный":     func(m map[string]any) { m["serial"] = 1.5 },
		"номер строкой":     func(m map[string]any) { m["serial"] = "1" },
		"ключ короче":       func(m map[string]any) { m["public_key"] = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		"время с зоной":     func(m map[string]any) { m["not_before"] = "2026-10-01T03:00:00+03:00" },
		"время с долями":    func(m map[string]any) { m["not_after"] = "2027-10-01T00:00:00.5Z" },
		"срок наоборот":     func(m map[string]any) { m["not_after"] = "2026-09-01T00:00:00Z" },
		"срок больше 5 лет": func(m map[string]any) { m["not_after"] = "2032-10-01T00:00:00Z" },
		"лишнее поле":       func(m map[string]any) { m["usage"] = "all" },
		"нет срока":         func(m map[string]any) { delete(m, "not_after") },
		"управляющий":       func(m map[string]any) { m["comment"] = "a\x00b" },
		"профиль":           func(m map[string]any) { m["profile"] = "gost2" },
	} {
		t.Run(name, func(t *testing.T) {
			data := resign(t, f.file, mutate, f.vendor)
			if _, _, err := VerifyEndorsement(f.p, f.vendorVerifier(t), data, EndorsementCheck{Purpose: PurposeServiceDB, At: endorseNow}); !errors.Is(err, ErrEndorsementFormat) {
				t.Fatalf("ожидался отказ формата, получено %v", err)
			}
		})
	}
	// Ключ профиля gost в установке standard — отказ.
	data := resign(t, f.file, func(m map[string]any) { m["profile"] = ProfileGOST }, f.vendor)
	if _, _, err := VerifyEndorsement(f.p, f.vendorVerifier(t), data, EndorsementCheck{Purpose: PurposeServiceDB}); !errors.Is(err, ErrEndorsementFormat) {
		t.Fatalf("профиль: %v", err)
	}
}

func TestSignEndorsementChecksFields(t *testing.T) {
	f := newEndorseFixture(t, PurposeServiceDB)
	bad := f.statemt
	bad.NotAfter = bad.NotBefore
	if _, err := SignEndorsement(f.vendor, bad); err == nil {
		t.Fatal("заявление с пустым сроком подписано")
	}
	bad = f.statemt
	bad.Purpose = "any"
	if _, err := SignEndorsement(f.vendor, bad); err == nil {
		t.Fatal("заявление с неизвестным назначением подписано")
	}
}

func TestServiceDBRoundTrip(t *testing.T) {
	f := newEndorseFixture(t, PurposeServiceDB)
	payload := []byte("format: aisec-shadow-ai-catalog-v1\nversion: 1\n")
	db, err := SignServiceDB(f.sub, f.file, "shadow_ai_catalog", payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyServiceDB(f.p, f.vendorVerifier(t), db, "shadow_ai_catalog", EndorsementCheck{At: endorseNow})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "shadow_ai_catalog" || !bytes.Equal(got.Payload, payload) || got.Endorsement.Serial != 7 {
		t.Fatalf("база: %+v", got)
	}
	ins, err := InspectServiceDB(db)
	if err != nil || ins.Endorsement.Serial != 7 || !bytes.Equal(ins.Payload, payload) {
		t.Fatalf("inspect: %+v %v", ins, err)
	}
}

func TestServiceDBRejects(t *testing.T) {
	f := newEndorseFixture(t, PurposeServiceDB)
	payload := []byte("version: 1\n")
	db, err := SignServiceDB(f.sub, f.file, "shadow_ai_catalog", payload)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(db, &env); err != nil {
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
	lic := newEndorseFixture(t, PurposeLicense)
	licDB := mutated(func(m map[string]any) {
		var e any
		if err := json.Unmarshal(lic.file, &e); err != nil {
			t.Fatal(err)
		}
		m["endorsement"] = e
	})
	other := must(f.p.NewSigner(bytes.Repeat([]byte{9}, SigningSeedSize)))(t)
	foreignSig := must(other.Sign(serviceDBMessage("shadow_ai_catalog", payload)))(t)
	ok := EndorsementCheck{At: endorseNow}
	for name, tc := range map[string]struct {
		data  []byte
		kind  string
		check EndorsementCheck
		want  error
	}{
		"содержимое подменено": {mutated(func(m map[string]any) { m["payload"] = base64.StdEncoding.EncodeToString([]byte("version: 2\n")) }),
			"shadow_ai_catalog", ok, ErrServiceDBSignature},
		"вид подменён": {mutated(func(m map[string]any) { m["kind"] = "license_db" }), "license_db", ok, ErrServiceDBSignature},
		"чужой вид":    {db, "other_db", ok, ErrServiceDBKind},
		"подпись чужим ключом": {mutated(func(m map[string]any) { m["signature"] = base64.StdEncoding.EncodeToString(foreignSig) }),
			"shadow_ai_catalog", ok, ErrServiceDBSignature},
		"заверение лицензий": {licDB, "shadow_ai_catalog", ok, ErrEndorsementPurpose},
		"истёкшее заверение": {db, "shadow_ai_catalog", EndorsementCheck{At: endorseEnd.AddDate(0, 0, 1)}, ErrEndorsementExpired},
		"отозванное":         {db, "shadow_ai_catalog", EndorsementCheck{Revoked: func(uint64) bool { return true }}, ErrEndorsementRevoked},
		"формат":             {mutated(func(m map[string]any) { m["format"] = "aisec-service-db-v0" }), "shadow_ai_catalog", ok, ErrServiceDBFormat},
		"лишнее поле":        {mutated(func(m map[string]any) { m["note"] = "x" }), "shadow_ai_catalog", ok, ErrServiceDBFormat},
		"заверение строкой":  {mutated(func(m map[string]any) { m["endorsement"] = "x" }), "shadow_ai_catalog", ok, ErrServiceDBFormat},
		"мусор":              {[]byte{0xff, 0xfe, 0, 1}, "shadow_ai_catalog", ok, ErrServiceDBFormat},
		"сверх размера":      {append(bytes.Repeat([]byte(" "), MaxServiceDBSize), db...), "shadow_ai_catalog", ok, ErrServiceDBFormat},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyServiceDB(f.p, f.vendorVerifier(t), tc.data, tc.kind, tc.check); !errors.Is(err, tc.want) {
				t.Fatalf("ожидалась %v, получено %v", tc.want, err)
			}
		})
	}
}

func TestSignServiceDBChecksKey(t *testing.T) {
	f := newEndorseFixture(t, PurposeServiceDB)
	if _, err := SignServiceDB(f.vendor, f.file, "shadow_ai_catalog", []byte("x")); err == nil {
		t.Fatal("подписано ключом не из заверения")
	}
	lic := newEndorseFixture(t, PurposeLicense)
	if _, err := SignServiceDB(lic.sub, lic.file, "shadow_ai_catalog", []byte("x")); !errors.Is(err, ErrEndorsementPurpose) {
		t.Fatalf("заверение лицензий: %v", err)
	}
	for _, kind := range []string{"", "Shadow", "a b", strings.Repeat("a", 65)} {
		if _, err := SignServiceDB(f.sub, f.file, kind, []byte("x")); err == nil {
			t.Fatalf("вид %q принят", kind)
		}
	}
	if _, err := SignServiceDB(f.sub, f.file, "k", make([]byte, MaxServiceDBPayload+1)); err == nil {
		t.Fatal("содержимое сверх предела подписано")
	}
}

// FuzzParseEndorsement: недоверенный файл заверения не роняет разбор, а
// принятым оказывается только подписанный ключом производителя.
func FuzzParseEndorsement(f *testing.F) {
	fx := newEndorseFixture(f, PurposeServiceDB)
	f.Add(fx.file)
	f.Add([]byte(`{"statement":"e30=","signature":"AA=="}`))
	f.Add([]byte(`{"statement":"","signature":""}`))
	f.Add([]byte(`[]`))
	vendor := fx.vendorVerifier(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = InspectEndorsement(data) //nolint:gosec // G104: проверяется только отсутствие паники
		e, v, err := VerifyEndorsement(fx.p, vendor, data, EndorsementCheck{Purpose: PurposeServiceDB})
		if err == nil && (v == nil || e.Serial != 7) {
			t.Fatalf("принято чужое заверение: %+v", e)
		}
	})
}

// FuzzParseServiceDB: недоверенный файл базы не роняет разбор; принимается
// только содержимое, подписанное заверенным рабочим ключом.
func FuzzParseServiceDB(f *testing.F) {
	fx := newEndorseFixture(f, PurposeServiceDB)
	db, err := SignServiceDB(fx.sub, fx.file, "shadow_ai_catalog", []byte("version: 1\n"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(db)
	f.Add([]byte(`{"format":"aisec-service-db-v1","kind":"k","endorsement":{},"payload":"AA==","signature":"AA=="}`))
	vendor := fx.vendorVerifier(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = InspectServiceDB(data) //nolint:gosec // G104: проверяется только отсутствие паники
		got, err := VerifyServiceDB(fx.p, vendor, data, "shadow_ai_catalog", EndorsementCheck{})
		if err == nil && string(got.Payload) != "version: 1\n" {
			t.Fatalf("принято чужое содержимое: %q", got.Payload)
		}
	})
}

// must — значение без ошибки; ошибка останавливает тест.
func must[T any](v T, err error) func(testing.TB) T {
	return func(t testing.TB) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}
