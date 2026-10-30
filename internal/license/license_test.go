package license

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

const (
	testSubkey      = "../../testdata/license/subkey-test.signkey"
	testEndorsement = "../../testdata/license/subkey-test.endorsement"
	testLicenseJSON = "../../testdata/license/license-test.json"
	testLicenseFile = "../../testdata/license/license-test.aiseclic"
	// Заверение служебных баз (теневой ИИ) — чужое назначение.
	testDBSubkey      = "../../testdata/shadowai/subkey-test.signkey"
	testDBEndorsement = "../../testdata/shadowai/subkey-test.endorsement"
	// testINN — синтетический ИНН: региона 00 нет, контрольная цифра верная.
	testINN = "0012345673"
)

// day — полночь UTC.
func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: фикстура теста из репозитория
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func provider(t testing.TB) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func loadSubkey(t testing.TB, p aisecCrypto.Provider, path string) aisecCrypto.Signer {
	t.Helper()
	_, seed, err := aisecCrypto.DecodeKeyPEM(readFile(t, path), aisecCrypto.KeyKindVendorSubkey)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// baseLicense — коммерческая лицензия № n на год с 28.10.2026.
func baseLicense(n uint64) *License {
	return &License{Number: n, Licensee: Licensee{Organization: "ООО «Пример»", INN: testINN},
		IssuedAt: day(2026, 10, 28), ValidFrom: day(2026, 10, 28), ValidUntil: day(2027, 10, 28), Type: TypeCommercial,
		Limits: Limits{Gateways: 2, Applications: 3}, Modules: []string{ModuleAgents}}
}

// signTest подписывает лицензию тестовым рабочим ключом лицензий.
func signTest(t testing.TB, l *License) []byte {
	t.Helper()
	p := provider(t)
	payload, err := Encode(l)
	if err != nil {
		t.Fatal(err)
	}
	file, err := aisecCrypto.SignLicense(loadSubkey(t, p, testSubkey), readFile(t, testEndorsement), payload)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestTestLicenseMatchesSource(t *testing.T) {
	p := provider(t)
	vendor, err := VendorVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := Verify(p, vendor, readFile(t, testLicenseFile), day(2026, 10, 28))
	if err != nil {
		t.Fatal(err)
	}
	src, err := Parse(readFile(t, testLicenseJSON))
	if err != nil {
		t.Fatal(err)
	}
	a, err := Encode(src)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(sg.License)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) || sg.Endorsement.Serial != 2 || sg.Endorsement.Purpose != aisecCrypto.PurposeLicense {
		t.Fatalf("тестовая лицензия не совпадает с исходником: %s", b)
	}
}

func TestParseRoundTrip(t *testing.T) {
	l := baseLicense(42)
	l.Modules = []string{ModuleShadowAI, ModuleAgents}
	data, err := Encode(l)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Number != 42 || got.Licensee != l.Licensee || !got.ValidUntil.Equal(l.ValidUntil) || got.Limits != l.Limits ||
		strings.Join(got.Modules, ",") != "agents,shadow_ai" || !got.HasModule(ModuleShadowAI) || got.HasModule(ModuleML) {
		t.Fatalf("разбор: %+v", got)
	}
	// Без модулей и без пределов (0 — без ограничения).
	l = baseLicense(1)
	l.Modules, l.Limits = nil, Limits{}
	if data, err = Encode(l); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"modules":[]`) {
		t.Fatalf("modules: %s", data)
	}
}

func TestParseRejects(t *testing.T) {
	good := string(must(Encode(baseLicense(5)))(t))
	set := func(k, v string) string {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(good), &m); err != nil {
			t.Fatal(err)
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = json.RawMessage(v)
		}
		return string(must(json.Marshal(m))(t))
	}
	for name, data := range map[string]string{
		"не JSON":                   "x",
		"массив":                    "[]",
		"повтор ключа":              `{"number":1,` + good[1:],
		"данные после объекта":      good + "{}",
		"неизвестное поле":          set("note", `"x"`),
		"ключ в другом регистре":    strings.Replace(good, `"number"`, `"Number"`, 1),
		"нет номера":                set("number", ""),
		"номер 0":                   set("number", "0"),
		"номер дробный":             set("number", "1.0"),
		"номер с экспонентой":       set("number", "1e2"),
		"номер строкой":             set("number", `"5"`),
		"номер сверх 2^53":          set("number", "9007199254740992"),
		"формат":                    set("format", `"aisec-license-data-v0"`),
		"пустая организация":        set("licensee", `{"organization":"","inn":"`+testINN+`"}`),
		"организация с переводом":   set("licensee", `{"organization":"A\nB","inn":"`+testINN+`"}`),
		"организация с пробелом":    set("licensee", `{"organization":" A","inn":"`+testINN+`"}`),
		"длинная организация":       set("licensee", `{"organization":"`+strings.Repeat("я", 201)+`","inn":"`+testINN+`"}`),
		"ИНН с неверной суммой":     set("licensee", `{"organization":"A","inn":"0012345670"}`),
		"ИНН из 11 цифр":            set("licensee", `{"organization":"A","inn":"00123456731"}`),
		"лишнее поле владельца":     set("licensee", `{"organization":"A","inn":"`+testINN+`","kpp":"1"}`),
		"время без Z":               set("valid_until", `"2027-10-28T00:00:00+03:00"`),
		"время с долями":            set("valid_until", `"2027-10-28T00:00:00.5Z"`),
		"конец раньше начала":       set("valid_until", `"2026-10-27T00:00:00Z"`),
		"выдана после конца":        set("issued_at", `"2027-10-29T00:00:00Z"`),
		"срок больше 5 лет":         set("valid_until", `"2031-10-30T00:00:00Z"`),
		"пилот дольше 92 суток":     set("type", `"pilot"`),
		"неизвестный тип":           set("type", `"trial"`),
		"предел отрицательный":      set("limits", `{"gateways":-1,"applications":1}`),
		"предел дробный":            set("limits", `{"gateways":1.5,"applications":1}`),
		"предел сверх миллиона":     set("limits", `{"gateways":1000001,"applications":1}`),
		"нет предела приложений":    set("limits", `{"gateways":1}`),
		"модули не массив":          set("modules", `"agents"`),
		"модули null":               set("modules", `null`),
		"неизвестный модуль":        set("modules", `["agents","siem"]`),
		"повтор модуля":             set("modules", `["agents","agents"]`),
		"сверх размера содержимого": `{"x":"` + strings.Repeat("a", aisecCrypto.MaxLicensePayload) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); !errors.Is(err, ErrPayload) {
				t.Fatalf("принято: %v", err)
			}
		})
	}
}

func TestValidINN(t *testing.T) {
	for _, s := range []string{testINN, "0098765437", "001234567887"} {
		if !ValidINN(s) {
			t.Errorf("%s отклонён", s)
		}
	}
	for _, s := range []string{"", "0", "0012345674", "001234567888", "001234567877", "00123456a3", "００12345673"} {
		if ValidINN(s) {
			t.Errorf("%q принят", s)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	p := provider(t)
	vendor, err := VendorVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	at := day(2026, 10, 28)
	good := signTest(t, baseLicense(1))
	if _, err := Verify(p, vendor, good, at); err != nil {
		t.Fatal(err)
	}
	// Подпись лицензии ключом служебных баз с его заверением.
	payload := must(Encode(baseLicense(1)))(t)
	dbSub := loadSubkey(t, p, testDBSubkey)
	sig := must(dbSub.Sign(append([]byte("aisec-license-v1\n"), payload...)))(t)
	foreignPurpose := must(json.Marshal(map[string]any{"format": "aisec-license-v1",
		"endorsement": json.RawMessage(bytes.TrimSpace(readFile(t, testDBEndorsement))),
		"license":     base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(sig)}))(t)
	// Дата выдачи до начала срока заверения (01.10.2026).
	early := baseLicense(1)
	early.IssuedAt, early.ValidFrom = day(2026, 9, 1), day(2026, 9, 1)
	// Ключ производителя не тот.
	other := must(p.NewSigner(bytes.Repeat([]byte{7}, aisecCrypto.SigningSeedSize)))(t)
	for name, tc := range map[string]struct {
		data   []byte
		vendor aisecCrypto.Verifier
		at     time.Time
		want   error
	}{
		"чужое назначение заверения": {foreignPurpose, vendor, at, aisecCrypto.ErrEndorsementPurpose},
		"истёкшее заверение":         {good, vendor, day(2031, 10, 1), aisecCrypto.ErrEndorsementExpired},
		"дата выдачи вне заверения":  {signTest(t, early), vendor, time.Time{}, ErrIssuedDate},
		"чужой ключ производителя":   {good, must(p.NewVerifier(other.PublicKey()))(t), at, aisecCrypto.ErrEndorsementSignature},
		"подменённое содержимое":     {swapPayload(t, good, must(Encode(baseLicense(2)))(t)), vendor, at, aisecCrypto.ErrLicenseSignature},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(p, tc.vendor, tc.data, tc.at); !errors.Is(err, tc.want) {
				t.Fatalf("ожидалась %v, получено %v", tc.want, err)
			}
		})
	}
	// Отозванный номер заверения — TestRevokedServiceDBAndLicense в
	// internal/integrity.
}

// swapPayload — файл с подменённым содержимым и прежней подписью.
func swapPayload(t testing.TB, file, payload []byte) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(file, &m); err != nil {
		t.Fatal(err)
	}
	m["license"] = must(json.Marshal(base64.StdEncoding.EncodeToString(payload)))(t)
	return must(json.Marshal(m))(t)
}

// FuzzParseLicense: недоверенное содержимое не роняет разбор, а принятое
// снова кодируется и разбирается в то же самое.
func FuzzParseLicense(f *testing.F) {
	f.Add(must(Encode(baseLicense(7)))(f))
	f.Add([]byte(`{"format":"aisec-license-data-v1","number":1,"licensee":{"organization":"A","inn":"0012345673"},` +
		`"issued_at":"2026-10-28T00:00:00Z","valid_from":"2026-10-28T00:00:00Z","valid_until":"2026-11-28T00:00:00Z",` +
		`"type":"pilot","limits":{"gateways":0,"applications":0},"modules":[]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := Parse(data)
		if err != nil {
			return
		}
		again, err := Encode(l)
		if err != nil {
			t.Fatalf("принятое не кодируется: %v", err)
		}
		l2, err := Parse(again)
		if err != nil || l2.Number != l.Number || !l2.ValidUntil.Equal(l.ValidUntil) || l2.Limits != l.Limits {
			t.Fatalf("повторный разбор: %+v %v", l2, err)
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
