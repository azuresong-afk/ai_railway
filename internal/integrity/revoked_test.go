package integrity_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/compliance"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/license"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: фикстура теста из репозитория
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Ревью 4.r4: один список отозванных номеров на назначение. Номер рабочего
// ключа service_db (заверение № 1 в testdata/shadowai) отзывает и каталог
// теневого ИИ, и базу требований, но не лицензию; номер ключа лицензий
// (№ 2 в testdata/license) — только лицензию.
func TestRevokedServiceDBAndLicense(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	// Ключ производителя — тестовый ключ репозитория, а не встроенный: тест
	// идёт и в release-test, где встроена имитация ключа производителя.
	_, pub, err := aisecCrypto.DecodeKeyPEM(readFixture(t, "keys/manifest-test.pub"), aisecCrypto.KeyKindManifestSigningPublic)
	if err != nil {
		t.Fatal(err)
	}
	vendor, err := p.NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, seed, err := aisecCrypto.DecodeKeyPEM(readFixture(t, "../../testdata/shadowai/subkey-test.signkey"), aisecCrypto.KeyKindVendorSubkey)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	base, err := aisecCrypto.SignServiceDB(sub, readFixture(t, "../../testdata/shadowai/subkey-test.endorsement"), compliance.BaseKind,
		[]byte("format: aisec-compliance-base-v1\nversion: 1\ndate: \"2026-10-28\"\nsources:\n  - {id: src-a, title: Источник А}\n"+
			"requirements:\n  - {id: manual.one, source: src-a, clause: п. 1, title: Ручной, summary: Пересказ, applies: [gis], manual: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	catalog := readFixture(t, "../../testdata/shadowai/catalog-test.aisecdb")
	lic := readFixture(t, "../../testdata/license/license-test.aiseclic")
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	verify := map[string]func() error{
		"каталог": func() error { _, err := shadowai.VerifyCatalog(p, vendor, catalog, at); return err },
		"база":    func() error { _, err := compliance.VerifyBase(p, vendor, base, at); return err },
		"лицензия": func() error {
			_, err := license.Verify(p, vendor, lic, at)
			return err
		},
	}
	for _, tc := range []struct {
		name               string
		serviceDB, license []uint64
		revoked            []string
	}{
		{"ничего не отозвано", nil, nil, nil},
		{"ключ служебных баз", []uint64{1}, nil, []string{"каталог", "база"}},
		{"ключ лицензий", nil, []uint64{2}, []string{"лицензия"}},
		{"номер лицензий в списке служебных баз", []uint64{2}, []uint64{1}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := integrity.SetRevoked(tc.serviceDB, tc.license)
			defer restore()
			for name, f := range verify {
				err := f()
				want := false
				for _, r := range tc.revoked {
					want = want || r == name
				}
				if got := errors.Is(err, aisecCrypto.ErrEndorsementRevoked); got != want {
					t.Errorf("%s: отозвано %v, ожидалось %v (%v)", name, got, want, err)
				} else if !want && err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
		})
	}
}
