//go:build aisec_release

package integrity

import (
	"bytes"
	"os"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Тесты поставочной сборки (make release-test). В make check вместо
// keys/manifest.pub встроена имитация ключа производителя
// (keys/manifest-release-ci.pub, go test -overlay): ею можно подписать и
// проверить путь «принят». С RELEASE=1 встроен настоящий ключ производителя,
// его закрытой пары здесь нет — тогда идут только тесты на отказ и
// TestReleaseKeyIsNotTestKey.
func init() { allowReleaseCIKey = true }

func releaseCIOverlay(t *testing.T) bool {
	t.Helper()
	_, pub, err := aisecCrypto.DecodeKeyPEM(embeddedKeyPEM, aisecCrypto.KeyKindManifestSigningPublic)
	if err != nil {
		t.Fatal(err)
	}
	return isReleaseCIKey(pub)
}

// releaseCISigner — закрытая пара имитации ключа производителя.
func releaseCISigner(t *testing.T) aisecCrypto.Signer {
	t.Helper()
	data, err := os.ReadFile("../../testdata/integrity/manifest-release-ci.signkey")
	if err != nil {
		t.Fatal(err)
	}
	_, seed, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindManifestSigning)
	if err != nil {
		t.Fatal(err)
	}
	s, err := provider(t).NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func repoTestSigner(t *testing.T) aisecCrypto.Signer {
	t.Helper()
	data, err := os.ReadFile("../../testdata/integrity/manifest-test.signkey")
	if err != nil {
		t.Fatal(err)
	}
	_, seed, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindManifestSigning)
	if err != nil {
		t.Fatal(err)
	}
	s, err := provider(t).NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// embeddedCheck — проверка установки встроенным ключом сборки.
func embeddedCheck(t *testing.T, in *install) Result {
	t.Helper()
	cfg := in.config(t)
	cfg.Verifier = nil
	return check(t, cfg)
}

func manifestBytes(t *testing.T, in *install) []byte {
	t.Helper()
	data, err := os.ReadFile(in.manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Н35 ревью 2.r4: в поставочную сборку встроен настоящий ключ производителя,
// а не ключ из репозитория.
func TestReleaseKeyIsNotTestKey(t *testing.T) {
	if releaseCIOverlay(t) {
		t.Skip("встроена имитация ключа производителя; настоящий ключ проверяет make release-test RELEASE=1")
	}
	if embeddedTestKey {
		t.Fatal("поставочная сборка помечена как тестовая")
	}
	if bytes.Equal(bytes.TrimSpace(embeddedKeyPEM), bytes.TrimSpace(testKeyPEM)) {
		t.Fatal("keys/manifest.pub совпадает с manifest-test.pub")
	}
	allowReleaseCIKey = false
	t.Cleanup(func() { allowReleaseCIKey = true })
	if _, _, err := EmbeddedVerifier(provider(t)); err != nil {
		t.Fatal(err)
	}
}

// Манифест, подписанный ключом производителя, поставочная сборка принимает,
// и итог не помечен как тестовый.
func TestReleaseAcceptsVendorSignature(t *testing.T) {
	if !releaseCIOverlay(t) {
		t.Skip("закрытый ключ производителя вне репозитория")
	}
	in := newInstall(t)
	in.writeManifest(t, manifestBytes(t, in), releaseCISigner(t))
	if res := embeddedCheck(t, in); !res.OK() || res.TestSigned {
		t.Fatalf("%+v", res)
	}
}

// Подмена манифеста после подписи ключом производителя — отказ.
func TestReleaseRejectsTamperedManifest(t *testing.T) {
	if !releaseCIOverlay(t) {
		t.Skip("закрытый ключ производителя вне репозитория")
	}
	in := newInstall(t)
	data := manifestBytes(t, in)
	in.writeManifest(t, data, releaseCISigner(t))
	writeFile(t, in.manifest, bytes.Replace(data, []byte("1.0.0-test"), []byte("1.0.1-test"), 1))
	if res := embeddedCheck(t, in); res.Reason != ReasonSignatureInvalid {
		t.Fatalf("%+v", res)
	}
}

// Подпись тестовым ключом репозитория или чужим ключом поставочная сборка
// не принимает.
func TestReleaseRejectsOtherSigners(t *testing.T) {
	other, err := provider(t).GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]aisecCrypto.Signer{
		"тестовый ключ репозитория": repoTestSigner(t),
		"чужой ключ":                other,
	} {
		t.Run(name, func(t *testing.T) {
			in := newInstall(t)
			in.writeManifest(t, manifestBytes(t, in), s)
			if res := embeddedCheck(t, in); res.Reason != ReasonSignatureInvalid || res.TestSigned {
				t.Fatalf("%+v", res)
			}
		})
	}
}

// Ключ из репозитория, встроенный в поставочную сборку, отвергается до
// проверки: тестовый — всегда, имитация ключа производителя — вне тестов.
func TestReleaseRefusesRepositoryKeys(t *testing.T) {
	saved := embeddedKeyPEM
	t.Cleanup(func() { embeddedKeyPEM, allowReleaseCIKey = saved, true })
	allowReleaseCIKey = false
	for name, key := range map[string][]byte{"тестовый": testKeyPEM, "имитация ключа производителя": releaseCIKeyPEM} {
		embeddedKeyPEM = key
		if _, _, err := EmbeddedVerifier(provider(t)); err == nil {
			t.Errorf("%s ключ принят поставочной сборкой", name)
		}
		if _, _, err := EmbeddedFingerprint(provider(t)); err == nil {
			t.Errorf("%s ключ: отпечаток без ошибки", name)
		}
	}
}
