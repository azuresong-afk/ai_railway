package integrity

import (
	"bytes"
	_ "embed"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// testKeyPEM — тестовый открытый ключ манифеста, встроенный в любую сборку,
// чтобы его можно было узнать (Н35 ревью 2.r4): его закрытая пара лежит в
// репозитории.
//
//go:embed keys/manifest-test.pub
var testKeyPEM []byte

// releaseCIKeyPEM — имитация ключа производителя для тестов выпускной сборки
// в CI (ADR-0022): make release-test подставляет её вместо keys/manifest.pub
// через go test -overlay. Закрытая пара тоже в репозитории, поэтому
// поставочная сборка её не принимает.
//
//go:embed keys/manifest-release-ci.pub
var releaseCIKeyPEM []byte

// IsTestPublicKey — pub совпадает с ключом из репозитория (тестовым или
// имитацией ключа производителя): им может подписать манифест любой, у кого
// есть репозиторий.
func IsTestPublicKey(pub []byte) bool {
	return samePublicKey(testKeyPEM, pub) || isReleaseCIKey(pub)
}

func isReleaseCIKey(pub []byte) bool {
	return samePublicKey(releaseCIKeyPEM, pub)
}

func samePublicKey(pemData, pub []byte) bool {
	_, known, err := aisecCrypto.DecodeKeyPEM(pemData, aisecCrypto.KeyKindManifestSigningPublic)
	return err == nil && len(pub) > 0 && bytes.Equal(pub, known)
}
