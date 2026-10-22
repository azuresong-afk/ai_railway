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

// IsTestPublicKey — pub совпадает с тестовым ключом репозитория: им может
// подписать манифест любой, у кого есть репозиторий.
func IsTestPublicKey(pub []byte) bool {
	_, testPub, err := aisecCrypto.DecodeKeyPEM(testKeyPEM, aisecCrypto.KeyKindManifestSigningPublic)
	return err == nil && bytes.Equal(pub, testPub)
}
