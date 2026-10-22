package integrity

import (
	"errors"
	"fmt"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// EmbeddedVerifier — встроенный в бинарник открытый ключ проверки
// манифеста (ТЗ 10.4, Р10). testKey = true — сборка без тега aisec_release
// с тестовым ключом из репозитория: такая сборка не для поставки, и это
// видно в каждом результате проверки.
func EmbeddedVerifier(p aisecCrypto.Provider) (v aisecCrypto.Verifier, testKey bool, err error) {
	profile, pub, err := aisecCrypto.DecodeKeyPEM(embeddedKeyPEM, aisecCrypto.KeyKindManifestSigningPublic)
	if err != nil {
		return nil, false, fmt.Errorf("встроенный ключ проверки манифеста: %w", err)
	}
	if profile != p.Name() {
		return nil, false, fmt.Errorf("встроенный ключ проверки манифеста профиля %s, а компонент работает в профиле %s", profile, p.Name())
	}
	// Поставочная сборка с тестовым ключом (keys/manifest.pub скопирован с
	// manifest-test.pub) приняла бы манифест, подписанный ключом из
	// репозитория (Н35 ревью 2.r4).
	if !embeddedTestKey && IsTestPublicKey(pub) {
		return nil, false, errors.New("в поставочную сборку встроен тестовый ключ проверки манифеста")
	}
	v, err = p.NewVerifier(pub)
	if err != nil {
		return nil, false, fmt.Errorf("встроенный ключ проверки манифеста: %w", err)
	}
	return v, embeddedTestKey, nil
}
