package integrity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// allowReleaseCIKey разрешает поставочной сборке имитацию ключа
// производителя. Включают только тесты с тегом aisec_release (make
// release-test): в бинарники продукта тестовые файлы не попадают.
var allowReleaseCIKey = false

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
	// Поставочная сборка с ключом из репозитория (keys/manifest.pub
	// скопирован с manifest-test.pub или manifest-release-ci.pub) приняла бы
	// манифест, подписанный кем угодно (Н35 ревью 2.r4, ADR-0022).
	if !embeddedTestKey && IsTestPublicKey(pub) && (!allowReleaseCIKey || !isReleaseCIKey(pub)) {
		return nil, false, errors.New("в поставочную сборку встроен тестовый ключ проверки манифеста")
	}
	v, err = p.NewVerifier(pub)
	if err != nil {
		return nil, false, fmt.Errorf("встроенный ключ проверки манифеста: %w", err)
	}
	return v, embeddedTestKey, nil
}

// Fingerprint — отпечаток открытого ключа проверки манифеста (ADR-0022):
// хеш профиля (SHA-256 в standard) от байтов ключа, шестнадцатеричный, по
// четыре знака через двоеточие. Его печатают tools/manifest и aisec-cli
// verify -release, публикует руководство установки, а verify-release.sh
// сверяет с AISEC_VENDOR_FINGERPRINT.
func Fingerprint(p aisecCrypto.Provider, pub []byte) (string, error) {
	if len(pub) == 0 {
		return "", errors.New("отпечаток: пустой ключ")
	}
	h, err := p.Hasher()
	if err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(pub))
	groups := make([]string, 0, len(sum)/4)
	for i := 0; i < len(sum); i += 4 {
		groups = append(groups, sum[i:min(i+4, len(sum))])
	}
	return strings.Join(groups, ":"), nil
}

// EmbeddedFingerprint — отпечаток встроенного ключа проверки манифеста.
func EmbeddedFingerprint(p aisecCrypto.Provider) (fp string, testKey bool, err error) {
	v, testKey, err := EmbeddedVerifier(p)
	if err != nil {
		return "", false, err
	}
	fp, err = Fingerprint(p, v.PublicKey())
	return fp, testKey, err
}
