//go:build !aisec_release

package integrity

import _ "embed"

// embeddedKeyPEM — тестовый открытый ключ манифеста. НЕ ДЛЯ ПОСТАВКИ: его
// закрытая пара лежит в репозитории (testdata/integrity/), ею подписывает
// make manifest без MANIFEST_KEY. Поставочная сборка — с тегом
// aisec_release (key_release.go).
//
//go:embed keys/manifest-test.pub
var embeddedKeyPEM []byte

const embeddedTestKey = true
