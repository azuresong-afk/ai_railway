//go:build aisec_release

package integrity

import _ "embed"

// embeddedKeyPEM — открытый ключ производителя для проверки манифеста
// (ТЗ 10.4, Р10). Файл keys/manifest.pub кладёт владелец ключа; закрытый
// ключ хранится вне репозитория. Без файла поставочная сборка не
// собирается — это намеренно (ADR-0012).
//
//go:embed keys/manifest.pub
var embeddedKeyPEM []byte

const embeddedTestKey = false
