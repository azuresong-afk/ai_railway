// Package kinds — все виды служебных баз, известные выпуску (ADR-0028,
// п. 1). Им пользуются инструмент подписи (sign-db) и aisec-cli servicedb
// inspect; модули этот пакет не импортируют. Новый вид — строка в All
// (эталоны шаблонов чата — 5.21; сценарии тестирования — 5.31).
package kinds

import (
	"github.com/azuresong-afk/ai_railway/internal/compliance"
	"github.com/azuresong-afk/ai_railway/internal/inventory"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

// All — виды служебных баз выпуска.
func All() []servicedb.Kind {
	return []servicedb.Kind{shadowai.DBKind(), compliance.DBKind(), inventory.TemplatesDBKind()}
}
