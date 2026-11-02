// Package kinds — все виды служебных баз, известные выпуску (ADR-0028,
// п. 1). Им пользуются инструмент подписи (sign-db) и aisec-cli servicedb
// inspect; модули этот пакет не импортируют. Новый вид (5.21, 5.31) —
// строка в All.
package kinds

import (
	"github.com/azuresong-afk/ai_railway/internal/compliance"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

// All — виды служебных баз выпуска.
func All() []servicedb.Kind {
	return []servicedb.Kind{shadowai.DBKind(), compliance.DBKind()}
}
