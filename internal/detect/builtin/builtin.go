// Пакет builtin — встроенные детекторы шлюза (ТЗ, 5.2). Новый детектор
// добавляется в All; утилита tools/detector-quality проверяет, что у каждого
// есть строка в docs/detectors.md и корпус в testdata/corpus/<ID>/.
package builtin

import (
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/canary"
	"github.com/azuresong-afk/ai_railway/internal/detect/exfil"
	"github.com/azuresong-afk/ai_railway/internal/detect/injection"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
	"github.com/azuresong-afk/ai_railway/internal/detect/secretscan"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
	"github.com/azuresong-afk/ai_railway/internal/detect/unihidden"
)

// All — встроенные детекторы в порядке запуска.
func All() []detect.Detector {
	return []detect.Detector{
		unihidden.New(), pii.New(), secretscan.New(), injection.New(), lists.New(),
		canary.New(), exfil.New(),
	}
}

// Catalog — детекторы, которые может назвать политика: All и детекторы
// уровня запроса и сессии (internal/detect/session: session.risk,
// prompt.integrity, history.integrity). Текст проверяют только детекторы
// All, поэтому корпуса, метрики качества и эталоны самотеста — у них.
func Catalog() []detect.Detector {
	return append(All(), session.All()...)
}
