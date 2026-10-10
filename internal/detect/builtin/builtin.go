// Пакет builtin — встроенные детекторы шлюза (ТЗ, 5.2). Новый детектор
// добавляется в All; утилита tools/detector-quality проверяет, что у каждого
// есть строка в docs/detectors.md и корпус в testdata/corpus/<ID>/.
package builtin

import (
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
)

// All — встроенные детекторы в порядке запуска.
func All() []detect.Detector {
	return []detect.Detector{pii.New()}
}
