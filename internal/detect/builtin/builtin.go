// Пакет builtin — встроенные детекторы шлюза (ТЗ, 5.2). Новый детектор
// добавляется в All; утилита tools/detector-quality проверяет, что у каждого
// есть строка в docs/detectors.md и корпус в testdata/corpus/<ID>/.
package builtin

import "github.com/azuresong-afk/ai_railway/internal/detect"

// All — встроенные детекторы в порядке запуска. Детекторы появляются с
// задачи 1.11 этапа 1.
func All() []detect.Detector {
	return nil
}
