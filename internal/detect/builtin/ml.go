package builtin

import (
	"context"
	"errors"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// ML-детекторы (ADR-0024, задача 4.19): текст проверяет модель в
// изолированном процессе aisec-ml. Здесь — только их описание: ID, модель
// пакета, метки и категории, порог. Без aisec-ml (сервер, песочница
// политик, шлюз без -ml-socket) детектор отвечает «недоступен» — событие и
// ответ получают признак ml_unavailable, решение принимается по остальным
// детекторам (fail-open для ML). Шлюз с -ml-socket подставляет вместо
// заглушки детектор с клиентом aisec-ml (gateway.MLDetector).
//
// Метки, модели и пороги — предварительные: модели выбирает владелец
// (дополнение ADR-0024 от 28.10.2026), пороги и включение в поставку по
// критерию Р4 — часть 2 задачи 4.19. До неё пакета моделей в поставке нет.

// ID ML-детекторов.
const (
	InjectionMLID = "injection.ml"
	ToxicityMLID  = "toxicity.ml"
)

// MLSpec — описание ML-детектора.
type MLSpec struct {
	// ID — ID детектора: injection.ml, toxicity.ml, pii.ner.
	ID string
	// Version — версия кода детектора (x.y.z); версия модели — в Rule находки.
	Version string
	// Model — ID модели в пакете aisec-ml.
	Model      string
	Directions []detect.Direction
	// Categories — метка модели → категория находки; метки без категории
	// (например, benign) находок не дают.
	Categories map[string]string
	// Threat — строка матрицы обнаружения (DM-NN).
	Threat string
	// Threshold — минимальная оценка находки.
	Threshold float64
}

// MLSpecs — ML-детекторы поставки.
func MLSpecs() []MLSpec {
	return []MLSpec{
		{
			ID: InjectionMLID, Version: "1.0.0", Model: "injection-ru-en",
			Directions: []detect.Direction{detect.Input},
			Categories: map[string]string{"injection": "injection.ml"},
			Threat:     "DM-01", Threshold: 0.8,
		},
		{
			ID: ToxicityMLID, Version: "1.0.0", Model: "toxicity-ru",
			Directions: []detect.Direction{detect.Input, detect.Output},
			Categories: map[string]string{
				"insult": "toxicity.insult", "obscenity": "toxicity.obscenity",
				"threat": "toxicity.threat", "dangerous": "toxicity.dangerous",
			},
			Threat: "DM-18", Threshold: 0.7,
		},
	}
}

// ErrMLNotConnected — у компонента нет связи с aisec-ml: сервер, песочница
// политик или шлюз без -ml-socket.
var ErrMLNotConnected = errors.New("aisec-ml не подключён")

// MLCategories — категории находок детектора по возрастанию.
func (s MLSpec) MLCategories() []string {
	var out []string
	for _, c := range s.Categories {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// mlStub — ML-детектор без aisec-ml: политика может его назвать, а
// проверка текста всегда «недоступна».
type mlStub struct{ spec MLSpec }

func (d mlStub) ID() string                     { return d.spec.ID }
func (d mlStub) Version() string                { return d.spec.Version }
func (d mlStub) Directions() []detect.Direction { return slices.Clone(d.spec.Directions) }
func (d mlStub) Categories() []string           { return d.spec.MLCategories() }

// MLBacked — сбой детектора не включает fail_closed, а ставит признак
// ml_unavailable (ADR-0024, раздел 4).
func (mlStub) MLBacked() bool { return true }

func (mlStub) Detect(context.Context, detect.Text) ([]detect.Finding, error) {
	return nil, ErrMLNotConnected
}

// ML — ML-детекторы без aisec-ml (заглушки), в порядке MLSpecs.
func ML() []detect.Detector {
	specs := MLSpecs()
	out := make([]detect.Detector, 0, len(specs))
	for _, s := range specs {
		out = append(out, mlStub{spec: s})
	}
	return out
}
