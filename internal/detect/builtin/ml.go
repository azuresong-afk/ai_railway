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
// Модели — решение владельца от 28.10.2026 (ADR-0024, «Решение
// владельца»): injection.ml — своя дообучка rubert-tiny2 (метки benign и
// injection, softmax), toxicity.ml — cointegrated/rubert-tiny-toxicity
// (метки non-toxic, insult, obscenity, threat, dangerous; каждая — своя
// сигмоида). pii.ner (задача 4.20) — разметка токенов по схеме BIO
// (сущности per, org, loc, addr; loc находок не даёт: город или страна сами
// по себе не ПДн), модель — решение владельца 30.10.2026 (ADR-0024,
// дополнение о pii.ner). Threshold здесь — нижняя
// граница находки; порог решения — в правиле политики (threshold), в
// шаблонах — по замеру Р4 (docs/detectors.md). До замера Р4 правила шаблонов только журналируют
// (Log): новые детекторы начинают в мониторинге.

// ID ML-детекторов.
const (
	InjectionMLID = "injection.ml"
	ToxicityMLID  = "toxicity.ml"
	PIINERID      = "pii.ner"
)

// Категории находок pii.ner — тип псевдонима по последней части
// (pseudonym.TypeOf): PERSON, ORGANIZATION, ADDRESS.
const (
	CatPerson       = "pii.person"
	CatOrganization = "pii.organization"
	CatAddress      = "pii.address"
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
	// Threat — строка матрицы обнаружения (DM-NN); OutputThreat — строка
	// для ответа модели, если она другая (pii.ner: DM-31 в запросе, DM-09 в
	// ответе, как у pii.ru).
	Threat, OutputThreat string
	// Spans — находки модели — фрагменты текста (разметка токенов): шлюз
	// расширяет их до целых слов, чтобы маскирование не оставляло часть
	// имени (gateway.MLDetector).
	Spans bool
	// Threshold — минимальная оценка находки.
	Threshold float64
}

// MLFindingFloor — нижняя граница оценки находки ML-детектора: ниже —
// находки нет. Как порог правила по умолчанию (policy.DefaultThreshold) и
// порог метрик качества.
const MLFindingFloor = 0.5

// MLSpecs — ML-детекторы поставки.
func MLSpecs() []MLSpec {
	return []MLSpec{
		{
			ID: InjectionMLID, Version: "1.0.0", Model: "injection-ru-en",
			Directions: []detect.Direction{detect.Input},
			Categories: map[string]string{"injection": "injection.ml"},
			Threat:     "DM-01", Threshold: MLFindingFloor,
		},
		{
			ID: ToxicityMLID, Version: "1.0.0", Model: "toxicity-ru",
			Directions: []detect.Direction{detect.Input, detect.Output},
			Categories: map[string]string{
				"insult": "toxicity.insult", "obscenity": "toxicity.obscenity",
				"threat": "toxicity.threat", "dangerous": "toxicity.dangerous",
			},
			Threat: "DM-18", Threshold: MLFindingFloor,
		},
		{
			ID: PIINERID, Version: "1.0.0", Model: "pii-ner-ru",
			Directions: []detect.Direction{detect.Input, detect.Output},
			Categories: map[string]string{"per": CatPerson, "org": CatOrganization, "addr": CatAddress},
			Threat:     "DM-31", OutputThreat: "DM-09", Spans: true, Threshold: MLFindingFloor,
		},
	}
}

// ThreatFor — строка матрицы находки в направлении dir.
func (s MLSpec) ThreatFor(dir detect.Direction) string {
	if dir == detect.Output && s.OutputThreat != "" {
		return s.OutputThreat
	}
	return s.Threat
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

// MLConnected — связи с aisec-ml нет: правила шаблонов политик с этим
// детектором опускаются (policy.TemplateFor), чтобы шаблон по умолчанию на
// шлюзе без aisec-ml не ставил ml_unavailable каждому событию. Политика
// заказчика, назвавшая ML-детектор, по-прежнему получает ml_unavailable.
func (mlStub) MLConnected() bool { return false }

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
