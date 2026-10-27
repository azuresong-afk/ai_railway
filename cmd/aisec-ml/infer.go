package main

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// Общая часть исполнителя моделей, не зависящая от ONNX Runtime: описание
// входов и выходов модели, токенизатор и разбор выхода модели в находки.
// Код на ONNX Runtime (executor_onnx.go) собирается только с тегом
// aisec_onnx; эта часть проверяется обычными тестами.

// Имена входов и выхода модели (соглашение экспорта трансформеров в ONNX).
const (
	inputIDs      = "input_ids"
	inputMask     = "attention_mask"
	inputTypeIDs  = "token_type_ids"
	outputLogits  = "logits"
	labelOutside  = "O" // метка «вне фрагмента» у разметки токенов
	maxIOOfModels = 8
)

// tensorKind — тип элемента тензора входа или выхода.
type tensorKind int

const (
	kindOther tensorKind = iota
	kindInt64
	kindFloat32
)

// ioInfo — вход или выход модели: имя, тип элемента, размерности (-1 —
// задаётся при вызове).
type ioInfo struct {
	Name string
	Kind tensorKind
	Dims []int64
}

// modelIO — проверенные входы модели: какие из необязательных есть.
type modelIO struct {
	Inputs   []string
	TypeIDs  bool
	MaxBatch int64
}

// checkIO сверяет входы и выходы модели с описанием из манифеста пакета:
// input_ids и attention_mask (int64, [пакет, токены]), необязательный
// token_type_ids; выход logits (float32) — [пакет, метки] у классификации
// и [пакет, токены, метки] у разметки токенов. Модель с другими входами или
// выходами не загружается: исполнитель не угадывает их смысл.
func checkIO(spec ml.ModelSpec, inputs, outputs []ioInfo) (modelIO, error) {
	var io modelIO
	if len(inputs) == 0 || len(inputs) > maxIOOfModels || len(outputs) == 0 || len(outputs) > maxIOOfModels {
		return io, errors.New("число входов или выходов модели вне пределов")
	}
	seen := map[string]bool{}
	for _, in := range inputs {
		if seen[in.Name] {
			return io, fmt.Errorf("вход %q повторяется", in.Name)
		}
		seen[in.Name] = true
		switch in.Name {
		case inputIDs, inputMask, inputTypeIDs:
		default:
			return io, fmt.Errorf("неизвестный вход модели %q", in.Name)
		}
		if in.Kind != kindInt64 || len(in.Dims) != 2 || !dimOK(in.Dims[1], int64(spec.MaxTokens)) {
			return io, fmt.Errorf("вход %q: нужен int64 [пакет, токены]", in.Name)
		}
		io.Inputs = append(io.Inputs, in.Name)
	}
	if !seen[inputIDs] || !seen[inputMask] {
		return io, errors.New("у модели нет входов input_ids и attention_mask")
	}
	io.TypeIDs = seen[inputTypeIDs]
	var logits *ioInfo
	for i := range outputs {
		if outputs[i].Name == outputLogits {
			logits = &outputs[i]
		}
	}
	if logits == nil || logits.Kind != kindFloat32 {
		return io, errors.New("у модели нет выхода logits типа float32")
	}
	labels := int64(len(spec.Labels))
	switch spec.Task {
	case ml.TaskClassification:
		if len(logits.Dims) != 2 || !dimOK(logits.Dims[1], labels) {
			return io, fmt.Errorf("выход logits: нужен [пакет, %d]", labels)
		}
	case ml.TaskTokenClassification:
		if len(logits.Dims) != 3 || !dimOK(logits.Dims[1], int64(spec.MaxTokens)) || !dimOK(logits.Dims[2], labels) {
			return io, fmt.Errorf("выход logits: нужен [пакет, токены, %d]", labels)
		}
		if !slices.Contains(spec.Labels, labelOutside) {
			return io, fmt.Errorf("у разметки токенов нет метки %q", labelOutside)
		}
	default:
		return io, fmt.Errorf("задача %q не поддерживается", spec.Task)
	}
	return io, nil
}

// dimOK — размерность задаётся при вызове (-1) или равна want (для токенов —
// не меньше окна модели).
func dimOK(d, want int64) bool {
	return d == -1 || d == want
}

// tokenizer — перевод текста в номера токенов модели. offsets — байтовые
// границы токена в тексте (у служебных токенов [0, 0]); truncated — текст
// длиннее окна модели и проверен не весь.
type tokenizer interface {
	Encode(text string, maxTokens int) (ids []int64, offsets [][2]int, truncated bool, err error)
}

// errNoTokenizer — формат токенизатора пакета не поддерживается.
var errNoTokenizer = errors.New("формат токенизатора не поддерживается: токенизаторы появятся вместе с первыми моделями (задачи 4.19, 4.20)")

// newTokenizer — токенизатор модели по tokenizer.json из проверенного
// пакета. В 4.18 форматов нет: модель с любым токенизатором не загружается,
// а не работает с неверными номерами токенов.
var newTokenizer = func(spec ml.ModelSpec, data []byte) (tokenizer, error) {
	return nil, errNoTokenizer
}

// encodeInputs — тензоры входов модели для одного текста ([1, n]).
func encodeInputs(io modelIO, ids []int64) map[string][]int64 {
	n := len(ids)
	mask := make([]int64, n)
	for i := range mask {
		mask[i] = 1
	}
	out := map[string][]int64{inputIDs: ids, inputMask: mask}
	if io.TypeIDs {
		out[inputTypeIDs] = make([]int64, n)
	}
	return out
}

// softmax — вероятности по логитам; NaN и бесконечности — ошибка модели.
func softmax(logits []float32) ([]float64, error) {
	if len(logits) == 0 {
		return nil, errors.New("пустой выход модели")
	}
	m := math.Inf(-1)
	for _, v := range logits {
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, errors.New("выход модели не число")
		}
		m = max(m, f)
	}
	out := make([]float64, len(logits))
	var sum float64
	for i, v := range logits {
		out[i] = math.Exp(float64(v) - m)
		sum += out[i]
	}
	for i := range out {
		out[i] /= sum
	}
	return out, nil
}

// textSpan — байтовые границы проверенной части текста по токенам.
func textSpan(offsets [][2]int) (start, end int) {
	start = -1
	for _, o := range offsets {
		if o[1] <= o[0] {
			continue
		}
		if start < 0 {
			start = o[0]
		}
		end = max(end, o[1])
	}
	if start < 0 {
		return 0, 0
	}
	return start, end
}

// classify — оценка каждой метки по тексту целиком: находка на проверенной
// части текста. Метки без категории (например, benign) отбрасывает шлюз.
func classify(logits []float32, labels []string, offsets [][2]int) ([]ml.Score, error) {
	if len(logits) != len(labels) {
		return nil, fmt.Errorf("выход модели: %d значений, меток %d", len(logits), len(labels))
	}
	p, err := softmax(logits)
	if err != nil {
		return nil, err
	}
	start, end := textSpan(offsets)
	out := make([]ml.Score, 0, len(labels))
	for i, l := range labels {
		out = append(out, ml.Score{Label: l, Score: p[i], Start: start, End: end})
	}
	return out, nil
}

// tokenSpans — разметка токенов: метка с наибольшей вероятностью у каждого
// токена, соседние токены с одной меткой (кроме «O») — один фрагмент с
// наименьшей из их оценок. Служебные токены (пустые границы) фрагмент
// прерывают.
func tokenSpans(logits []float32, labels []string, offsets [][2]int) ([]ml.Score, error) {
	nl := len(labels)
	if nl == 0 || len(logits) != len(offsets)*nl {
		return nil, fmt.Errorf("выход модели: %d значений, токенов %d, меток %d", len(logits), len(offsets), nl)
	}
	var out []ml.Score
	cur := -1 // индекс открытого фрагмента в out
	curLabel := ""
	for t, o := range offsets {
		p, err := softmax(logits[t*nl : (t+1)*nl])
		if err != nil {
			return nil, err
		}
		best := 0
		for i := range p {
			if p[i] > p[best] {
				best = i
			}
		}
		label := labels[best] //nolint:gosec // G602: best — индекс в p, а len(p) == len(labels)
		if o[1] <= o[0] || label == labelOutside {
			cur, curLabel = -1, ""
			continue
		}
		if cur >= 0 && label == curLabel && o[0] >= out[cur].End {
			out[cur].End = o[1]
			out[cur].Score = min(out[cur].Score, p[best])
			continue
		}
		if len(out) == ml.MaxFindings {
			break
		}
		out = append(out, ml.Score{Label: label, Score: p[best], Start: o[0], End: o[1]})
		cur, curLabel = len(out)-1, label
	}
	return out, nil
}
