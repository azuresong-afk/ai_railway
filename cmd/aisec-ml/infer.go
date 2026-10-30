package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"

	"github.com/azuresong-afk/ai_railway/internal/ml"
	"github.com/azuresong-afk/ai_railway/internal/ml/wordpiece"
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
	case ml.TaskClassification, ml.TaskMultiLabel:
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

// tokenizer — перевод текста в номера токенов модели: токены без служебных
// с байтовыми границами в тексте, не больше limit; truncated — у текста
// есть ещё токены. Special — номера [CLS] и [SEP].
type tokenizer interface {
	Encode(text string, limit int) (ids []int64, offsets [][2]int, truncated bool, err error)
	Special() (cls, sep int64)
}

// newTokenizer — токенизатор модели по tokenizer.json из проверенного
// пакета: WordPiece (internal/ml/wordpiece) — для моделей семейства BERT.
// Другой формат — отказ загрузки модели, а не неверные номера токенов.
var newTokenizer = func(spec ml.ModelSpec, data []byte) (tokenizer, error) {
	tk, err := wordpiece.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("модель %s: %w", spec.ID, err)
	}
	return tk, nil
}

// Окна длинного текста (ADR-0024, раздел 6): окно — [CLS], до max_tokens-2
// токенов текста, [SEP]; соседние окна перекрываются, чтобы фраза на стыке
// попала в окно целиком. Окон не больше maxWindows; остаток не проверяется
// (truncated, шлюз ставит ml_unavailable, если находок нет).
const (
	maxWindows    = 16
	windowOverlap = 64
)

// window — окно: номера токенов со служебными, границы токенов в тексте
// (у служебных [0, 0]) и номера «своих» токенов окна [own[0], own[1]) — для
// разметки токенов каждый токен перекрытия относится к одному окну.
type window struct {
	ids     []int64
	offsets [][2]int
	own     [2]int
}

// splitWindows режет текст на окна по maxTokens токенов. Токенизатор
// останавливается на пределе всех окон: длина текста не увеличивает работу
// сверх maxWindows окон.
func splitWindows(tok tokenizer, text string, maxTokens int) ([]window, bool, error) {
	w := maxTokens - 2
	if w < 1 {
		return nil, false, fmt.Errorf("окно модели %d токенов: нужно не меньше 3", maxTokens)
	}
	overlap := min(windowOverlap, w/4)
	stride := w - overlap
	ids, offs, truncated, err := tok.Encode(text, w+(maxWindows-1)*stride)
	if err != nil {
		return nil, false, err
	}
	if len(ids) != len(offs) {
		return nil, false, errors.New("токенизатор вернул неверное число границ")
	}
	cls, sep := tok.Special()
	var out []window
	for start := 0; start < len(ids); start += stride {
		end := min(start+w, len(ids))
		win := window{ids: make([]int64, 0, end-start+2), offsets: make([][2]int, 0, end-start+2)}
		win.ids = append(append(append(win.ids, cls), ids[start:end]...), sep)
		win.offsets = append(append(append(win.offsets, [2]int{}), offs[start:end]...), [2]int{})
		// Свои токены окна — без половины перекрытия с каждым соседом.
		win.own = [2]int{1, 1 + end - start}
		if start > 0 {
			win.own[0] += overlap / 2
		}
		last := end == len(ids)
		if !last {
			win.own[1] -= overlap - overlap/2
		}
		out = append(out, win)
		if last {
			break
		}
	}
	return out, truncated, nil
}

// inferFunc — вывод модели на одном окне: logits окна.
type inferFunc func(ctx context.Context, ids []int64) ([]float32, error)

// runWindows — вывод модели на тексте по окнам. Окна одного текста
// выполняются одновременно, каждое занимает место в slots (общий предел
// выводов исполнителя, -workers): задержка длинного текста при свободных
// ядрах — около одного окна, а одновременных выводов не больше -workers.
// slots == nil — окна по очереди. Классификация: у каждой метки —
// наибольшая оценка среди окон и границы этого окна. Разметка токенов:
// фрагменты по своим токенам окон подряд. Текст без токенов (пустой, только
// пробелы) находок не даёт.
func runWindows(ctx context.Context, spec ml.ModelSpec, tok tokenizer, text string, infer inferFunc, slots chan struct{}) (ml.Result, error) {
	info := spec.Info()
	res := ml.Result{Model: info.ID, Version: info.Version, Findings: []ml.Score{}}
	wins, truncated, err := splitWindows(tok, text, spec.MaxTokens)
	if err != nil {
		return ml.Result{}, err
	}
	res.Truncated = truncated
	logits, err := inferAll(ctx, wins, infer, slots)
	if err != nil {
		return ml.Result{}, err
	}
	nl := len(spec.Labels)
	var tokLogits []float32
	var tokOffs [][2]int
	for i, win := range wins {
		switch spec.Task {
		case ml.TaskClassification, ml.TaskMultiLabel:
			scores, err := classify(logits[i], spec.Labels, win.offsets, spec.Task == ml.TaskMultiLabel)
			if err != nil {
				return ml.Result{}, err
			}
			res.Findings = mergeMax(res.Findings, scores)
		case ml.TaskTokenClassification:
			if len(logits[i]) != len(win.ids)*nl {
				return ml.Result{}, fmt.Errorf("выход модели: %d значений, токенов %d, меток %d", len(logits[i]), len(win.ids), nl)
			}
			tokLogits = append(tokLogits, logits[i][win.own[0]*nl:win.own[1]*nl]...)
			tokOffs = append(tokOffs, win.offsets[win.own[0]:win.own[1]]...)
		default:
			return ml.Result{}, fmt.Errorf("задача %q не поддерживается", spec.Task)
		}
	}
	if spec.Task == ml.TaskTokenClassification && len(tokOffs) > 0 {
		if res.Findings, err = tokenSpans(tokLogits, spec.Labels, tokOffs); err != nil {
			return ml.Result{}, err
		}
	}
	return res, nil
}

// inferAll — вывод на всех окнах: по очереди (slots == nil) или
// одновременно в пределах slots. Первый сбой отменяет остальные окна.
func inferAll(ctx context.Context, wins []window, infer inferFunc, slots chan struct{}) ([][]float32, error) {
	out := make([][]float32, len(wins))
	if slots == nil || len(wins) == 1 {
		for i, w := range wins {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			l, err := infer(ctx, w.ids)
			if err != nil {
				return nil, err
			}
			out[i] = l
		}
		return out, nil
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	for i, w := range wins {
		wg.Go(func() {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-slots }()
			if ctx.Err() != nil {
				return
			}
			l, err := infer(ctx, w.ids)
			if err != nil {
				cancel(err)
				return
			}
			out[i] = l
		})
	}
	wg.Wait()
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// mergeMax — оценки меток по окнам: у каждой метки — наибольшая.
func mergeMax(acc, scores []ml.Score) []ml.Score {
	if len(acc) == 0 {
		return scores
	}
	if len(scores) != len(acc) { // окно без токенов текста оценок не даёт
		return acc
	}
	for i := range acc {
		if scores[i].Score > acc[i].Score {
			acc[i] = scores[i]
		}
	}
	return acc
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

// sigmoid — вероятность каждой метки отдельно (многометочная модель);
// NaN и бесконечности — ошибка модели.
func sigmoid(logits []float32) ([]float64, error) {
	if len(logits) == 0 {
		return nil, errors.New("пустой выход модели")
	}
	out := make([]float64, len(logits))
	for i, v := range logits {
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, errors.New("выход модели не число")
		}
		out[i] = 1 / (1 + math.Exp(-f))
	}
	return out, nil
}

// classify — оценка каждой метки по окну текста: находка на проверенной
// части окна. multi — метки независимы (сигмоида), иначе одна из всех
// (softmax). Окно без токенов текста находок не даёт. Метки без категории
// (например, benign) отбрасывает шлюз.
func classify(logits []float32, labels []string, offsets [][2]int, multi bool) ([]ml.Score, error) {
	if len(logits) != len(labels) {
		return nil, fmt.Errorf("выход модели: %d значений, меток %d", len(logits), len(labels))
	}
	prob := softmax
	if multi {
		prob = sigmoid
	}
	p, err := prob(logits)
	if err != nil {
		return nil, err
	}
	start, end := textSpan(offsets)
	if end <= start {
		return nil, nil
	}
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
