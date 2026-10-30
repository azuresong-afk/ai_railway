//go:build aisec_onnx && cgo

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"

	ort "github.com/yalue/onnxruntime_go"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// Исполнитель моделей на ONNX Runtime (ADR-0024, разделы 6 и 8). Собирается
// только с тегом aisec_onnx и CGO_ENABLED=1; обвязка onnxruntime_go
// разрешена только в cmd/aisec-ml (depguard).

// ortLibHash — хеш библиотеки ONNX Runtime (хеш профиля, шестнадцатеричный),
// встраивается при сборке: -ldflags "-X main.ortLibHash=…". Без него
// aisec-ml библиотеку не загружает.
var ortLibHash string

// maxORTLib — предел размера библиотеки ORT при проверке хеша.
const maxORTLib = 512 << 20

var (
	ortOnce sync.Once
	ortErr  error
)

// newExecutor проверяет хеш библиотеки ORT до её загрузки и поднимает среду
// ONNX Runtime (один раз на процесс).
func newExecutor(cfg *config, p aisecCrypto.Provider) (ml.Executor, error) {
	ortOnce.Do(func() { ortErr = initORT(cfg.ORTLib, p, ortLibHash) })
	if ortErr != nil {
		return nil, ortErr
	}
	return newONNXExecutor(cfg), nil
}

// newONNXExecutor — исполнитель с пределом одновременных выводов окон:
// -workers (0 — по числу процессоров), как у сервера протокола.
func newONNXExecutor(cfg *config) onnxExecutor {
	n := cfg.Workers
	if n <= 0 {
		n = runtime.GOMAXPROCS(0)
	}
	return onnxExecutor{slots: make(chan struct{}, n)}
}

// initORT сверяет хеш файла библиотеки и загружает её по дескриптору уже
// проверенного файла (/proc/self/fd/N): путь не может между проверкой и
// загрузкой начать указывать на другой файл. Содержимое того же файла
// защищено корневой ФС образа только для чтения.
func initORT(path string, p aisecCrypto.Provider, wantHex string) error {
	if wantHex == "" {
		return errors.New("сборка без хеша библиотеки ONNX Runtime (-X main.ortLibHash): загрузка запрещена")
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		return fmt.Errorf("встроенный хеш библиотеки ONNX Runtime: %w", err)
	}
	hasher, err := p.Hasher()
	if err != nil {
		return err
	}
	f, err := os.Open(path) //nolint:gosec // G304: путь задаёт администратор флагом -ort-lib, файл проверяется по хешу
	if err != nil {
		return fmt.Errorf("библиотека ONNX Runtime: %w", err)
	}
	defer f.Close() //nolint:errcheck // файл только читается; после dlopen дескриптор не нужен
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxORTLib {
		return fmt.Errorf("библиотека ONNX Runtime %s: не обычный файл или больше %d байт", path, maxORTLib)
	}
	h := hasher.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxORTLib)); err != nil {
		return fmt.Errorf("библиотека ONNX Runtime: %w", err)
	}
	if !aisecCrypto.Equal(h.Sum(nil), want) {
		return fmt.Errorf("библиотека ONNX Runtime %s: хеш не совпадает со встроенным при сборке", path)
	}
	ort.SetSharedLibraryPath("/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10))
	if err := ort.InitializeEnvironment(ort.WithLogLevelError()); err != nil {
		return fmt.Errorf("среда ONNX Runtime: %w", err)
	}
	// Своя сборка — без телеметрии (--no_telemetry); вызов — вторая линия.
	if err := ort.DisableTelemetry(); err != nil {
		return fmt.Errorf("телеметрия ONNX Runtime: %w", err)
	}
	return nil
}

// onnxExecutor — исполнитель; slots — общий предел одновременных выводов
// окон всех моделей.
type onnxExecutor struct{ slots chan struct{} }

// Load создаёт сеанс из проверенных байтов модели: файл модели повторно не
// читается. Входы и выходы сверяются с манифестом пакета.
func (e onnxExecutor) Load(lm ml.LoadedModel) (ml.Model, error) {
	tok, err := newTokenizer(lm.Spec, lm.Tokenizer)
	if err != nil {
		return nil, err
	}
	ins, outs, err := ort.GetInputOutputInfoWithONNXData(lm.Model)
	if err != nil {
		return nil, fmt.Errorf("модель не разбирается ONNX Runtime: %w", err)
	}
	mio, err := checkIO(lm.Spec, convertIO(ins), convertIO(outs))
	if err != nil {
		return nil, err
	}
	opts, err := ort.NewSessionOptions()
	if err != nil {
		return nil, err
	}
	defer opts.Destroy() //nolint:errcheck // параметры нужны только при создании сеанса
	// Параллельность — число исполнителей сервера (-workers), не потоки
	// внутри одного вывода: так предел CPU и памяти предсказуем.
	if err := opts.SetIntraOpNumThreads(1); err != nil {
		return nil, err
	}
	if err := opts.SetInterOpNumThreads(1); err != nil {
		return nil, err
	}
	s, err := ort.NewDynamicAdvancedSessionWithONNXData(lm.Model, mio.Inputs, []string{outputLogits}, opts)
	if err != nil {
		return nil, fmt.Errorf("сеанс ONNX Runtime: %w", err)
	}
	return &onnxModel{spec: lm.Spec, info: lm.Spec.Info(), io: mio, tok: tok, s: s, slots: e.slots}, nil
}

func convertIO(in []ort.InputOutputInfo) []ioInfo {
	out := make([]ioInfo, 0, len(in))
	for _, i := range in {
		k := kindOther
		if i.OrtValueType == ort.ONNXTypeTensor {
			switch i.DataType {
			case ort.TensorElementDataTypeInt64:
				k = kindInt64
			case ort.TensorElementDataTypeFloat:
				k = kindFloat32
			}
		}
		out = append(out, ioInfo{Name: i.Name, Kind: k, Dims: []int64(i.Dimensions)})
	}
	return out
}

type onnxModel struct {
	spec  ml.ModelSpec
	info  ml.ModelInfo
	io    modelIO
	tok   tokenizer
	s     *ort.DynamicAdvancedSession
	slots chan struct{}
}

func (m *onnxModel) Info() ml.ModelInfo { return m.info }

// Run — вывод на тексте по окнам (runWindows): окна одного текста —
// одновременно в пределах -workers. Отмена ctx прерывает вывод в ONNX
// Runtime (RunOptions.Terminate).
func (m *onnxModel) Run(ctx context.Context, text string) (ml.Result, error) {
	return runWindows(ctx, m.spec, m.tok, text, m.infer, m.slots)
}

// infer — вывод на одном окне [1, len(ids)].
func (m *onnxModel) infer(ctx context.Context, ids []int64) ([]float32, error) {
	if len(ids) == 0 || len(ids) > m.spec.MaxTokens {
		return nil, errors.New("окно токенов вне пределов модели")
	}
	shape := ort.NewShape(1, int64(len(ids)))
	data := encodeInputs(m.io, ids)
	inputs := make([]ort.Value, 0, len(m.io.Inputs))
	defer func() {
		for _, v := range inputs {
			_ = v.Destroy() //nolint:gosec // G104: освобождение тензора
		}
	}()
	for _, name := range m.io.Inputs {
		t, err := ort.NewTensor(shape, data[name])
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, t)
	}
	ro, err := ort.NewRunOptions()
	if err != nil {
		return nil, err
	}
	defer ro.Destroy()                                            //nolint:errcheck // параметры вызова освобождаются после вывода
	stop := context.AfterFunc(ctx, func() { _ = ro.Terminate() }) //nolint:gosec // G104: прерывание вывода
	defer stop()
	outputs := []ort.Value{nil}
	if err := m.s.RunWithOptions(inputs, outputs, ro); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("вывод модели: %w", err)
	}
	defer outputs[0].Destroy() //nolint:errcheck // выход освобождается после разбора
	logits, ok := outputs[0].(*ort.Tensor[float32])
	if !ok {
		return nil, errors.New("выход logits — не тензор float32")
	}
	// Копия: тензор освобождается при выходе.
	return slices.Clone(logits.GetData()), nil
}

func (m *onnxModel) Close() error { return m.s.Destroy() }
