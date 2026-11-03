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
	"github.com/azuresong-afk/ai_railway/internal/media"
)

// Исполнитель моделей OCR на ONNX Runtime (ADR-0033, задача 5.41), как в
// aisec-ml (ADR-0024, раздел 8): собирается только с тегом aisec_onnx и
// CGO_ENABLED=1; обвязка onnxruntime_go разрешена только в cmd/aisec-ml и
// cmd/aisec-media (depguard onnx-binding). Только процессор: других
// поставщиков исполнения в сборке ORT нет.

// ortLibHash — хеш библиотеки ONNX Runtime (хеш профиля, шестнадцатеричный),
// встраивается при сборке: -ldflags "-X main.ortLibHash=…". Без него
// aisec-media библиотеку не загружает.
var ortLibHash string

// ocrBuilt — сборка с исполнителем OCR.
const ocrBuilt = true

// maxORTLib — предел размера библиотеки ORT при проверке хеша.
const maxORTLib = 512 << 20

var (
	ortOnce sync.Once
	ortErr  error
)

// newOCREngine проверяет хеш библиотеки ORT до её загрузки, хеши моделей —
// до создания сеансов, и поднимает исполнитель.
func newOCREngine(cfg *config, p aisecCrypto.Provider) (media.OCREngine, error) {
	ortOnce.Do(func() { ortErr = initORT(cfg.ORTLib, p, ortLibHash) })
	if ortErr != nil {
		return nil, ortErr
	}
	det, err := loadOCRModel(cfg.Models, ocrDetModel, p)
	if err != nil {
		return nil, err
	}
	rec, err := loadOCRModel(cfg.Models, ocrRecModel, p)
	if err != nil {
		return nil, err
	}
	// Параллельность — исполнители сервера (-workers); потоков внутри
	// одного вывода — доля процессоров контейнера на исполнителя (GOMAXPROCS
	// учитывает квоту cgroup). По замеру на корпусе (docs/detectors.md,
	// «OCR») при двух изображениях одновременно это быстрее общего пула на
	// все процессоры: потоки не вытесняют друг друга.
	threads := max(1, runtime.GOMAXPROCS(0)/max(1, cfg.Workers))
	e := &ortEngine{}
	if e.det, e.detIO, err = newSession(det, threads); err != nil {
		return nil, fmt.Errorf("детектор строк: %w", err)
	}
	if e.rec, e.recIO, err = newSession(rec, threads); err != nil {
		_ = e.det.Destroy() //nolint:gosec // G104: освобождение при ошибке
		return nil, fmt.Errorf("распознавание: %w", err)
	}
	if e.charset, err = recCharset(e.rec, e.recIO); err != nil {
		_ = e.det.Destroy() //nolint:gosec // G104: освобождение при ошибке
		_ = e.rec.Destroy() //nolint:gosec // G104: освобождение при ошибке
		return nil, err
	}
	return e, nil
}

// initORT сверяет хеш файла библиотеки и загружает её по дескриптору уже
// проверенного файла (/proc/self/fd/N), как aisec-ml: путь не может между
// проверкой и загрузкой начать указывать на другой файл.
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
	// Своя сборка — без телеметрии; вызов — вторая линия.
	if err := ort.DisableTelemetry(); err != nil {
		return fmt.Errorf("телеметрия ONNX Runtime: %w", err)
	}
	return nil
}

// modelIO — имена единственного входа и выхода модели и размерности выхода.
type modelIO struct {
	in, out string
	outDims []int64
}

// newSession — сеанс из проверенных байтов модели: один вход и один выход
// float32 (у моделей PaddleOCR — x и карта или вероятности классов).
func newSession(data []byte, threads int) (*ort.DynamicAdvancedSession, modelIO, error) {
	ins, outs, err := ort.GetInputOutputInfoWithONNXData(data)
	if err != nil {
		return nil, modelIO{}, fmt.Errorf("модель не разбирается ONNX Runtime: %w", err)
	}
	if len(ins) != 1 || len(outs) != 1 || ins[0].DataType != ort.TensorElementDataTypeFloat || outs[0].DataType != ort.TensorElementDataTypeFloat ||
		len(ins[0].Dimensions) != 4 {
		return nil, modelIO{}, errors.New("модель: ожидаются один вход NCHW float32 и один выход float32")
	}
	mio := modelIO{in: ins[0].Name, out: outs[0].Name, outDims: slices.Clone(outs[0].Dimensions)}
	opts, err := ort.NewSessionOptions()
	if err != nil {
		return nil, modelIO{}, err
	}
	defer opts.Destroy() //nolint:errcheck // параметры нужны только при создании сеанса
	if err := opts.SetIntraOpNumThreads(threads); err != nil {
		return nil, modelIO{}, err
	}
	if err := opts.SetInterOpNumThreads(1); err != nil {
		return nil, modelIO{}, err
	}
	s, err := ort.NewDynamicAdvancedSessionWithONNXData(data, []string{mio.in}, []string{mio.out}, opts)
	if err != nil {
		return nil, modelIO{}, fmt.Errorf("сеанс ONNX Runtime: %w", err)
	}
	return s, mio, nil
}

// recCharset — таблица символов из метаданных модели распознавания.
func recCharset(s *ort.DynamicAdvancedSession, mio modelIO) ([]string, error) {
	if len(mio.outDims) != 3 || mio.outDims[2] < 2 {
		return nil, errors.New("модель распознавания: выход не [N, T, классы]")
	}
	md, err := s.GetModelMetadata()
	if err != nil {
		return nil, err
	}
	defer md.Destroy() //nolint:errcheck // метаданные нужны только здесь
	chars, ok, err := md.LookupCustomMetadataMap("character")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("модель распознавания: в метаданных нет таблицы символов (character)")
	}
	return parseCharset(chars, mio.outDims[2])
}

// ortEngine — исполнитель моделей OCR (media.OCREngine).
type ortEngine struct {
	det, rec     *ort.DynamicAdvancedSession
	detIO, recIO modelIO
	charset      []string
}

func (e *ortEngine) Charset() []string { return e.charset }

// Detect — карта вероятностей [1, 1, h, w] детектора строк.
func (e *ortEngine) Detect(ctx context.Context, x []float32, h, w int) ([]float32, error) {
	out, dims, err := runModel(ctx, e.det, x, ort.NewShape(1, 3, int64(h), int64(w)))
	if err != nil {
		return nil, err
	}
	if len(dims) != 4 || dims[0] != 1 || dims[1] != 1 || dims[2] != int64(h) || dims[3] != int64(w) {
		return nil, media.ErrOCRModel
	}
	return out, nil
}

// Recognize — вероятности классов [1, T, C] распознавания строки.
func (e *ortEngine) Recognize(ctx context.Context, x []float32, w int) ([]float32, int, error) {
	out, dims, err := runModel(ctx, e.rec, x, ort.NewShape(1, 3, 48, int64(w)))
	if err != nil {
		return nil, 0, err
	}
	if len(dims) != 3 || dims[0] != 1 || dims[2] < 2 {
		return nil, 0, media.ErrOCRModel
	}
	return out, int(dims[2]), nil
}

// runModel — вывод с одним входом; отмена ctx прерывает его
// (RunOptions.Terminate). Итог — копия выхода и его размерности.
func runModel(ctx context.Context, s *ort.DynamicAdvancedSession, x []float32, shape ort.Shape) ([]float32, []int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	in, err := ort.NewTensor(shape, x)
	if err != nil {
		return nil, nil, err
	}
	defer in.Destroy() //nolint:errcheck // вход освобождается после вывода
	ro, err := ort.NewRunOptions()
	if err != nil {
		return nil, nil, err
	}
	defer ro.Destroy()                                            //nolint:errcheck // параметры вызова освобождаются после вывода
	stop := context.AfterFunc(ctx, func() { _ = ro.Terminate() }) //nolint:gosec // G104: прерывание вывода
	defer stop()
	outputs := []ort.Value{nil}
	if err := s.RunWithOptions([]ort.Value{in}, outputs, ro); err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, fmt.Errorf("вывод модели OCR: %w", err)
	}
	defer outputs[0].Destroy() //nolint:errcheck // выход освобождается после копирования
	t, ok := outputs[0].(*ort.Tensor[float32])
	if !ok {
		return nil, nil, media.ErrOCRModel
	}
	return slices.Clone(t.GetData()), slices.Clone([]int64(t.GetShape())), nil
}
