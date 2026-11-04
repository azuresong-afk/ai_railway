package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"slices"

	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"
	"golang.org/x/image/webp"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Пределы до декодирования по умолчанию (ТЗ 5.17, ADR-0032, раздел 6).
const (
	DefaultMaxBytes  = 10 << 20
	DefaultMaxPixels = 25_000_000
	// MinMaxBytes — наименьший допустимый -max-bytes.
	MinMaxBytes = 1 << 20
	// DefaultMaxRasterBytes — предел памяти растров одного анализа (5В4
	// ревью 5.r4, ADR-0032, раздел 5): при умолчаниях укладывается RGBA
	// 25 Мпикс с OCR и очисткой (оценка 302 МиБ), а два исполнителя и
	// запас под ONNX Runtime — в mem_limit 1 ГиБ.
	DefaultMaxRasterBytes = 320 << 20
	// MinMaxRasterBytes и MaxMaxRasterBytes — допустимый -max-raster-mib.
	MinMaxRasterBytes = 96 << 20
	MaxMaxRasterBytes = 8 << 30
)

// Limits — пределы, проверяемые по заголовку до декодирования.
type Limits struct {
	MaxBytes  int64
	MaxPixels int64
	// MaxRasterBytes — предел оценки памяти растров одного анализа по
	// заголовку (rasterCost); 0 — DefaultMaxRasterBytes.
	MaxRasterBytes int64
}

// Validate проверяет пределы: размер файла — от 1 МиБ до предела протокола,
// пиксели — от 1 до 100 Мпикс, память растров — 0 (умолчание) или от
// 96 МиБ до 8 ГиБ.
func (l Limits) Validate() error {
	if l.MaxBytes < MinMaxBytes || l.MaxBytes > wire.MaxContent {
		return fmt.Errorf("aisec-media: предел размера — от %d до %d байт", MinMaxBytes, wire.MaxContent)
	}
	if l.MaxPixels < 1 || l.MaxPixels > wire.MaxPixelsLimit {
		return fmt.Errorf("aisec-media: предел пикселей — от 1 до %d", wire.MaxPixelsLimit)
	}
	if l.MaxRasterBytes != 0 && (l.MaxRasterBytes < MinMaxRasterBytes || l.MaxRasterBytes > MaxMaxRasterBytes) {
		return fmt.Errorf("aisec-media: предел памяти растров — от %d до %d байт", MinMaxRasterBytes, MaxMaxRasterBytes)
	}
	return nil
}

// rasterBudget — действующий предел памяти растров.
func (l Limits) rasterBudget() int64 {
	if l.MaxRasterBytes == 0 {
		return DefaultMaxRasterBytes
	}
	return l.MaxRasterBytes
}

// Оценка памяти анализа по заголовку (5В4 ревью 5.r4). Предел пикселей
// один для всех форматов, а память растра — нет: PNG и TIFF с глубиной
// 16 бит декодируются в 8 байт на пиксель, а не в 4. Поэтому до
// декодирования, по модели цвета из DecodeConfig того же декодера,
// оценивается вся память пути: декодированные кадры, копии кадра на белом
// фоне и в сером для OCR, растр QR, копия RGBA при уменьшении в очистке,
// холст первого кадра GIF, поворот по ориентации EXIF, плюс входы
// детектора OCR. Коэффициенты проверены замером наибольшей кучи
// (TestRasterCostCoversPeakHeap): оценка — верхняя граница.
const (
	// rasterWorkPerPixel — байт на пиксель кадра сверх декодированного:
	// RGBA для OCR (4), серый для «контраста» (1), QR (до 1,3; к OCR уже
	// освобождён). Очистка (RGBA для уменьшения, 4) — не больше этого.
	rasterWorkPerPixel = 6
	// rasterCanvasPerPixel — холст первого кадра GIF (NRGBA) и кадр после
	// поворота по ориентации EXIF (RGBA).
	rasterCanvasPerPixel = 4
	// rasterFixed — не зависящее от размера: входы и карты детектора OCR
	// на проходе ×2 (до 1920×1920), вход распознавания, буферы декодера.
	rasterFixed = 64 << 20
)

// bytesPerPixel — байт на пиксель растра, который вернёт декодер с этой
// моделью цвета; неизвестная модель — 8 (наибольшее у декодеров Go).
func bytesPerPixel(m color.Model) int64 {
	if _, ok := m.(color.Palette); ok {
		return 1
	}
	switch m {
	case color.GrayModel, color.AlphaModel:
		return 1
	case color.Gray16Model, color.Alpha16Model:
		return 2
	case color.YCbCrModel:
		return 3 // 4:4:4 — наибольшее
	case color.RGBAModel, color.NRGBAModel, color.CMYKModel, color.NYCbCrAModel:
		return 4
	}
	return 8
}

// rasterCost — оценка памяти анализа или очистки изображения, байт.
// rotated — кадр будет повёрнут по ориентации EXIF (копия RGBA).
func rasterCost(info Info, m color.Model, rotated bool) int64 {
	frame := info.Width * info.Height
	cost := info.Pixels*bytesPerPixel(m) + frame*rasterWorkPerPixel + rasterFixed
	if info.Format == wire.FormatGIF {
		cost += frame * rasterCanvasPerPixel
	}
	if rotated {
		cost += frame * rasterCanvasPerPixel
	}
	return cost
}

// errRasterBudget — оценка памяти растров больше предела: итог —
// rejected too_many_pixels, декодер не вызывается.
var errRasterBudget = errors.New("aisec-media: оценка памяти растров больше предела")

// decodable — форматы с декодером: PNG, JPEG, GIF — стандартная
// библиотека; WebP, BMP и TIFF — golang.org/x/image v0.47.0 (согласие
// владельца 02.11.2026, задача 5.42), только в internal/media (depguard
// media-decoders).
var decodable = []wire.Format{wire.FormatPNG, wire.FormatJPEG, wire.FormatGIF, wire.FormatWebP, wire.FormatBMP, wire.FormatTIFF}

// Decodable — форматы с декодером (для hello_ok).
func Decodable() []wire.Format { return append([]wire.Format(nil), decodable...) }

// errDecoderPanic — декодер завершился аварийно: итог запроса — internal.
var errDecoderPanic = errors.New("aisec-media: декодер завершился аварийно")

// errDecoderUnsupported — разновидность формата, которую декодер не знает
// (сжатие BMP, редкая схема TIFF): итог — unsupported, а не malformed.
var errDecoderUnsupported = errors.New("aisec-media: разновидность формата не поддерживается декодером")

// Analyze — анализ без OCR (сборка без исполнителя моделей, тесты и fuzz).
func Analyze(data []byte, l Limits) (wire.Result, error) {
	return Analyzer{Limits: l}.Analyze(context.Background(), data)
}

// Analyzer — анализ изображения с пределами и, если есть, OCR.
type Analyzer struct {
	Limits Limits
	// OCR — распознавание текста (ADR-0033); nil — без OCR: проверки без
	// ocr, изображение у шлюза «не проверено» (no_ocr).
	OCR *OCR
}

// Analyze проверяет изображение: размер, формат по сигнатуре, пределы по
// своему разбору заголовка — и только затем декодирует. Ошибка — аварийное
// завершение декодера, отмена ctx или сбой OCR; отказы по формату и
// пределам — в итоге.
func (a Analyzer) Analyze(ctx context.Context, data []byte) (wire.Result, error) {
	l := a.Limits
	if int64(len(data)) > l.MaxBytes {
		return rejected(Info{}, wire.ReasonTooLarge), nil
	}
	info, err := ParseHeader(data)
	if res, failed := headerFailure(info, err); failed {
		return res, nil
	}
	if reason := l.exceeded(info); reason != "" {
		return rejected(info, reason), nil
	}
	if !canDecode(info) {
		return unsupported(info), nil
	}
	frames, err := decode(data, info, l.rasterBudget())
	if err != nil {
		switch {
		case errors.Is(err, errDecoderPanic):
			return wire.Result{}, err
		case errors.Is(err, errDecoderUnsupported):
			return unsupported(info), nil
		case errors.Is(err, errRasterBudget):
			return rejected(info, wire.ReasonTooManyPixels), nil
		}
		return rejected(info, wire.ReasonMalformed), nil
	}
	// Текст — только у принятого декодером файла: метаданные, затем QR
	// (задача 5.43), затем OCR (5.42). Порядок задаёт, что останется при
	// пределе протокола. OCR — по первому кадру (у GIF — первый кадр
	// анимации, обычно полный).
	var ts textSet
	readMetadata(data, info.Format, &ts)
	if err := readQR(frames, &ts); err != nil {
		return wire.Result{}, err
	}
	if a.OCR != nil {
		if err := a.OCR.Read(ctx, frames[0], &ts); err != nil {
			return wire.Result{}, err
		}
	}
	return wire.Result{Status: wire.StatusOK, Format: info.Format, Width: info.Width, Height: info.Height,
		Frames: info.Frames, Checks: a.Checks(), Texts: ts.texts}, nil
}

// checksDone — проверки принятого изображения без OCR.
var checksDone = []wire.Check{wire.CheckDecode, wire.CheckMetadata, wire.CheckQR}

// Checks — проверки анализатора (для hello_ok и итога): с OCR — и ocr.
func (a Analyzer) Checks() []wire.Check {
	if a.OCR == nil {
		return slices.Clone(checksDone)
	}
	return []wire.Check{wire.CheckDecode, wire.CheckOCR, wire.CheckMetadata, wire.CheckQR}
}

// Checks — проверки анализатора без OCR.
func Checks() []wire.Check { return slices.Clone(checksDone) }

// headerFailure — итог, если заголовок не разобран: формат не распознан
// или разновидность не поддерживается — unsupported, иначе — malformed.
func headerFailure(info Info, err error) (wire.Result, bool) {
	switch {
	case err == nil:
		return wire.Result{}, false
	case errors.Is(err, ErrUnknownFormat):
		return wire.Result{Status: wire.StatusUnsupported, Checks: []wire.Check{}}, true
	case errors.Is(err, ErrUnsupportedVariant):
		return unsupported(info), true
	}
	return rejected(info, wire.ReasonMalformed), true
}

// exceeded — причина отказа по пределам или "".
func (l Limits) exceeded(info Info) wire.Reason {
	switch {
	case (info.Format == wire.FormatGIF && info.Frames > MaxGIFFrames) || (info.Format == wire.FormatTIFF && info.Frames > MaxTIFFPages):
		return wire.ReasonTooManyFrames
	case info.Scans > MaxJPEGScans:
		return wire.ReasonTooManyScans
	case info.Pixels > l.MaxPixels:
		return wire.ReasonTooManyPixels
	}
	return ""
}

// canDecode — есть декодер: формат из decodable, у JPEG — кадр SOF0–SOF2.
func canDecode(info Info) bool {
	switch info.Format {
	case wire.FormatPNG, wire.FormatGIF, wire.FormatWebP, wire.FormatBMP, wire.FormatTIFF:
		return true
	case wire.FormatJPEG:
		return info.jpegSOF >= 0xC0 && info.jpegSOF <= 0xC2
	}
	return false
}

func rejected(info Info, r wire.Reason) wire.Result {
	return wire.Result{Status: wire.StatusRejected, Reason: r, Format: info.Format, Width: info.Width, Height: info.Height,
		Frames: info.Frames, Checks: []wire.Check{}}
}

func unsupported(info Info) wire.Result {
	return wire.Result{Status: wire.StatusUnsupported, Format: info.Format, Width: info.Width, Height: info.Height,
		Frames: info.Frames, Checks: []wire.Check{}}
}

// decode декодирует растр стандартной библиотекой. Перед декодером размеры
// сверяются с DecodeConfig того же пакета: расхождение своего разбора и
// разбора декодера обошло бы предел. Затем по модели цвета декодера
// оценивается память пути (rasterCost): больше budget — errRasterBudget.
// После — границы растра обязаны совпасть с заголовком. Итог — кадры (у
// GIF — все, у остальных — один). Паника декодера — errDecoderPanic.
func decode(data []byte, info Info, budget int64) (frames []image.Image, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = errDecoderPanic
		}
	}()
	var cfg image.Config
	switch info.Format {
	case wire.FormatPNG:
		cfg, err = png.DecodeConfig(bytes.NewReader(data))
	case wire.FormatJPEG:
		cfg, err = jpeg.DecodeConfig(bytes.NewReader(data))
	case wire.FormatGIF:
		cfg, err = gif.DecodeConfig(bytes.NewReader(data))
	case wire.FormatWebP:
		cfg, err = webp.DecodeConfig(bytes.NewReader(data))
	case wire.FormatBMP:
		cfg, err = bmp.DecodeConfig(bytes.NewReader(data))
	case wire.FormatTIFF:
		cfg, err = tiff.DecodeConfig(bytes.NewReader(data))
	default:
		return nil, errors.New("aisec-media: нет декодера")
	}
	if err != nil {
		return nil, decoderError(err)
	}
	if int64(cfg.Width) != info.Width || int64(cfg.Height) != info.Height {
		return nil, errors.New("aisec-media: размеры декодера не совпали с заголовком")
	}
	if rasterCost(info, cfg.ColorModel, false) > budget {
		return nil, errRasterBudget
	}
	return decodeRaster(data, info)
}

// decodeRaster — декодирование после проверки размеров. Растр получают
// QR (5.43) и OCR (5.42, ADR-0032, раздел 9).
func decodeRaster(data []byte, info Info) ([]image.Image, error) {
	bounds := image.Rect(0, 0, int(info.Width), int(info.Height))
	var img image.Image
	var err error
	switch info.Format {
	case wire.FormatPNG:
		img, err = png.Decode(bytes.NewReader(data))
	case wire.FormatJPEG:
		img, err = jpeg.Decode(bytes.NewReader(data))
	case wire.FormatWebP:
		img, err = webp.Decode(bytes.NewReader(data))
	case wire.FormatBMP:
		img, err = bmp.Decode(bytes.NewReader(data))
	case wire.FormatTIFF:
		// Первая страница: остальные страницы x/image/tiff не декодирует,
		// их число уже ограничено своим разбором (MaxTIFFPages).
		img, err = tiff.Decode(bytes.NewReader(data))
	default:
		// GIF: все кадры — инструкция может быть не на первом. Число кадров
		// и их размеры уже сверены своим разбором.
		g, gerr := gif.DecodeAll(bytes.NewReader(data))
		if gerr != nil {
			return nil, gerr
		}
		if int64(len(g.Image)) != info.Frames {
			return nil, errors.New("aisec-media: число кадров GIF не совпало с заголовком")
		}
		frames := make([]image.Image, 0, len(g.Image))
		for _, f := range g.Image {
			if !f.Bounds().In(bounds) {
				return nil, errors.New("aisec-media: кадр GIF за пределами экрана")
			}
			frames = append(frames, f)
		}
		return frames, nil
	}
	if err != nil {
		return nil, decoderError(err)
	}
	if err := sameBounds(img.Bounds(), bounds); err != nil {
		return nil, err
	}
	return []image.Image{img}, nil
}

// decoderError — ошибка декодера: неподдерживаемая разновидность BMP и
// TIFF — errDecoderUnsupported, остальное — повреждённый файл.
func decoderError(err error) error {
	var tu tiff.UnsupportedError
	if errors.Is(err, bmp.ErrUnsupported) || errors.As(err, &tu) {
		return fmt.Errorf("%w: %w", errDecoderUnsupported, err)
	}
	return err
}

func sameBounds(got, want image.Rectangle) error {
	if got != want {
		return errors.New("aisec-media: границы растра не совпали с заголовком")
	}
	return nil
}
