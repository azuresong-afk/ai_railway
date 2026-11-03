package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
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
)

// Limits — пределы, проверяемые по заголовку до декодирования.
type Limits struct {
	MaxBytes  int64
	MaxPixels int64
}

// Validate проверяет пределы: размер файла — от 1 МиБ до предела протокола,
// пиксели — от 1 до 100 Мпикс.
func (l Limits) Validate() error {
	if l.MaxBytes < MinMaxBytes || l.MaxBytes > wire.MaxContent {
		return fmt.Errorf("aisec-media: предел размера — от %d до %d байт", MinMaxBytes, wire.MaxContent)
	}
	if l.MaxPixels < 1 || l.MaxPixels > wire.MaxPixelsLimit {
		return fmt.Errorf("aisec-media: предел пикселей — от 1 до %d", wire.MaxPixelsLimit)
	}
	return nil
}

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
	frames, err := decode(data, info)
	if err != nil {
		switch {
		case errors.Is(err, errDecoderPanic):
			return wire.Result{}, err
		case errors.Is(err, errDecoderUnsupported):
			return unsupported(info), nil
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
// разбора декодера обошло бы предел. После — границы растра обязаны
// совпасть с заголовком. Итог — кадры (у GIF — все, у остальных — один).
// Паника декодера — errDecoderPanic.
func decode(data []byte, info Info) (frames []image.Image, err error) {
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
