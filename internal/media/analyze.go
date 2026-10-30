package media

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"

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

// decodable — форматы, которые декодирует стандартная библиотека. WebP,
// BMP и TIFF — после согласия на golang.org/x/image (задача 5.42).
var decodable = []wire.Format{wire.FormatPNG, wire.FormatJPEG, wire.FormatGIF}

// Decodable — форматы с декодером (для hello_ok).
func Decodable() []wire.Format { return append([]wire.Format(nil), decodable...) }

// errDecoderPanic — декодер завершился аварийно: итог запроса — internal.
var errDecoderPanic = errors.New("aisec-media: декодер завершился аварийно")

// Analyze проверяет изображение: размер, формат по сигнатуре, пределы по
// своему разбору заголовка — и только затем декодирует. Ошибка — только
// аварийное завершение декодера; отказы по формату и пределам — в итоге.
func Analyze(data []byte, l Limits) (wire.Result, error) {
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
	if err := decode(data, info); err != nil {
		if errors.Is(err, errDecoderPanic) {
			return wire.Result{}, err
		}
		return rejected(info, wire.ReasonMalformed), nil
	}
	return wire.Result{Status: wire.StatusOK, Format: info.Format, Width: info.Width, Height: info.Height,
		Frames: info.Frames, Checks: []wire.Check{wire.CheckDecode}}, nil
}

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
	case wire.FormatPNG, wire.FormatGIF:
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
// совпасть с заголовком. Паника декодера — errDecoderPanic.
func decode(data []byte, info Info) (err error) {
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
	default:
		return errors.New("aisec-media: нет декодера")
	}
	if err != nil {
		return err
	}
	if int64(cfg.Width) != info.Width || int64(cfg.Height) != info.Height {
		return errors.New("aisec-media: размеры декодера не совпали с заголовком")
	}
	return decodeRaster(data, info)
}

// decodeRaster — декодирование после проверки размеров. Растр в каркасе
// не используется; с задачи 5.42 его получает OCR (ADR-0032, раздел 9).
func decodeRaster(data []byte, info Info) error {
	bounds := image.Rect(0, 0, int(info.Width), int(info.Height))
	switch info.Format {
	case wire.FormatPNG:
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			return err
		}
		return sameBounds(img.Bounds(), bounds)
	case wire.FormatJPEG:
		img, err := jpeg.Decode(bytes.NewReader(data))
		if err != nil {
			return err
		}
		return sameBounds(img.Bounds(), bounds)
	default:
		// GIF: все кадры — инструкция может быть не на первом. Число кадров
		// и их размеры уже сверены своим разбором.
		g, err := gif.DecodeAll(bytes.NewReader(data))
		if err != nil {
			return err
		}
		if int64(len(g.Image)) != info.Frames {
			return errors.New("aisec-media: число кадров GIF не совпало с заголовком")
		}
		for _, f := range g.Image {
			if !f.Bounds().In(bounds) {
				return errors.New("aisec-media: кадр GIF за пределами экрана")
			}
		}
		return nil
	}
}

func sameBounds(got, want image.Rectangle) error {
	if got != want {
		return errors.New("aisec-media: границы растра не совпали с заголовком")
	}
	return nil
}
