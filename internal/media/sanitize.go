package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	"image/png"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Очистка изображения перед отправкой провайдеру (media_sanitize, ТЗ 5.17,
// ADR-0032, дополнение 5.45). Изображение проверяется теми же пределами,
// что и при анализе, декодируется, поворачивается по ориентации EXIF (тег
// перекодирование снимает, 5Н28), уменьшается до SanitizeMaxSide по
// большей стороне и кодируется заново: JPEG — в JPEG, остальные форматы —
// в PNG. Кодировщики стандартной библиотеки не пишут метаданных, поэтому в
// итоге нет EXIF, XMP, текстовых чанков, комментариев, профилей и миниатюр;
// у GIF остаётся первый кадр, у TIFF — первая страница. Закрашивания нет
// (Р9): очистка снимает скрытые данные и часть состязательных искажений,
// но не находит их.

// Пределы стороны очищенного изображения (-sanitize-max-side).
const (
	DefaultSanitizeMaxSide = 2048
	MinSanitizeMaxSide     = 256
	MaxSanitizeMaxSide     = 8192
	// sanitizeJPEGQuality — качество перекодированного JPEG.
	sanitizeJPEGQuality = 90
)

// ErrSanitizeRejected — изображение нельзя очистить: формат не распознан
// или без декодера, отказ по пределам, повреждённый файл или итог больше
// предела. Ответ шлюзу — rejected.
var ErrSanitizeRejected = errors.New("aisec-media: изображение нельзя очистить")

// Sanitize очищает изображение: пределы до декодирования, декодирование,
// первый кадр, уменьшение, перекодирование. Итог не больше l.MaxBytes.
// Паника декодера или кодировщика — errDecoderPanic; отмена ctx проверяется
// между шагами (декодеры её не принимают).
func Sanitize(ctx context.Context, data []byte, l Limits, maxSide int) (out []byte, format wire.Format, err error) {
	defer func() {
		if p := recover(); p != nil {
			out, format, err = nil, "", errDecoderPanic
		}
	}()
	if maxSide < MinSanitizeMaxSide || maxSide > MaxSanitizeMaxSide {
		return nil, "", fmt.Errorf("aisec-media: сторона очищенного изображения — от %d до %d", MinSanitizeMaxSide, MaxSanitizeMaxSide)
	}
	if int64(len(data)) > l.MaxBytes {
		return nil, "", fmt.Errorf("%w: больше предела размера", ErrSanitizeRejected)
	}
	info, err := ParseHeader(data)
	if err != nil {
		return nil, "", fmt.Errorf("%w: заголовок не разобран", ErrSanitizeRejected)
	}
	if reason := l.exceeded(info); reason != "" {
		return nil, "", fmt.Errorf("%w: %s", ErrSanitizeRejected, reason)
	}
	// firstFrame рисует кадр GIF на холст размером с логический экран, а
	// Pixels у GIF — сумма по кадрам: экран 65535×65535 с кадром 4×4
	// проходил предел и требовал 17 ГБ. Экран проверяется до декодирования.
	if info.Width*info.Height > l.MaxPixels {
		return nil, "", fmt.Errorf("%w: %s", ErrSanitizeRejected, wire.ReasonTooManyPixels)
	}
	if !canDecode(info) {
		return nil, "", fmt.Errorf("%w: нет декодера", ErrSanitizeRejected)
	}
	frames, err := decode(data, info, l.rasterBudget())
	if err != nil {
		switch {
		case errors.Is(err, errDecoderPanic):
			return nil, "", err
		case errors.Is(err, errRasterBudget):
			return nil, "", fmt.Errorf("%w: %s", ErrSanitizeRejected, wire.ReasonTooManyPixels)
		}
		return nil, "", fmt.Errorf("%w: не декодировано", ErrSanitizeRejected)
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	img := firstFrame(frames[0], info)
	if w, h := img.Bounds().Dx(), img.Bounds().Dy(); w > maxSide || h > maxSide {
		img = downscale(img, maxSide)
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
	}
	var buf bytes.Buffer
	format = wire.FormatPNG
	if info.Format == wire.FormatJPEG {
		format = wire.FormatJPEG
		err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: sanitizeJPEGQuality})
	} else {
		err = (&png.Encoder{CompressionLevel: png.DefaultCompression}).Encode(&buf, img)
	}
	if err != nil {
		return nil, "", fmt.Errorf("aisec-media: перекодирование: %w", err)
	}
	if int64(buf.Len()) > l.MaxBytes || buf.Len() > wire.MaxSanitizedBody {
		return nil, "", fmt.Errorf("%w: итог больше предела размера", ErrSanitizeRejected)
	}
	return buf.Bytes(), format, nil
}

// firstFrame — кадр в границах экрана с началом в (0, 0): у GIF первый
// кадр может занимать часть экрана, остальное — прозрачное. Остальные
// форматы — как есть (кадр уже повёрнут по ориентации EXIF, 5Н28).
func firstFrame(f image.Image, info Info) image.Image {
	screen := image.Rect(0, 0, int(info.Width), int(info.Height))
	if info.Format != wire.FormatGIF || f.Bounds() == screen {
		return f
	}
	dst := image.NewNRGBA(screen)
	draw.Draw(dst, f.Bounds(), f, f.Bounds().Min, draw.Src)
	return dst
}

// downscale уменьшает изображение так, чтобы большая сторона стала maxSide:
// усреднение по области (каждый пиксель итога — среднее пикселей исходной
// области, доли на границах учитываются целыми пикселями). Вычисления — в
// RGBA с предумножением альфы, итог — RGBA.
func downscale(src image.Image, maxSide int) image.Image {
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	dw, dh := maxSide, maxSide
	if sw >= sh {
		dh = max(1, sh*maxSide/sw)
	} else {
		dw = max(1, sw*maxSide/sh)
	}
	rgba := image.NewRGBA(image.Rect(0, 0, sw, sh))
	draw.Draw(rgba, rgba.Bounds(), src, sb.Min, draw.Src)
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := range dh {
		y0, y1 := y*sh/dh, max((y+1)*sh/dh, y*sh/dh+1)
		for x := range dw {
			x0, x1 := x*sw/dw, max((x+1)*sw/dw, x*sw/dw+1)
			var r, g, b, a, n uint64
			for yy := y0; yy < y1; yy++ {
				row := rgba.Pix[yy*rgba.Stride+x0*4 : yy*rgba.Stride+x1*4]
				for i := 0; i < len(row); i += 4 {
					r += uint64(row[i])
					g += uint64(row[i+1])
					b += uint64(row[i+2])
					a += uint64(row[i+3])
					n++
				}
			}
			o := dst.PixOffset(x, y)
			dst.Pix[o], dst.Pix[o+1], dst.Pix[o+2], dst.Pix[o+3] = uint8(r/n), uint8(g/n), uint8(b/n), uint8(a/n) //nolint:gosec // G115: среднее байтов — байт
		}
	}
	return dst
}
