package media

import (
	"image"
	"math"

	"github.com/makiuchi-d/gozxing"
	qrmulti "github.com/makiuchi-d/gozxing/multi/qrcode"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// QR-коды на изображении (задача 5.43, DM-47): декодер gozxing (MIT, порт
// ZXing; ADR-0032, «Зависимости») получает уже декодированный и
// ограниченный пределами растр, а не файл. Ищутся несколько кодов на
// кадре; у GIF — первые maxQRFrames кадров. Режим TRY_HARDER выключен: на
// шуме 25 Мпикс он занимает около 4 с против 0,3 с без него, а коды
// корпуса читаются и так. Рамка — по точкам шаблонов
// поиска в координатах экрана. Паника декодера — errDecoderPanic, как у
// декодеров изображений.

// Пределы чтения QR.
const (
	maxQRFrames = 4
	maxQRCodes  = 16
)

// readQR передаёт текст QR-кодов кадров в ts.
func readQR(frames []image.Image, ts *textSet) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = errDecoderPanic
		}
	}()
	for _, img := range frames[:min(len(frames), maxQRFrames)] {
		b := img.Bounds()
		if b.Dx() < 21 || b.Dy() < 21 { // меньше наименьшего QR-кода
			continue
		}
		bmp, berr := gozxing.NewBinaryBitmapFromImage(img)
		if berr != nil {
			continue
		}
		res, derr := qrmulti.NewQRCodeMultiReader().DecodeMultiple(bmp, nil)
		if derr != nil { // кода нет или он повреждён
			continue
		}
		for _, r := range res[:min(len(res), maxQRCodes)] {
			if !ts.add(wire.SourceQR, r.GetText(), qrBox(r.GetResultPoints(), b)) {
				return nil
			}
		}
	}
	return nil
}

// qrBox — рамка по точкам кода (относительно кадра) в координатах экрана,
// в пределах кадра; nil — точек нет.
func qrBox(pts []gozxing.ResultPoint, b image.Rectangle) *wire.Box {
	if len(pts) == 0 {
		return nil
	}
	x0, y0, x1, y1 := math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
	for _, p := range pts {
		if p == nil {
			continue
		}
		x0, y0 = math.Min(x0, p.GetX()), math.Min(y0, p.GetY())
		x1, y1 = math.Max(x1, p.GetX()), math.Max(y1, p.GetY())
	}
	if math.IsInf(x0, 0) || math.IsNaN(x0+y0+x1+y1) {
		return nil
	}
	clamp := func(v float64, hi int) int64 { return int64(math.Max(0, math.Min(v, float64(hi)))) }
	w, h := b.Dx(), b.Dy()
	bx0, by0 := clamp(math.Floor(x0), w-1), clamp(math.Floor(y0), h-1)
	bx1, by1 := clamp(math.Ceil(x1), w), clamp(math.Ceil(y1), h)
	box := &wire.Box{X: int64(b.Min.X) + bx0, Y: int64(b.Min.Y) + by0, W: max(1, bx1-bx0), H: max(1, by1-by0)}
	if bx0+box.W > int64(w) {
		box.W = int64(w) - bx0
	}
	if by0+box.H > int64(h) {
		box.H = int64(h) - by0
	}
	return box
}
