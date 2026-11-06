package media

import (
	"image"
	"image/draw"
)

// Ориентация EXIF (5Н28 ревью 5.r4 этапа 5): снимок с телефона хранит
// пиксели как у сенсора, а тег Orientation (0x0112) говорит, как повернуть
// их для показа. Браузер и провайдер с исходным файлом видят снимок
// повёрнутым правильно; очистка снимает тег перекодированием, а OCR читает
// растр как есть — поэтому кадр поворачивается сразу после декодирования,
// до QR, OCR и очистки. Память поворота (копия RGBA) учтена в rasterCost.

// orientImage — кадр в ориентации показа для Orientation 2–8 (RGBA с
// началом в (0, 0)); 1 и неизвестное значение — кадр без изменений.
// Сначала кадр переводится в RGBA (быстрые пути image/draw), затем
// пиксели переставляются; исходный растр после этого не нужен.
func orientImage(src image.Image, o int) image.Image {
	if o < 2 || o > 8 {
		return src
	}
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	tmp := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(tmp, tmp.Bounds(), src, b.Min, draw.Src)
	dw, dh := w, h
	if o >= 5 {
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := range dh {
		for x := range dw {
			sx, sy := orientSource(o, x, y, w, h)
			si, di := tmp.PixOffset(sx, sy), dst.PixOffset(x, y)
			copy(dst.Pix[di:di+4], tmp.Pix[si:si+4])
		}
	}
	return dst
}

// orientSource — точка исходного кадра w×h, которая при ориентации o
// показывается в точке (x, y): 2 — зеркально по горизонтали, 3 — поворот
// на 180°, 4 — зеркально по вертикали, 5 — транспонирование, 6 — поворот
// на 90° по часовой, 7 — поперечное транспонирование, 8 — поворот на 90°
// против часовой.
func orientSource(o, x, y, w, h int) (int, int) {
	switch o {
	case 2:
		return w - 1 - x, y
	case 3:
		return w - 1 - x, h - 1 - y
	case 4:
		return x, h - 1 - y
	case 5:
		return y, x
	case 6:
		return y, h - 1 - x
	case 7:
		return w - 1 - y, h - 1 - x
	case 8:
		return w - 1 - y, x
	}
	return x, y
}
