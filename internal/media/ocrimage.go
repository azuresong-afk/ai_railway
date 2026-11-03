package media

import (
	"image"
	"image/draw"
	"math"
)

// Растр для OCR (задача 5.42, ADR-0033): декодированное изображение
// приводится к RGB на белом фоне (прозрачный текст PNG становится видимым
// так же, как в браузере), проход «контраст» — к серому со степенной
// кривой. Масштабирование и вырезка строк — билинейная выборка своим кодом:
// библиотек обработки изображений в aisec-media нет (ADR-0033, «Последствия»).

// raster — растр прохода: 4 байта на пиксель (RGBA, альфа — 255) или 1
// (серый).
type raster struct {
	w, h, ch int
	pix      []uint8
}

// rows — полоса строк [y0, y1) того же растра без копирования (растр
// только читается).
func (r *raster) rows(y0, y1 int) *raster {
	return &raster{w: r.w, h: y1 - y0, ch: r.ch, pix: r.pix[y0*r.w*r.ch : y1*r.w*r.ch]}
}

// rgbRaster рисует кадр на белом фоне. image/draw — стандартная
// библиотека, быстрые пути для RGBA, NRGBA, YCbCr и Gray.
func rgbRaster(img image.Image) *raster {
	b := img.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(dst, dst.Bounds(), image.White, image.Point{}, draw.Src)
	draw.Draw(dst, dst.Bounds(), img, b.Min, draw.Over)
	return &raster{w: b.Dx(), h: b.Dy(), ch: 4, pix: dst.Pix}
}

// contrastGamma — показатель кривой прохода «контраст» (ADR-0033, п. 2):
// бледный #eeeeee на белом становится серым 50 %.
const contrastGamma = 10.0

// contrastRaster — серый растр с кривой 255·(v/255)^10. Тёмный фон
// (медиана яркости ниже середины) сначала обращается: иначе кривая гасит
// светлый текст на тёмном (терминал, «системное сообщение», ADR-0033).
func contrastRaster(r *raster) *raster {
	var lut [256]uint8
	for v := range lut {
		lut[v] = uint8(math.Round(255 * math.Pow(float64(v)/255, contrastGamma)))
	}
	gray := make([]uint8, r.w*r.h)
	var hist [256]int
	for i := range gray {
		p := r.pix[i*4 : i*4+3]
		g := uint8((299*int(p[0]) + 587*int(p[1]) + 114*int(p[2]) + 500) / 1000) //nolint:gosec // G115: взвешенное среднее трёх байтов, не больше 255
		gray[i] = g
		hist[g]++
	}
	invert := false
	for v, n := 0, 0; v < 256; v++ {
		if n += hist[v]; 2*n >= len(gray) {
			invert = v < 128
			break
		}
	}
	for i, g := range gray {
		if invert {
			g = 255 - g
		}
		gray[i] = lut[g]
	}
	return &raster{w: r.w, h: r.h, ch: 1, pix: gray}
}

// bgr — каналы точки в порядке BGR (как cv2 в PaddleOCR).
func (r *raster) bgr(x, y int) (b, g, rd float32) {
	if r.ch == 1 {
		v := float32(r.pix[y*r.w+x])
		return v, v, v
	}
	p := r.pix[(y*r.w+x)*4:]
	return float32(p[2]), float32(p[1]), float32(p[0])
}

// sample — билинейная выборка в точке (x, y) (центры пикселей — целые),
// координаты за краем прижимаются к краю.
func (r *raster) sample(x, y float64) (b, g, rd float32) {
	x = clampF(x, 0, float64(r.w-1))
	y = clampF(y, 0, float64(r.h-1))
	x0, y0 := int(x), int(y)
	x1, y1 := min(x0+1, r.w-1), min(y0+1, r.h-1)
	wx, wy := float32(x-float64(x0)), float32(y-float64(y0))
	b00, g00, r00 := r.bgr(x0, y0)
	b01, g01, r01 := r.bgr(x1, y0)
	b10, g10, r10 := r.bgr(x0, y1)
	b11, g11, r11 := r.bgr(x1, y1)
	lerp := func(a, b, c, d float32) float32 {
		top := a + (b-a)*wx
		bot := c + (d-c)*wx
		return top + (bot-top)*wy
	}
	return lerp(b00, b01, b10, b11), lerp(g00, g01, g10, g11), lerp(r00, r01, r10, r11)
}

func clampF(v, lo, hi float64) float64 {
	return math.Max(lo, math.Min(hi, v))
}

// Нормализация входа детектора строк (ImageNet, порядок BGR).
var (
	detMean = [3]float32{0.485, 0.456, 0.406}
	detStd  = [3]float32{0.229, 0.224, 0.225}
)

// detInput — вход детектора NCHW [1, 3, rh, rw]: растр, масштабированный
// билинейно (углы пикселей, как cv2.INTER_LINEAR), нормализованный.
func detInput(r *raster, rh, rw int) []float32 {
	out := make([]float32, 3*rh*rw)
	plane := rh * rw
	sy, sx := float64(r.h)/float64(rh), float64(r.w)/float64(rw)
	for y := range rh {
		fy := (float64(y)+0.5)*sy - 0.5
		for x := range rw {
			fx := (float64(x)+0.5)*sx - 0.5
			b, g, rd := r.sample(fx, fy)
			i := y*rw + x
			out[i] = (b/255 - detMean[0]) / detStd[0]
			out[plane+i] = (g/255 - detMean[1]) / detStd[1]
			out[2*plane+i] = (rd/255 - detMean[2]) / detStd[2]
		}
	}
	return out
}

// Вход распознавания: высота строки и предел ширины (PaddleOCR rec).
const (
	recH    = 48
	recMaxW = 3200
	recMinW = 8
)

// recInput — вход распознавания NCHW [1, 3, 48, rw] для строки q (углы в
// пикселях растра: левый верхний, правый верхний, правый нижний, левый
// нижний): вырезка повёрнутой строки и масштаб — одной билинейной
// выборкой. Вертикальная строка (высота не меньше 1,5 ширины)
// поворачивается против часовой стрелки, как в PaddleOCR. Итог nil —
// строка меньше 3 пикселей.
func recInput(r *raster, q quad, scale float64) ([]float32, int) {
	w := math.Max(q[1].dist(q[0]), q[2].dist(q[3]))
	h := math.Max(q[3].dist(q[0]), q[2].dist(q[1]))
	if w*scale < 3 || h*scale < 3 {
		return nil, 0
	}
	vertical := h >= 1.5*w
	if vertical {
		w, h = h, w
	}
	rw := min(recMaxW, max(recMinW, int(math.Ceil(recH*w/h))))
	out := make([]float32, 3*recH*rw)
	plane := recH * rw
	for i := range recH {
		a := (float64(i) + 0.5) / recH
		for j := range rw {
			b := (float64(j) + 0.5) / float64(rw)
			// u — вдоль верхней стороны q (от q0 к q1), v — от верхней к нижней.
			u, v := b, a
			if vertical {
				u, v = 1-a, b
			}
			top := q[0].add(q[1].sub(q[0]).mul(u))
			bot := q[3].add(q[2].sub(q[3]).mul(u))
			p := top.add(bot.sub(top).mul(v))
			bl, g, rd := r.sample(p.x-0.5, p.y-0.5)
			k := i*rw + j
			out[k] = (bl/255 - 0.5) / 0.5
			out[plane+k] = (g/255 - 0.5) / 0.5
			out[2*plane+k] = (rd/255 - 0.5) / 0.5
		}
	}
	return out, rw
}
