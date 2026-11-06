package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Цвета углов эталона в ориентации показа: верхний левый, верхний правый,
// нижний левый, нижний правый.
var orientColors = [4]color.RGBA{{220, 30, 30, 255}, {30, 200, 30, 255}, {30, 30, 220, 255}, {240, 240, 240, 255}}

// storedCorners — какой угол эталона лежит в каждом углу хранимого кадра
// при ориентации o (таблица EXIF 2.32, тег Orientation; независимо от
// orientSource): индексы orientColors для углов TL, TR, BL, BR.
var storedCorners = map[int][4]int{
	1: {0, 1, 2, 3},
	2: {1, 0, 3, 2}, // зеркально по горизонтали
	3: {3, 2, 1, 0}, // поворот на 180°
	4: {2, 3, 0, 1}, // зеркально по вертикали
	5: {0, 2, 1, 3}, // транспонирование
	6: {1, 3, 0, 2}, // хранится повёрнутым на 90° против часовой
	7: {3, 1, 2, 0}, // поперечное транспонирование
	8: {2, 0, 3, 1}, // хранится повёрнутым на 90° по часовой
}

// orientShown — размеры эталона в ориентации показа.
const orientW, orientH = 48, 32

// storedImage — хранимый кадр для ориентации o: четыре одноцветных
// квадранта, цвета — по storedCorners.
func storedImage(o int) *image.RGBA {
	w, h := orientW, orientH
	if o >= 5 {
		w, h = h, w
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	c := storedCorners[o]
	for y := range h {
		for x := range w {
			q := 0
			if x >= w/2 {
				q++
			}
			if y >= h/2 {
				q += 2
			}
			img.SetRGBA(x, y, orientColors[c[q]])
		}
	}
	return img
}

func orientEXIF(bo byteOrder, o int) []byte {
	return exifBlock(bo, []exifEntry{{orientationTag, 3, bo.AppendUint16(nil, uint16(o))}}, nil) //nolint:gosec // G115: 1–8
}

// orientedPNG — PNG хранимого кадра с чанком eXIf.
func orientedPNG(t *testing.T, o int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, storedImage(o)); err != nil {
		t.Fatal(err)
	}
	const ihdrEnd = 8 + 25
	data := b.Bytes()
	out := append([]byte(nil), data[:ihdrEnd]...)
	out = append(out, pngChunk("eXIf", orientEXIF(binary.BigEndian, o))...)
	return append(out, data[ihdrEnd:]...)
}

// orientedJPEG — JPEG хранимого кадра с APP1 EXIF сразу после SOI.
func orientedJPEG(t *testing.T, o int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, storedImage(o), &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	app1 := jpegSegment(0xE1, append(append([]byte(nil), exifPrefix...), orientEXIF(binary.LittleEndian, o)...))
	data := b.Bytes()
	return append(append(append([]byte(nil), data[:2]...), app1...), data[2:]...)
}

// assertUpright — углы изображения совпадают с эталоном в ориентации показа.
func assertUpright(t *testing.T, name string, img image.Image, tol int) {
	t.Helper()
	b := img.Bounds()
	if b.Dx() != orientW || b.Dy() != orientH {
		t.Fatalf("%s: размеры %v, ждали %d×%d", name, b, orientW, orientH)
	}
	pts := [4]image.Point{{4, 4}, {orientW - 5, 4}, {4, orientH - 5}, {orientW - 5, orientH - 5}}
	for i, p := range pts {
		r, g, bl, _ := img.At(b.Min.X+p.X, b.Min.Y+p.Y).RGBA()
		want := orientColors[i]
		if abs(int(r>>8)-int(want.R)) > tol || abs(int(g>>8)-int(want.G)) > tol || abs(int(bl>>8)-int(want.B)) > tol {
			t.Fatalf("%s: угол %d — %d,%d,%d, ждали %v", name, i, r>>8, g>>8, bl>>8, want)
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// 5Н28 ревью 5.r4 этапа 5: снимок с тегом Orientation 2–8 после очистки
// уходит провайдеру в ориентации показа (тег перекодирование снимает), а
// анализ сообщает размеры показа. PNG — точно, JPEG — с допуском сжатия.
func TestSanitizeAppliesEXIFOrientation(t *testing.T) {
	ctx := context.Background()
	for o := 1; o <= 8; o++ {
		for _, f := range []struct {
			name string
			data []byte
			tol  int
		}{{"PNG", orientedPNG(t, o), 0}, {"JPEG", orientedJPEG(t, o), 24}} {
			if got := orientation(f.data, map[string]wire.Format{"PNG": wire.FormatPNG, "JPEG": wire.FormatJPEG}[f.name]); got != o {
				t.Fatalf("%s %d: прочитана ориентация %d", f.name, o, got)
			}
			out, _, err := Sanitize(ctx, f.data, testLimits, DefaultSanitizeMaxSide)
			if err != nil {
				t.Fatalf("%s %d: %v", f.name, o, err)
			}
			img, _, err := image.Decode(bytes.NewReader(out))
			if err != nil {
				t.Fatal(err)
			}
			assertUpright(t, f.name+" очистка", img, f.tol)
			r, err := Analyze(f.data, testLimits)
			if err != nil || r.Status != wire.StatusOK || r.Width != orientW || r.Height != orientH || r.Validate() != nil {
				t.Fatalf("%s %d: анализ %+v %v", f.name, o, r, err)
			}
		}
	}
}

// OCR читает кадр в ориентации показа: вход детектора снимка, хранимого
// «стоя» (Orientation 6 и 8), — альбомный, как эталон.
func TestOCRUsesEXIFOrientation(t *testing.T) {
	for _, o := range []int{1, 6, 8} {
		e := newFakeEngine(fakeLine{0.1, 0.4, 0.9, 0.6, "строка"})
		ocr, err := NewOCR(e)
		if err != nil {
			t.Fatal(err)
		}
		r, err := (Analyzer{Limits: testLimits, OCR: ocr}).Analyze(context.Background(), orientedPNG(t, o))
		if err != nil || r.Status != wire.StatusOK {
			t.Fatalf("%d: %+v %v", o, r, err)
		}
		if len(e.detDims) == 0 || e.detDims[0][0] >= e.detDims[0][1] {
			t.Fatalf("%d: вход детектора %v — не альбомный", o, e.detDims)
		}
		for _, tx := range r.Texts {
			if tx.Box != nil && (tx.Box.X+tx.Box.W > orientW || tx.Box.Y+tx.Box.H > orientH) {
				t.Fatalf("%d: рамка %+v вне %d×%d", o, tx.Box, orientW, orientH)
			}
		}
	}
}

// Значение тега вне 1–8, другой тип, несколько значений, повреждённый блок
// — ориентация 1 (кадр не поворачивается).
func TestEXIFOrientationInvalid(t *testing.T) {
	le := binary.LittleEndian
	for name, b := range map[string][]byte{
		"0":        orientEXIF(le, 0),
		"9":        orientEXIF(le, 9),
		"LONG":     exifBlock(le, []exifEntry{{orientationTag, 4, le.AppendUint32(nil, 6)}}, nil),
		"два":      exifBlock(le, []exifEntry{{orientationTag, 3, append(le.AppendUint16(nil, 6), 6, 0)}}, nil),
		"обрезан":  orientEXIF(le, 6)[:12],
		"не TIFF":  []byte("XX*\x00\x08\x00\x00\x00"),
		"пусто":    nil,
		"смещение": append([]byte("II*\x00"), 0xFF, 0xFF, 0xFF, 0xFF),
	} {
		if o := exifOrientation(b); o != 1 {
			t.Errorf("%s: %d", name, o)
		}
	}
	if o := exifOrientation(orientEXIF(binary.BigEndian, 6)); o != 6 {
		t.Fatalf("MM: %d", o)
	}
}
