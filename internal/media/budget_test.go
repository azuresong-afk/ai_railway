package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// pngHeaderOnly — PNG только с IHDR и IEND: разбор заголовка и
// DecodeConfig проходят, декодер растра — нет (данных нет). Так пределы
// по заголовку проверяются без сотен мегабайт растра.
func pngHeaderOnly(w, h uint32, depth, colorType byte) []byte {
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	put := func(typ string, data []byte) {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(data))) //nolint:gosec // G104, G115: запись в память, длина мала
		c := crc32.NewIEEE()
		_, _ = c.Write([]byte(typ)) //nolint:gosec // G104: hash.Hash.Write не завершается ошибкой
		_, _ = c.Write(data)        //nolint:gosec // G104: то же
		b.WriteString(typ)
		b.Write(data)
		_ = binary.Write(&b, binary.BigEndian, c.Sum32()) //nolint:gosec // G104: запись в память
	}
	ihdr := binary.BigEndian.AppendUint32(nil, w)
	ihdr = binary.BigEndian.AppendUint32(ihdr, h)
	put("IHDR", append(ihdr, depth, colorType, 0, 0, 0))
	put("IEND", nil)
	return b.Bytes()
}

// 5В4 ревью 5.r4 этапа 5: PNG 5000×5000 с глубиной 16 бит (файл в
// пределах 10 МиБ и 25 Мпикс) декодируется в 8 байт на пиксель, и путь
// анализа с OCR требует около 350 МиБ. При умолчаниях такой файл — отказ
// too_many_pixels до декодирования, в анализе и в очистке; RGBA 8 бит того
// же размера в бюджет укладывается и доходит до декодера.
func TestRasterBudgetRejectsBeforeDecode(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name         string
		depth, color byte
		over         bool
	}{
		{"RGBA 16 бит", 16, 6, true},
		{"RGB 16 бит", 16, 2, true},
		{"RGBA 8 бит", 8, 6, false},
		{"серый 16 бит", 16, 0, false},
	} {
		data := pngHeaderOnly(5000, 5000, tc.depth, tc.color)
		r, err := Analyze(data, testLimits)
		if err != nil {
			t.Fatal(err)
		}
		_, _, serr := Sanitize(ctx, data, testLimits, DefaultSanitizeMaxSide)
		if tc.over {
			if r.Status != wire.StatusRejected || r.Reason != wire.ReasonTooManyPixels || r.Width != 5000 {
				t.Errorf("%s: анализ %+v", tc.name, r)
			}
			if !errors.Is(serr, ErrSanitizeRejected) || !bytes.Contains([]byte(serr.Error()), []byte(wire.ReasonTooManyPixels)) {
				t.Errorf("%s: очистка %v", tc.name, serr)
			}
			continue
		}
		// В бюджете: дошло до декодера, данных растра нет — malformed.
		if r.Status != wire.StatusRejected || r.Reason != wire.ReasonMalformed {
			t.Errorf("%s: анализ %+v", tc.name, r)
		}
	}
	// Граница: предел растров выше — тот же файл доходит до декодера; ниже
	// оценки RGBA 8 бит — отказ и ему.
	big := pngHeaderOnly(5000, 5000, 16, 6)
	if r, _ := Analyze(big, Limits{MaxBytes: DefaultMaxBytes, MaxPixels: DefaultMaxPixels, MaxRasterBytes: 1 << 30}); r.Reason != wire.ReasonMalformed { //nolint:gosec // G104: ошибка только при панике декодера
		t.Errorf("предел 1 ГиБ: %+v", r)
	}
	small := pngHeaderOnly(5000, 5000, 8, 6)
	if r, _ := Analyze(small, Limits{MaxBytes: DefaultMaxBytes, MaxPixels: DefaultMaxPixels, MaxRasterBytes: MinMaxRasterBytes}); r.Reason != wire.ReasonTooManyPixels { //nolint:gosec // G104: то же
		t.Errorf("предел 96 МиБ: %+v", r)
	}
}

func TestBytesPerPixel(t *testing.T) {
	for i, c := range []struct {
		m    color.Model
		want int64
	}{{color.NRGBA64Model, 8}, {color.RGBA64Model, 8}, {color.Gray16Model, 2}, {color.GrayModel, 1}, {color.RGBAModel, 4},
		{color.NRGBAModel, 4}, {color.CMYKModel, 4}, {color.YCbCrModel, 3}, {color.NYCbCrAModel, 4}, {color.Palette{color.Black}, 1},
		{color.ModelFunc(func(c color.Color) color.Color { return c }), 8}} {
		if got := bytesPerPixel(c.m); got != c.want {
			t.Errorf("%d (%T): %d, ждали %d", i, c.m, got, c.want)
		}
	}
}

// peakHeap — наибольший объём объектов кучи во время f сверх исходного
// (опрос runtime/metrics; GOGC снижен, чтобы мусор не завышал итог).
func peakHeap(f func()) uint64 {
	runtime.GC()
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	base := sample[0].Value.Uint64()
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		for {
			select {
			case <-stop:
				return
			default:
			}
			metrics.Read(s)
			if v := s[0].Value.Uint64(); v > peak.Load() {
				peak.Store(v)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	f()
	close(stop)
	<-done
	if p := peak.Load(); p > base {
		return p - base
	}
	return 0
}

// Оценка rasterCost — верхняя граница наибольшей кучи анализа с OCR (с
// проходом ×2 по всему кадру — наибольшим входом детектора) и очистки для
// форматов с разной моделью цвета (5В4 ревью 5.r4). Без этого бюджет по
// заголовку мог бы снова разойтись с декодером.
func TestRasterCostCoversPeakHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("замер памяти — не в -short")
	}
	old := debug.SetGCPercent(5)
	defer debug.SetGCPercent(old)
	const w, h = 3000, 3000
	rgba := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := 3; i < len(rgba.Pix); i += 4 {
		rgba.Pix[i] = 128
	}
	enc := func(f func(*bytes.Buffer) error) []byte {
		var b bytes.Buffer
		if err := f(&b); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	pngEnc := func(img image.Image) []byte {
		return enc(func(b *bytes.Buffer) error { return (&png.Encoder{CompressionLevel: png.BestSpeed}).Encode(b, img) })
	}
	// GIF: первый кадр — часть экрана (очистка рисует его на холст экрана).
	pal := color.Palette{color.Black, color.White}
	g := &gif.GIF{Image: []*image.Paletted{image.NewPaletted(image.Rect(0, 0, w/2, h), pal)}, Delay: []int{0},
		Config: image.Config{ColorModel: pal, Width: w, Height: h}}
	cases := map[string][]byte{
		"PNG 16 бит":       pngEnc(image.NewNRGBA64(image.Rect(0, 0, w, h))),
		"PNG RGBA":         pngEnc(rgba),
		"PNG серый 16 бит": pngEnc(image.NewGray16(image.Rect(0, 0, w, h))),
		"JPEG":             enc(func(b *bytes.Buffer) error { return jpeg.Encode(b, rgba, &jpeg.Options{Quality: 50}) }),
		"GIF":              enc(func(b *bytes.Buffer) error { return gif.EncodeAll(b, g) }),
	}
	// Девять мелких строк — проход ×2 по всему кадру (x2MaxBands).
	var lines []fakeLine
	for i := range 9 {
		y := 0.05 + float64(i)*0.1
		lines = append(lines, fakeLine{0.1, y, 0.9, y + 0.003, "мелкий текст"})
	}
	ocr, err := NewOCR(newFakeEngine(lines...))
	if err != nil {
		t.Fatal(err)
	}
	l := Limits{MaxBytes: wire.MaxContent, MaxPixels: wire.MaxPixelsLimit, MaxRasterBytes: MaxMaxRasterBytes}
	for name, data := range cases {
		info, err := ParseHeader(data)
		if err != nil {
			t.Fatal(err)
		}
		cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		cost := uint64(rasterCost(info, cfg.ColorModel, false)) //nolint:gosec // G115: оценка положительна
		an := peakHeap(func() {
			if r, err := (Analyzer{Limits: l, OCR: ocr}).Analyze(context.Background(), data); err != nil || r.Status != wire.StatusOK {
				t.Fatalf("%s: %+v %v", name, r, err)
			}
		})
		sa := peakHeap(func() {
			if _, _, err := Sanitize(context.Background(), data, l, DefaultSanitizeMaxSide); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
		t.Logf("%s: оценка %d МиБ, анализ с OCR %d МиБ, очистка %d МиБ", name, cost>>20, an>>20, sa>>20)
		if an > cost || sa > cost {
			t.Errorf("%s: оценка %d МиБ меньше замера (анализ %d МиБ, очистка %d МиБ)", name, cost>>20, an>>20, sa>>20)
		}
	}
}
