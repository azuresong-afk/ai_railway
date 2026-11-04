package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// metadataMarkers — признаки метаданных в байтах изображения: EXIF, XMP.
var metadataMarkers = [][]byte{[]byte("Exif\x00"), []byte("<x:xmpmeta"), []byte("http://ns.adobe.com/xap/")}

// containerParts — чанки PNG или маркеры JPEG до первого SOS: по ним видно,
// что метаданных в контейнере нет (сжатые данные не разбираются).
func containerParts(t *testing.T, b []byte) []string {
	t.Helper()
	var out []string
	if bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) {
		for i := 8; i+12 <= len(b); {
			n := int(binary.BigEndian.Uint32(b[i:]))
			out = append(out, string(b[i+4:i+8]))
			i += 12 + n
		}
		return out
	}
	for i := 2; i+4 <= len(b) && b[i] == 0xFF; {
		m := b[i+1]
		out = append(out, fmt.Sprintf("%02X", m))
		if m == 0xDA {
			break
		}
		i += 2 + int(binary.BigEndian.Uint16(b[i+2:]))
	}
	return out
}

// allowedParts — что пишут кодировщики стандартной библиотеки: PNG —
// IHDR, PLTE, tRNS, IDAT, IEND; JPEG — DQT, SOF0, DHT, SOS.
var allowedParts = []string{"IHDR", "PLTE", "tRNS", "IDAT", "IEND", "DB", "C0", "C4", "DA"}

// checkSanitized — очищенное изображение: формат по ADR (JPEG — JPEG,
// остальное — PNG), без метаданных, разбирается анализатором без текста
// метаданных, размеры в пределах стороны.
func checkSanitized(t *testing.T, name string, in, out []byte, f wire.Format, maxSide int) wire.Result {
	t.Helper()
	inInfo, err := ParseHeader(in)
	if err != nil {
		t.Fatalf("%s: исходное: %v", name, err)
	}
	want := wire.FormatPNG
	if inInfo.Format == wire.FormatJPEG {
		want = wire.FormatJPEG
	}
	if got, err := wire.SanitizedFormat(out); err != nil || got != want || f != want {
		t.Fatalf("%s: формат %s/%s, ожидался %s (%v)", name, got, f, want, err)
	}
	for _, m := range metadataMarkers {
		if bytes.Contains(out, m) {
			t.Errorf("%s: в очищенном изображении осталось %q", name, m)
		}
	}
	parts := containerParts(t, out)
	if len(parts) == 0 {
		t.Fatalf("%s: контейнер не разобран", name)
	}
	for _, p := range parts {
		if !slices.Contains(allowedParts, p) {
			t.Errorf("%s: в очищенном изображении часть %s (%v)", name, p, parts)
		}
	}
	res, err := Analyze(out, testLimits)
	if err != nil || res.Status != wire.StatusOK || res.Frames != 1 {
		t.Fatalf("%s: очищенное не разобрано: %+v %v", name, res, err)
	}
	for _, tx := range res.Texts {
		if tx.Source == wire.SourceMetadata {
			t.Errorf("%s: текст метаданных после очистки: %q", name, tx.Text)
		}
	}
	if res.Width > int64(maxSide) || res.Height > int64(maxSide) {
		t.Errorf("%s: %d×%d больше стороны %d", name, res.Width, res.Height, maxSide)
	}
	if inInfo.Width <= int64(maxSide) && inInfo.Height <= int64(maxSide) && (res.Width != inInfo.Width || res.Height != inInfo.Height) {
		t.Errorf("%s: размеры изменились без нужды: %d×%d → %d×%d", name, inInfo.Width, inInfo.Height, res.Width, res.Height)
	}
	return res
}

// Задача 5.45: очистка всего корпуса изображений — метаданные (EXIF, XMP,
// чанки PNG, комментарии JPEG) удалены, формат по ADR, размеры прежние;
// QR и видимый текст остаются (очистка не закрашивает, Р9).
func TestSanitizeCorpus(t *testing.T) {
	ctx := context.Background()
	withMeta := 0
	for _, s := range corpusSamples(t) {
		in := readTestFile(t, filepath.Join(corpusDir, s.File))
		before, err := Analyze(in, testLimits)
		if err != nil {
			t.Fatal(err)
		}
		hadMeta := slices.ContainsFunc(before.Texts, func(tx wire.Text) bool { return tx.Source == wire.SourceMetadata })
		if hadMeta {
			withMeta++
		}
		out, f, err := Sanitize(ctx, in, testLimits, DefaultSanitizeMaxSide)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		after := checkSanitized(t, s.ID, in, out, f, DefaultSanitizeMaxSide)
		if len(s.QR) > 0 && !slices.ContainsFunc(after.Texts, func(tx wire.Text) bool { return tx.Source == wire.SourceQR }) {
			t.Errorf("%s: QR не читается после очистки", s.ID)
		}
	}
	if withMeta < 5 {
		t.Fatalf("в корпусе %d изображений с метаданными — проверка ничего не доказывает", withMeta)
	}
}

// Метаданные всех видов, которые читает анализатор (5.43), после очистки
// исчезают: PNG с tEXt, zTXt, iTXt (XMP) и eXIf; JPEG с APP1 (EXIF, XMP) и
// COM.
func TestSanitizeStripsMetadata(t *testing.T) {
	cases := map[string][]byte{
		"png": pngWith(t, pngChunk("tEXt", []byte("Comment\x00секрет в tEXt")),
			pngChunk("iTXt", append([]byte("XML:com.adobe.xmp\x00\x00\x00\x00\x00"), []byte(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>секрет в XMP</dc:title></rdf:Description></rdf:RDF></x:xmpmeta>`)...))),
		"jpeg": jpegWith(t, jpegSegment(0xFE, []byte("секрет в комментарии"))),
	}
	for name, in := range cases {
		before, err := Analyze(in, testLimits)
		if err != nil || len(before.Texts) == 0 {
			t.Fatalf("%s: в исходном нет текста метаданных: %+v %v", name, before, err)
		}
		out, f, err := Sanitize(context.Background(), in, testLimits, DefaultSanitizeMaxSide)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Contains(out, []byte("секрет")) {
			t.Errorf("%s: текст метаданных в байтах очищенного", name)
		}
		checkSanitized(t, name, in, out, f, DefaultSanitizeMaxSide)
	}
}

// Уменьшение: большая сторона — maxSide, пропорции сохранены; другие
// форматы — в PNG; у GIF — первый кадр на весь экран.
func TestSanitizeDownscaleAndFormats(t *testing.T) {
	ctx := context.Background()
	in := encodeJPEG(t, 1200, 300)
	out, f, err := Sanitize(ctx, in, testLimits, MinSanitizeMaxSide)
	if err != nil {
		t.Fatal(err)
	}
	if res := checkSanitized(t, "jpeg", in, out, f, MinSanitizeMaxSide); res.Width != 256 || res.Height != 64 {
		t.Fatalf("уменьшение: %d×%d", res.Width, res.Height)
	}
	in = encodePNG(t, 100, 900)
	out, f, err = Sanitize(ctx, in, testLimits, MinSanitizeMaxSide)
	if err != nil {
		t.Fatal(err)
	}
	if res := checkSanitized(t, "png", in, out, f, MinSanitizeMaxSide); res.Width != 28 || res.Height != 256 {
		t.Fatalf("уменьшение по высоте: %d×%d", res.Width, res.Height)
	}
	// GIF из двух кадров, первый — в части экрана.
	pal := color.Palette{color.Black, color.White}
	g := &gif.GIF{Image: []*image.Paletted{image.NewPaletted(image.Rect(10, 10, 20, 20), pal), image.NewPaletted(image.Rect(0, 0, 40, 30), pal)},
		Delay: []int{1, 1}, Config: image.Config{Width: 40, Height: 30, ColorModel: pal}}
	var gb bytes.Buffer
	if err := gif.EncodeAll(&gb, g); err != nil {
		t.Fatal(err)
	}
	var bb, tb bytes.Buffer
	if err := bmp.Encode(&bb, testImage(30, 20)); err != nil {
		t.Fatal(err)
	}
	if err := tiff.Encode(&tb, testImage(30, 20), nil); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string][]byte{"gif": gb.Bytes(), "bmp": bb.Bytes(), "tiff": tb.Bytes(),
		"webp": readTestFile(t, "testdata/lossy-meta.webp")} {
		out, f, err := Sanitize(ctx, in, testLimits, DefaultSanitizeMaxSide)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkSanitized(t, name, in, out, f, DefaultSanitizeMaxSide)
	}
}

// Отказы: неизвестный формат, превышение пределов и повреждённый файл —
// ErrSanitizeRejected (изображение не уходит провайдеру); неверная
// сторона — ошибка параметров; отмена — ошибка контекста.
func TestSanitizeRejects(t *testing.T) {
	ctx := context.Background()
	small := Limits{MaxBytes: MinMaxBytes, MaxPixels: 100}
	jpg := encodeJPEG(t, 64, 64)
	for name, c := range map[string]struct {
		in []byte
		l  Limits
	}{
		"не изображение":     {[]byte("просто текст, не картинка"), testLimits},
		"пикселей сверх":     {jpg, small},
		"больше max-bytes":   {make([]byte, MinMaxBytes+1), small},
		"обрезанный JPEG":    {jpg[:len(jpg)/2], testLimits},
		"анимированный WebP": {readTestFile(t, "testdata/animated.webp"), testLimits},
	} {
		if _, _, err := Sanitize(ctx, c.in, c.l, DefaultSanitizeMaxSide); !errors.Is(err, ErrSanitizeRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// GIF: логический экран сверх предела пикселей при кадре 4×4 — отказ до
	// декодирования (холст firstFrame — размером с экран); экран ровно на
	// пределе — очищается (вход fuzz: экран 65408×65535 требовал 17 ГБ).
	screenGIF := func(w, h int) []byte {
		pal := color.Palette{color.Black, color.White}
		g := &gif.GIF{Image: []*image.Paletted{image.NewPaletted(image.Rect(0, 0, 4, 4), pal)}, Delay: []int{1},
			Config: image.Config{Width: w, Height: h, ColorModel: pal}}
		var b bytes.Buffer
		if err := gif.EncodeAll(&b, g); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	gifLimits := Limits{MaxBytes: MinMaxBytes, MaxPixels: 256 * 256}
	if _, _, err := Sanitize(ctx, screenGIF(257, 256), gifLimits, DefaultSanitizeMaxSide); !errors.Is(err, ErrSanitizeRejected) {
		t.Errorf("экран GIF сверх предела: %v", err)
	}
	if _, _, err := Sanitize(ctx, screenGIF(256, 256), gifLimits, DefaultSanitizeMaxSide); err != nil {
		t.Errorf("экран GIF на пределе: %v", err)
	}
	if _, _, err := Sanitize(ctx, jpg, testLimits, MinSanitizeMaxSide-1); err == nil || errors.Is(err, ErrSanitizeRejected) {
		t.Errorf("сторона меньше предела: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := Sanitize(cctx, jpg, testLimits, DefaultSanitizeMaxSide); !errors.Is(err, context.Canceled) {
		t.Errorf("отменённый контекст: %v", err)
	}
}

// FuzzSanitize — очистка недоверенного изображения: без паники; итог —
// PNG или JPEG в пределах, без метаданных, разбирается анализатором.
func FuzzSanitize(f *testing.F) {
	f.Add(encodePNG(f, 8, 8))
	f.Add(encodeJPEG(f, 8, 8))
	f.Add(encodeGIF(f, 2, 4, 4))
	l := Limits{MaxBytes: MinMaxBytes, MaxPixels: 1 << 16}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, format, err := Sanitize(context.Background(), data, l, MinSanitizeMaxSide)
		if err != nil {
			return
		}
		if got, ferr := wire.SanitizedFormat(out); ferr != nil || got != format || int64(len(out)) > l.MaxBytes {
			t.Fatalf("итог %s/%s, %d байт", got, format, len(out))
		}
		res, err := Analyze(out, Limits{MaxBytes: MinMaxBytes, MaxPixels: MinSanitizeMaxSide * MinSanitizeMaxSide})
		if err != nil || res.Status != wire.StatusOK || res.Width > MinSanitizeMaxSide || res.Height > MinSanitizeMaxSide {
			t.Fatalf("очищенное не разобрано: %+v %v", res, err)
		}
		for _, tx := range res.Texts {
			if tx.Source == wire.SourceMetadata {
				t.Fatalf("текст метаданных после очистки: %q", tx.Text)
			}
		}
	})
}
