package media

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"runtime"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

var testLimits = Limits{MaxBytes: DefaultMaxBytes, MaxPixels: DefaultMaxPixels}

func testImage(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := range w {
		img.Set(x, x%h, color.RGBA{R: 200, A: 255})
	}
	return img
}

func encodePNG(t testing.TB, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, testImage(w, h)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func encodeJPEG(t testing.TB, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, testImage(w, h), nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func encodeGIF(t testing.TB, frames, w, h int) []byte {
	t.Helper()
	g := &gif.GIF{}
	pal := color.Palette{color.Black, color.White}
	for range frames {
		g.Image = append(g.Image, image.NewPaletted(image.Rect(0, 0, w, h), pal))
		g.Delay = append(g.Delay, 1)
	}
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, g); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// gifRaw — GIF с кадрами w × h без данных растра: заголовок для разбора.
func gifRaw(frames int, w, h uint16) []byte {
	b := append([]byte("GIF89a"), 0, 0, 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint16(b[6:], w)
	binary.LittleEndian.PutUint16(b[8:], h)
	for range frames {
		b = append(b, 0x2C, 0, 0, 0, 0)
		b = binary.LittleEndian.AppendUint16(b, w)
		b = binary.LittleEndian.AppendUint16(b, h)
		b = append(b, 0, 2, 0) // без палитры, код LZW 2, конец подблоков
	}
	return append(b, 0x3B)
}

// pngHeader — сигнатура и IHDR с заданными размерами (CRC не считается:
// до декодера он не проверяется).
func pngHeader(w, h uint32) []byte {
	b := append([]byte{}, pngSignature...)
	b = binary.BigEndian.AppendUint32(b, 13)
	b = append(b, "IHDR"...)
	b = binary.BigEndian.AppendUint32(b, w)
	b = binary.BigEndian.AppendUint32(b, h)
	b = append(b, 8, 6, 0, 0, 0)
	return append(b, 0, 0, 0, 0)
}

func webpVP8L(w, h uint32) []byte {
	bits := (w - 1) | (h-1)<<14
	chunk := binary.LittleEndian.AppendUint32([]byte{0x2F}, bits)
	b := append([]byte("RIFF"), 0, 0, 0, 0)
	b = append(b, "WEBPVP8L"...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(chunk))) //nolint:gosec // G115: 5 байт
	return append(b, chunk...)
}

// putUint24 — младшие 24 бита v в порядке little-endian (поле VP8X).
func putUint24(b []byte, v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	copy(b, t[:3])
}

func webpVP8X(w, h uint32) []byte {
	chunk := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	putUint24(chunk[4:], w-1)
	putUint24(chunk[7:], h-1)
	b := append([]byte("RIFF"), 0, 0, 0, 0)
	b = append(b, "WEBPVP8X"...)
	b = binary.LittleEndian.AppendUint32(b, 10)
	return append(b, chunk...)
}

func webpVP8(w, h uint16) []byte {
	chunk := []byte{0x10, 0, 0, 0x9D, 0x01, 0x2A}
	chunk = binary.LittleEndian.AppendUint16(chunk, w)
	chunk = binary.LittleEndian.AppendUint16(chunk, h)
	b := append([]byte("RIFF"), 0, 0, 0, 0)
	b = append(b, "WEBPVP8 "...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(chunk))) //nolint:gosec // G115: 10 байт
	return append(b, chunk...)
}

func bmpHeader(dib uint32, w, h int32) []byte {
	b := append([]byte("BM"), make([]byte, 12)...)
	b = binary.LittleEndian.AppendUint32(b, dib)
	if dib == 12 {
		b = binary.LittleEndian.AppendUint16(b, uint16(w)) //nolint:gosec // G115: тест задаёт малые размеры
		b = binary.LittleEndian.AppendUint16(b, uint16(h)) //nolint:gosec // G115: тест задаёт малые размеры
		return append(b, 1, 0, 24, 0)
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(w)) //nolint:gosec // G115: поле BMP — 32 бита со знаком
	b = binary.LittleEndian.AppendUint32(b, uint32(h)) //nolint:gosec // G115: поле BMP — 32 бита со знаком
	return append(b, make([]byte, int(dib)-12)...)
}

// byteOrder — порядок байтов с дописыванием.
type byteOrder interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

// tiffFile — TIFF с pages страницами, ширина — SHORT, высота — LONG;
// loop — последняя страница ссылается на первую.
func tiffFile(bo byteOrder, pages int, w, h uint32, loop bool) []byte {
	var b []byte
	if bo.String() == binary.BigEndian.String() {
		b = []byte("MM\x00*")
	} else {
		b = []byte("II*\x00")
	}
	b = bo.AppendUint32(b, 8)
	for p := range pages {
		off := uint32(len(b))             //nolint:gosec // G115: тестовый файл мал
		b = bo.AppendUint16(b, 2)         // две записи
		b = bo.AppendUint16(b, 256)       // ширина
		b = bo.AppendUint16(b, 3)         // SHORT
		b = bo.AppendUint32(b, 1)         // одно значение
		b = bo.AppendUint16(b, uint16(w)) //nolint:gosec // G115: тест задаёт малую ширину
		b = append(b, 0, 0)               // выравнивание поля значения
		b = bo.AppendUint16(b, 257)       // высота
		b = bo.AppendUint16(b, 4)         // LONG
		b = bo.AppendUint32(b, 1)         // одно значение
		b = bo.AppendUint32(b, h)         // значение
		next := off + 2 + 2*12 + 4        // следующий IFD сразу за этим
		switch {
		case p == pages-1 && loop:
			next = 8
		case p == pages-1:
			next = 0
		}
		b = bo.AppendUint32(b, next)
	}
	return b
}

func TestParseHeaderFormats(t *testing.T) {
	cases := map[string]struct {
		data   []byte
		format wire.Format
		w, h   int64
		frames int64
	}{
		"PNG":            {encodePNG(t, 30, 20), wire.FormatPNG, 30, 20, 1},
		"JPEG":           {encodeJPEG(t, 33, 17), wire.FormatJPEG, 33, 17, 1},
		"GIF три кадра":  {encodeGIF(t, 3, 12, 7), wire.FormatGIF, 12, 7, 3},
		"WebP VP8L":      {webpVP8L(640, 480), wire.FormatWebP, 640, 480, 1},
		"WebP VP8X":      {webpVP8X(5000, 3), wire.FormatWebP, 5000, 3, 1},
		"WebP VP8":       {webpVP8(100, 50), wire.FormatWebP, 100, 50, 1},
		"BMP 40":         {bmpHeader(40, 64, -32), wire.FormatBMP, 64, 32, 1},
		"BMP 12":         {bmpHeader(12, 8, 9), wire.FormatBMP, 8, 9, 1},
		"BMP 124":        {bmpHeader(124, 3, 4), wire.FormatBMP, 3, 4, 1},
		"TIFF LE":        {tiffFile(binary.LittleEndian, 1, 300, 200, false), wire.FormatTIFF, 300, 200, 1},
		"TIFF BE 3 стр.": {tiffFile(binary.BigEndian, 3, 30, 20, false), wire.FormatTIFF, 30, 20, 3},
	}
	for name, c := range cases {
		info, err := ParseHeader(c.data)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if info.Format != c.format || info.Width != c.w || info.Height != c.h || info.Frames != c.frames {
			t.Errorf("%s: %+v", name, info)
		}
	}
}

func TestParseHeaderRejects(t *testing.T) {
	png := encodePNG(t, 4, 4)
	jpg := encodeJPEG(t, 4, 4)
	gifData := encodeGIF(t, 1, 4, 4)
	badDepth := pngHeader(4, 4)
	badDepth[24] = 3 // RGBA с глубиной 3
	cases := map[string]struct {
		data []byte
		want error
	}{
		"пусто":               {nil, ErrUnknownFormat},
		"текст":               {[]byte("hello"), ErrUnknownFormat},
		"SVG":                 {[]byte("<svg xmlns="), ErrUnknownFormat},
		"PNG обрезан":         {png[:20], ErrMalformed},
		"PNG нулевая ширина":  {pngHeader(0, 4), ErrMalformed},
		"PNG ширина 2^31":     {pngHeader(1<<31, 4), ErrMalformed},
		"PNG глубина":         {badDepth, ErrMalformed},
		"JPEG без кадра":      {[]byte{0xFF, 0xD8, 0xFF, 0xD9}, ErrMalformed},
		"JPEG обрезан":        {jpg[:30], ErrMalformed},
		"GIF без trailer":     {gifData[:len(gifData)-1], ErrMalformed},
		"GIF нулевой экран":   {append([]byte("GIF89a"), make([]byte, 7)...), ErrMalformed},
		"WebP чанк длиннее":   {webpVP8L(4, 4)[:22], ErrMalformed},
		"WebP VP8 без кода":   {append(webpVP8(4, 4)[:23], 0, 0, 0, 0, 0, 0, 0), ErrMalformed},
		"BMP заголовок DIB 7": {bmpHeader(40, 4, 4)[:20], ErrMalformed},
		"BMP нулевая высота":  {bmpHeader(40, 4, 0), ErrMalformed},
		"BMP отриц. ширина":   {bmpHeader(40, -4, 4), ErrMalformed},
		"TIFF петля IFD":      {tiffFile(binary.LittleEndian, 2, 4, 4, true), ErrMalformed},
		"TIFF без высоты":     {tiffFile(binary.LittleEndian, 1, 4, 0, false), ErrMalformed},
		"BigTIFF":             {[]byte("II+\x00\x08\x00\x00\x00"), ErrUnsupportedVariant},
	}
	for name, c := range cases {
		if _, err := ParseHeader(c.data); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, ожидалось %v", name, err, c.want)
		}
	}
}

// Прогрессивный JPEG из множества сканов и GIF из множества кадров —
// разбор считает их и останавливается за пределом.
func TestParseHeaderCountsScansAndFrames(t *testing.T) {
	jpg := encodeJPEG(t, 8, 8)
	eoi := len(jpg) - 2
	scan := []byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x12, 0x34}
	many := append([]byte{}, jpg[:eoi]...)
	for range MaxJPEGScans + 5 {
		many = append(many, scan...)
	}
	many = append(many, 0xFF, 0xD9)
	info, err := ParseHeader(many)
	if err != nil || info.Scans != MaxJPEGScans+1 {
		t.Fatalf("сканов %d: %v", info.Scans, err)
	}
	g := gifRaw(MaxGIFFrames+3, 1, 1)
	info, err = ParseHeader(g)
	if err != nil || info.Frames != MaxGIFFrames+1 {
		t.Fatalf("кадров %d: %v", info.Frames, err)
	}
	if r, _ := Analyze(g, testLimits); r.Reason != wire.ReasonTooManyFrames { //nolint:gosec // G104: ошибка только при панике декодера
		t.Fatalf("итог %+v", r)
	}
	if r, _ := Analyze(many, testLimits); r.Reason != wire.ReasonTooManyScans { //nolint:gosec // G104: ошибка только при панике декодера
		t.Fatalf("итог %+v", r)
	}
	tiff := tiffFile(binary.LittleEndian, MaxTIFFPages+2, 2, 2, false)
	if r, _ := Analyze(tiff, testLimits); r.Reason != wire.ReasonTooManyFrames { //nolint:gosec // G104: ошибка только при панике декодера
		t.Fatalf("итог %+v", r)
	}
}

func TestAnalyzeDecodes(t *testing.T) {
	for name, data := range map[string][]byte{
		"PNG":  encodePNG(t, 40, 30),
		"JPEG": encodeJPEG(t, 40, 30),
		"GIF":  encodeGIF(t, 2, 40, 30),
	} {
		r, err := Analyze(data, testLimits)
		if err != nil || r.Status != wire.StatusOK || r.Width != 40 || r.Height != 30 || len(r.Checks) != 1 || r.Checks[0] != wire.CheckDecode {
			t.Errorf("%s: %+v %v", name, r, err)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: итог не проходит проверку: %v", name, err)
		}
	}
}

// WebP, BMP и TIFF до согласия на x/image — «формат не поддерживается», но
// размеры по заголовку уже проверены.
func TestAnalyzeUnsupportedUntilXImage(t *testing.T) {
	for name, data := range map[string][]byte{
		"WebP": webpVP8L(10, 10),
		"BMP":  bmpHeader(40, 10, 10),
		"TIFF": tiffFile(binary.LittleEndian, 1, 10, 10, false),
	} {
		r, err := Analyze(data, testLimits)
		if err != nil || r.Status != wire.StatusUnsupported || r.Width != 10 {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
	if r, _ := Analyze([]byte("просто текст"), testLimits); r.Status != wire.StatusUnsupported || r.Format != "" { //nolint:gosec // G104: ошибка только при панике декодера
		t.Errorf("неизвестный формат: %+v", r)
	}
	// Прогрессивный JPEG декодируется, арифметическое кодирование (SOF9) — нет.
	jpg := encodeJPEG(t, 8, 8)
	i := bytes.Index(jpg, []byte{0xFF, 0xC0})
	jpg[i+1] = 0xC9
	if r, _ := Analyze(jpg, testLimits); r.Status != wire.StatusUnsupported || r.Format != wire.FormatJPEG { //nolint:gosec // G104: ошибка только при панике декодера
		t.Errorf("SOF9: %+v", r)
	}
}

// totalAlloc — байт выделено при вызове f.
func totalAlloc(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// Превышение пикселей по заголовку — отказ без декодирования: растр
// 40 000 × 40 000 (6,4 ГБ в RGBA) не выделяется, выделений — единицы.
func TestAnalyzePixelLimitBeforeDecode(t *testing.T) {
	bombs := map[string][]byte{
		"PNG":  pngHeader(40_000, 40_000),
		"WebP": webpVP8X(1<<24, 1<<24),
		"BMP":  bmpHeader(40, 1<<20, 1<<20),
		"TIFF": tiffFile(binary.LittleEndian, 1, 60_000, 1<<20, false),
		"GIF":  gifRaw(2, 4000, 4000),
	}
	jpg := encodeJPEG(t, 8, 8)
	i := bytes.Index(jpg, []byte{0xFF, 0xC0})
	binary.BigEndian.PutUint16(jpg[i+5:], 60_000) // высота
	binary.BigEndian.PutUint16(jpg[i+7:], 60_000) // ширина
	bombs["JPEG"] = jpg
	for name, data := range bombs {
		var r wire.Result
		allocs := testing.AllocsPerRun(20, func() { r, _ = Analyze(data, testLimits) }) //nolint:gosec // G104: ошибка только при панике декодера
		if r.Status != wire.StatusRejected || r.Reason != wire.ReasonTooManyPixels {
			t.Errorf("%s: %+v", name, r)
		}
		// Итог и пустой список проверок; у TIFF — ещё множество IFD.
		if allocs > 8 {
			t.Errorf("%s: выделений %.0f — похоже на декодирование", name, allocs)
		}
		if n := totalAlloc(func() { _, _ = Analyze(data, testLimits) }); n > 64<<10 { //nolint:gosec // G104: ошибка только при панике декодера
			t.Errorf("%s: выделено %d байт", name, n)
		}
	}
}

// Превышение размера файла — отказ до разбора заголовка.
func TestAnalyzeSizeLimitBeforeParse(t *testing.T) {
	data := encodePNG(t, 2, 2)
	data = append(data, make([]byte, MinMaxBytes)...)
	l := Limits{MaxBytes: MinMaxBytes, MaxPixels: DefaultMaxPixels}
	var r wire.Result
	allocs := testing.AllocsPerRun(20, func() { r, _ = Analyze(data, l) }) //nolint:gosec // G104: ошибка только при панике декодера
	if r.Status != wire.StatusRejected || r.Reason != wire.ReasonTooLarge || r.Format != "" {
		t.Fatalf("%+v", r)
	}
	if allocs > 2 {
		t.Fatalf("выделений %.0f", allocs)
	}
}

// Граница: ровно предел пикселей — декодируется, на пиксель больше — нет.
func TestAnalyzePixelLimitBoundary(t *testing.T) {
	l := Limits{MaxBytes: DefaultMaxBytes, MaxPixels: 600}
	if r, _ := Analyze(encodePNG(t, 30, 20), l); r.Status != wire.StatusOK { //nolint:gosec // G104: ошибка только при панике декодера
		t.Fatalf("ровно предел: %+v", r)
	}
	if r, _ := Analyze(encodePNG(t, 601, 1), l); r.Reason != wire.ReasonTooManyPixels { //nolint:gosec // G104: ошибка только при панике декодера
		t.Fatalf("сверх предела: %+v", r)
	}
	// У GIF — сумма кадров: 3 × 200 = 600 проходит, 4 × 200 — нет.
	if r, _ := Analyze(encodeGIF(t, 3, 20, 10), l); r.Status != wire.StatusOK { //nolint:gosec // G104: ошибка только при панике декодера
		t.Fatalf("GIF ровно предел: %+v", r)
	}
	if r, _ := Analyze(encodeGIF(t, 4, 20, 10), l); r.Reason != wire.ReasonTooManyPixels { //nolint:gosec // G104: ошибка только при панике декодера
		t.Fatalf("GIF сверх предела: %+v", r)
	}
}

// Свой разбор и разбор декодера расходятся (подменены размеры в IHDR,
// CRC не сходится) — отказ, декодер растра не вызывается.
func TestAnalyzeHeaderMismatch(t *testing.T) {
	data := encodePNG(t, 10, 10)
	binary.BigEndian.PutUint32(data[16:], 11)
	r, err := Analyze(data, testLimits)
	if err != nil || r.Status != wire.StatusRejected || r.Reason != wire.ReasonMalformed {
		t.Fatalf("%+v %v", r, err)
	}
	// Повреждённые данные после верного заголовка.
	data = encodePNG(t, 10, 10)
	data = data[:len(data)-20]
	if r, _ := Analyze(data, testLimits); r.Reason != wire.ReasonMalformed { //nolint:gosec // G104: ошибка только при панике декодера
		t.Fatalf("обрезанный PNG: %+v", r)
	}
}

func TestLimitsValidate(t *testing.T) {
	for _, l := range []Limits{{MinMaxBytes - 1, 1}, {wire.MaxContent + 1, 1}, {MinMaxBytes, 0}, {MinMaxBytes, wire.MaxPixelsLimit + 1}} {
		if l.Validate() == nil {
			t.Errorf("принято %+v", l)
		}
	}
	if err := (Limits{MinMaxBytes, 1}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCacheLRU(t *testing.T) {
	c := NewCache(2)
	ok := wire.Result{Status: wire.StatusOK, Format: wire.FormatPNG, Width: 1, Height: 1, Frames: 1, Checks: []wire.Check{wire.CheckDecode}}
	c.Put([]byte("a"), ok)
	c.Put([]byte("b"), ok)
	if _, hit := c.Get([]byte("a")); !hit { // a становится недавней
		t.Fatal("нет a")
	}
	c.Put([]byte("c"), ok) // вытесняет b
	if _, hit := c.Get([]byte("b")); hit {
		t.Fatal("b не вытеснена")
	}
	r, hit := c.Get([]byte("a"))
	if !hit || !r.Cached || c.Len() != 2 {
		t.Fatalf("%+v %v %d", r, hit, c.Len())
	}
	r.Checks[0] = wire.CheckOCR // копия: запись в кэше не меняется
	if r2, _ := c.Get([]byte("a")); r2.Checks[0] != wire.CheckDecode {
		t.Fatal("кэш отдал общий срез")
	}
	off := NewCache(-1)
	off.Put([]byte("a"), ok)
	if off.Len() != 0 {
		t.Fatal("выключенный кэш запомнил итог")
	}
}

// fuzzHeader — общая проверка разборщика: без паники, принятый итог —
// согласованные размеры в пределах протокола.
func fuzzHeader(t *testing.T, parse func([]byte) (Info, error), data []byte) {
	info, err := parse(data)
	if err != nil {
		return
	}
	if info.Width <= 0 || info.Height <= 0 || info.Width > wire.MaxDimension || info.Height > wire.MaxDimension ||
		info.Frames < 1 || info.Pixels <= 0 || info.Scans < 0 {
		t.Fatalf("принят неверный заголовок %+v", info)
	}
	if r, err := Analyze(data, Limits{MaxBytes: wire.MaxContent, MaxPixels: 1 << 16}); err == nil && r.Validate() != nil {
		t.Fatalf("неверный итог %+v", r)
	}
}

func FuzzParsePNG(f *testing.F) {
	f.Add(encodePNG(f, 3, 2))
	f.Add(pngHeader(1<<30, 1))
	f.Fuzz(func(t *testing.T, data []byte) { fuzzHeader(t, parsePNG, data) })
}

func FuzzParseJPEG(f *testing.F) {
	f.Add(encodeJPEG(f, 3, 2))
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xDA, 0x00, 0x02, 0xFF, 0xD9})
	f.Fuzz(func(t *testing.T, data []byte) { fuzzHeader(t, parseJPEG, data) })
}

func FuzzParseGIF(f *testing.F) {
	f.Add(encodeGIF(f, 2, 3, 2))
	f.Add(gifRaw(3, 2, 2))
	f.Fuzz(func(t *testing.T, data []byte) { fuzzHeader(t, parseGIF, data) })
}

func FuzzParseWebP(f *testing.F) {
	f.Add(webpVP8L(3, 2))
	f.Add(webpVP8X(3, 2))
	f.Add(webpVP8(3, 2))
	f.Fuzz(func(t *testing.T, data []byte) { fuzzHeader(t, parseWebP, data) })
}

func FuzzParseBMP(f *testing.F) {
	f.Add(bmpHeader(40, 3, -2))
	f.Add(bmpHeader(12, 3, 2))
	f.Fuzz(func(t *testing.T, data []byte) { fuzzHeader(t, parseBMP, data) })
}

func FuzzParseTIFF(f *testing.F) {
	f.Add(tiffFile(binary.LittleEndian, 2, 3, 2, false))
	f.Add(tiffFile(binary.BigEndian, 1, 3, 2, false))
	f.Fuzz(func(t *testing.T, data []byte) { fuzzHeader(t, parseTIFF, data) })
}
