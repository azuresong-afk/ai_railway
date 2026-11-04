package media

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/png"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"rsc.io/qr"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Строители метаданных для тестов (синтетические тексты).

func pngChunk(typ string, body []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(body))) //nolint:gosec // G115: тела тестов малы
	b = append(b, typ...)
	b = append(b, body...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(append([]byte(typ), body...)))
}

// pngWith — PNG 8×8 с чанками после IHDR.
func pngWith(t testing.TB, chunks ...[]byte) []byte {
	t.Helper()
	base := encodePNG(t, 8, 8)
	const ihdrEnd = 8 + 25
	out := append([]byte(nil), base[:ihdrEnd]...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return append(out, base[ihdrEnd:]...)
}

func zlibBytes(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zTXt(t testing.TB, kw string, text []byte) []byte {
	return pngChunk("zTXt", append(append([]byte(kw), 0, 0), zlibBytes(t, text)...))
}

func iTXt(t testing.TB, kw string, compressed bool, text string) []byte {
	body := append([]byte(kw), 0)
	data := []byte(text)
	if compressed {
		body = append(body, 1, 0)
		data = zlibBytes(t, data)
	} else {
		body = append(body, 0, 0)
	}
	body = append(body, "ru"...)
	body = append(body, 0, 0) // язык, пустое переведённое слово
	return pngChunk("iTXt", append(body, data...))
}

type exifEntry struct {
	tag, typ uint16
	val      []byte
}

// exifBlock — TIFF с IFD0 и, если есть sub, Exif IFD.
func exifBlock(bo byteOrder, ifd0, sub []exifEntry) []byte {
	hdr := []byte("II*\x00")
	if bo == binary.BigEndian {
		hdr = []byte("MM\x00*")
	}
	var out []byte
	out = append(out, hdr...)
	out = bo.AppendUint32(out, 8)
	if sub != nil {
		ifd0 = append(ifd0, exifEntry{tag: exifIFDTag, typ: 4, val: make([]byte, 4)})
	}
	write := func(ents []exifEntry, base int) ([]byte, int) {
		dataOff := base + 2 + 12*len(ents) + 4
		var dir, data []byte
		dir = bo.AppendUint16(dir, uint16(len(ents))) //nolint:gosec // G115: тест
		for _, e := range ents {
			dir = bo.AppendUint16(dir, e.tag)
			dir = bo.AppendUint16(dir, e.typ)
			dir = bo.AppendUint32(dir, uint32(len(e.val)/max(1, exifTypeSize(e.typ)))) //nolint:gosec // G115: тест
			if len(e.val) <= 4 {
				v := append(append([]byte(nil), e.val...), make([]byte, 4-len(e.val))...)
				dir = append(dir, v...)
				continue
			}
			dir = bo.AppendUint32(dir, uint32(dataOff+len(data))) //nolint:gosec // G115: тест
			data = append(data, e.val...)
		}
		dir = bo.AppendUint32(dir, 0)
		return append(dir, data...), base + len(dir) + len(data)
	}
	first, end := write(ifd0, 8)
	if sub != nil {
		// Указатель на Exif IFD — последняя запись IFD0 (значение в записи).
		p := 2 + 12*(len(ifd0)-1) + 8
		bo.PutUint32(first[p:p+4], uint32(end)) //nolint:gosec // G115: тест
		second, _ := write(sub, end)
		return append(append(out, first...), second...)
	}
	return append(out, first...)
}

func ascii(s string) []byte { return append([]byte(s), 0) }

func ucs2Bytes(s string, bo byteOrder) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = bo.AppendUint16(b, u)
	}
	return append(b, 0, 0)
}

func jpegSegment(m byte, body []byte) []byte {
	n := uint16(len(body) + 2) //nolint:gosec // G115: сегменты тестов меньше 64 КиБ
	return append([]byte{0xFF, m, byte(n >> 8), byte(n)}, body...)
}

// jpegWith — JPEG 8×8 с сегментами после SOI.
func jpegWith(t testing.TB, segs ...[]byte) []byte {
	t.Helper()
	base := encodeJPEG(t, 8, 8)
	out := append([]byte(nil), base[:2]...)
	for _, s := range segs {
		out = append(out, s...)
	}
	return append(out, base[2:]...)
}

func xmpPacket(body string) string {
	return `<?xpacket begin="` + "\ufeff" + `" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/">` +
		`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">` + body + `</rdf:RDF></x:xmpmeta><?xpacket end="w"?>`
}

func metaTexts(t *testing.T, data []byte) []string {
	t.Helper()
	r, err := Analyze(data, testLimits)
	if err != nil || r.Status != wire.StatusOK || r.Validate() != nil {
		t.Fatalf("итог %+v, %v", r, err)
	}
	var out []string
	for _, x := range r.Texts {
		if x.Source != wire.SourceMetadata || x.Box != nil {
			t.Fatalf("текст %+v", x)
		}
		out = append(out, x.Text)
	}
	return out
}

func TestPNGTextChunks(t *testing.T) {
	data := pngWith(t,
		pngChunk("tEXt", append([]byte("Description\x00"), 'C', 'a', 'f', 0xE9)), // ISO-8859-1
		zTXt(t, "Author", []byte("Контакт в zTXt")),
		iTXt(t, "Comment", false, "Комментарий iTXt"),
		iTXt(t, "Title", true, "Сжатый iTXt"),
		iTXt(t, xmpKeyword, false, xmpPacket(`<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title><rdf:Alt><rdf:li>XMP в PNG</rdf:li></rdf:Alt></dc:title></rdf:Description>`)),
		pngChunk("eXIf", exifBlock(binary.BigEndian, []exifEntry{{0x010E, 2, ascii("EXIF в PNG")}}, nil)),
		pngChunk("tEXt", []byte("NoSeparator")), // без NUL — пропуск
	)
	got := metaTexts(t, data)
	want := []string{"Café", "Контакт в zTXt", "Комментарий iTXt", "Сжатый iTXt", "XMP в PNG", "EXIF в PNG"}
	if !slices.Equal(got, want) {
		t.Fatalf("тексты %q, ожидалось %q", got, want)
	}
}

// Бомба распаковки в zTXt: распаковка ограничена, файл обрабатывается
// быстро, текст — в пределах протокола.
func TestPNGZTXtInflateLimit(t *testing.T) {
	bomb := zTXt(t, "Comment", bytes.Repeat([]byte("A"), 8<<20))
	data := pngWith(t, bomb, bomb, bomb, bomb, bomb, bomb)
	r, err := Analyze(data, testLimits)
	if err != nil || r.Status != wire.StatusOK || r.Validate() != nil {
		t.Fatalf("итог %+v, %v", r.Status, err)
	}
	total := 0
	for _, x := range r.Texts {
		total += len(x.Text)
	}
	if total == 0 || total > wire.MaxTextsBytes {
		t.Fatalf("объём текста %d", total)
	}
	budget := maxInflateTotal
	for range 5 {
		_, _ = inflate(zlibBytes(t, bytes.Repeat([]byte("A"), 1<<20)), &budget) //nolint:gosec // G104: проверяется бюджет
	}
	if budget != 0 {
		t.Fatalf("бюджет распаковки %d", budget)
	}
	if out, more := inflate(zlibBytes(t, []byte("x")), &budget); out != nil || more {
		t.Fatal("распаковка сверх бюджета")
	}
}

func TestEXIFTags(t *testing.T) {
	for _, bo := range []byteOrder{binary.LittleEndian, binary.BigEndian} {
		block := exifBlock(bo, []exifEntry{
			{0x010E, 2, ascii("Описание")},
			{0x010F, 2, ascii("Cam")},                 // до 4 байт — в самой записи
			{0x0132, 2, ascii("2026:11:03 10:00:00")}, // DateTime — не текст
			{0x9C9C, 1, ucs2Bytes("Комментарий XP", binary.LittleEndian)},
			{0x0100, 3, []byte{0, 8}}, // ширина — не текст
		}, []exifEntry{
			{userComment, 7, append([]byte("UNICODE\x00"), ucs2Bytes("Юникод в порядке блока", bo)...)},
			{0xA430, 2, ascii("Владелец")},
		})
		got := metaTexts(t, jpegWith(t, jpegSegment(0xE1, append(append([]byte(nil), exifPrefix...), block...))))
		want := []string{"Описание", "Cam", "Комментарий XP", "Юникод в порядке блока", "Владелец"}
		if !slices.Equal(got, want) {
			t.Errorf("%v: %q", bo, got)
		}
	}
	var got []string
	add := func(s string) bool { got = append(got, s); return true }
	if err := parseEXIF(exifBlock(binary.LittleEndian, nil, []exifEntry{{userComment, 7, append([]byte("ASCII\x00\x00\x00"), "plain"...)}}), add); err != nil || !slices.Equal(got, []string{"plain"}) {
		t.Errorf("UserComment ASCII: %q %v", got, err)
	}
}

func TestEXIFRejects(t *testing.T) {
	good := exifBlock(binary.LittleEndian, []exifEntry{{0x010E, 2, ascii("ImageDescription text")}}, nil)
	noop := func(string) bool { return true }
	cases := map[string][]byte{
		"короткий":        good[:7],
		"сигнатура":       append([]byte("XX*\x00"), good[4:]...),
		"IFD за границей": append(append([]byte(nil), good[:4]...), 0xFF, 0xFF, 0, 0),
		"IFD в заголовке": append(append([]byte(nil), good[:4]...), 4, 0, 0, 0),
		"записи за границей": func() []byte {
			b := slices.Clone(good)
			binary.LittleEndian.PutUint16(b[8:10], 500)
			return b
		}(),
		"значение за границей": func() []byte {
			b := slices.Clone(good)
			binary.LittleEndian.PutUint32(b[8+2+8:8+2+12], 1<<30)
			return b
		}(),
		"огромное число значений": func() []byte {
			b := slices.Clone(good)
			binary.LittleEndian.PutUint32(b[8+2+4:8+2+8], 0xFFFFFFFF)
			return b
		}(),
		"неизвестный тип": func() []byte {
			b := slices.Clone(good)
			binary.LittleEndian.PutUint16(b[8+2+2:8+2+4], 99)
			return b
		}(),
	}
	for name, b := range cases {
		if err := parseEXIF(b, noop); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
	// Exif IFD указывает на IFD0: читается один раз повторно, без цикла.
	loop := exifBlock(binary.LittleEndian, []exifEntry{{0x010E, 2, ascii("ImageDescription text")}}, []exifEntry{})
	binary.LittleEndian.PutUint32(loop[8+2+12+8:8+2+12+12], 8)
	n := 0
	if err := parseEXIF(loop, func(string) bool { n++; return true }); err != nil || n != 2 {
		t.Errorf("петля: %d %v", n, err)
	}
}

func TestXMPProperties(t *testing.T) {
	packet := xmpPacket(`<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/"` +
		` xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmp:CreatorTool="Редактор" xmp:CreateDate="2026-11-03T10:00:00" xmpMM:DocumentID="xmp.did:0a1b2c3d4e5f">` +
		`<dc:description><rdf:Alt><rdf:li xml:lang="x-default">Описание &amp; подпись</rdf:li></rdf:Alt></dc:description>` +
		`<dc:creator><rdf:Seq><rdf:li>Автор один</rdf:li><rdf:li>Автор два</rdf:li></rdf:Seq></dc:creator>` +
		`<xmpMM:History><rdf:Seq><rdf:li rdf:parseType="Resource"><stEvt:action xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#">saved</stEvt:action></rdf:li></rdf:Seq></xmpMM:History>` +
		`</rdf:Description>`)
	got := metaTexts(t, jpegWith(t, jpegSegment(0xE1, append(append([]byte(nil), xmpPrefix...), packet...)), jpegSegment(0xFE, []byte("Комментарий COM"))))
	want := []string{"Редактор", "Описание & подпись", "Автор один", "Автор два", "Комментарий COM"}
	if !slices.Equal(got, want) {
		t.Fatalf("тексты %q, ожидалось %q", got, want)
	}
}

func TestXMPRejects(t *testing.T) {
	noop := func(string) bool { return true }
	deep := strings.Repeat("<a>", maxXMPDepth+1) + strings.Repeat("</a>", maxXMPDepth+1)
	many := "<r>" + strings.Repeat("<a/>", maxXMPTokens) + "</r>"
	// Сущности DTD не раскрываются: «бомба» — ошибка, а не рост памяти.
	laughs := `<!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><x>&b;&b;&b;</x>`
	for name, b := range map[string]string{"глубина": deep, "элементы": many, "сущности": laughs, "оборван": "<x><y>", "размер": strings.Repeat(" ", maxXMPBytes+1)} {
		if err := parseXMP([]byte(b), noop); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
}

func TestTextSetLimits(t *testing.T) {
	var ts textSet
	long := strings.Repeat("я", wire.MaxTextBytes) // 2 байта на символ
	ts.add(wire.SourceMetadata, long, nil)
	if len(ts.texts) != 2 || len(ts.texts[0].Text) != wire.MaxTextBytes || !wire.ValidText(ts.texts[1].Text) {
		t.Fatalf("разбиение: %d частей", len(ts.texts))
	}
	ts.add(wire.SourceMetadata, long, nil) // повтор
	if len(ts.texts) != 2 {
		t.Fatal("повтор добавлен")
	}
	ts.add(wire.SourceMetadata, "a\x00b\rc\x1bd\u0085e\ufeff", nil)
	if got := ts.texts[2].Text; got != "a b\nc d e" {
		t.Fatalf("очистка: %q", got)
	}
	for i := 0; !ts.full; i++ {
		ts.add(wire.SourceQR, strings.Repeat("x", 1000)+string(rune('a'+i%26))+strings.Repeat("y", i), nil)
	}
	r := wire.Result{Status: wire.StatusOK, Format: wire.FormatPNG, Width: 1, Height: 1, Frames: 1, Checks: Checks(), Texts: ts.texts}
	if ts.total > wire.MaxTextsBytes || r.Validate() != nil {
		t.Fatalf("предел: %d байт, %v", ts.total, r.Validate())
	}
	b, err := wire.MarshalBody(r)
	if err != nil || len(b) > wire.MaxResultBody {
		t.Fatalf("тело %d байт", len(b))
	}
	var many textSet
	for i := range wire.MaxTexts + 5 {
		many.add(wire.SourceQR, string(rune('A'+i%26))+strings.Repeat("!", i/26), nil)
	}
	if len(many.texts) != wire.MaxTexts || !many.full {
		t.Fatalf("число текстов %d", len(many.texts))
	}
}

// Худший случай кодирования JSON укладывается в предел тела result.
func TestTextsWorstCaseFitsResultBody(t *testing.T) {
	var ts textSet
	for i := 0; !ts.full; i++ {
		ts.add(wire.SourceQR, strings.Repeat("<", wire.MaxTextBytes-1)+string(rune('a'+i)), &wire.Box{X: 1 << 30, Y: 1 << 30, W: 1 << 30, H: 1 << 30})
	}
	r := wire.Result{Status: wire.StatusOK, Format: wire.FormatPNG, Width: 1 << 31, Height: 1 << 31, Frames: 1, Checks: Checks(), Texts: ts.texts}
	b, err := wire.MarshalBody(r)
	if err != nil || len(b) > wire.MaxResultBody || r.Validate() != nil {
		t.Fatalf("тело %d байт, %v", len(b), r.Validate())
	}
}

func qrImage(t testing.TB, text string, scale int) image.Image {
	t.Helper()
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	c.Scale = scale
	return c.Image()
}

func TestQRCodes(t *testing.T) {
	a, b := qrImage(t, "Первый код", 4), qrImage(t, "https://second.example.test/", 4)
	canvas := image.NewGray(image.Rect(0, 0, 400, 220))
	draw.Draw(canvas, canvas.Bounds(), image.White, image.Point{}, draw.Src)
	draw.Draw(canvas, a.Bounds().Add(image.Pt(10, 20)), a, image.Point{}, draw.Src)
	draw.Draw(canvas, b.Bounds().Add(image.Pt(220, 20)), b, image.Point{}, draw.Src)
	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(buf.Bytes(), testLimits)
	if err != nil || r.Validate() != nil {
		t.Fatalf("%+v %v", r, err)
	}
	got := map[string]*wire.Box{}
	for _, x := range r.Texts {
		if x.Source != wire.SourceQR || x.Box == nil {
			t.Fatalf("текст %+v", x)
		}
		got[x.Text] = x.Box
	}
	if len(got) != 2 || got["Первый код"] == nil || got["https://second.example.test/"] == nil {
		t.Fatalf("коды %v", got)
	}
	if bx := got["Первый код"]; bx.X < 10 || bx.X+bx.W > int64(10+a.Bounds().Dx()) {
		t.Errorf("рамка первого кода %+v", bx)
	}
	if bx := got["https://second.example.test/"]; bx.X < 220 {
		t.Errorf("рамка второго кода %+v", bx)
	}
}

// QR на втором кадре GIF со смещением: рамка — в координатах экрана.
func TestQRInGIFFrame(t *testing.T) {
	code := qrImage(t, "Кадр два", 3)
	cb := code.Bounds()
	pal := color.Palette{color.White, color.Black}
	first := image.NewPaletted(image.Rect(0, 0, 300, 200), pal)
	second := image.NewPaletted(cb.Add(image.Pt(150, 40)), pal)
	draw.Draw(second, second.Bounds(), code, image.Point{}, draw.Src)
	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, &gif.GIF{Image: []*image.Paletted{first, second}, Delay: []int{0, 0},
		Config: image.Config{ColorModel: pal, Width: 300, Height: 200}}); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(buf.Bytes(), testLimits)
	if err != nil || r.Validate() != nil || len(r.Texts) != 1 || r.Texts[0].Text != "Кадр два" {
		t.Fatalf("%+v %v", r, err)
	}
	if bx := r.Texts[0].Box; bx.X < 150 || bx.Y < 40 || bx.X+bx.W > int64(150+cb.Dx()) {
		t.Fatalf("рамка %+v", bx)
	}
}

// Итог с текстом не попадает в кэш анализатора (ТЗ 5.17).
func TestCacheSkipsTexts(t *testing.T) {
	c := NewCache(4)
	r := wire.Result{Status: wire.StatusOK, Format: wire.FormatPNG, Width: 1, Height: 1, Frames: 1, Checks: Checks(),
		Texts: []wire.Text{{Text: "секрет", Source: wire.SourceMetadata}}}
	c.Put([]byte("a"), r)
	if _, ok := c.Get([]byte("a")); ok || c.Len() != 0 {
		t.Fatal("итог с текстом в кэше")
	}
}

// fuzzTexts — набор текстов из любого разбора укладывается в протокол.
func fuzzTexts(t *testing.T, ts *textSet) {
	r := wire.Result{Status: wire.StatusOK, Format: wire.FormatPNG, Width: 1 << 16, Height: 1 << 16, Frames: 1, Checks: Checks(), Texts: ts.texts}
	if ts.total > wire.MaxTextsBytes || len(ts.texts) > wire.MaxTexts {
		t.Fatalf("сверх предела: %d текстов, %d байт", len(ts.texts), ts.total)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("итог не проходит проверку: %v", err)
	}
}

func FuzzPNGMetadata(f *testing.F) {
	f.Add(pngWith(f, pngChunk("tEXt", []byte("k\x00v")), zTXt(f, "z", []byte("сжатый")), iTXt(f, xmpKeyword, true, xmpPacket(""))))
	f.Add(pngWith(f, pngChunk("eXIf", exifBlock(binary.LittleEndian, []exifEntry{{0x010E, 2, ascii("описание")}}, nil))))
	f.Fuzz(func(t *testing.T, data []byte) {
		var ts textSet
		readMetadata(data, wire.FormatPNG, &ts)
		fuzzTexts(t, &ts)
		if o := orientation(data, wire.FormatPNG); o < 1 || o > 8 {
			t.Fatalf("ориентация %d", o)
		}
	})
}

func FuzzJPEGMetadata(f *testing.F) {
	f.Add(jpegWith(f, jpegSegment(0xFE, []byte("comment")),
		jpegSegment(0xE1, append(append([]byte(nil), exifPrefix...), exifBlock(binary.BigEndian, []exifEntry{{0x013B, 2, ascii("Artist")}}, nil)...))))
	f.Add(jpegWith(f, jpegSegment(0xE1, append(append([]byte(nil), xmpPrefix...), xmpPacket(`<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" dc:title="t"/>`)...))))
	f.Fuzz(func(t *testing.T, data []byte) {
		var ts textSet
		readMetadata(data, wire.FormatJPEG, &ts)
		fuzzTexts(t, &ts)
		if o := orientation(data, wire.FormatJPEG); o < 1 || o > 8 {
			t.Fatalf("ориентация %d", o)
		}
	})
}

func FuzzParseEXIF(f *testing.F) {
	f.Add(exifBlock(binary.LittleEndian, []exifEntry{{0x010E, 2, ascii("описание")}, {0x9C9C, 1, ucs2Bytes("XP", binary.LittleEndian)}},
		[]exifEntry{{userComment, 7, append([]byte("UNICODE\x00"), ucs2Bytes("комментарий", binary.LittleEndian)...)}}))
	f.Add(exifBlock(binary.BigEndian, []exifEntry{{0x8298, 2, ascii("(c)")}}, []exifEntry{}))
	f.Add(exifBlock(binary.LittleEndian, []exifEntry{{orientationTag, 3, []byte{6, 0}}}, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		var ts textSet
		_ = parseEXIF(data, func(s string) bool { return ts.add(wire.SourceMetadata, s, nil) }) //nolint:gosec // G104: проверяются пределы
		fuzzTexts(t, &ts)
		if o := exifOrientation(data); o < 1 || o > 8 {
			t.Fatalf("ориентация %d", o)
		}
	})
}

func FuzzParseXMP(f *testing.F) {
	f.Add([]byte(xmpPacket(`<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title><rdf:Alt><rdf:li>t</rdf:li></rdf:Alt></dc:title></rdf:Description>`)))
	f.Add([]byte(`<x a="1"><y>z</y></x>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var ts textSet
		_ = parseXMP(data, func(s string) bool { return ts.add(wire.SourceMetadata, s, nil) }) //nolint:gosec // G104: проверяются пределы
		fuzzTexts(t, &ts)
	})
}

// FuzzReadQR — декодер QR на произвольном растре 21–96 пикселей: без паники,
// тексты и рамки — в пределах протокола и изображения.
func FuzzReadQR(f *testing.F) {
	img := qrImage(f, "seed", 2)
	g := image.NewGray(img.Bounds())
	draw.Draw(g, g.Bounds(), img, image.Point{}, draw.Src)
	f.Add(uint8(g.Bounds().Dx()), g.Pix) //nolint:gosec // G115: сторона кода меньше 256
	f.Add(uint8(30), bytes.Repeat([]byte{0, 255}, 450))
	f.Fuzz(func(t *testing.T, w uint8, pix []byte) {
		side := 21 + int(w)%76
		if len(pix) < side {
			return
		}
		h := min(len(pix)/side, 96)
		if h < 21 {
			return
		}
		g := &image.Gray{Pix: pix[:side*h], Stride: side, Rect: image.Rect(0, 0, side, h)}
		var ts textSet
		if err := readQR([]image.Image{g}, &ts); err != nil {
			t.Fatalf("паника декодера: %v", err)
		}
		r := wire.Result{Status: wire.StatusOK, Format: wire.FormatPNG, Width: int64(side), Height: int64(h), Frames: 1, Checks: Checks(), Texts: ts.texts}
		if err := r.Validate(); err != nil {
			t.Fatalf("итог %+v: %v", r.Texts, err)
		}
	})
}
