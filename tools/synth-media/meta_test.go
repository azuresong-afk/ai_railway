package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func corpusFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpusDir, name)) //nolint:gosec // G304: файл корпуса
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPNGTextRoundTrip(t *testing.T) {
	base := corpusFile(t, "card-03.png")
	items := []metaItem{
		{"png-text", "Description", "plain ascii"},
		{"png-ztxt", "Comment", "compressed ascii"},
		{"png-itxt", "Title", "Заголовок по-русски"},
	}
	out, err := addPNGText(base, items)
	if err != nil {
		t.Fatal(err)
	}
	format, w, h, meta, err := imageInfo(out)
	if err != nil || format != "png" || w != 900 || h != 310 {
		t.Fatalf("imageInfo: %s %d×%d %v", format, w, h, err)
	}
	if !slices.Equal(meta, items) {
		t.Fatalf("метаданные: %+v", meta)
	}
	// Текстовые чанки — сразу после IHDR, до IDAT.
	chunks, err := parsePNG(out)
	if err != nil {
		t.Fatal(err)
	}
	if chunks[1].Type != "tEXt" || chunks[3].Type != "iTXt" {
		t.Fatalf("порядок чанков: %s, %s", chunks[1].Type, chunks[3].Type)
	}
}

func TestPNGTextRejects(t *testing.T) {
	base := corpusFile(t, "card-03.png")
	cases := map[string]metaItem{
		"кириллица в tEXt":      {"png-text", "Description", "текст"},
		"кириллица в zTXt":      {"png-ztxt", "Description", "текст"},
		"пустое ключевое":       {"png-text", "", "x"},
		"длинное ключевое":      {"png-text", string(bytes.Repeat([]byte("k"), 80)), "x"},
		"неизвестный контейнер": {"exif", "Description", "x"},
		"слишком длинный текст": {"png-itxt", "Comment", string(bytes.Repeat([]byte("x"), maxMetaText+1))},
	}
	for name, it := range cases {
		if _, err := addPNGText(base, []metaItem{it}); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestParsePNGRejects(t *testing.T) {
	good := corpusFile(t, "card-03.png")
	mut := func(f func([]byte) []byte) []byte { return f(bytes.Clone(good)) }
	cases := map[string][]byte{
		"нет сигнатуры":      mut(func(b []byte) []byte { b[1] = 'X'; return b }),
		"неверный CRC":       mut(func(b []byte) []byte { b[8+8+13] ^= 1; return b }),
		"обрезан":            good[:len(good)-5],
		"данные после IEND":  append(bytes.Clone(good), 0),
		"длина за пределами": mut(func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], 1<<30); return b }),
	}
	for name, b := range cases {
		if _, err := parsePNG(b); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestJPEGMetaRoundTrip(t *testing.T) {
	base := corpusFile(t, "clean-03.jpg")
	items := []metaItem{
		{"exif", "ImageDescription", "ascii description"},
		{"exif", "XPComment", "Комментарий Windows"},
		{"exif", "UserComment", "Комментарий EXIF"},
		{"exif", "Artist", "Synth"},
		{"xmp", "dc:description", "Описание <XMP> & прочее"},
		{"xmp", "dc:creator", "author@example.test"},
		{"jpeg-com", "", "comment segment"},
	}
	out, err := addJPEGMeta(base, items)
	if err != nil {
		t.Fatal(err)
	}
	format, w, h, meta, err := imageInfo(out)
	if err != nil || format != "jpeg" || w != 1000 || h != 500 {
		t.Fatalf("imageInfo: %s %d×%d %v", format, w, h, err)
	}
	for _, it := range items {
		if !slices.Contains(meta, it) {
			t.Errorf("нет %+v в %+v", it, meta)
		}
	}
	// APP0 (JFIF) остаётся первым сегментом.
	segs, _, err := parseJPEG(out)
	if err != nil || segs[0].Marker != 0xe0 || segs[1].Marker != 0xe1 {
		t.Fatalf("порядок сегментов: %v", err)
	}
}

func TestJPEGMetaRejects(t *testing.T) {
	base := corpusFile(t, "clean-03.jpg")
	cases := map[string]metaItem{
		"кириллица в ASCII-теге": {"exif", "ImageDescription", "текст"},
		"неизвестный тег":        {"exif", "GPSLatitude", "1"},
		"неизвестное поле XMP":   {"xmp", "dc:rights", "x"},
		"неизвестный контейнер":  {"png-text", "Description", "x"},
	}
	for name, it := range cases {
		if _, err := addJPEGMeta(base, []metaItem{it}); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	// Сегмент длиннее 64 КиБ не помещается в JPEG.
	big := string(bytes.Repeat([]byte("x"), maxMetaText))
	var many []metaItem
	for range 5 {
		many = append(many, metaItem{"jpeg-com", "", big})
	}
	if _, err := addJPEGMeta(base, []metaItem{{"xmp", "dc:description", big + big + big + big + big}}); err == nil {
		t.Error("текст больше предела принят")
	}
	if _, err := addJPEGMeta(base, many); err != nil {
		t.Errorf("пять комментариев по 16 КиБ: %v", err)
	}
}

func TestParseJPEGRejects(t *testing.T) {
	good := corpusFile(t, "clean-03.jpg")
	cases := map[string][]byte{
		"нет SOI":              good[2:],
		"обрезан до SOS":       good[:20],
		"длина за файлом":      append([]byte{0xff, 0xd8, 0xff, 0xe0, 0xff, 0xff}, 0),
		"EOI до SOS":           {0xff, 0xd8, 0xff, 0xd9, 0, 0},
		"мусор вместо маркера": {0xff, 0xd8, 0x00, 0x00, 0, 0},
	}
	for name, b := range cases {
		if _, _, err := parseJPEG(b); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if _, _, err := parseJPEG(append([]byte{0xff, 0xd8, 0xff, 0xe0, 0, 2}, 0xff, 0xda, 0, 2)); err != nil {
		t.Errorf("пустой APP0 и SOS: %v", err)
	}
	segs, _, err := parseJPEG([]byte{0xff, 0xd8, 0xff, 0xda, 0, 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := jpegSize(segs); err == nil {
		t.Error("JPEG без SOF принят")
	}
}

func TestReadExifRejects(t *testing.T) {
	cases := map[string][]byte{
		"big-endian":       []byte("MM\x00*\x00\x00\x00\x08"),
		"IFD за пределами": []byte("II*\x00\xff\x00\x00\x00"),
		"короткий":         []byte("II*"),
	}
	for name, b := range cases {
		if _, err := readExif(b); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	// Значение за пределами блока.
	b := []byte("II*\x00\x08\x00\x00\x00\x01\x00\x0e\x01\x02\x00\x10\x00\x00\x00\xf0\x00\x00\x00\x00\x00\x00\x00")
	if _, err := readExif(b); err == nil {
		t.Error("значение за пределами блока принято")
	}
}

// Разборщики чанков PNG, сегментов JPEG, EXIF и XMP не паникуют и не
// выходят за пределы на произвольном входе (CLAUDE.md: fuzz для каждого
// разборщика).
func FuzzImageInfo(f *testing.F) {
	// Маленькие затравки: большие файлы корпуса замедляют перебор в сотни раз.
	png := encodePNG([]pngChunk{{"IHDR", []byte{0, 0, 0, 4, 0, 0, 0, 3, 8, 2, 0, 0, 0}}, {"IEND", nil}})
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0, 2, 0xff, 0xc0, 0, 8, 8, 0, 3, 0, 4, 0, 0xff, 0xda, 0, 2}
	pngMeta, err := addPNGText(png, []metaItem{{"png-text", "A", "b"}, {"png-ztxt", "C", "d"}, {"png-itxt", "E", "ф"}})
	if err != nil {
		f.Fatal(err)
	}
	jpegMeta, err := addJPEGMeta(jpeg, []metaItem{{"exif", "Artist", "a"}, {"exif", "UserComment", "ф"}, {"xmp", "dc:title", "t"}, {"jpeg-com", "", "c"}})
	if err != nil {
		f.Fatal(err)
	}
	for _, b := range [][]byte{png, jpeg, pngMeta, jpegMeta} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		format, w, h, _, err := imageInfo(b)
		if err == nil && (format == "" || w <= 0 || h <= 0) {
			t.Fatalf("без ошибки, но %q %d×%d", format, w, h)
		}
	})
}

func FuzzReadExif(f *testing.F) {
	d, err := buildExif([]metaItem{{"exif", "ImageDescription", "x"}, {"exif", "UserComment", "текст"}, {"exif", "XPComment", "y"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(d[len(exifPrefix):])
	f.Add([]byte("II*\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		items, err := readExif(b)
		if err != nil {
			return
		}
		for _, it := range items {
			if len(it.Text) > 4*maxMetaText+16 {
				t.Fatalf("текст длиной %d", len(it.Text))
			}
		}
	})
}
