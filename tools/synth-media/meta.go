package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf16"
)

// Свои писатели и читатели метаданных PNG и JPEG (задача 5.36). Декодеры
// изображений генератору не нужны и запрещены вне internal/media (depguard
// media-decoders): файлы разбираются только на уровне чанков и сегментов,
// растр не трогается. Читатели нужны для сверки корпуса: размеры по
// заголовку и текст метаданных, записанный генератором.

const (
	// maxImageBytes — предел файла при разборе: больше рабочего предела
	// aisec-media (10 МиБ, ADR-0032) корпус не бывает.
	maxImageBytes = 32 << 20
	// maxMetaText — предел одного текста метаданных при записи и чтении.
	maxMetaText = 16 << 10
	// maxChunks — предел числа чанков PNG и сегментов JPEG при разборе.
	maxChunks = 4096
)

var pngSig = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// pngChunk — чанк PNG без длины и CRC.
type pngChunk struct {
	Type string
	Data []byte
}

// parsePNG разбирает файл на чанки до IEND с проверкой длин и CRC.
func parsePNG(b []byte) ([]pngChunk, error) {
	if len(b) > maxImageBytes {
		return nil, errors.New("png: файл больше предела")
	}
	if !bytes.HasPrefix(b, pngSig) {
		return nil, errors.New("png: нет сигнатуры")
	}
	var out []pngChunk
	p := b[len(pngSig):]
	for len(p) > 0 {
		if len(out) >= maxChunks {
			return nil, errors.New("png: слишком много чанков")
		}
		if len(p) < 12 {
			return nil, errors.New("png: обрезанный чанк")
		}
		n := binary.BigEndian.Uint32(p)
		if uint64(n) > uint64(len(p)-12) { //nolint:gosec // G115: len(p) ≥ 12 проверено выше
			return nil, errors.New("png: длина чанка за пределами файла")
		}
		typ := string(p[4:8])
		for _, c := range []byte(typ) {
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
				return nil, errors.New("png: недопустимый тип чанка")
			}
		}
		data := p[8 : 8+n]
		if crc32.ChecksumIEEE(p[4:8+n]) != binary.BigEndian.Uint32(p[8+n:]) {
			return nil, fmt.Errorf("png: неверный CRC чанка %s", typ)
		}
		out = append(out, pngChunk{Type: typ, Data: data})
		p = p[12+n:]
		if typ == "IEND" {
			if len(p) != 0 {
				return nil, errors.New("png: данные после IEND")
			}
			break
		}
	}
	if len(out) == 0 || out[0].Type != "IHDR" || out[len(out)-1].Type != "IEND" {
		return nil, errors.New("png: нет IHDR в начале или IEND в конце")
	}
	return out, nil
}

// pngSize — ширина и высота из IHDR.
func pngSize(chunks []pngChunk) (int, int, error) {
	h := chunks[0].Data
	if len(h) != 13 {
		return 0, 0, errors.New("png: длина IHDR не 13")
	}
	w, ht := binary.BigEndian.Uint32(h), binary.BigEndian.Uint32(h[4:])
	if w == 0 || ht == 0 || w > 1<<20 || ht > 1<<20 {
		return 0, 0, errors.New("png: недопустимые размеры")
	}
	return int(w), int(ht), nil
}

func encodePNG(chunks []pngChunk) []byte {
	var b bytes.Buffer
	b.Write(pngSig)
	for _, c := range chunks {
		var hdr [8]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(c.Data))) //nolint:gosec // G115: длина ограничена maxImageBytes
		copy(hdr[4:], c.Type)
		b.Write(hdr[:])
		b.Write(c.Data)
		crc := crc32.NewIEEE()
		_, _ = crc.Write([]byte(c.Type))                    //nolint:gosec // G104: запись в хеш не возвращает ошибку
		_, _ = crc.Write(c.Data)                            //nolint:gosec // G104: запись в хеш не возвращает ошибку
		_ = binary.Write(&b, binary.BigEndian, crc.Sum32()) //nolint:gosec // G104: запись в bytes.Buffer не возвращает ошибку
	}
	return b.Bytes()
}

// metaItem — текст в метаданных изображения. Container: png-text (tEXt),
// png-ztxt (zTXt), png-itxt (iTXt), exif, xmp, jpeg-com. Field — ключевое
// слово PNG, тег EXIF (ImageDescription, Artist, Software, Make, Model,
// XPComment, UserComment) или поле XMP (dc:description, dc:title,
// dc:creator); у jpeg-com — пусто.
type metaItem struct {
	Container string `json:"container"`
	Field     string `json:"field,omitempty"`
	Text      string `json:"text"`
}

// addPNGText вставляет текстовые чанки сразу после IHDR.
func addPNGText(b []byte, items []metaItem) ([]byte, error) {
	chunks, err := parsePNG(b)
	if err != nil {
		return nil, err
	}
	var add []pngChunk
	for _, it := range items {
		if len(it.Text) > maxMetaText || it.Field == "" || len(it.Field) > 79 || !latin1Printable(it.Field) {
			return nil, fmt.Errorf("png: недопустимое поле %q", it.Field)
		}
		var d bytes.Buffer
		d.WriteString(it.Field)
		d.WriteByte(0)
		switch it.Container {
		case "png-text":
			if !latin1Printable(it.Text) {
				return nil, errors.New("png: в tEXt только печатные символы ASCII, иначе — iTXt")
			}
			d.WriteString(it.Text)
			add = append(add, pngChunk{"tEXt", d.Bytes()})
		case "png-ztxt":
			if !latin1Printable(it.Text) {
				return nil, errors.New("png: в zTXt только печатные символы ASCII, иначе — iTXt")
			}
			d.WriteByte(0) // метод сжатия: deflate
			zw := zlib.NewWriter(&d)
			if _, err := zw.Write([]byte(it.Text)); err != nil {
				return nil, err
			}
			if err := zw.Close(); err != nil {
				return nil, err
			}
			add = append(add, pngChunk{"zTXt", d.Bytes()})
		case "png-itxt":
			d.Write([]byte{0, 0}) // без сжатия, метод 0
			d.WriteString("ru")   // язык
			d.WriteByte(0)
			d.WriteByte(0) // переведённое ключевое слово — пусто
			d.WriteString(it.Text)
			add = append(add, pngChunk{"iTXt", d.Bytes()})
		default:
			return nil, fmt.Errorf("png: неизвестный контейнер %q", it.Container)
		}
	}
	out := append([]pngChunk{chunks[0]}, add...)
	out = append(out, chunks[1:]...)
	return encodePNG(out), nil
}

func latin1Printable(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// pngTexts читает текстовые чанки (tEXt, zTXt, iTXt без сжатия и со сжатием).
func pngTexts(chunks []pngChunk) ([]metaItem, error) {
	var out []metaItem
	for _, c := range chunks {
		var cont string
		switch c.Type {
		case "tEXt":
			cont = "png-text"
		case "zTXt":
			cont = "png-ztxt"
		case "iTXt":
			cont = "png-itxt"
		default:
			continue
		}
		key, rest, ok := bytes.Cut(c.Data, []byte{0})
		if !ok || len(key) == 0 || len(key) > 79 {
			return nil, fmt.Errorf("png: %s без ключевого слова", c.Type)
		}
		var text []byte
		switch c.Type {
		case "tEXt":
			text = rest
		case "zTXt":
			if len(rest) < 1 || rest[0] != 0 {
				return nil, errors.New("png: zTXt с неизвестным методом сжатия")
			}
			t, err := inflate(rest[1:])
			if err != nil {
				return nil, err
			}
			text = t
		case "iTXt":
			if len(rest) < 2 {
				return nil, errors.New("png: обрезанный iTXt")
			}
			flag, method := rest[0], rest[1]
			_, rest, ok = bytes.Cut(rest[2:], []byte{0}) // язык
			if !ok {
				return nil, errors.New("png: iTXt без языка")
			}
			_, rest, ok = bytes.Cut(rest, []byte{0}) // переведённое ключевое слово
			if !ok {
				return nil, errors.New("png: iTXt без переведённого ключевого слова")
			}
			switch {
			case flag == 0:
				text = rest
			case flag == 1 && method == 0:
				t, err := inflate(rest)
				if err != nil {
					return nil, err
				}
				text = t
			default:
				return nil, errors.New("png: iTXt с неизвестным сжатием")
			}
		}
		if len(text) > maxMetaText {
			return nil, errors.New("png: текст метаданных больше предела")
		}
		out = append(out, metaItem{Container: cont, Field: string(key), Text: string(text)})
	}
	return out, nil
}

// inflate распаковывает zlib с пределом результата: «бомба» в чанке не
// раздувает память генератора.
func inflate(b []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("png: zlib: %w", err)
	}
	defer func() { _ = zr.Close() }() //nolint:gosec // G104: закрытие читателя в памяти
	out, err := io.ReadAll(io.LimitReader(zr, maxMetaText+1))
	if err != nil {
		return nil, fmt.Errorf("png: zlib: %w", err)
	}
	if len(out) > maxMetaText {
		return nil, errors.New("png: текст метаданных больше предела")
	}
	return out, nil
}

// jpegSeg — сегмент JPEG до первого SOS: маркер и данные без длины.
type jpegSeg struct {
	Marker byte
	Data   []byte
}

// parseJPEG разбирает сегменты от SOI до первого SOS; rest — SOS и всё,
// что после него (сжатые данные), без разбора.
func parseJPEG(b []byte) (segs []jpegSeg, rest []byte, err error) {
	if len(b) > maxImageBytes {
		return nil, nil, errors.New("jpeg: файл больше предела")
	}
	if len(b) < 4 || b[0] != 0xff || b[1] != 0xd8 {
		return nil, nil, errors.New("jpeg: нет SOI")
	}
	p := b[2:]
	for {
		if len(segs) >= maxChunks {
			return nil, nil, errors.New("jpeg: слишком много сегментов")
		}
		if len(p) < 4 || p[0] != 0xff {
			return nil, nil, errors.New("jpeg: ожидается маркер")
		}
		m := p[1]
		switch {
		case m == 0xda: // SOS
			return segs, p, nil
		case m == 0xd8 || m == 0xd9 || (m >= 0xd0 && m <= 0xd7) || m == 0x01 || m == 0xff || m == 0x00:
			return nil, nil, fmt.Errorf("jpeg: маркер 0x%02x до SOS", m)
		}
		n := int(binary.BigEndian.Uint16(p[2:]))
		if n < 2 || n > len(p)-2 {
			return nil, nil, errors.New("jpeg: длина сегмента за пределами файла")
		}
		segs = append(segs, jpegSeg{Marker: m, Data: p[4 : 2+n]})
		p = p[2+n:]
	}
}

func encodeJPEG(segs []jpegSeg, rest []byte) ([]byte, error) {
	var b bytes.Buffer
	b.Write([]byte{0xff, 0xd8})
	for _, s := range segs {
		if len(s.Data) > 0xffff-2 {
			return nil, fmt.Errorf("jpeg: сегмент 0x%02x длиннее 64 КиБ", s.Marker)
		}
		b.Write([]byte{0xff, s.Marker})
		_ = binary.Write(&b, binary.BigEndian, uint16(len(s.Data)+2)) //nolint:gosec // G104, G115: bytes.Buffer, длина проверена выше
		b.Write(s.Data)
	}
	b.Write(rest)
	return b.Bytes(), nil
}

// jpegSize — ширина и высота из кадра SOFn (кроме DHT, JPG, DAC).
func jpegSize(segs []jpegSeg) (int, int, error) {
	for _, s := range segs {
		if s.Marker < 0xc0 || s.Marker > 0xcf || s.Marker == 0xc4 || s.Marker == 0xc8 || s.Marker == 0xcc {
			continue
		}
		if len(s.Data) < 6 {
			return 0, 0, errors.New("jpeg: обрезанный SOF")
		}
		h, w := int(binary.BigEndian.Uint16(s.Data[1:])), int(binary.BigEndian.Uint16(s.Data[3:]))
		if w == 0 || h == 0 {
			return 0, 0, errors.New("jpeg: нулевые размеры")
		}
		return w, h, nil
	}
	return 0, 0, errors.New("jpeg: нет SOF до SOS")
}

const (
	exifPrefix = "Exif\x00\x00"
	xmpPrefix  = "http://ns.adobe.com/xap/1.0/\x00"
)

// Теги EXIF, которые пишет генератор. ASCII — только печатные символы
// ASCII; XPComment — UCS-2LE (теги Windows), UserComment — с кодировкой
// «UNICODE» (UCS-2 в порядке байтов TIFF, здесь — little-endian).
var exifTags = map[string]uint16{
	"ImageDescription": 0x010e, "Make": 0x010f, "Model": 0x0110, "Software": 0x0131,
	"Artist": 0x013b, "XPComment": 0x9c9c, "UserComment": 0x9286,
}

const exifIFDPointer = 0x8769

// addJPEGMeta вставляет APP1 EXIF, APP1 XMP и COM после APP0 (JFIF).
func addJPEGMeta(b []byte, items []metaItem) ([]byte, error) {
	segs, rest, err := parseJPEG(b)
	if err != nil {
		return nil, err
	}
	var exif, xmp []metaItem
	var add []jpegSeg
	for _, it := range items {
		if len(it.Text) > maxMetaText {
			return nil, errors.New("jpeg: текст метаданных больше предела")
		}
		switch it.Container {
		case "exif":
			exif = append(exif, it)
		case "xmp":
			xmp = append(xmp, it)
		case "jpeg-com":
			add = append(add, jpegSeg{Marker: 0xfe, Data: []byte(it.Text)})
		default:
			return nil, fmt.Errorf("jpeg: неизвестный контейнер %q", it.Container)
		}
	}
	var app []jpegSeg
	if len(exif) > 0 {
		d, err := buildExif(exif)
		if err != nil {
			return nil, err
		}
		app = append(app, jpegSeg{Marker: 0xe1, Data: d})
	}
	if len(xmp) > 0 {
		d, err := buildXMP(xmp)
		if err != nil {
			return nil, err
		}
		app = append(app, jpegSeg{Marker: 0xe1, Data: d})
	}
	at := 0
	if len(segs) > 0 && segs[0].Marker == 0xe0 {
		at = 1
	}
	out := append([]jpegSeg{}, segs[:at]...)
	out = append(out, app...)
	out = append(out, segs[at:]...)
	out = append(out, add...)
	return encodeJPEG(out, rest)
}

type ifdEntry struct {
	tag, typ uint16
	count    uint32
	value    []byte
}

// buildExif — блок «Exif\0\0» + TIFF (little-endian): IFD0 и при
// необходимости Exif IFD с UserComment.
func buildExif(items []metaItem) ([]byte, error) {
	var ifd0, sub []ifdEntry
	for _, it := range items {
		tag, ok := exifTags[it.Field]
		if !ok {
			return nil, fmt.Errorf("exif: неизвестный тег %q", it.Field)
		}
		switch it.Field {
		case "XPComment":
			v := ucs2le(it.Text + "\x00")
			ifd0 = append(ifd0, ifdEntry{tag, 1, uint32(len(v)), v}) //nolint:gosec // G115: длина ограничена maxMetaText
		case "UserComment":
			v := append([]byte("UNICODE\x00"), ucs2le(it.Text)...)
			sub = append(sub, ifdEntry{tag, 7, uint32(len(v)), v}) //nolint:gosec // G115: длина ограничена maxMetaText
		default:
			if !latin1Printable(it.Text) {
				return nil, fmt.Errorf("exif: в %s только печатные символы ASCII, иначе — XPComment или UserComment", it.Field)
			}
			v := []byte(it.Text + "\x00")
			ifd0 = append(ifd0, ifdEntry{tag, 2, uint32(len(v)), v}) //nolint:gosec // G115: длина ограничена maxMetaText
		}
	}
	if len(sub) > 0 {
		// Значение указателя заполняется после раскладки IFD0.
		ifd0 = append(ifd0, ifdEntry{exifIFDPointer, 4, 1, make([]byte, 4)})
	}
	sortEntries(ifd0)
	sortEntries(sub)
	le := binary.LittleEndian
	tiff := []byte{'I', 'I', 42, 0, 8, 0, 0, 0}
	// Раскладка: IFD0, его данные, Exif IFD, его данные.
	ifd0Size := 2 + 12*len(ifd0) + 4
	data0 := 0
	for _, e := range ifd0 {
		if len(e.value) > 4 {
			data0 += len(e.value) + len(e.value)%2
		}
	}
	subOff := 8 + ifd0Size + data0
	for i := range ifd0 {
		if ifd0[i].tag == exifIFDPointer {
			le.PutUint32(ifd0[i].value, uint32(subOff)) //nolint:gosec // G115: смещение внутри сегмента до 64 КиБ
		}
	}
	tiff = appendIFD(tiff, ifd0, 8)
	if len(sub) > 0 {
		tiff = appendIFD(tiff, sub, subOff)
	}
	return append([]byte(exifPrefix), tiff...), nil
}

func sortEntries(es []ifdEntry) {
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && es[j].tag < es[j-1].tag; j-- {
			es[j], es[j-1] = es[j-1], es[j]
		}
	}
}

// appendIFD дописывает IFD по смещению off (от начала TIFF) и его данные.
func appendIFD(b []byte, es []ifdEntry, off int) []byte {
	le := binary.LittleEndian
	dataOff := off + 2 + 12*len(es) + 4
	b = le.AppendUint16(b, uint16(len(es))) //nolint:gosec // G115: тегов единицы
	var data []byte
	for _, e := range es {
		b = le.AppendUint16(b, e.tag)
		b = le.AppendUint16(b, e.typ)
		b = le.AppendUint32(b, e.count)
		if len(e.value) <= 4 {
			v := make([]byte, 4)
			copy(v, e.value)
			b = append(b, v...)
			continue
		}
		b = le.AppendUint32(b, uint32(dataOff+len(data))) //nolint:gosec // G115: смещение внутри сегмента до 64 КиБ
		data = append(data, e.value...)
		if len(e.value)%2 == 1 {
			data = append(data, 0)
		}
	}
	b = le.AppendUint32(b, 0) // следующего IFD нет
	return append(b, data...)
}

func ucs2le(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(u))
	for _, c := range u {
		out = binary.LittleEndian.AppendUint16(out, c)
	}
	return out
}

func fromUCS2LE(b []byte) string {
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// XMP: поля Dublin Core в rdf:Alt (description, title) и rdf:Seq (creator).
func buildXMP(items []metaItem) ([]byte, error) {
	var b strings.Builder
	b.WriteString(xmpPrefix)
	b.WriteString(`<?xpacket begin="` + "\ufeff" + `" id="W5M0MpCehiHzreSzNTczkc9d"?>` + "\n")
	b.WriteString(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">` + "\n")
	b.WriteString(`<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">` + "\n")
	for _, it := range items {
		var tag, wrap string
		switch it.Field {
		case "dc:description", "dc:title":
			tag, wrap = it.Field, "rdf:Alt"
		case "dc:creator":
			tag, wrap = it.Field, "rdf:Seq"
		default:
			return nil, fmt.Errorf("xmp: неизвестное поле %q", it.Field)
		}
		lang := ""
		if wrap == "rdf:Alt" {
			lang = ` xml:lang="x-default"`
		}
		fmt.Fprintf(&b, "<%s><%s><rdf:li%s>%s</rdf:li></%s></%s>\n", tag, wrap, lang, xmlEscape(it.Text), wrap, tag)
	}
	b.WriteString("</rdf:Description></rdf:RDF></x:xmpmeta>\n<?xpacket end=\"w\"?>")
	return []byte(b.String()), nil
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func xmlUnescape(s string) string {
	return strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&amp;", "&").Replace(s)
}

// jpegTexts читает метаданные, записанные генератором: COM, теги EXIF из
// exifTags и поля XMP. Это не общий разборщик EXIF и XMP (он — задача 5.43
// в aisec-media), а сверка корпуса с его описанием.
func jpegTexts(segs []jpegSeg) ([]metaItem, error) {
	var out []metaItem
	for _, s := range segs {
		switch {
		case s.Marker == 0xfe:
			out = append(out, metaItem{Container: "jpeg-com", Text: string(s.Data)})
		case s.Marker == 0xe1 && bytes.HasPrefix(s.Data, []byte(exifPrefix)):
			items, err := readExif(s.Data[len(exifPrefix):])
			if err != nil {
				return nil, err
			}
			out = append(out, items...)
		case s.Marker == 0xe1 && bytes.HasPrefix(s.Data, []byte(xmpPrefix)):
			out = append(out, readXMP(string(s.Data[len(xmpPrefix):]))...)
		}
	}
	return out, nil
}

func readExif(t []byte) ([]metaItem, error) {
	if len(t) < 8 || string(t[:4]) != "II*\x00" {
		return nil, errors.New("exif: ожидается TIFF little-endian")
	}
	names := map[uint16]string{}
	for k, v := range exifTags {
		names[v] = k
	}
	le := binary.LittleEndian
	var out []metaItem
	off := int(le.Uint32(t[4:]))
	for depth := 0; off != 0 && depth < 2; depth++ {
		if off < 8 || off+2 > len(t) {
			return nil, errors.New("exif: смещение IFD за пределами блока")
		}
		n := int(le.Uint16(t[off:]))
		if off+2+12*n+4 > len(t) {
			return nil, errors.New("exif: IFD за пределами блока")
		}
		next := 0
		for i := range n {
			e := t[off+2+12*i:]
			tag, typ, count := le.Uint16(e), le.Uint16(e[2:]), int(le.Uint32(e[4:]))
			if tag == exifIFDPointer {
				next = int(le.Uint32(e[8:]))
				continue
			}
			name, ok := names[tag]
			if !ok {
				continue
			}
			if count < 0 || count > maxMetaText*2+8 {
				return nil, errors.New("exif: слишком длинное значение")
			}
			v := e[8:12]
			if count > 4 {
				o := int(le.Uint32(e[8:]))
				if o < 0 || o+count > len(t) {
					return nil, errors.New("exif: значение за пределами блока")
				}
				v = t[o : o+count]
			} else {
				v = v[:count]
			}
			var text string
			switch {
			case typ == 2:
				text = strings.TrimRight(string(v), "\x00")
			case typ == 1 && name == "XPComment":
				text = fromUCS2LE(v)
			case typ == 7 && name == "UserComment" && len(v) >= 8:
				if string(v[:8]) == "UNICODE\x00" {
					text = fromUCS2LE(v[8:])
				} else {
					text = strings.TrimRight(string(v[8:]), "\x00")
				}
			default:
				return nil, fmt.Errorf("exif: тег %s с типом %d", name, typ)
			}
			out = append(out, metaItem{Container: "exif", Field: name, Text: text})
		}
		off = next
	}
	return out, nil
}

func readXMP(s string) []metaItem {
	var out []metaItem
	for _, f := range []string{"dc:description", "dc:title", "dc:creator"} {
		_, rest, ok := strings.Cut(s, "<"+f+">")
		if !ok {
			continue
		}
		body, _, ok := strings.Cut(rest, "</"+f+">")
		if !ok {
			continue
		}
		_, li, ok := strings.Cut(body, "<rdf:li")
		if !ok {
			continue
		}
		_, li, ok = strings.Cut(li, ">")
		if !ok {
			continue
		}
		text, _, _ := strings.Cut(li, "</rdf:li>")
		out = append(out, metaItem{Container: "xmp", Field: f, Text: xmlUnescape(text)})
	}
	return out
}

// imageInfo — формат по сигнатуре, размеры по заголовку и текст метаданных.
func imageInfo(b []byte) (format string, w, h int, meta []metaItem, err error) {
	switch {
	case bytes.HasPrefix(b, pngSig):
		chunks, err := parsePNG(b)
		if err != nil {
			return "", 0, 0, nil, err
		}
		if w, h, err = pngSize(chunks); err != nil {
			return "", 0, 0, nil, err
		}
		meta, err = pngTexts(chunks)
		return "png", w, h, meta, err
	case len(b) > 2 && b[0] == 0xff && b[1] == 0xd8:
		segs, _, err := parseJPEG(b)
		if err != nil {
			return "", 0, 0, nil, err
		}
		if w, h, err = jpegSize(segs); err != nil {
			return "", 0, 0, nil, err
		}
		meta, err = jpegTexts(segs)
		return "jpeg", w, h, meta, err
	}
	return "", 0, 0, nil, errors.New("неизвестный формат")
}
