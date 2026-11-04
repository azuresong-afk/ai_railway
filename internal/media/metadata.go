package media

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Текст метаданных (задача 5.43, DM-47; ADR-0032, раздел 4): текстовые
// чанки PNG (tEXt, zTXt, iTXt, в том числе XMP) и чанк eXIf, у JPEG —
// сегменты APP1 (EXIF и XMP) и комментарии COM. Разбор — своим кодом по
// уже принятому декодером файлу, с пределами: распаковка zTXt и iTXt — не
// больше maxInflateChunk на чанк и maxInflateTotal на файл, объём текста —
// пределы протокола (textSet). Повреждённый блок разбирается до первой
// ошибки: собранный текст остаётся. TIFF (задача 5.42) — текстовые теги
// IFD0 и Exif IFD тем же разбором EXIF (файл TIFF и есть блок EXIF), WebP —
// чанки EXIF и «XMP ». Не читаются: IPTC (APP13), расширенный XMP в
// нескольких APP1, комментарии GIF.

// Пределы распаковки сжатых текстовых чанков PNG.
const (
	maxInflateChunk = 256 << 10
	maxInflateTotal = 1 << 20
)

// Префиксы сегментов APP1 JPEG.
var (
	exifPrefix = []byte("Exif\x00\x00")
	xmpPrefix  = []byte("http://ns.adobe.com/xap/1.0/\x00")
)

// xmpKeyword — ключевое слово iTXt с пакетом XMP.
const xmpKeyword = "XML:com.adobe.xmp"

// readMetadata собирает текст метаданных принятого файла в ts.
func readMetadata(data []byte, f wire.Format, ts *textSet) {
	add := func(s string) bool { return ts.add(wire.SourceMetadata, s, nil) }
	switch f {
	case wire.FormatPNG:
		pngMetadata(data, add)
	case wire.FormatJPEG:
		jpegMetadata(data, add)
	case wire.FormatTIFF:
		exifInto(data, add)
	case wire.FormatWebP:
		webpMetadata(data, add)
	}
}

// webpChunks — обход чанков RIFF по длинам (с выравниванием до чётного);
// fn возвращает false — обход остановлен.
func webpChunks(data []byte, fn func(typ string, body []byte) bool) {
	for i := 12; i+8 <= len(data); {
		typ := string(data[i : i+4])
		n := binary.LittleEndian.Uint32(data[i+4 : i+8])
		if uint64(n) > uint64(len(data)-i-8) { //nolint:gosec // G115: i+8 <= len(data) по условию цикла
			return
		}
		body := data[i+8 : i+8+int(n)]
		i += 8 + int(n) + int(n&1)
		if !fn(typ, body) {
			return
		}
	}
}

// webpMetadata — чанки EXIF (блок TIFF, у некоторых программ — с
// префиксом «Exif\0\0») и «XMP ».
func webpMetadata(data []byte, add func(string) bool) {
	webpChunks(data, func(typ string, body []byte) bool {
		switch typ {
		case "EXIF":
			return exifInto(bytes.TrimPrefix(body, exifPrefix), add)
		case "XMP ":
			return xmpInto(body, add)
		}
		return true
	})
}

// pngChunks — обход чанков PNG по длинам до IEND; fn возвращает false —
// обход остановлен.
func pngChunks(data []byte, fn func(typ string, body []byte) bool) {
	for i := len(pngSignature); i+12 <= len(data); {
		n := binary.BigEndian.Uint32(data[i : i+4])
		typ := string(data[i+4 : i+8])
		if uint64(n) > uint64(len(data)-i-12) { //nolint:gosec // G115: i+12 <= len(data) по условию цикла
			return
		}
		body := data[i+8 : i+8+int(n)]
		i += 12 + int(n)
		if typ == "IEND" || !fn(typ, body) {
			return
		}
	}
}

// pngMetadata — текстовые чанки и eXIf.
func pngMetadata(data []byte, add func(string) bool) {
	budget := maxInflateTotal
	pngChunks(data, func(typ string, body []byte) bool {
		switch typ {
		case "tEXt":
			return pngText(body, add)
		case "zTXt":
			return pngZText(body, &budget, add)
		case "iTXt":
			return pngIText(body, &budget, add)
		case "eXIf":
			return exifInto(body, add)
		}
		return true
	})
}

// pngText — tEXt: ключевое слово, NUL, текст. По спецификации —
// ISO-8859-1, но программы пишут и UTF-8: допустимый UTF-8 читается как
// UTF-8 (так же zTXt).
func pngText(b []byte, add func(string) bool) bool {
	_, text, found := bytes.Cut(b, []byte{0})
	return !found || add(utf8OrLatin1(text))
}

// pngZText — zTXt: ключевое слово, NUL, метод 0, сжатый текст.
func pngZText(b []byte, budget *int, add func(string) bool) bool {
	_, rest, found := bytes.Cut(b, []byte{0})
	if !found || len(rest) < 1 || rest[0] != 0 {
		return true
	}
	text, ok := inflate(rest[1:], budget)
	if len(text) > 0 && !add(utf8OrLatin1(text)) {
		return false
	}
	return ok
}

// pngIText — iTXt: ключевое слово, NUL, признак и метод сжатия, язык, NUL,
// переведённое ключевое слово (UTF-8), NUL, текст UTF-8 (возможно,
// сжатый). Пакет XMP — по ключевому слову.
func pngIText(b []byte, budget *int, add func(string) bool) bool {
	kw, rest, found := bytes.Cut(b, []byte{0})
	if !found || len(rest) < 2 {
		return true
	}
	compressed, method := rest[0], rest[1]
	_, rest, found = bytes.Cut(rest[2:], []byte{0}) // язык
	if !found {
		return true
	}
	trans, text, found := bytes.Cut(rest, []byte{0})
	if !found || compressed > 1 || (compressed == 1 && method != 0) {
		return true
	}
	if len(trans) > 0 && !add(utf8OrLatin1(trans)) {
		return false
	}
	ok := true
	if compressed == 1 {
		text, ok = inflate(text, budget)
	}
	if string(kw) == xmpKeyword {
		return xmpInto(text, add) && ok
	}
	if len(text) > 0 && !add(utf8OrLatin1(text)) {
		return false
	}
	return ok
}

// inflate распаковывает zlib не больше остатка бюджета и maxInflateChunk;
// false — бюджет исчерпан, дальше не распаковывать. Оборванный или
// повреждённый поток — то, что успело распаковаться.
func inflate(b []byte, budget *int) ([]byte, bool) {
	limit := min(maxInflateChunk, *budget)
	if limit <= 0 {
		return nil, false
	}
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, true
	}
	out, _ := io.ReadAll(io.LimitReader(zr, int64(limit)+1)) //nolint:gosec // G104: повреждённый поток — то, что распаковано
	_ = zr.Close()                                           //nolint:gosec // G104: чтение из памяти
	if len(out) > limit {
		*budget -= limit
		return out[:limit], *budget > 0
	}
	*budget -= len(out)
	return out, true
}

// jpegSegments — обход сегментов JPEG по длинам, как parseJPEG;
// энтропийные данные сканов пропускаются. fn получает маркер и тело
// сегмента; false — обход остановлен.
func jpegSegments(data []byte, fn func(m byte, seg []byte) bool) {
	for i := 2; i < len(data); {
		if data[i] != 0xFF {
			return
		}
		for i < len(data) && data[i] == 0xFF {
			i++
		}
		if i >= len(data) {
			return
		}
		m := data[i]
		i++
		switch {
		case m == 0xD9:
			return
		case m == 0x01 || (m >= 0xD0 && m <= 0xD7):
			continue
		}
		if i+2 > len(data) {
			return
		}
		n := int(binary.BigEndian.Uint16(data[i : i+2]))
		if n < 2 || i+n > len(data) {
			return
		}
		seg := data[i+2 : i+n]
		i += n
		if m == 0xDA {
			i = skipEntropy(data, i)
		}
		if !fn(m, seg) {
			return
		}
	}
}

// jpegMetadata — APP1 с EXIF или XMP и COM.
func jpegMetadata(data []byte, add func(string) bool) {
	jpegSegments(data, func(m byte, seg []byte) bool {
		switch {
		case m == 0xE1 && bytes.HasPrefix(seg, exifPrefix):
			return exifInto(seg[len(exifPrefix):], add)
		case m == 0xE1 && bytes.HasPrefix(seg, xmpPrefix):
			return xmpInto(seg[len(xmpPrefix):], add)
		case m == 0xFE:
			return add(utf8OrLatin1(seg))
		}
		return true
	})
}

// orientation — ориентация из тега 0x0112 первого блока EXIF файла (5Н28
// ревью 5.r4): JPEG — APP1 до первого скана, PNG — eXIf, WebP — чанк
// EXIF, TIFF — IFD0 самого файла. 1 — тега нет, блок не разобран или
// значение вне 1–8; у GIF и BMP EXIF нет.
func orientation(data []byte, f wire.Format) int {
	o := 1
	first := func(b []byte) bool {
		o = exifOrientation(b)
		return false
	}
	switch f {
	case wire.FormatTIFF:
		return exifOrientation(data)
	case wire.FormatJPEG:
		jpegSegments(data, func(m byte, seg []byte) bool {
			switch {
			case m == 0xDA:
				return false
			case m == 0xE1 && bytes.HasPrefix(seg, exifPrefix):
				return first(seg[len(exifPrefix):])
			}
			return true
		})
	case wire.FormatPNG:
		pngChunks(data, func(typ string, body []byte) bool {
			if typ == "eXIf" {
				return first(body)
			}
			return typ != "IDAT"
		})
	case wire.FormatWebP:
		webpChunks(data, func(typ string, body []byte) bool {
			if typ == "EXIF" {
				return first(bytes.TrimPrefix(body, exifPrefix))
			}
			return true
		})
	}
	return o
}

// exifInto и xmpInto — разбор блока; false — набор текстов заполнен.
// Ошибка разбора блока не останавливает обход остальных.
func exifInto(b []byte, add func(string) bool) bool {
	full := false
	_ = parseEXIF(b, func(s string) bool { //nolint:gosec // G104: повреждённый блок — разобранная часть
		if !add(s) {
			full = true
		}
		return !full
	})
	return !full
}

func xmpInto(b []byte, add func(string) bool) bool {
	full := false
	_ = parseXMP(b, func(s string) bool { //nolint:gosec // G104: повреждённый пакет — разобранная часть
		if !add(s) {
			full = true
		}
		return !full
	})
	return !full
}
