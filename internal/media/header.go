package media

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Разбор заголовков изображений своими функциями (ADR-0032, раздел 6):
// формат по сигнатуре, ширина, высота, число кадров или страниц, у JPEG —
// число сканов. Разбор читает только нужные байты, не выделяет память под
// растр и не вызывает декодеры: пределы проверяются по его итогу до
// декодирования. Каждый разборщик закрыт своим fuzz-тестом.

// Ошибки разбора заголовка.
var (
	// ErrUnknownFormat — сигнатура не распознана.
	ErrUnknownFormat = errors.New("aisec-media: формат не распознан")
	// ErrMalformed — заголовок не разобран или противоречив.
	ErrMalformed = errors.New("aisec-media: заголовок изображения не разобран")
	// ErrUnsupportedVariant — формат распознан, но эта разновидность не
	// поддерживается (BigTIFF).
	ErrUnsupportedVariant = errors.New("aisec-media: разновидность формата не поддерживается")
)

// Пределы, которые разбор считает сам: число кадров и сканов не видно по
// одному заголовку (ADR-0032, раздел 6).
const (
	MaxGIFFrames = 256
	MaxTIFFPages = 16
	MaxJPEGScans = 100
)

// Info — итог разбора заголовка.
type Info struct {
	Format        wire.Format
	Width, Height int64
	// Frames — кадров GIF или страниц TIFF (не больше предела + 1:
	// разбор останавливается, как только предел превышен), у остальных — 1.
	Frames int64
	// Pixels — пикселей, которые выделит декодер: у GIF — сумма по кадрам,
	// у TIFF — первая страница, у остальных — ширина × высота.
	Pixels int64
	// Scans — сканов JPEG (не больше MaxJPEGScans + 1).
	Scans int
	// jpegSOF — маркер кадра JPEG (0xC0–0xCF): стандартная библиотека
	// декодирует только 0xC0–0xC2.
	jpegSOF byte
}

// ParseHeader определяет формат по сигнатуре и разбирает заголовок.
func ParseHeader(data []byte) (Info, error) {
	switch {
	case bytes.HasPrefix(data, pngSignature):
		return parsePNG(data)
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return parseJPEG(data)
	case bytes.HasPrefix(data, []byte("GIF87a")), bytes.HasPrefix(data, []byte("GIF89a")):
		return parseGIF(data)
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return parseWebP(data)
	case bytes.HasPrefix(data, []byte("BM")):
		return parseBMP(data)
	case bytes.HasPrefix(data, []byte("II")), bytes.HasPrefix(data, []byte("MM")):
		if len(data) >= 4 && (string(data[:4]) == "II*\x00" || string(data[:4]) == "MM\x00*" ||
			string(data[:4]) == "II+\x00" || string(data[:4]) == "MM\x00+") {
			return parseTIFF(data)
		}
	}
	return Info{}, ErrUnknownFormat
}

// single — итог разбора формата с одним кадром.
func single(f wire.Format, w, h int64) (Info, error) {
	if w <= 0 || h <= 0 || w > wire.MaxDimension || h > wire.MaxDimension {
		return Info{Format: f}, ErrMalformed
	}
	return Info{Format: f, Width: w, Height: h, Frames: 1, Pixels: w * h}, nil
}

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

// parsePNG — сигнатура и первый чанк IHDR (длина 13, допустимые сочетания
// глубины и типа цвета, сжатие и фильтр 0, чересстрочность 0 или 1).
// Контрольная сумма чанка сверяется декодером (png.DecodeConfig).
func parsePNG(data []byte) (Info, error) {
	const ihdrEnd = 8 + 8 + 13 + 4 // сигнатура, длина и тип, данные, CRC
	fail := Info{Format: wire.FormatPNG}
	if len(data) < ihdrEnd || binary.BigEndian.Uint32(data[8:12]) != 13 || string(data[12:16]) != "IHDR" {
		return fail, ErrMalformed
	}
	d := data[16:29]
	w, h := binary.BigEndian.Uint32(d[0:4]), binary.BigEndian.Uint32(d[4:8])
	depth, color := d[8], d[9]
	if w > math.MaxInt32 || h > math.MaxInt32 || !pngDepthOK(color, depth) || d[10] != 0 || d[11] != 0 || d[12] > 1 {
		return fail, ErrMalformed
	}
	return single(wire.FormatPNG, int64(w), int64(h))
}

func pngDepthOK(color, depth byte) bool {
	switch color {
	case 0: // оттенки серого
		return depth == 1 || depth == 2 || depth == 4 || depth == 8 || depth == 16
	case 3: // палитра
		return depth == 1 || depth == 2 || depth == 4 || depth == 8
	case 2, 4, 6: // RGB, серый с альфой, RGBA
		return depth == 8 || depth == 16
	}
	return false
}

// parseJPEG — маркеры от SOI: длины сегментов, единственный кадр SOF0–SOF15
// (кроме DHT, JPG, DAC) до первого скана, затем сканы по всему файлу:
// энтропийные данные пропускаются до следующего маркера. Высота 0 (DNL) —
// отказ. Сканов больше MaxJPEGScans — разбор останавливается.
func parseJPEG(data []byte) (Info, error) {
	info := Info{Format: wire.FormatJPEG}
	i := 2 // после SOI
	for i < len(data) {
		if data[i] != 0xFF {
			return info, ErrMalformed
		}
		for i < len(data) && data[i] == 0xFF { // байты заполнения
			i++
		}
		if i >= len(data) {
			break
		}
		m := data[i]
		i++
		switch {
		case m == 0xD9: // EOI
			return jpegDone(info)
		case m == 0xD8 || m == 0x00:
			return info, ErrMalformed
		case m == 0x01 || (m >= 0xD0 && m <= 0xD7): // без длины
			continue
		}
		if i+2 > len(data) {
			return info, ErrMalformed
		}
		n := int(binary.BigEndian.Uint16(data[i : i+2]))
		if n < 2 || i+n > len(data) {
			return info, ErrMalformed
		}
		seg := data[i+2 : i+n]
		i += n
		switch {
		case m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC:
			if info.jpegSOF != 0 || info.Scans > 0 || len(seg) < 6 {
				return info, ErrMalformed
			}
			info.jpegSOF = m
			info.Height = int64(binary.BigEndian.Uint16(seg[1:3]))
			info.Width = int64(binary.BigEndian.Uint16(seg[3:5]))
			if info.Width == 0 || info.Height == 0 || seg[5] == 0 {
				return info, ErrMalformed
			}
		case m == 0xDA: // SOS: дальше энтропийные данные
			if info.jpegSOF == 0 {
				return info, ErrMalformed
			}
			info.Scans++
			if info.Scans > MaxJPEGScans {
				return jpegDone(info)
			}
			i = skipEntropy(data, i)
		}
	}
	// Файл без EOI: размеры известны, если был кадр и скан; оборванные
	// данные скана отвергнет декодер.
	return jpegDone(info)
}

// skipEntropy — позиция следующего маркера после энтропийных данных скана:
// 0xFF 0x00 — экранированный байт, 0xFF 0xD0–0xD7 — маркер перезапуска
// внутри скана.
func skipEntropy(data []byte, i int) int {
	for ; i+1 < len(data); i++ {
		if data[i] != 0xFF {
			continue
		}
		b := data[i+1]
		if b == 0x00 || (b >= 0xD0 && b <= 0xD7) || b == 0xFF {
			continue
		}
		return i
	}
	return len(data)
}

func jpegDone(info Info) (Info, error) {
	if info.jpegSOF == 0 || info.Scans == 0 {
		return Info{Format: wire.FormatJPEG}, ErrMalformed
	}
	info.Frames, info.Pixels = 1, info.Width*info.Height
	return info, nil
}

// parseGIF — логический экран и обход всех блоков до trailer: расширения и
// подблоки пропускаются по длинам, у каждого кадра — размеры и положение в
// пределах экрана, минимальный размер кода LZW 2–8. Пиксели — сумма по
// кадрам: декодируются все кадры. Кадров больше MaxGIFFrames — разбор
// останавливается.
func parseGIF(data []byte) (Info, error) {
	info := Info{Format: wire.FormatGIF}
	if len(data) < 13 {
		return info, ErrMalformed
	}
	sw, sh := int64(binary.LittleEndian.Uint16(data[6:8])), int64(binary.LittleEndian.Uint16(data[8:10]))
	if sw == 0 || sh == 0 {
		return info, ErrMalformed
	}
	info.Width, info.Height = sw, sh
	i := 13
	if data[10]&0x80 != 0 {
		i += 3 << (1 + data[10]&7)
	}
	for i < len(data) {
		b := data[i]
		i++
		switch b {
		case 0x3B: // trailer
			if info.Frames == 0 {
				return Info{Format: wire.FormatGIF}, ErrMalformed
			}
			return info, nil
		case 0x21: // расширение: метка и подблоки
			if i >= len(data) {
				return Info{Format: wire.FormatGIF}, ErrMalformed
			}
			var ok bool
			if i, ok = skipSubBlocks(data, i+1); !ok {
				return Info{Format: wire.FormatGIF}, ErrMalformed
			}
		case 0x2C: // описание кадра
			if i+9 > len(data) {
				return Info{Format: wire.FormatGIF}, ErrMalformed
			}
			d := data[i : i+9]
			left, top := int64(binary.LittleEndian.Uint16(d[0:2])), int64(binary.LittleEndian.Uint16(d[2:4]))
			w, h := int64(binary.LittleEndian.Uint16(d[4:6])), int64(binary.LittleEndian.Uint16(d[6:8]))
			if w == 0 || h == 0 || left+w > sw || top+h > sh {
				return Info{Format: wire.FormatGIF}, ErrMalformed
			}
			i += 9
			if d[8]&0x80 != 0 {
				i += 3 << (1 + d[8]&7)
			}
			if i >= len(data) || data[i] < 2 || data[i] > 8 {
				return Info{Format: wire.FormatGIF}, ErrMalformed
			}
			var ok bool
			if i, ok = skipSubBlocks(data, i+1); !ok {
				return Info{Format: wire.FormatGIF}, ErrMalformed
			}
			info.Frames++
			info.Pixels += w * h
			if info.Frames > MaxGIFFrames {
				return info, nil
			}
		default:
			return Info{Format: wire.FormatGIF}, ErrMalformed
		}
	}
	return Info{Format: wire.FormatGIF}, ErrMalformed // нет trailer
}

// skipSubBlocks пропускает подблоки GIF до нулевого; false — данные
// оборвались.
func skipSubBlocks(data []byte, i int) (int, bool) {
	for i < len(data) {
		n := int(data[i])
		i++
		if n == 0 {
			return i, true
		}
		i += n
	}
	return i, false
}

// parseWebP — RIFF/WEBP и первый чанк: VP8 (ключевой кадр, стартовый код),
// VP8L (сигнатура 0x2F, версия 0) или VP8X (размер холста).
func parseWebP(data []byte) (Info, error) {
	fail := Info{Format: wire.FormatWebP}
	if len(data) < 20 {
		return fail, ErrMalformed
	}
	n := int64(binary.LittleEndian.Uint32(data[16:20]))
	if n > int64(len(data)-20) {
		return fail, ErrMalformed
	}
	c := data[20 : 20+n]
	switch string(data[12:16]) {
	case "VP8 ":
		if len(c) < 10 || c[0]&1 != 0 || c[3] != 0x9D || c[4] != 0x01 || c[5] != 0x2A {
			return fail, ErrMalformed
		}
		return single(wire.FormatWebP, int64(binary.LittleEndian.Uint16(c[6:8])&0x3FFF), int64(binary.LittleEndian.Uint16(c[8:10])&0x3FFF))
	case "VP8L":
		if len(c) < 5 || c[0] != 0x2F {
			return fail, ErrMalformed
		}
		bits := binary.LittleEndian.Uint32(c[1:5])
		if bits>>29 != 0 {
			return fail, ErrMalformed
		}
		return single(wire.FormatWebP, int64(bits&0x3FFF)+1, int64(bits>>14&0x3FFF)+1)
	case "VP8X":
		if len(c) < 10 {
			return fail, ErrMalformed
		}
		w := int64(c[4]) | int64(c[5])<<8 | int64(c[6])<<16
		h := int64(c[7]) | int64(c[8])<<8 | int64(c[9])<<16
		return single(wire.FormatWebP, w+1, h+1)
	}
	return fail, ErrMalformed
}

// parseBMP — BM и заголовок DIB: 12 байт (OS/2, размеры без знака) или
// 40, 52, 56, 64, 108, 124 байта (размеры со знаком; отрицательная высота —
// строки сверху вниз).
func parseBMP(data []byte) (Info, error) {
	fail := Info{Format: wire.FormatBMP}
	if len(data) < 18 {
		return fail, ErrMalformed
	}
	size := binary.LittleEndian.Uint32(data[14:18])
	if int64(size) > int64(len(data)-14) {
		return fail, ErrMalformed
	}
	d := data[14:]
	switch size {
	case 12:
		return single(wire.FormatBMP, int64(binary.LittleEndian.Uint16(d[4:6])), int64(binary.LittleEndian.Uint16(d[6:8])))
	case 40, 52, 56, 64, 108, 124:
		w := int64(int32(binary.LittleEndian.Uint32(d[4:8])))  //nolint:gosec // G115: поле BMP — 32 бита со знаком
		h := int64(int32(binary.LittleEndian.Uint32(d[8:12]))) //nolint:gosec // G115: поле BMP — 32 бита со знаком
		if h < 0 {
			h = -h
		}
		return single(wire.FormatBMP, w, h)
	}
	return fail, ErrMalformed
}

// parseTIFF — порядок байтов, первый IFD (ширина — тег 256, высота — 257,
// тип SHORT или LONG, одно значение) и цепочка IFD с защитой от петель:
// страниц больше MaxTIFFPages — обход останавливается. BigTIFF не
// поддерживается. Пиксели — первой страницы: её декодирует x/image/tiff.
func parseTIFF(data []byte) (Info, error) {
	info := Info{Format: wire.FormatTIFF}
	if len(data) < 4 {
		return info, ErrMalformed
	}
	var bo binary.ByteOrder = binary.LittleEndian
	if data[0] == 'M' {
		bo = binary.BigEndian
	}
	if bo.Uint16(data[2:4]) == 43 {
		return info, ErrUnsupportedVariant
	}
	if len(data) < 8 {
		return info, ErrMalformed
	}
	off := int64(bo.Uint32(data[4:8]))
	seen := map[int64]bool{}
	for off != 0 {
		if off < 8 || off+2 > int64(len(data)) || seen[off] {
			return Info{Format: wire.FormatTIFF}, ErrMalformed
		}
		seen[off] = true
		n := int64(bo.Uint16(data[off : off+2]))
		end := off + 2 + 12*n
		if n == 0 || end+4 > int64(len(data)) {
			return Info{Format: wire.FormatTIFF}, ErrMalformed
		}
		if info.Frames == 0 {
			for e := off + 2; e < end; e += 12 {
				ent := data[e : e+12]
				tag := bo.Uint16(ent[0:2])
				if tag != 256 && tag != 257 {
					continue
				}
				v, ok := tiffValue(bo, ent)
				if !ok {
					return Info{Format: wire.FormatTIFF}, ErrMalformed
				}
				if tag == 256 {
					info.Width = v
				} else {
					info.Height = v
				}
			}
			if info.Width == 0 || info.Height == 0 || info.Width > wire.MaxDimension || info.Height > wire.MaxDimension {
				return Info{Format: wire.FormatTIFF}, ErrMalformed
			}
			info.Pixels = info.Width * info.Height
		}
		info.Frames++
		if info.Frames > MaxTIFFPages {
			return info, nil
		}
		off = int64(bo.Uint32(data[end : end+4]))
	}
	if info.Frames == 0 { // смещение первого IFD — 0
		return Info{Format: wire.FormatTIFF}, ErrMalformed
	}
	return info, nil
}

// tiffValue — одно значение SHORT (3) или LONG (4) записи IFD.
func tiffValue(bo binary.ByteOrder, ent []byte) (int64, bool) {
	if bo.Uint32(ent[4:8]) != 1 {
		return 0, false
	}
	switch bo.Uint16(ent[2:4]) {
	case 3:
		return int64(bo.Uint16(ent[8:10])), true
	case 4:
		return int64(bo.Uint32(ent[8:12])), true
	}
	return 0, false
}
