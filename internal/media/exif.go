package media

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Разбор EXIF своим кодом (задача 5.43, DM-47): блок TIFF (II или MM), IFD0
// и Exif IFD, только текстовые теги из списка. IFD1 (миниатюра), GPS и
// MakerNote не читаются. Все смещения и длины сверяются с границами блока;
// число записей и каталогов ограничено. Ошибка — блок разобран до неё,
// собранные тексты остаются.

// errEXIF — блок EXIF не разобран.
var errEXIF = errors.New("aisec-media: блок EXIF не разобран")

// Пределы разбора EXIF.
const (
	maxIFDEntries = 1024
	exifIFDTag    = 0x8769
	userComment   = 0x9286
)

// exifASCII — текстовые теги ASCII: описание, авторство, программа,
// камера. Дата и время, числовые и служебные теги — не текст для
// детекторов.
var exifASCII = map[uint16]bool{
	0x010D: true, // DocumentName
	0x010E: true, // ImageDescription
	0x010F: true, // Make
	0x0110: true, // Model
	0x011D: true, // PageName
	0x0131: true, // Software
	0x013B: true, // Artist
	0x013C: true, // HostComputer
	0x8298: true, // Copyright
	0xA430: true, // CameraOwnerName
	0xA433: true, // LensMake
	0xA434: true, // LensModel
}

// exifXP — теги Windows (XPTitle, XPComment, XPAuthor, XPKeywords,
// XPSubject): тип BYTE, UCS-2 little-endian.
var exifXP = map[uint16]bool{0x9C9B: true, 0x9C9C: true, 0x9C9D: true, 0x9C9E: true, 0x9C9F: true}

// exifTypeSize — размер значения типа TIFF; 0 — тип неизвестен.
func exifTypeSize(typ uint16) int {
	switch typ {
	case 1, 2, 6, 7: // BYTE, ASCII, SBYTE, UNDEFINED
		return 1
	case 3, 8: // SHORT, SSHORT
		return 2
	case 4, 9, 11: // LONG, SLONG, FLOAT
		return 4
	case 5, 10, 12: // RATIONAL, SRATIONAL, DOUBLE
		return 8
	}
	return 0
}

// parseEXIF разбирает блок TIFF (без префикса «Exif\0\0») и передаёт
// тексты в add; add возвращает false — набор заполнен.
func parseEXIF(t []byte, add func(string) bool) error {
	if len(t) < 8 {
		return errEXIF
	}
	var bo binary.ByteOrder
	switch {
	case bytes.HasPrefix(t, []byte("II*\x00")):
		bo = binary.LittleEndian
	case bytes.HasPrefix(t, []byte("MM\x00*")):
		bo = binary.BigEndian
	default:
		return errEXIF
	}
	exifOff, err := readIFD(t, bo, bo.Uint32(t[4:8]), add)
	if err != nil || exifOff == 0 {
		return err
	}
	_, err = readIFD(t, bo, exifOff, add)
	return err
}

// readIFD читает один каталог; итог — смещение Exif IFD из него (0 — нет).
// Указатель на Exif IFD в самом Exif IFD не следуется: каталогов не больше
// двух, циклов нет.
func readIFD(t []byte, bo binary.ByteOrder, off uint32, add func(string) bool) (uint32, error) {
	if off < 8 || uint64(off)+2 > uint64(len(t)) {
		return 0, errEXIF
	}
	n := int(bo.Uint16(t[off : off+2]))
	start := int(off) + 2
	if n > maxIFDEntries || start+12*n > len(t) {
		return 0, errEXIF
	}
	var exifOff uint32
	for k := range n {
		e := t[start+12*k : start+12*k+12]
		tag, typ, count := bo.Uint16(e[0:2]), bo.Uint16(e[2:4]), bo.Uint32(e[4:8])
		if tag == exifIFDTag && (typ == 4 || typ == 13) && count == 1 {
			exifOff = bo.Uint32(e[8:12])
			continue
		}
		if !exifASCII[tag] && !exifXP[tag] && tag != userComment {
			continue
		}
		v, ok := exifValue(t, bo, e, typ, count)
		if !ok {
			return 0, errEXIF
		}
		if !add(exifText(tag, typ, v, bo)) {
			return 0, nil
		}
	}
	return exifOff, nil
}

// exifValue — байты значения записи: до 4 байт — в самой записи, иначе
// по смещению в пределах блока.
func exifValue(t []byte, bo binary.ByteOrder, e []byte, typ uint16, count uint32) ([]byte, bool) {
	size := exifTypeSize(typ)
	if size == 0 || uint64(count) > uint64(len(t)) {
		return nil, false
	}
	n := uint64(count) * uint64(size) //nolint:gosec // G115: size — от 1 до 8
	if n <= 4 {
		return e[8 : 8+n], true
	}
	off := uint64(bo.Uint32(e[8:12]))
	if off+n > uint64(len(t)) {
		return nil, false
	}
	return t[off : off+n], true
}

// exifText — текст значения: ASCII — UTF-8 или ISO-8859-1 до NUL, теги
// XP — UCS-2LE, UserComment — по коду кодировки из первых 8 байт
// (ASCII, UNICODE — UCS-2 в порядке байтов блока, неопределённый — как
// ASCII; JIS не поддерживается).
func exifText(tag, typ uint16, v []byte, bo binary.ByteOrder) string {
	switch {
	case exifXP[tag]:
		if typ != 1 && typ != 7 {
			return ""
		}
		return ucs2(v, true)
	case tag == userComment:
		if typ != 7 || len(v) < 8 {
			return ""
		}
		code, body := string(v[:8]), v[8:]
		switch code {
		case "UNICODE\x00":
			little := bo == binary.LittleEndian
			if len(body) >= 2 && (body[0] == 0xFF && body[1] == 0xFE || body[0] == 0xFE && body[1] == 0xFF) {
				little, body = body[0] == 0xFF, body[2:]
			}
			return ucs2(body, little)
		case "ASCII\x00\x00\x00", "\x00\x00\x00\x00\x00\x00\x00\x00":
			return cString(body)
		}
		return ""
	case typ == 2:
		return cString(v)
	}
	return ""
}

// cString — строка до первого NUL: UTF-8 или ISO-8859-1.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return utf8OrLatin1(b)
}
