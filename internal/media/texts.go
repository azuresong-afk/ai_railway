package media

import (
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Тексты изображения для итога анализа (ADR-0032, раздел 4; задача 5.43):
// нормализация, разбиение длинных фрагментов, повторы и общий предел
// протокола. Текст не пишется в журнал и не попадает в кэш (ТЗ 5.17).

// textSet — набор текстов одного изображения в пределах протокола.
type textSet struct {
	texts []wire.Text
	total int
	seen  map[string]bool
	// full — достигнут предел числа или объёма: дальнейшие тексты
	// отбрасываются, разборщики могут остановиться.
	full bool
}

// add добавляет текст источника src: управляющие символы заменяются
// пробелом, длинный текст режется на части по MaxTextBytes по границе
// символа, повтор того же текста того же источника и места не добавляется.
// false — набор заполнен.
func (s *textSet) add(src wire.Source, text string, box *wire.Box) bool {
	if s.full {
		return false
	}
	text = cleanText(text)
	if text == "" {
		return true
	}
	key := string(src) + "\x00" + boxKey(box) + "\x00" + text
	if s.seen[key] {
		return true
	}
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	s.seen[key] = true
	for text != "" {
		if len(s.texts) >= wire.MaxTexts || s.total >= wire.MaxTextsBytes {
			s.full = true
			return false
		}
		part := cutUTF8(text, min(wire.MaxTextBytes, wire.MaxTextsBytes-s.total))
		if part == "" {
			s.full = true
			return false
		}
		text = strings.TrimLeft(text[len(part):], " \t\n")
		part = strings.TrimRight(part, " \t\n")
		if part == "" {
			continue
		}
		s.texts = append(s.texts, wire.Text{Text: part, Source: src, Box: box})
		s.total += len(part)
	}
	return true
}

func boxKey(b *wire.Box) string {
	if b == nil {
		return ""
	}
	return fmt.Sprint(b.X, ",", b.Y, ",", b.W, ",", b.H)
}

// cleanText — UTF-8 без управляющих символов (кроме \t и \n), \r\n и \r —
// перевод строки, без пробелов и NUL по краям.
func cleanText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\r':
			return '\n'
		case r == utf8.RuneError, r == 0xFEFF:
			return ' '
		case (r < 0x20 && r != '\t' && r != '\n') || r == 0x7F || (r >= 0x80 && r < 0xA0):
			return ' '
		}
		return r
	}, s)
	return strings.Trim(s, " \t\n")
}

// cutUTF8 — префикс s не длиннее n байт по границе символа.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// latin1 — строка ISO-8859-1 (текстовые чанки PNG) в UTF-8.
func latin1(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// utf8OrLatin1 — UTF-8, если байты им являются, иначе ISO-8859-1:
// кодировка комментария JPEG и строк ASCII в EXIF не задана, а программы
// пишут туда UTF-8.
func utf8OrLatin1(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return latin1(b)
}

// ucs2 — UCS-2 (UTF-16) в заданном порядке байтов до первого NUL.
func ucs2(b []byte, little bool) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		var v uint16
		if little {
			v = uint16(b[i]) | uint16(b[i+1])<<8
		} else {
			v = uint16(b[i])<<8 | uint16(b[i+1])
		}
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return string(utf16.Decode(u))
}
