package gateway

import (
	"unicode"
	"unicode/utf8"
)

// Фрагменты разметки токенов (pii.ner, задача 4.20). Модель размечает куски
// слов (WordPiece), и граница фрагмента может пройти внутри слова, если
// модель отметила не все его куски. Маскирование такого фрагмента оставило
// бы провайдеру часть фамилии, поэтому шлюз расширяет фрагмент до целых
// слов — не дальше maxWordExpand байт в каждую сторону.

// maxWordExpand — предел расширения фрагмента в байтах с каждой стороны:
// слово длиннее — не имя и не адрес, а работа расширения не зависит от
// длины текста.
const maxWordExpand = 64

// wordRune — символ слова: буква, цифра, диакритический знак или знак
// форматирования (Cf: мягкий перенос U+00AD токенизатор выбрасывает, и
// модель видит «Ива\u00adнову» одним словом — 4Н34 ревью 4.r4).
func wordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Cf, r)
}

// expandWords — границы [start, end) фрагмента text, расширенные до целых
// слов. start и end — на границах символов (ml.ParseResult это проверил);
// результат — тоже: шаг идёт по целым символам.
func expandWords(text string, start, end int) (int, int) {
	if start < 0 || end > len(text) || start >= end {
		return start, end
	}
	// Начало: фрагмент начинается внутри слова — назад до его начала.
	if r, _ := utf8.DecodeRuneInString(text[start:]); wordRune(r) {
		for limit := max(0, start-maxWordExpand); start > limit; {
			r, size := utf8.DecodeLastRuneInString(text[:start])
			if r == utf8.RuneError && size <= 1 || !wordRune(r) || start-size < limit {
				break
			}
			start -= size
		}
	}
	// Конец: фрагмент кончается внутри слова — вперёд до его конца.
	if r, _ := utf8.DecodeLastRuneInString(text[:end]); wordRune(r) {
		for limit := min(len(text), end+maxWordExpand); end < limit; {
			r, size := utf8.DecodeRuneInString(text[end:])
			if r == utf8.RuneError && size <= 1 || !wordRune(r) || end+size > limit {
				break
			}
			end += size
		}
	}
	return start, end
}
