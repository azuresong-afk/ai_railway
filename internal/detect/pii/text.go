package pii

// Общие помощники детектора: разделители внутри чисел, границы значений,
// ключевые слова по границе слова, обход совпадений с проверкой срока.

import (
	"context"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// sepClass — разделители внутри числа для классов регулярных выражений:
// пробел, дефис и их типографские варианты из текстов Word и веба —
// неразрывный пробел U+00A0, узкий неразрывный U+202F, тонкий U+2009,
// дефис U+2010 и неразрывный дефис U+2011.
const sepClass = ` \-\x{00A0}\x{202F}\x{2009}\x{2010}\x{2011}`

// sepRune — разделитель r, приведённый к ' ' или '-'; 0 — не разделитель.
func sepRune(r rune) byte {
	switch r {
	case ' ', ' ', ' ', ' ':
		return ' '
	case '-', '‐', '‑':
		return '-'
	}
	return 0
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isASCIILetter(b byte) bool { return b|0x20 >= 'a' && b|0x20 <= 'z' }

// isLetter — буква или знак при букве (U+0306 в «й» в форме NFD).
func isLetter(r rune) bool { return unicode.IsLetter(r) || unicode.IsMark(r) }

// standalone — число [s, e) стоит отдельно: не продолжает более длинное
// число или дробь («0.6366197723675814»), не часть идентификатора или хеша
// с латиницей и «_» («ID4000004705411241x»). Кириллица рядом допустима:
// «ИНН7707083893».
func standalone(text string, s, e int) bool {
	if s > 0 {
		b := text[s-1]
		if isDigit(b) || isASCIILetter(b) || b == '_' || (b == '.' || b == ',') && s > 1 && isDigit(text[s-2]) {
			return false
		}
	}
	if e < len(text) {
		b := text[e]
		if isDigit(b) || isASCIILetter(b) || b == '_' || (b == '.' || b == ',') && e+1 < len(text) && isDigit(text[e+1]) {
			return false
		}
	}
	return true
}

// bounded — значение [s, e) не продолжает более длинное число (для дат:
// «1990-11-07T00:00:00» — дата рождения в JSON, буква рядом допустима).
func bounded(text string, s, e int) bool {
	return (s == 0 || !isDigit(text[s-1])) && (e == len(text) || !isDigit(text[e]))
}

// keyword — ключевое слово контекста. Ищется без учёта регистра и только с
// начала слова («инн» в «длинное» не считается); prefix — начало слова
// («телефон…»), иначе слово целиком («тел.», но не «телевизор»).
type keyword struct {
	s      string
	first  rune // первая буква в нижнем регистре — быстрый отсев
	prefix bool
}

// kws строит список ключевых слов: «слово*» — начало слова, «слово» — целиком.
// Каждое слово начинается с буквы.
func kws(list ...string) []keyword {
	out := make([]keyword, len(list))
	for i, s := range list {
		p := strings.HasSuffix(s, "*")
		s = strings.TrimSuffix(s, "*")
		r, _ := utf8.DecodeRuneInString(s)
		out[i] = keyword{s, unicode.ToLower(r), p}
	}
	return out
}

// keywordAt — ключевое слово из ks начинается в позиции i (на границе слова);
// возвращает конец слова или -1.
func keywordAt(text string, i int, ks []keyword) int {
	r, _ := utf8.DecodeRuneInString(text[i:])
	if !unicode.IsLetter(r) {
		return -1
	}
	if i > 0 {
		if p, _ := utf8.DecodeLastRuneInString(text[:i]); isLetter(p) {
			return -1
		}
	}
	r = unicode.ToLower(r)
	for _, k := range ks {
		e := i + len(k.s)
		if k.first != r || e > len(text) || !strings.EqualFold(text[i:e], k.s) {
			continue
		}
		if !k.prefix && e < len(text) {
			if n, _ := utf8.DecodeRuneInString(text[e:]); isLetter(n) {
				continue
			}
		}
		return e
	}
	return -1
}

// lastKeyword — конец последнего ключевого слова из ks, которое начинается
// в [from, to), или -1.
func lastKeyword(text string, from, to int, ks []keyword) int {
	from = max(from, 0)
	for from < to && !utf8.RuneStart(text[from]) {
		from++
	}
	best := -1
	for i := from; i < to; {
		if e := keywordAt(text, i, ks); e > best {
			best = e
		}
		_, size := utf8.DecodeRuneInString(text[i:])
		i += size
	}
	return best
}

// maxValueLen — наибольшая длина в байтах значения, которое ищется
// выражением в окне (телефон, дата, паспорт с «№»): с запасом на
// трёхбайтовые разделители.
const maxValueLen = 64

// anchoredMatches вызывает f для совпадений выражения re (привязанного к
// началу, «^») в позициях, где startAt разрешает начало значения, слева
// направо без пересечений. Выражение применяется к окну maxValueLen байт,
// а не ко всему тексту: так в разы быстрее, а время линейно от длины текста.
// ctx проверяется каждые 4096 позиций — детектор останавливается в срок.
func anchoredMatches(ctx context.Context, re *regexp.Regexp, text string, startAt func(string, int) bool, f func(s, e int)) error {
	for i, n := 0, 0; i < len(text); n++ {
		if n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if !startAt(text, i) {
			i++
			continue
		}
		m := re.FindStringIndex(text[i:min(i+maxValueLen, len(text))])
		if m == nil || m[1] == 0 {
			i++
			continue
		}
		f(i, i+m[1])
		i += m[1]
	}
	return nil
}

// numberStart — в позиции i начинается число (цифра, перед ней не цифра).
func numberStart(text string, i int) bool {
	return isDigit(text[i]) && (i == 0 || !isDigit(text[i-1]))
}

// candidateEnd — конец последовательности цифр с одиночными разделителями,
// которая начинается в i; ctx проверяется каждые 4096 групп.
func candidateEnd(ctx context.Context, text string, i int) (int, error) {
	for n := 1; ; n++ {
		if n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		for i < len(text) && isDigit(text[i]) {
			i++
		}
		if i == len(text) {
			return i, nil
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		if sepRune(r) == 0 || i+size >= len(text) || !isDigit(text[i+size]) {
			return i, nil
		}
		i += size
	}
}

// containsFold — в text есть хотя бы одна из строк words (в нижнем
// регистре) без учёта регистра. Текст переводится в нижний регистр частями
// по 64 КиБ с перекрытием, ctx проверяется после каждой части.
func containsFold(ctx context.Context, text string, words []string) (bool, error) {
	const chunk, overlap = 64 << 10, 32
	for off := 0; off < len(text); {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		end := min(off+chunk+overlap, len(text))
		for end < len(text) && !utf8.RuneStart(text[end]) {
			end++
		}
		lower := strings.ToLower(text[off:end])
		for _, w := range words {
			if strings.Contains(lower, w) {
				return true, nil
			}
		}
		if end == len(text) {
			break
		}
		off += chunk
		for off < len(text) && !utf8.RuneStart(text[off]) {
			off++
		}
	}
	return false, nil
}
