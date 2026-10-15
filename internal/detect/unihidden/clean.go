package unihidden

import (
	"unicode"
	"unicode/utf8"
)

// Clean готовит текст для поиска шаблонов (injection.heuristic): шаблон
// «ignore previous» должен совпасть и с «ig\u200Bnore», и с «ignоre» с
// кириллической «о», и со спрятанным в тегах текстом.
//
//   - скрытые символы удаляются: невидимые, управление направлением,
//     селекторы вариантов, мягкий перенос, управляющие (кроме табуляции и
//     перевода строки);
//   - теги U+E0020–E007E расшифровываются в ASCII — спрятанный текст
//     становится видимым для детекторов;
//   - полноширинные и математические буквы и цифры — в ASCII;
//   - в слове со смешением латиницы, кириллицы и греческого похожие буквы
//     меньшинства заменяются буквами основной письменности слова (при
//     равенстве — латиницей). Невидимые символы внутри слова его не
//     разрывают.
//
// offs[i] — позиция в text байта i результата, offs[len(clean)] = len(text):
// фрагмент [i, j) результата — это [offs[i], offs[j]) исходного текста (по
// таким позициям детектор отмечает находку в исходном тексте).
func Clean(text string) (clean string, offs []int) {
	out := make([]byte, 0, len(text))
	offs = make([]int, 0, len(text)+1)
	var word []wordRune // буквы текущего слова
	flush := func() {
		if len(word) == 0 {
			return
		}
		var cnt [sGreek + 1]int
		for _, w := range word {
			cnt[scriptOf(w.r)]++
		}
		target := sOther
		if cnt[sLatin] > 0 && cnt[sCyrillic]+cnt[sGreek] > 0 || cnt[sCyrillic] > 0 && cnt[sGreek] > 0 {
			target = sLatin
			if cnt[sCyrillic] > cnt[sLatin] && cnt[sCyrillic] >= cnt[sGreek] {
				target = sCyrillic
			}
		}
		for _, w := range word {
			r := w.r
			if target != sOther {
				r = toScript(r, target)
			}
			out, offs = appendRune(out, offs, r, w.pos)
		}
		word = word[:0]
	}
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		pos := i
		i += size
		switch k := classify(r); {
		case k == kTag:
			if r < 0xE0020 || r > 0xE007E {
				continue // начало и отмена тегов
			}
			r -= 0xE0000
		case k != kNone:
			continue
		}
		if a := asciiLookalike(r); a != 0 {
			r = a
		}
		if unicode.IsLetter(r) || unicode.IsMark(r) && len(word) > 0 {
			word = append(word, wordRune{r, pos})
			continue
		}
		flush()
		out, offs = appendRune(out, offs, r, pos)
	}
	flush()
	offs = append(offs, len(text))
	return string(out), offs
}

type wordRune struct {
	r   rune
	pos int
}

// appendRune дописывает r в результат и позицию исходного символа для
// каждого байта.
func appendRune(out []byte, offs []int, r rune, pos int) ([]byte, []int) {
	n := len(out)
	out = utf8.AppendRune(out, r)
	for range len(out) - n {
		offs = append(offs, pos)
	}
	return out, offs
}

// toScript — буква r в письменности target, если она там есть такая же на
// вид; иначе r.
func toScript(r rune, target script) rune {
	var m map[rune]rune
	switch s := scriptOf(r); {
	case s == target:
		return r
	case s == sCyrillic && target == sLatin:
		m = cyrToLat
	case s == sGreek && target == sLatin:
		m = greekToLat
	case s == sLatin && target == sCyrillic:
		m = latToCyr
	default:
		return r
	}
	if v, ok := m[r]; ok {
		return v
	}
	return r
}
