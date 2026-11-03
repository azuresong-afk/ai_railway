package media

import (
	"strings"
	"unicode"
)

// Смешение алфавитов в тексте OCR (ADR-0033, п. 3): модель распознавания
// читает «ИНН» как кириллическую «И» и латинские «HH». Внутри слова похожие
// буквы приводятся к алфавиту, который задают остальные (непохожие) буквы
// слова: «ИHH» → «ИНН», «Pаssword» → «Password». Слово только из похожих
// букв или с непохожими буквами обоих алфавитов не меняется. Так текст
// ближе к изображению (CER) и детекторы ПДн и секретов видят нужное слово.
// Находку unicode.homoglyph для текста изображения шлюз не создаёт вовсе
// (internal/detect/unihidden): у OCR это шум распознавания, а не подмена.

// latinToCyr — латинские буквы, неотличимые на растре от кириллических.
var latinToCyr = map[rune]rune{
	'A': 'А', 'B': 'В', 'C': 'С', 'E': 'Е', 'H': 'Н', 'K': 'К', 'M': 'М', 'O': 'О', 'P': 'Р', 'T': 'Т', 'X': 'Х', 'Y': 'У',
	'a': 'а', 'c': 'с', 'e': 'е', 'o': 'о', 'p': 'р', 'x': 'х', 'y': 'у',
}

// cyrToLatin — обратная таблица.
var cyrToLatin = func() map[rune]rune {
	m := make(map[rune]rune, len(latinToCyr))
	for l, c := range latinToCyr {
		m[c] = l
	}
	return m
}()

// normalizeScripts приводит похожие буквы каждого слова к алфавиту слова.
func normalizeScripts(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	word := make([]rune, 0, 32)
	flush := func() {
		if len(word) > 0 {
			b.WriteString(string(fixWord(word)))
			word = word[:0]
		}
	}
	for _, r := range s {
		if unicode.IsLetter(r) {
			word = append(word, r)
			continue
		}
		flush()
		b.WriteRune(r)
	}
	flush()
	return b.String()
}

// fixWord — слово с похожими буквами, приведёнными к алфавиту остальных.
func fixWord(w []rune) []rune {
	cyr, lat := false, false
	for _, r := range w {
		switch {
		case latinToCyr[r] != 0 || cyrToLatin[r] != 0:
		case unicode.Is(unicode.Cyrillic, r):
			cyr = true
		case unicode.Is(unicode.Latin, r):
			lat = true
		}
	}
	if cyr == lat {
		return w
	}
	table := cyrToLatin
	if cyr {
		table = latinToCyr
	}
	for i, r := range w {
		if t := table[r]; t != 0 {
			w[i] = t
		}
	}
	return w
}
