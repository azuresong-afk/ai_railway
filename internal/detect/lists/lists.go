// Пакет lists — детектор lists: словари и регулярные выражения заказчика —
// запрещённые темы, кодовые названия проектов, стоп-слова (ТЗ, 5.2; DM-35,
// DM-32, DM-18, DM-19). Применяется к запросу и ответу; что делать с
// находкой, решает политика.
//
// Словарь ищет слова и фразы без учёта регистра (ё = е), не обращая
// внимания на знаки препинания, скрытые символы и подмену букв
// латиницей/кириллицей (через unihidden.Clean); слово с основой
// («взрывчат*») находит любые формы. Выражения — стандартный regexp (RE2,
// линейное время) по исходному тексту; число и размер правил ограничены
// (spec.go). Находка называет список и вид, но не содержит найденного
// текста.
package lists

import (
	"context"
	"sort"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// ID и версия детектора.
const (
	ID      = "lists"
	Version = "1.0.0"
)

// Пределы работы.
const (
	// MaxFindings — предел находок на текст: список из тысяч совпадений не
	// должен раздувать событие. Решение принимается и по первым.
	MaxFindings = 256
	// partBytes и overlapBytes — текст обрабатывается частями (память Clean
	// пропорциональна части, а не тексту); соседние части перекрываются,
	// чтобы не потерять фразу на границе.
	partBytes    = 64 << 10
	overlapBytes = 1 << 10
)

// Detector — детектор lists с набором списков. Без изменяемого состояния,
// безопасен для одновременного вызова.
type Detector struct {
	c *compiled
}

// Compile готовит детектор по спискам заказчика (раздел lists приложения).
// Ошибки правил возвращаются все сразу.
func Compile(specs []Spec) (*Detector, error) {
	c, err := compile(specs)
	if err != nil {
		return nil, err
	}
	return &Detector{c: c}, nil
}

// defaultSpecs — встроенный список: грифы конфиденциальности документов.
// Короткий и точный: словари заказчика подключаются через Compile.
var defaultSpecs = []Spec{{
	ID: "confidentiality-marks", Category: "marker", Threat: "DM-32", Score: 0.6, Direction: "input",
	Words: []string{
		"строго конфиденциально",
		"для служебного пользования",
		"не для передачи третьим лицам",
		"strictly confidential",
		"for internal use only",
	},
}}

// New — детектор со встроенным списком грифов. Конвейер шлюза (задача 1.22)
// собирает детектор приложения через Compile.
func New() *Detector {
	d, err := Compile(defaultSpecs)
	if err != nil {
		panic("lists: встроенный список: " + err.Error())
	}
	return d
}

// ID — идентификатор детектора.
func (*Detector) ID() string { return ID }

// Version — версия детектора.
func (*Detector) Version() string { return Version }

// Directions — запрос и ответ; список выбирает своё направление.
func (*Detector) Directions() []detect.Direction {
	return []detect.Direction{detect.Input, detect.Output}
}

// Detect находит слова, фразы и совпадения выражений. Срок проверяется
// между частями текста и между выражениями.
func (d *Detector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	dir := 0
	if t.Direction == detect.Output {
		dir = 1
	}
	var out []detect.Finding
	add := func(list int, rule string, s, e int) bool {
		li := d.c.lists[list]
		if len(out) >= MaxFindings {
			return false
		}
		out = append(out, detect.Finding{
			Detector: ID, Version: Version, Category: "lists." + li.category, Threat: li.threat,
			Score: li.score, Start: s, End: e, Rule: "list." + li.id + rule,
		})
		return true
	}
	if d.hasWords() {
		if err := d.scanWords(ctx, t.Text, dir, add); err != nil {
			return nil, err
		}
	}
	for _, rr := range d.c.rx {
		if !d.c.lists[rr.list].dirs[dir] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, m := range rr.re.FindAllStringIndex(t.Text, MaxFindings-len(out)+1) {
			if m[0] == m[1] || !detect.OnRuneBoundary(t.Text, m[0]) || !detect.OnRuneBoundary(t.Text, m[1]) {
				continue
			}
			if !add(rr.list, ".re", m[0], m[1]) {
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

func (d *Detector) hasWords() bool {
	if len(d.c.exact) > 0 {
		return true
	}
	for _, m := range d.c.stem {
		if len(m) > 0 {
			return true
		}
	}
	return false
}

// scanWords просматривает текст частями. Часть кончается на границе слова,
// следующая начинается на overlapBytes раньше; находки, целиком лежащие в
// уже просмотренном перекрытии, пропускаются.
func (d *Detector) scanWords(ctx context.Context, text string, dir int, add func(list int, rule string, s, e int) bool) error {
	scanned := 0 // всё до этой позиции уже просмотрено
	for start := 0; start < len(text); {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(start+partBytes, len(text))
		if end < len(text) {
			end = wordEdge(text, end)
		}
		if !d.scanPart(text, start, end, scanned, dir, add) {
			return nil
		}
		scanned = end
		if end >= len(text) {
			break
		}
		start = end - overlapBytes
		for start > 0 && !utf8.RuneStart(text[start]) {
			start--
		}
		if start < 0 {
			start = 0
		}
	}
	return nil
}

// wordEdge сдвигает конец части вперёд до пробела (не дальше 4 КиБ), иначе
// до границы символа.
func wordEdge(text string, end int) int {
	limit := min(end+4096, len(text))
	for i := end; i < limit; i++ {
		if text[i] == ' ' || text[i] == '\n' {
			return i
		}
	}
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	return end
}

func (d *Detector) scanPart(text string, s, e, scanned, dir int, add func(int, string, int, int) bool) bool {
	_, toks, norm := tokenize(text[s:e])
	ns := string(norm)
	emit := func(lists []uint16, rule string, from, to int) bool {
		os, oe := s+toks[from].os, s+toks[to].oe
		if oe <= scanned {
			return true // найдено в предыдущей части
		}
		for _, li := range lists {
			if d.c.lists[li].dirs[dir] && !add(int(li), rule, os, oe) {
				return false
			}
		}
		return true
	}
	for i := range toks {
		maxN := 1
		mask := d.c.first[ns[toks[i].ns:toks[i].ne]]
		for n := 2; n <= MaxWordTokens; n++ {
			if mask&(1<<n) != 0 {
				maxN = n
			}
		}
		for n := 1; n <= maxN && i+n <= len(toks); n++ {
			if n > 1 && mask&(1<<n) == 0 {
				continue
			}
			last := i + n - 1
			key := ns[toks[i].ns:toks[last].ne]
			if ls, ok := d.c.exact[key]; ok && !emit(ls, ".word", i, last) {
				return false
			}
			if len(d.c.stemLens[n]) == 0 {
				continue
			}
			// основа: префикс последнего слова заданной длины
			head := ns[toks[i].ns:toks[last].ns]
			word := ns[toks[last].ns:toks[last].ne]
			for _, l := range d.c.stemLens[n] {
				p := runePrefix(word, l)
				if p < 0 {
					continue
				}
				if ls, ok := d.c.stem[n][head+word[:p]]; ok && !emit(ls, ".stem", i, last) {
					return false
				}
			}
		}
	}
	return true
}

// runePrefix — длина в байтах первых l символов слова; -1, если слово короче.
func runePrefix(w string, l int) int {
	p := 0
	for range l {
		if p >= len(w) {
			return -1
		}
		_, size := utf8.DecodeRuneInString(w[p:])
		p += size
	}
	return p
}
