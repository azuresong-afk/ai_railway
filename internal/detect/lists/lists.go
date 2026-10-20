// Пакет lists — детектор lists: словари и регулярные выражения заказчика —
// запрещённые темы, кодовые названия проектов, стоп-слова (ТЗ, 5.2; DM-35,
// DM-32, DM-18, DM-19). Применяется к запросу и ответу; что делать с
// находкой, решает политика.
//
// Словарь ищет слова и фразы без учёта регистра (ё = е), не обращая
// внимания на знаки препинания, скрытые символы, ударения и другие
// комбинируемые знаки над буквами и подмену букв латиницей/кириллицей
// (через unihidden.Clean); слово с основой
// («взрывчат*») находит любые формы. Выражения — стандартный regexp (RE2,
// линейное время) по исходному тексту; число и размер правил ограничены
// (spec.go). Находка называет список и вид, но не содержит найденного
// текста.
package lists

import (
	"context"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// ID и версия детектора.
const (
	ID      = "lists"
	Version = "1.1.0"
)

// Пределы работы.
const (
	// MaxFindings — предел находок на текст: список из тысяч совпадений не
	// должен раздувать событие. Решение принимается и по первым.
	MaxFindings = 256
	// partBytes — текст обрабатывается частями (память Clean
	// пропорциональна части, а не тексту); соседние части перекрываются на
	// MaxWordTokens слов, чтобы не потерять слово или фразу на границе.
	partBytes = 64 << 10
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

// WithDefaults — встроенный список грифов и списки приложения: встроенный
// список действует всегда, заказчик его только дополняет. Его ID
// (confidentiality-marks) занят, а своих списков у приложения — до MaxLists-1.
func WithDefaults(specs []Spec) []Spec {
	return append(slices.Clone(defaultSpecs), specs...)
}

// New — детектор со встроенным списком грифов. Конвейер шлюза (задача 1.22)
// собирает детектор приложения через Compile(WithDefaults(…)).
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

// scanWords просматривает текст частями. Часть кончается на границе слова
// (wordEdge), но слово может быть и разрезано: между его буквами бывают
// тысячи невидимых символов, которые Clean удаляет. А между словами фразы
// бывают тысячи пробелов, поэтому перекрытие частей считается в словах, а
// не в байтах (см. scanPart): последний токен части, возможно обрезанный,
// разбирается заново в следующей части, а предыдущие MaxWordTokens-1
// токенов переносятся в неё готовыми — с них могут начинаться фразы, конец
// которых в следующей части. Каждый байт разбирается не больше двух раз.
func (d *Detector) scanWords(ctx context.Context, text string, dir int, add func(list int, rule string, s, e int) bool) error {
	var c carry
	for start := 0; start < len(text); {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(start+partBytes, len(text))
		if end < len(text) {
			end = wordEdge(text, end)
		}
		final := end >= len(text)
		next, ok := d.scanPart(text, start, end, final, &c, dir, add)
		if !ok || final {
			return nil
		}
		start = next
	}
	return nil
}

// carry — токены, перенесённые в следующую часть: с них начинаются фразы,
// ещё не проверенные целиком. Позиции os, oe — в тексте, ns, ne — в norm.
type carry struct {
	norm string
	toks []token
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

// scanPart ищет слова и фразы в части [s, e) вместе с перенесёнными из
// предыдущей части токенами c; final — часть последняя. Сообщает фразы,
// которые начинаются не позже MaxWordTokens токенов до конца части: их
// последнее слово не дальше предпоследнего токена, то есть целое. Остальные
// токены, кроме последнего, переносятся в c; следующая часть начинается с
// последнего токена (next), чтобы разобрать его целиком. Если последний
// токен начинается в начале части (слово длиннее части), он считается
// целым: иначе разбор не продвинулся бы. Возвращает false, если достигнут
// предел находок.
func (d *Detector) scanPart(text string, s, e int, final bool, c *carry, dir int, add func(int, string, int, int) bool) (next int, ok bool) {
	_, part, norm := tokenize(text[s:e])
	ns := string(norm)
	toks := part
	if len(c.toks) > 0 {
		shift := len(c.norm) + 1
		ns = c.norm + " " + ns
		toks = make([]token, 0, len(c.toks)+len(part))
		toks = append(toks, c.toks...)
		for _, t := range part {
			t.ns, t.ne = t.ns+shift, t.ne+shift
			toks = append(toks, t)
		}
	}
	for i := len(toks) - len(part); i < len(toks); i++ {
		toks[i].os, toks[i].oe = toks[i].os+s, toks[i].oe+s
	}
	// Фразы с токена from и дальше — в следующей части; [from, keep) переносятся.
	from, keep := len(toks), len(toks)
	next = e
	if !final {
		if n := len(toks); len(part) > 0 && toks[n-1].os > s {
			next, keep = toks[n-1].os, n-1
		}
		from = max(keep-(MaxWordTokens-1), 0)
	}
	defer func() {
		c.toks = c.toks[:0]
		c.norm = ""
		if from < keep {
			base := toks[from].ns
			c.norm = strings.Clone(ns[base:toks[keep-1].ne])
			for _, t := range toks[from:keep] {
				t.ns, t.ne = t.ns-base, t.ne-base
				c.toks = append(c.toks, t)
			}
		}
	}()
	emit := func(lists []uint16, rule string, first, last int) bool {
		os, oe := toks[first].os, toks[last].oe
		for _, li := range lists {
			if d.c.lists[li].dirs[dir] && !add(int(li), rule, os, oe) {
				return false
			}
		}
		return true
	}
	for i := range from {
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
				return next, false
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
					return next, false
				}
			}
		}
	}
	return next, true
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
