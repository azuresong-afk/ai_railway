// Пакет unihidden — детектор unicode.hidden: скрытые инструкции в Unicode —
// невидимые символы, теги Unicode, управление направлением текста,
// гомоглифы (ТЗ, 5.2; DM-05). Применяется к запросу, документам RAG и
// ответам инструментов. Действия по политике — вырезать или блокировать:
// позиции находок охватывают сами скрытые символы (для вырезания) или
// слово с подменёнными буквами.
//
// Законные случаи не считаются: последовательности эмодзи с ZWJ, флаги
// регионов из тегов, ZWNJ в персидском и индийских письменностях, метки
// направления в тексте на иврите и арабском, селектор варианта после эмодзи
// и иероглифа, BOM в начале, одиночный мягкий перенос внутри слова — ниже
// порога.
//
// Clean (clean.go) готовит текст для поиска шаблонов: удаляет скрытые
// символы, расшифровывает теги, сводит гомоглифы к одной письменности.
package unihidden

import (
	"context"
	"sort"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// ID и версия детектора.
const (
	ID      = "unicode.hidden"
	Version = "1.0.0"
)

// Категории находок.
const (
	CatTag       = "unicode.tag"
	CatBidi      = "unicode.bidi"
	CatInvisible = "unicode.invisible"
	CatHomoglyph = "unicode.homoglyph"
)

// Detector — детектор unicode.hidden. Без состояния, безопасен для
// одновременного вызова.
type Detector struct{}

// New создаёт детектор.
func New() Detector { return Detector{} }

// ID — идентификатор детектора.
func (Detector) ID() string { return ID }

// Version — версия детектора.
func (Detector) Version() string { return Version }

// Directions — запрос (в том числе документы RAG и ответы инструментов).
func (Detector) Directions() []detect.Direction { return []detect.Direction{detect.Input} }

// Detect находит скрытые символы и гомоглифы.
func (Detector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	text := t.Text
	rtl, err := hasRTL(ctx, text)
	if err != nil {
		return nil, err
	}
	var out []detect.Finding
	add := func(cat, rule string, s, e int, score float64) {
		out = append(out, detect.Finding{Detector: ID, Version: Version, Category: cat, Threat: "DM-05", Score: score, Start: s, End: e, Rule: rule})
	}
	if err := hiddenRuns(ctx, text, rtl, add); err != nil {
		return nil, err
	}
	if err := homoglyphs(ctx, text, add); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

// hasRTL — в тексте есть буквы письменности справа налево: тогда метки и
// встраивания направления — обычная вёрстка.
func hasRTL(ctx context.Context, text string) (bool, error) {
	n := 0
	for _, r := range text {
		if n++; n%(64<<10) == 0 {
			if err := ctx.Err(); err != nil {
				return false, err
			}
		}
		if isRTL(r) {
			return true, nil
		}
	}
	return false, ctx.Err()
}

// run — последовательность скрытых символов подряд.
type run struct {
	s, e       int
	counts     [kControl + 1]int
	prev, next rune // видимые символы до и после; -1 — край текста
	first      rune
	flag       bool // теги образуют флаг региона после U+1F3F4
}

// hiddenRuns находит последовательности скрытых символов и оценивает каждую
// по самому подозрительному символу в ней.
func hiddenRuns(ctx context.Context, text string, rtl bool, add func(cat, rule string, s, e int, score float64)) error {
	prev := rune(-1)
	n := 0
	for i := 0; i < len(text); {
		if n++; n%(64<<10) == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		k := classify(r)
		if k == kNone {
			prev = r
			i += size
			continue
		}
		ru := run{s: i, prev: prev, first: r, next: -1}
		tagsOK := prev == 0x1F3F4
		for i < len(text) {
			r, size = utf8.DecodeRuneInString(text[i:])
			k = classify(r)
			if k == kNone {
				ru.next = r
				break
			}
			ru.counts[k]++
			if !flagTag(r) {
				tagsOK = false
			}
			i += size
		}
		ru.e = i
		ru.flag = tagsOK && ru.counts[kTag] >= 3 && ru.counts[kTag] <= 8 && text[ru.e-4:ru.e] == "\U000E007F"
		if cat, rule, score, ok := assess(&ru, rtl); ok {
			add(cat, rule, ru.s, ru.e, score)
		}
		prev = -1
	}
	return nil
}

// assess оценивает последовательность скрытых символов.
func assess(ru *run, rtl bool) (cat, rule string, score float64, ok bool) {
	best := func(c, r string, s float64) {
		if s > score {
			cat, rule, score, ok = c, r, s, true
		}
	}
	c := ru.counts
	if c[kTag] > 0 && !ru.flag {
		if c[kTag] >= 3 {
			best(CatTag, "tag", 0.95)
		} else {
			best(CatTag, "tag", 0.7)
		}
	}
	if c[kOverride] > 0 {
		if rtl {
			best(CatBidi, "override", 0.6)
		} else {
			best(CatBidi, "override", 0.9)
		}
	}
	if c[kEmbed] > 0 {
		if rtl {
			best(CatBidi, "embed", 0.3)
		} else {
			best(CatBidi, "embed", 0.7)
		}
	}
	if c[kMark] > 0 && !rtl {
		best(CatBidi, "mark", 0.4)
	}
	switch {
	case c[kVS] >= 2:
		// Несколько селекторов подряд — способ спрятать байты данных.
		best(CatInvisible, "variation.run", 0.9)
	case c[kVS] == 1 && !legitVS(ru):
		best(CatInvisible, "variation", 0.6)
	}
	// Невидимые символы, которые в этом месте не нужны: ZWJ вне эмодзи и
	// соединяющих письменностей, ZWNJ вне них, BOM не в начале текста.
	inv := c[kInvisible]
	joining := isJoiningScript(ru.prev) && isJoiningScript(ru.next)
	emoji := isEmoji(ru.prev) && isEmoji(ru.next)
	if c[kZWJ] > 0 && !joining && !emoji {
		inv += c[kZWJ]
	}
	if c[kZWNJ] > 0 && !joining {
		inv += c[kZWNJ]
	}
	if c[kBOM] > 0 {
		inv += c[kBOM]
		if ru.s == 0 && ru.first == 0xFEFF {
			inv--
		}
	}
	inWord := isWordRune(ru.prev) && isWordRune(ru.next)
	switch {
	case inv >= 3:
		best(CatInvisible, "invisible.run", 0.9)
	case inv > 0 && inWord:
		// Невидимый символ разрывает слово: так обходят фильтры («ig\u200Bnore»).
		best(CatInvisible, "invisible.word", 0.8)
	case inv > 0:
		best(CatInvisible, "invisible", 0.5)
	}
	switch {
	case c[kSoftHyphen] == 1 && inWord:
		best(CatInvisible, "soft_hyphen", 0.2)
	case c[kSoftHyphen] > 0:
		best(CatInvisible, "soft_hyphen", 0.5)
	}
	if c[kControl] > 0 {
		best(CatInvisible, "control", 0.6)
	}
	return cat, rule, score, ok
}

// flagTag — тег из флага региона: буква, цифра или отменяющий тег.
func flagTag(r rune) bool {
	return r == 0xE007F || r >= 0xE0061 && r <= 0xE007A || r >= 0xE0030 && r <= 0xE0039
}

// legitVS — одиночный селектор варианта на своём месте: VS15/VS16
// (текстовое или эмодзи-начертание) или после эмодзи и иероглифа.
func legitVS(ru *run) bool {
	return ru.first == 0xFE0E || ru.first == 0xFE0F || isEmoji(ru.prev) || isCJK(ru.prev)
}

func isWordRune(r rune) bool { return r >= 0 && (unicode.IsLetter(r) || unicode.IsDigit(r)) }

// homoglyphs — слова со смешением письменностей из похожих букв
// («раssword»: кириллические «р», «а»), слова из полноширинных и
// математических букв («𝐢𝐠𝐧𝐨𝐫𝐞»).
func homoglyphs(ctx context.Context, text string, add func(cat, rule string, s, e int, score float64)) error {
	n := 0
	for i := 0; i < len(text); {
		if n++; n%(64<<10) == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		if !unicode.IsLetter(r) {
			i += size
			continue
		}
		s := i
		var cnt [sGreek + 1]int
		letters, wide, math := 0, 0, 0
		for i < len(text) {
			r, size = utf8.DecodeRuneInString(text[i:])
			if !unicode.IsLetter(r) && !unicode.IsMark(r) {
				break
			}
			if unicode.IsLetter(r) {
				letters++
				cnt[scriptOf(r)]++
				switch {
				case r >= 0xFF21 && r <= 0xFF5A:
					wide++
				case r >= 0x1D400 && r <= 0x1D7FF:
					math++
				}
			}
			i += size
		}
		if letters < 3 {
			continue
		}
		word := text[s:i]
		switch {
		case math > 0:
			add(CatHomoglyph, "math", s, i, 0.7)
		case wide >= 3:
			add(CatHomoglyph, "fullwidth", s, i, 0.6)
		default:
			if rule, score, ok := mixedScript(word, cnt); ok {
				add(CatHomoglyph, rule, s, i, score)
			}
		}
	}
	return nil
}

// mixedScript — в слове больше одной письменности из латиницы, кириллицы
// и греческого. Если все буквы меньшинства похожи на буквы основной
// письменности слова — подмена гомоглифами: в латинском слове (обход
// фильтров «ignоre») — 0,8, в кириллическом (часто раскладка клавиатуры) —
// 0,6. Иначе — 0,4.
func mixedScript(word string, cnt [sGreek + 1]int) (string, float64, bool) {
	present := 0
	major := sOther
	for s := sLatin; s <= sGreek; s++ {
		if cnt[s] > 0 {
			present++
			if major == sOther || cnt[s] > cnt[major] {
				major = s
			}
		}
	}
	if present < 2 {
		return "", 0, false
	}
	all := major != sGreek
	for _, r := range word {
		if s := scriptOf(r); s != major && s != sOther && !confusable(r, s, major) {
			all = false
			break
		}
	}
	switch {
	case all && major == sLatin:
		return "mixed.confusable", 0.8, true
	case all:
		return "mixed.confusable", 0.6, true
	}
	return "mixed", 0.4, true
}
