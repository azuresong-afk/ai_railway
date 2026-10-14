package unihidden

// Классификация символов: невидимые, управление направлением, теги,
// селекторы вариантов, гомоглифы.

import "unicode"

// kind — вид скрытого символа.
type kind uint8

const (
	kNone       kind = iota
	kTag             // теги U+E0000–E007F: невидимая копия ASCII
	kOverride        // переопределение направления: LRO, RLO (Trojan Source)
	kEmbed           // встраивания и изоляты: LRE, RLE, PDF, LRI, RLI, FSI, PDI
	kMark            // метки направления: LRM, RLM, ALM
	kZWJ             // соединитель нулевой ширины (эмодзи, индийские письменности)
	kZWNJ            // разъединитель нулевой ширины (персидский, индийские письменности)
	kVS              // селекторы вариантов
	kSoftHyphen      // мягкий перенос
	kBOM             // U+FEFF: метка порядка байтов, в середине — неразрывный пробел нулевой ширины
	kInvisible       // прочие невидимые: ZWSP, WJ, невидимые операторы, заполнители хангыля и т. п.
	kControl         // управляющие C0 (кроме табуляции и перевода строки), DEL, C1
)

func classify(r rune) kind {
	switch {
	case r < 0x20:
		if r == '\t' || r == '\n' || r == '\r' {
			return kNone
		}
		return kControl
	case r < 0x7F:
		return kNone
	case r <= 0x9F:
		return kControl
	case r == 0x00AD:
		return kSoftHyphen
	case r == 0x200D:
		return kZWJ
	case r == 0x200C:
		return kZWNJ
	case r == 0x200E || r == 0x200F || r == 0x061C:
		return kMark
	case r == 0x202D || r == 0x202E:
		return kOverride
	case r >= 0x202A && r <= 0x202C, r >= 0x2066 && r <= 0x2069:
		return kEmbed
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF, r >= 0x180B && r <= 0x180D, r == 0x180F:
		return kVS
	case r == 0xFEFF:
		return kBOM
	case r >= 0xE0000 && r <= 0xE007F:
		return kTag
	case r == 0x200B, r >= 0x2060 && r <= 0x2065, r >= 0x206A && r <= 0x206F, r == 0x034F,
		r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0, r == 0x17B4, r == 0x17B5, r == 0x180E,
		r >= 0xFFF9 && r <= 0xFFFB, r >= 0x1BCA0 && r <= 0x1BCA3, r >= 0x1D173 && r <= 0x1D17A:
		return kInvisible
	case unicode.Is(unicode.Cf, r):
		// Остальные символы форматирования (знаки аннотаций, номера
		// глав арабского письма и т. п.) — невидимы в обычном тексте.
		return kInvisible
	}
	return kNone
}

// isRTL — буква письменности справа налево: иврит, арабское, сирийское,
// тана, нко.
func isRTL(r rune) bool {
	return r >= 0x0590 && r <= 0x08FF || r >= 0xFB1D && r <= 0xFDFF || r >= 0xFE70 && r <= 0xFEFC
}

// isEmoji — эмодзи и пиктограммы (приближение Extended_Pictographic без
// внешних таблиц).
func isEmoji(r rune) bool {
	return r >= 0x1F000 && r <= 0x1FAFF || r >= 0x2600 && r <= 0x27BF || r >= 0x2300 && r <= 0x23FF ||
		r >= 0x2B00 && r <= 0x2BFF || r >= 0x2190 && r <= 0x21FF || r >= 0x25A0 && r <= 0x25FF ||
		r == 0x00A9 || r == 0x00AE || r == 0x2122 || r == 0x3030 || r == 0x303D || r == 0x3297 || r == 0x3299
}

// isJoiningScript — письменность, где ZWJ и ZWNJ — часть орфографии:
// арабское и персидское, индийские, сингальское, тибетское и т. п.
func isJoiningScript(r rune) bool {
	return r >= 0x0600 && r <= 0x06FF || r >= 0x0750 && r <= 0x077F || r >= 0x08A0 && r <= 0x08FF ||
		r >= 0x0900 && r <= 0x0DFF || r >= 0x0F00 && r <= 0x0FFF || r >= 0x1780 && r <= 0x17FF ||
		r >= 0xFB50 && r <= 0xFDFF || r >= 0xFE70 && r <= 0xFEFC
}

// isCJK — иероглифы: после них селекторы вариантов выбирают начертание.
func isCJK(r rune) bool {
	return unicode.Is(unicode.Han, r) || r >= 0x3000 && r <= 0x30FF
}

// script — письменность буквы для поиска смешения.
type script uint8

const (
	sOther script = iota
	sLatin
	sCyrillic
	sGreek
)

func scriptOf(r rune) script {
	switch {
	case r < 0x80:
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return sLatin
		}
		return sOther
	case unicode.Is(unicode.Cyrillic, r):
		return sCyrillic
	case unicode.Is(unicode.Greek, r):
		return sGreek
	case unicode.Is(unicode.Latin, r):
		return sLatin
	}
	return sOther
}

// cyrToLat — кириллические буквы, неотличимые от латинских.
var cyrToLat = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
	'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'һ': 'h', 'ӏ': 'l', 'ү': 'y',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
	'Х': 'X', 'У': 'Y', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S', 'Ү': 'Y',
}

// greekToLat — греческие буквы, неотличимые от латинских.
var greekToLat = map[rune]rune{
	'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'ι': 'i', 'κ': 'k', 'υ': 'u',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
	'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

// latToCyr — латинские буквы, неотличимые от кириллических.
var latToCyr = map[rune]rune{
	'a': 'а', 'c': 'с', 'e': 'е', 'o': 'о', 'p': 'р', 'x': 'х', 'y': 'у', 'i': 'і', 'j': 'ј', 's': 'ѕ',
	'A': 'А', 'B': 'В', 'C': 'С', 'E': 'Е', 'H': 'Н', 'K': 'К', 'M': 'М', 'O': 'О', 'P': 'Р', 'T': 'Т',
	'X': 'Х', 'Y': 'У',
}

// confusable — буква r письменности s похожа на букву письменности target.
func confusable(r rune, s, target script) bool {
	switch {
	case s == sCyrillic && target == sLatin:
		_, ok := cyrToLat[r]
		return ok
	case s == sGreek && target == sLatin:
		_, ok := greekToLat[r]
		return ok
	case s == sLatin && target == sCyrillic:
		_, ok := latToCyr[r]
		return ok
	}
	return false
}

// asciiLookalike — полноширинная или математическая буква и цифра в
// виде ASCII; 0 — не такая.
func asciiLookalike(r rune) rune {
	switch {
	case r >= 0xFF01 && r <= 0xFF5E: // полноширинные ASCII
		return r - 0xFEE0
	case r >= 0x1D400 && r <= 0x1D6A3: // математические латинские: 13 начертаний по 52 буквы
		i := (r - 0x1D400) % 52
		if i < 26 {
			return 'A' + i
		}
		return 'a' + i - 26
	case r >= 0x1D7CE && r <= 0x1D7FF: // математические цифры: 5 начертаний
		return '0' + (r-0x1D7CE)%10
	}
	return 0
}
