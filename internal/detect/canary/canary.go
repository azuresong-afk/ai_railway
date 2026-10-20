// Пакет canary — детектор canary: маркер-канарейка из системного промпта в
// ответе модели — утечка системного промпта (ТЗ, 5.2; DM-08, выход).
//
// Канарейка — функция по выбору владельца приложения: платформа генерирует
// маркер (Generate), владелец вставляет его в системный промпт. Детектор не
// хранит маркеры приложений: формат маркера самопроверяемый — тело и
// контрольные символы, поэтому любой маркер платформы находится в ответе
// без настройки, а случайная строка совпадает с ним с вероятностью 2^-20.
//
// Формат: AISEC-CANARY-XXXX-XXXX-XXXX-XXXX-CCCC, где XXXX — 16 символов тела
// (80 случайных бит в base32, RFC 4648), CCCC — 4 контрольных символа
// (20 младших бит CRC-32 тела). В теле и контрольных символах не меньше двух
// цифр: так тело без префикса не спутать с обычными словами.
//
// Модель может пересказать маркер с изменениями: другой регистр, пробелы,
// запятые, косые черты, переводы строк, обратные кавычки или невидимые
// символы между буквами, гомоглифы и полноширинные символы вместо букв.
// Такие варианты тоже находятся: между любыми двумя символами — до трёх
// разделителей и до четырёх пробельных символов. Ложные срабатывания
// сдерживают 11 букв префикса и контрольные символы.
package canary

import (
	"context"
	"errors"
	"hash/crc32"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/unihidden"
)

// ID и версия детектора.
const (
	ID      = "canary"
	Version = "1.1.0"
)

// CatLeak — категория находки: маркер или его часть в ответе.
const CatLeak = "canary.leak"

// Prefix — префикс маркера.
const Prefix = "AISEC-CANARY-"

const (
	bodyLen  = 16 // символов тела
	checkLen = 4  // контрольных символов
	symbols  = bodyLen + checkLen
	maxSeps  = 3 // разделителей (кроме пробельных) между соседними символами маркера
	// maxSpaces — пробельных символов между соседними символами маркера:
	// «C, -, C» (по символу через запятую) — три разделителя и два пробела.
	maxSpaces = 4
	// maxGap — длина разделителя групп тела без префикса в символах.
	maxGap    = 3
	minDigits = 2
	// partialMin — сколько символов после префикса нужно для находки
	// «изменённый или обрезанный маркер».
	partialMin = 8
	alphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// prefixLetters — буквы префикса без разделителей.
const prefixLetters = "AISECCANARY"

// Detector — детектор canary. Без состояния, безопасен для одновременного
// вызова.
type Detector struct{}

// New создаёт детектор.
func New() Detector { return Detector{} }

// ID — идентификатор детектора.
func (Detector) ID() string { return ID }

// Version — версия детектора.
func (Detector) Version() string { return Version }

// Directions — ответ модели и аргументы tool_calls.
func (Detector) Directions() []detect.Direction { return []detect.Direction{detect.Output} }

// Generate создаёт маркер из криптографически стойкого источника профиля.
func Generate(rnd crypto.Random) (string, error) {
	// Тело без двух цифр (около 16 % случаев) выбирается заново.
	for range 64 {
		raw, err := crypto.RandomBytes(rnd, 10)
		if err != nil {
			return "", err
		}
		body := encode(raw)
		sym := body + check(body)
		if countDigits(sym) < minDigits {
			continue
		}
		var b strings.Builder
		b.WriteString(Prefix)
		for i := 0; i < symbols; i += 4 {
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteString(sym[i : i+4])
		}
		return b.String(), nil
	}
	return "", errors.New("canary: источник случайности не дал подходящего маркера")
}

// Valid — строка является маркером платформы (с верными контрольными
// символами) в каноническом виде.
func Valid(s string) bool {
	if !strings.HasPrefix(s, Prefix) || len(s) != len(Prefix)+symbols+symbols/4-1 {
		return false
	}
	sym := strings.ReplaceAll(s[len(Prefix):], "-", "")
	if len(sym) != symbols || strings.ToUpper(sym) != sym {
		return false
	}
	for i := 4; i < len(s)-len(Prefix); i += 5 {
		if s[len(Prefix)+i] != '-' {
			return false
		}
	}
	return validSymbols(sym)
}

// encode — base32 (RFC 4648) без дополнения; 10 байт — 16 символов.
func encode(raw []byte) string {
	var b strings.Builder
	var acc uint64
	bits := 0
	for _, c := range raw {
		acc = acc<<8 | uint64(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			b.WriteByte(alphabet[(acc>>uint(bits))&31])
		}
	}
	return b.String()
}

// check — контрольные символы тела: 20 младших бит CRC-32.
func check(body string) string {
	sum := crc32.ChecksumIEEE([]byte(body))
	out := make([]byte, checkLen)
	for i := checkLen - 1; i >= 0; i-- {
		out[i] = alphabet[sum&31]
		sum >>= 5
	}
	return string(out)
}

// validSymbols — 20 символов в верхнем регистре: тело с верными
// контрольными символами и не меньше двух цифр.
func validSymbols(sym string) bool {
	if len(sym) != symbols || countDigits(sym) < minDigits {
		return false
	}
	for i := 0; i < len(sym); i++ {
		if strings.IndexByte(alphabet, sym[i]) < 0 {
			return false
		}
	}
	return check(sym[:bodyLen]) == sym[bodyLen:]
}

func countDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '2' && s[i] <= '7' {
			n++
		}
	}
	return n
}

// upper — символ base32 в верхнем регистре; 0 — не символ base32.
func upper(c byte) byte {
	switch {
	case c >= 'A' && c <= 'Z', c >= '2' && c <= '7':
		return c
	case c >= 'a' && c <= 'z':
		return c - 'a' + 'A'
	}
	return 0
}

// at — символ текста с позиции i: c — буква или цифра ASCII (после свёртки
// гомоглифов, полноширинных и математических символов, тегов) в исходном
// регистре или 0; sep — разделитель: любой символ ASCII, кроме букв и цифр,
// пробелы и знаки препинания Unicode (Z*, P*), символы форматирования (Cf)
// и скрытые символы; space — пробельный разделитель; n — длина в байтах
// («\r\n» — один символ).
//
// Свёртка — посимвольная (unihidden.ASCIIFold), а не через unihidden.Clean:
// маркер целиком латинский, поэтому подходит любой похожий символ, а Clean
// на ответе до 32 МиБ потребовал бы карту позиций по 8 байт на байт текста.
// Для ASCII свёртки нет — обычный текст проверяется без декодирования.
func at(text string, i int) (c byte, sep, space bool, n int) {
	b := text[i]
	if b < utf8.RuneSelf {
		switch {
		case alnum(b):
			return b, false, false, 1
		case b == '\r' && i+1 < len(text) && text[i+1] == '\n':
			return 0, true, true, 2
		}
		return 0, true, b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f', 1
	}
	var r rune
	if b >= 0xC2 && b < 0xE0 && i+1 < len(text) && text[i+1]&0xC0 == 0x80 {
		// Двухбайтовый символ (кириллица, греческий) — без общего декодера.
		r, n = rune(b&0x1F)<<6|rune(text[i+1]&0x3F), 2
	} else {
		r, n = utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && n == 1 {
			return 0, false, false, 1
		}
	}
	if f := unihidden.ASCIIFold(r); f != 0 {
		a := byte(f) //nolint:gosec // G115: ASCIIFold возвращает символ ASCII (< 0x80)
		if alnum(a) {
			return a, false, false, n
		}
		return 0, true, a == ' ', n
	}
	switch {
	case r >= 0x0400 && r <= 0x0482, r >= 0x048A && r <= 0x052F:
		return 0, false, false, n // кириллические буквы — самый частый случай
	case unicode.IsSpace(r), unicode.In(r, unicode.Z):
		return 0, true, true, n
	case unicode.In(r, unicode.P, unicode.Cf), unihidden.Hidden(r):
		return 0, true, false, n
	}
	return 0, false, false, n
}

// scanner собирает символы маркера, пропуская разделители.
type scanner struct {
	text string
	pos  int  // позиция после последнего собранного символа
	dash bool // между символами были только '-' и '_' (вид, в котором маркер выдаётся)
}

// next — следующий символ base32 после не больше maxSeps разделителей и
// maxSpaces пробельных символов. Возвращает 0, если его нет; позиция при
// этом не меняется.
func (s *scanner) next() byte {
	i, seps, spaces := s.pos, 0, 0
	plain := true
	for i < len(s.text) {
		c, sep, space, n := at(s.text, i)
		if c != 0 {
			u := upper(c)
			if u != 0 {
				s.pos = i + n
				if seps+spaces > 0 && !plain {
					s.dash = false
				}
			}
			return u
		}
		if !sep {
			return 0
		}
		if space {
			spaces++
		} else {
			seps++
		}
		if seps > maxSeps || spaces > maxSpaces {
			return 0
		}
		if s.text[i] != '-' && s.text[i] != '_' {
			plain = false
		}
		i += n
	}
	return 0
}

// matchPrefix сопоставляет AISEC-CANARY с позиции start (буква A или a);
// возвращает сканер после префикса.
func matchPrefix(text string, start int) (scanner, bool) {
	s := scanner{text: text, pos: start, dash: true}
	for k := 0; k < len(prefixLetters); k++ {
		var c byte
		if k == 0 {
			b, _, _, n := at(text, start)
			c = upper(b)
			s.pos = start + n
		} else {
			c = s.next()
		}
		if c != prefixLetters[k] {
			return s, false
		}
	}
	return s, true
}

// Detect находит маркер в ответе. Оценки:
//   - маркер с префиксом и верными контрольными символами — 0,99;
//   - тело без префикса (16 символов и 4 контрольных, группами по четыре
//     через один и тот же разделитель из 1–3 символов — дефис, пробел,
//     «, », « / », «` `», перевод строки, — либо подряд) с верными
//     контрольными символами — 0,9;
//   - префикс и не меньше восьми символов после него через дефисы или
//     подчёркивания (обрезанный или изменённый маркер), среди них цифра — 0,6;
//   - только префикс или заполнитель (AISEC-CANARY-XXXX) — 0,3, ниже порога.
func (Detector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	text := t.Text
	var out []detect.Finding
	add := func(rule string, s, e int, score float64) {
		out = append(out, detect.Finding{Detector: ID, Version: Version, Category: CatLeak, Threat: "DM-08", Score: score, Start: s, End: e, Rule: rule})
	}
	// Тело без префикса: слово из 20 символов или пять групп по четыре,
	// разделённые одним и тем же разделителем.
	groups := make([]group, 0, 5)
	var gsep string
	afterSym := false // предыдущий символ — буква или цифра (конец находки)
	for i, n := 0, 0; i < len(text); n++ {
		if n&0xFFFF == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		c, sep, _, size := at(text, i)
		if (c == 'a' || c == 'A') && !afterSym {
			if s, ok := matchPrefix(text, i); ok {
				end, rule, score := afterPrefix(&s)
				add(rule, i, end, score)
				i, groups, afterSym = end, groups[:0], true
				continue
			}
		}
		afterSym = false
		if c == 0 {
			if !sep {
				groups = groups[:0]
			}
			i += size
			continue
		}
		// Слово: подряд идущие буквы и цифры (после свёртки).
		var word [symbols]byte
		wl, j := 0, i
		for j < len(text) {
			wc, _, _, wn := at(text, j)
			if wc == 0 {
				break
			}
			if wl < symbols {
				word[wl] = wc
			}
			wl++
			j += wn
		}
		switch {
		case wl == symbols && bodyWord(word[:]):
			if validSymbols(strings.ToUpper(string(word[:]))) {
				add("body", i, j, 0.9)
			}
			groups = groups[:0]
		case wl == 4 && bodyWord(word[:4]):
			if n := len(groups); n > 0 {
				prev := groups[n-1]
				gap := text[prev.e:i]
				switch {
				case !gapOK(gap):
					groups = groups[:0]
				case n == 1:
					gsep = gap
				case gap != gsep:
					// Новая последовательность с предыдущей группы.
					groups, gsep = append(groups[:0], prev), gap
				}
			}
			if len(groups) == 5 {
				groups = append(groups[:0], groups[1:]...)
			}
			g := group{s: i, e: j}
			for q := range 4 {
				g.sym[q] = upper(word[q])
			}
			groups = append(groups, g)
			if len(groups) == 5 {
				var sym [symbols]byte
				for k, g := range groups {
					copy(sym[k*4:], g.sym[:])
				}
				if validSymbols(string(sym[:])) {
					add("body", groups[0].s, j, 0.9)
					groups = groups[:0]
				}
			}
		default:
			groups = groups[:0]
		}
		i = j
	}
	return out, nil
}

// group — группа из четырёх символов тела: позиции и символы после свёртки.
type group struct {
	s, e int
	sym  [4]byte
}

// gapOK — между группами тела от одного до maxGap разделителей.
func gapOK(gap string) bool {
	if gap == "" || len(gap) > maxGap*utf8.UTFMax {
		return false
	}
	k := 0
	for i := 0; i < len(gap); k++ {
		_, sep, _, n := at(gap, i)
		if !sep || k == maxGap {
			return false
		}
		i += n
	}
	return true
}

// afterPrefix оценивает символы после префикса; возвращает конец находки.
func afterPrefix(s *scanner) (end int, rule string, score float64) {
	prefixEnd := s.pos
	end = s.pos
	sym := make([]byte, 0, symbols)
	for len(sym) < symbols {
		c := s.next()
		if c == 0 {
			break
		}
		sym = append(sym, c)
		end = s.pos
	}
	switch {
	case len(sym) == symbols && validSymbols(string(sym)):
		return end, "marker", 0.99
	case len(sym) >= partialMin && countDigits(string(sym)) >= 1 && s.dash:
		return end, "partial", 0.6
	}
	return prefixEnd, "prefix", 0.3
}

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// bodyWord — слово из символов base32 в одном регистре.
func bodyWord(w []byte) bool {
	lower, upperCase := false, false
	for i := 0; i < len(w); i++ {
		c := w[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upperCase = true
		case c >= '2' && c <= '7':
		default:
			return false
		}
	}
	return !lower || !upperCase
}
