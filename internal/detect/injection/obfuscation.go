package injection

// Обфускация (DM-04, задача 1.16): атаку прячут в кодировку, транслит,
// leetspeak, разрядку, склейку строк, смешение языков. Детектор приводит
// текст к обычному виду и проверяет его теми же шаблонами.
//
//   - Отрезки в кодировках (base64, hex, %XX, \uXXXX, HTML-сущности)
//     декодируются, и, если результат похож на текст, проверяются целиком
//     как отдельный текст (до двух уровней вложенности). Позиции находки —
//     весь закодированный отрезок.
//   - Преобразования всей части текста (leetspeak, разрядка, склейка
//     строк, транслит, ROT13) дают производное представление с картой
//     позиций; засчитываются только сигналы, которые задевают изменённые
//     символы, — иначе обычный текст считался бы дважды.
//
// Найденное так — категория injection.obfuscation, правило —
// «способ.правило» («base64.ignore_instructions»).

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Пределы декодирования.
const (
	maxDepth   = 2       // уровней вложенности: base64 внутри base64
	maxEncoded = 1 << 20 // байт закодированного отрезка; дальше — не декодируется
	minB64     = 16      // символов base64: от 12 байт текста
	minHex     = 24      // шестнадцатеричных цифр подряд: от 12 байт
	minEscapes = 6       // экранированных символов (\x, %, \u, &#) подряд
	minDecoded = 8       // байт декодированного текста
)

// --- Производные представления ---

// builder собирает производное представление: байты, позиция каждого байта
// в исходном представлении и признак изменения.
type builder struct {
	out []byte
	idx []int
	chg []bool
	n   int // изменённых байтов
}

func newBuilder(size int) *builder {
	return &builder{out: make([]byte, 0, size), idx: make([]int, 0, size+1), chg: make([]bool, 0, size)}
}

// keep переносит src[i:j] без изменений.
func (b *builder) keep(src string, i, j int) {
	b.out = append(b.out, src[i:j]...)
	for k := i; k < j; k++ {
		b.idx = append(b.idx, k)
		b.chg = append(b.chg, false)
	}
}

// put дописывает s вместо символа исходного представления в позиции pos.
func (b *builder) put(s string, pos int, changed bool) {
	b.out = append(b.out, s...)
	for range len(s) {
		b.idx = append(b.idx, pos)
		b.chg = append(b.chg, changed)
	}
	if changed {
		b.n += len(s)
	}
}

// derive строит дочернее представление v по результату b: позиции — через
// карту v в исходный текст; chg — префиксные суммы изменённых байтов.
func (v *view) derive(method string, b *builder) *view {
	offs := make([]int, len(b.out)+1)
	chg := make([]int32, len(b.out)+1)
	for k := range b.out {
		offs[k] = v.offs[b.idx[k]]
		chg[k+1] = chg[k]
		if b.chg[k] {
			chg[k+1]++
		}
	}
	offs[len(b.out)] = v.offs[len(v.low)]
	return &view{low: string(b.out), offs: offs, bs: v.bs, cs: v.cs, ce: v.ce, lineBOL: v.lineBOL, method: method, chg: chg}
}

// transform — преобразование части текста; nil — менять нечего.
type transform struct {
	method string
	build  func(low string) *builder
}

var transforms = []transform{
	{"leet", leet},
	{"spaced", spaced},
	{"concat", concat},
	{"translit", translit},
	{"rot13", rot13},
}

// leet — leetspeak: в слове из букв и цифр («1gn0r3», «pr3v10us», «3абудь»)
// цифры и «@», «$» заменяются похожими буквами письменности слова. Слово —
// от двух букв: «4k», «x86» не трогаются. Разбираются только слова вокруг
// цифр и знаков (strings.IndexAny), остальной текст копируется.
func leet(low string) *builder {
	var b *builder
	last := 0
	for p := 0; p < len(low); {
		k := strings.IndexAny(low[p:], leetChars)
		if k < 0 {
			break
		}
		k += p
		// Границы слова вокруг k, не левее конца прошлого слова.
		s := k
		for s > last {
			r, size := utf8.DecodeLastRuneInString(low[last:s])
			if !isLeetRune(r) {
				break
			}
			s -= size
		}
		i := k
		letters, digits, cyr := 0, 0, 0
		for i < len(low) {
			r, size := utf8.DecodeRuneInString(low[i:])
			if !isLeetRune(r) {
				break
			}
			i += size
		}
		for _, r := range low[s:i] {
			switch {
			case leetLat[r] != "" || leetCyr[r] != "":
				digits++
			case unicode.IsLetter(r):
				letters++
				if unicode.Is(unicode.Cyrillic, r) {
					cyr++
				}
			}
		}
		p = max(i, k+1)
		if letters < 2 || digits == 0 {
			continue
		}
		m := leetLat
		if cyr*2 > letters {
			m = leetCyr
		}
		if b == nil {
			b = newBuilder(len(low))
		}
		b.keep(low, last, s)
		for k := s; k < i; {
			r, size := utf8.DecodeRuneInString(low[k:])
			if rep := m[r]; rep != "" {
				b.put(rep, k, true)
			} else {
				b.keep(low, k, k+size)
			}
			k += size
		}
		last = i
	}
	if b == nil || b.n == 0 {
		return nil
	}
	b.keep(low, last, len(low))
	return b
}

const leetChars = "01345678@$"

func isLeetRune(r rune) bool { return isLetterOrDigit(r) || r == '@' || r == '$' }

// spaced — разрядка: «i g n o r e  a l l», «и.г.н.о.р.и.р.у.й». Отрезок —
// от пяти однобуквенных «слов» через разделители до трёх символов. Самый
// частый разделитель отрезка убирается (он внутри слова), остальные
// становятся пробелом (они между словами). Каждое слово разбирается один
// раз.
func spaced(low string) *builder {
	var b *builder
	last := 0
	for i := 0; i < len(low); {
		r, size := utf8.DecodeRuneInString(low[i:])
		if !isLetterOrDigit(r) {
			i += size
			continue
		}
		j := i + size
		for j < len(low) {
			r2, s2 := utf8.DecodeRuneInString(low[j:])
			if !isLetterOrDigit(r2) {
				break
			}
			j += s2
		}
		if j-i != size || !unicode.IsLetter(r) {
			i = j
			continue
		}
		end, letters, seps := spacedRun(low, i)
		if letters < 5 {
			i = max(j, end)
			continue
		}
		// Самый частый разделитель.
		cnt := map[string]int{}
		dom := ""
		for _, sp := range seps {
			d := low[sp[0]:sp[1]]
			cnt[d]++
			if cnt[d] > cnt[dom] {
				dom = d
			}
		}
		if b == nil {
			b = newBuilder(len(low))
		}
		b.keep(low, last, i)
		k := i
		for _, sp := range seps {
			_, size := utf8.DecodeRuneInString(low[k:])
			b.put(low[k:k+size], k, true)
			if low[sp[0]:sp[1]] != dom {
				b.put(" ", sp[0], true)
			}
			k = sp[1]
		}
		_, size = utf8.DecodeRuneInString(low[k:])
		b.put(low[k:k+size], k, true)
		last = end
		i = end
	}
	if b == nil || b.n == 0 {
		return nil
	}
	b.keep(low, last, len(low))
	return b
}

// spacedRun разбирает отрезок разрядки с однобуквенного слова в позиции i:
// конец, число букв и позиции разделителей.
func spacedRun(low string, i int) (end, letters int, seps [][2]int) {
	k := i
	for {
		r, size := utf8.DecodeRuneInString(low[k:])
		if !unicode.IsLetter(r) || !wordEnd(low, k+size) {
			return k, letters, seps
		}
		letters++
		end = k + size
		// Разделитель до трёх символов и следующая буква.
		j := end
		for j < len(low) && j-end < 3 && strings.IndexByte(" .-_*/|", low[j]) >= 0 {
			j++
		}
		if j == end || j >= len(low) {
			return end, letters, seps
		}
		r, _ = utf8.DecodeRuneInString(low[j:])
		if !unicode.IsLetter(r) {
			return end, letters, seps
		}
		seps = append(seps, [2]int{end, j})
		k = j
	}
}

// concat — склейка строк: «"ign" + "ore all"», «'игно' + 'рируй'». Стык —
// закрывающая кавычка, «+», открывающая кавычка — убирается; символы по
// обе стороны стыка считаются изменёнными: сигнал через стык засчитывается.
func concat(low string) *builder {
	if !strings.Contains(low, "+") {
		return nil
	}
	var b *builder
	last := 0
	for p := 0; p < len(low); {
		k := strings.IndexByte(low[p:], '+')
		if k < 0 {
			break
		}
		k += p
		p = k + 1
		l := k
		for l > last && low[l-1] == ' ' {
			l--
		}
		r := k + 1
		for r < len(low) && low[r] == ' ' {
			r++
		}
		if l == last || r == len(low) {
			continue
		}
		ql, lsize := utf8.DecodeLastRuneInString(low[last:l])
		qr, rsize := utf8.DecodeRuneInString(low[r:])
		if !strings.ContainsRune(closeQuotes, ql) || !strings.ContainsRune(openQuotes, qr) {
			continue
		}
		js, je := l-lsize, r+rsize // стык [js, je)
		if b == nil {
			b = newBuilder(len(low))
		}
		b.keep(low, last, js)
		if n := len(b.chg); n > 0 && !b.chg[n-1] {
			b.chg[n-1] = true
			b.n++
		}
		last = je
		if _, size := utf8.DecodeRuneInString(low[je:]); size > 0 {
			b.put(low[je:je+size], je, true)
			last = je + size
		}
		p = max(p, last)
	}
	if b == nil || b.n == 0 {
		return nil
	}
	b.keep(low, last, len(low))
	return b
}

// translit — русский латиницей: «ignoriruj vse predydushchie instrukcii».
// Только если в тексте есть основа шаблона в транслите (translitStems):
// английский текст не перекодируется зря.
func translit(low string) *builder {
	if !containsAny(low, translitStems) {
		return nil
	}
	b := newBuilder(len(low) * 2)
	last := 0
	for i := 0; i < len(low); {
		if !isTranslitByte(low[i]) || !wordStart(low, i) {
			i++
			continue
		}
		j := i
		for j < len(low) && isTranslitByte(low[j]) {
			j++
		}
		if !wordEnd(low, j) {
			i = j
			continue
		}
		b.keep(low, last, i)
		translitWord(b, low, i, j)
		last = j
		i = j
	}
	if b.n == 0 {
		return nil
	}
	b.keep(low, last, len(low))
	return b
}

func isTranslitByte(c byte) bool { return c >= 'a' && c <= 'z' || c == '\'' }

// translitWord переводит слово low[i:j] латиницей в кириллицу: сначала
// сочетания (shch, zh, ya…), «y» — «й» после гласной, иначе «ы».
func translitWord(b *builder, low string, i, j int) {
	prevVowel := false
	for k := i; k < j; {
		matched := false
		for _, p := range translitPairs {
			if strings.HasPrefix(low[k:j], p[0]) {
				b.put(p[1], k, true)
				k += len(p[0])
				prevVowel = strings.Contains("яюеёэ", p[1])
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		c := low[k]
		var out string
		switch {
		case c == 'y' && (prevVowel || k == i):
			out = "й"
		case c == 'y':
			out = "ы"
		default:
			out = translitOne[c]
		}
		if out != "" {
			b.put(out, k, true)
		}
		prevVowel = strings.IndexByte("aeiouy", c) >= 0 && out != "й"
		k++
	}
}

// rot13 — сдвиг латиницы на 13. Только если текст об этом говорит
// («rot13», «caesar», «цезарь»): без подсказки модель закодированное не
// исполняет, а лишний проход — время.
func rot13(low string) *builder {
	if !containsAny(low, rot13Hints) {
		return nil
	}
	b := newBuilder(len(low))
	last := 0
	for i := 0; i < len(low); i++ {
		c := low[i]
		if c < 'a' || c > 'z' {
			continue
		}
		b.keep(low, last, i)
		b.put(string('a'+(c-'a'+13)%26), i, true)
		last = i + 1
	}
	if b.n == 0 {
		return nil
	}
	b.keep(low, last, len(low))
	return b
}

// --- Отрезки в кодировках ---

// segments находит в части текста отрезки в кодировках и проверяет
// декодированный текст. Ищутся в тексте после Clean до приведения регистра
// (base64 чувствителен к регистру). Засчитываются отрезки, которые
// начинаются в своей части; отрезок, обрезанный окном части, дочитывается
// из исходного текста (до maxEncoded байт).
func (st *state) segments(ctx context.Context, v *view) error {
	s := v.clean
	for i, n := 0, 0; i < len(s); n++ {
		if n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if !segmentStart(s, i) {
			i++
			continue
		}
		end, method, dec := decodeAt(s, i)
		if end == i {
			i++
			continue
		}
		if v.own(i) {
			so, eo := v.orig(i), v.orig(end)
			if end == len(s) && eo < len(st.text) {
				// Дочитывание — по исходному тексту без Clean (кодировки —
				// ASCII; карта позиций на мегабайт не нужна). Скрытые символы
				// внутри отрезка обрывают его — тогда остаётся разобранное в
				// окне.
				if e2, m2, d2 := decodeAt(st.text[so:min(so+maxEncoded, len(st.text))], 0); so+e2 > eo {
					eo, method, dec = so+e2, m2, d2
				}
			}
			if err := st.decoded(ctx, method, dec, so, eo); err != nil {
				return err
			}
		}
		i = end
	}
	return nil
}

// segmentStart — с позиции i может начинаться закодированный отрезок:
// начало слова, «\», «%», «&».
func segmentStart(s string, i int) bool {
	c := s[i]
	if c == '\\' || c == '%' || c == '&' {
		return true
	}
	if !isB64Byte(c) {
		return false
	}
	return i == 0 || !isB64Byte(s[i-1])
}

// decodeAt декодирует отрезок с позиции i: конец отрезка (i — не отрезок),
// способ и текст (nil — отрезок не похож на текст: двоичные данные, хеш,
// длинное слово).
func decodeAt(s string, i int) (end int, method string, dec []byte) {
	if e, m, d := escapes(s, i); e > i {
		return e, m, d
	}
	j := i
	for j < len(s) && j-i < maxEncoded && isB64Byte(s[j]) {
		j++
	}
	// MIME: строки base64 по 60–76 символов через перевод строки.
	for j-i >= 60 && j+1 < len(s) && j-i < maxEncoded && (s[j] == '\n' || s[j] == '\r') {
		k := j + 1
		if s[j] == '\r' && s[k] == '\n' {
			k++
		}
		e := k
		for e < len(s) && e-i < maxEncoded && isB64Byte(s[e]) {
			e++
		}
		if e == k {
			break
		}
		j = e
	}
	for j < len(s) && s[j] == '=' && j-i < maxEncoded {
		j++
	}
	run := s[i:j]
	if len(run) < minB64 {
		return i, "", nil
	}
	if isHexRun(run) {
		if d, err := hex.DecodeString(run[:len(run)&^1]); err == nil && textLike(d) {
			return j, "hex", d
		}
		return j, "", nil
	}
	if d := decodeB64(run); d != nil {
		return j, "base64", d
	}
	return j, "", nil
}

func isB64Byte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_'
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isHexRun(run string) bool {
	if len(run) < minHex {
		return false
	}
	for i := 0; i < len(run); i++ {
		if !isHexByte(run[i]) {
			return false
		}
	}
	return true
}

// decodeB64 декодирует base64 (обычный и URL-safe, с выравниванием и без,
// с переводами строк). Сначала проверяется начало — двоичные данные
// отбрасываются быстро.
func decodeB64(run string) []byte {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '=':
			return -1
		case '-':
			return '+'
		case '_':
			return '/'
		}
		return r
	}, run)
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	head := clean[:min(len(clean), 64)&^3]
	if hd, err := base64.RawStdEncoding.DecodeString(head); err != nil || !textLike(trimPartialRune(hd)) {
		return nil
	}
	d, err := base64.RawStdEncoding.DecodeString(clean)
	if err != nil || !textLike(d) {
		return nil
	}
	return d
}

// escapes — отрезок в %-кодировке (ссылки: «ignore%20all%20previous») или
// подряд идущие экранированные символы: \xHH, \uHHHH, &#NNN;, &#xHH;, 0xHH,
// пары шестнадцатеричных цифр через пробел. Между экранированными — до двух
// пробелов или запятых. Нужно от двух %HH или от minEscapes прочих.
func escapes(s string, i int) (end int, method string, dec []byte) {
	if e, d, ok := urlRun(s, i); ok {
		if d == nil {
			return e, "", nil
		}
		return e, "urlencode", d
	}
	var out []byte
	tokens := 0
	j := i
	for j < len(s) && j-i < maxEncoded {
		r, c, size, isByte := escapeAt(s, j)
		if size == 0 {
			break
		}
		if isByte {
			out = append(out, c)
		} else {
			out = utf8.AppendRune(out, r)
		}
		tokens++
		j += size
		// Разделитель — только если за ним следующий экранированный символ.
		k := j
		for k < len(s) && k-j < 2 && (s[k] == ' ' || s[k] == ',') {
			k++
		}
		if k > j {
			if _, _, next, _ := escapeAt(s, k); next == 0 {
				break
			}
			j = k
		}
	}
	if tokens < minEscapes {
		return i, "", nil
	}
	if !textLike(out) {
		return j, "", nil
	}
	return j, "escape", out
}

// urlRun — отрезок с %HH и обычными символами ссылки с позиции i; ok —
// %HH от двух. dec — nil, если декодированное не похоже на текст. Первое
// %HH — в первых 64 байтах отрезка: иначе каждое начало слова в длинной
// строке без % просматривало бы её до конца (квадратичное время).
func urlRun(s string, i int) (end int, dec []byte, ok bool) {
	tokens := 0
	j := i
	for j < len(s) && j-i < maxEncoded {
		if tokens == 0 && j-i >= 64 {
			return i, nil, false
		}
		c := s[j]
		if c == '%' && j+2 < len(s) && isHexByte(s[j+1]) && isHexByte(s[j+2]) {
			tokens++
			j += 3
			continue
		}
		if !isB64Byte(c) && c != '.' && c != '~' {
			break
		}
		j++
	}
	if tokens < 2 {
		return i, nil, false
	}
	out := make([]byte, 0, j-i)
	for k := i; k < j; {
		switch c := s[k]; c {
		case '%':
			v, _ := hexPair(s[k+1 : k+3]) // проверено при разборе
			out = append(out, v)
			k += 3
		case '+':
			out = append(out, ' ')
			k++
		default:
			out = append(out, c)
			k++
		}
	}
	if !textLike(out) {
		return j, nil, true
	}
	return j, out, true
}

// escapeAt — экранированный символ в позиции j: символ (\uHHHH, &#…;) или
// байт UTF-8 (\xHH, 0xHH, пара цифр через пробел), длина записи (0 — не
// экранированный).
func escapeAt(s string, j int) (r rune, c byte, size int, isByte bool) {
	rest := s[j:min(j+12, len(s))]
	// Отдельное значение: дальше не буква и не цифра.
	alone := func(n int) bool { return n >= len(rest) || !isLetterOrDigit(rune(rest[n])) }
	switch {
	case strings.HasPrefix(rest, `\x`) && len(rest) >= 4:
		if c, ok := hexPair(rest[2:4]); ok {
			return 0, c, 4, true
		}
	case strings.HasPrefix(rest, `\u`) && len(rest) >= 6:
		if r, ok := hexRune(rest[2:6]); ok {
			return r, 0, 6, false
		}
	case (strings.HasPrefix(rest, "0x") || strings.HasPrefix(rest, "0X")) && len(rest) >= 4 && alone(4):
		if c, ok := hexPair(rest[2:4]); ok {
			return 0, c, 4, true
		}
	case strings.HasPrefix(rest, "&#x") || strings.HasPrefix(rest, "&#X"):
		if k := strings.IndexByte(rest, ';'); k > 3 {
			if r, ok := hexRune(rest[3:k]); ok {
				return r, 0, k + 1, false
			}
		}
	case strings.HasPrefix(rest, "&#"):
		if k := strings.IndexByte(rest, ';'); k > 2 {
			var r rune
			for _, d := range rest[2:k] {
				if d < '0' || d > '9' {
					return 0, 0, 0, false
				}
				r = r*10 + d - '0'
			}
			if r <= unicode.MaxRune {
				return r, 0, k + 1, false
			}
		}
	case len(rest) >= 2 && alone(2) && (j == 0 || !isLetterOrDigit(rune(s[j-1]))):
		if c, ok := hexPair(rest[:2]); ok {
			return 0, c, 2, true
		}
	}
	return 0, 0, 0, false
}

// nibble — значение шестнадцатеричной цифры.
func nibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// hexPair — байт из двух шестнадцатеричных цифр.
func hexPair(h string) (byte, bool) {
	if len(h) != 2 {
		return 0, false
	}
	hi, ok1 := nibble(h[0])
	lo, ok2 := nibble(h[1])
	return hi<<4 | lo, ok1 && ok2
}

// hexRune — символ из шестнадцатеричной записи (до шести цифр).
func hexRune(h string) (rune, bool) {
	if h == "" || len(h) > 6 {
		return 0, false
	}
	var r rune
	for k := 0; k < len(h); k++ {
		n, ok := nibble(h[k])
		if !ok {
			return 0, false
		}
		r = r<<4 | rune(n)
	}
	return r, r <= unicode.MaxRune
}

// textLike — декодированные байты похожи на текст: верный UTF-8, не больше
// 5% непечатных символов, не меньше 40% букв.
func textLike(b []byte) bool {
	if len(b) < minDecoded || !utf8.Valid(b) {
		return false
	}
	n, letters, bad := 0, 0, 0
	for _, r := range string(b) {
		n++
		switch {
		case unicode.IsLetter(r):
			letters++
		case r == '\n' || r == '\t' || r == '\r':
		case !unicode.IsPrint(r) && !unicode.IsSpace(r):
			bad++
		}
	}
	return bad*20 <= n && letters*5 >= n*2
}

// trimPartialRune отрезает неполный символ UTF-8 в конце (начало base64,
// обрезанное по границе блока).
func trimPartialRune(b []byte) []byte {
	for k := 1; k <= 3 && k <= len(b); k++ {
		if utf8.RuneStart(b[len(b)-k]) {
			if !utf8.FullRune(b[len(b)-k:]) {
				return b[:len(b)-k]
			}
			break
		}
	}
	return b
}

// decoded проверяет декодированный текст как отдельный текст и переносит
// его сигналы в категорию обфускации на позиции [s, e) закодированного
// отрезка.
func (st *state) decoded(ctx context.Context, method string, dec []byte, s, e int) error {
	if st.depth >= maxDepth || method == "" || dec == nil || s >= e {
		return nil
	}
	sub := newState(string(dec), st.indirect)
	sub.depth = st.depth + 1
	if err := sub.run(ctx); err != nil {
		return err
	}
	sub.manyShot()
	for _, k := range sub.keys() {
		sg := sub.best[k]
		st.keep(signal{cat: CatObfuscation, rule: method + "." + sg.rule, w: sub.weight(sg), s: s, e: e})
	}
	return nil
}
