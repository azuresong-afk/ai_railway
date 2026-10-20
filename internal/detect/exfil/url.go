package exfil

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"net/url"
	"strings"
)

// Пределы разбора ссылки.
const (
	maxURL    = 64 << 10 // длиннее — обрезается, считается ссылкой с данными
	maxParams = 64       // параметров запроса больше — ссылка с данными
)

// urlInfo — разобранная ссылка. Разбор следует браузерам (WHATWG URL) там,
// где от этого зависит адресат: обратная косая черта как прямая, табуляция
// и перевод строки удаляются, схема без косых черт (https:host).
type urlInfo struct {
	scheme   string // в нижнем регистре; пусто — относительная или без схемы
	host     string // в нижнем регистре, без порта и userinfo
	rawHost  string // host в исходном регистре: base64 в метках поддомена
	userinfo bool   // перед хостом есть user[:password]@
	path     string
	query    string
	external bool // уходит на хост: http, https, ftp, ws, wss или //host
	long     bool // ссылка обрезана по maxURL
}

// origin — откуда адрес: от этого зависит, как его расшифрует получатель.
type origin int

const (
	fromText origin = iota // текст и JSON: «\/» и «\uXXXX» из JSON расшифровываются
	fromHTML               // атрибут HTML: ссылки на символы
	fromMD                 // адрес markdown: экранирование «\» и ссылки на символы
)

// cleanURL готовит значение ссылки к разбору так, как его увидит браузер:
// снимает экранирование источника (markdown, JSON), расшифровывает ссылки на
// символы HTML (&#106;, &colon; — так прячут javascript:), удаляет
// табуляцию и переводы строк, обрезает управляющие символы и пробелы по
// краям.
func cleanURL(raw string, o origin) (string, bool) {
	long := false
	if len(raw) > maxURL {
		raw, long = raw[:maxURL], true
	}
	if strings.IndexByte(raw, '\\') >= 0 {
		switch o {
		case fromMD:
			raw = unescapeMD(raw)
		case fromText:
			raw = unescapeJSON(raw)
		}
	}
	if o != fromText && strings.IndexByte(raw, '&') >= 0 {
		raw = decodeEntities(raw)
	}
	if strings.ContainsAny(raw, "\t\n\r") {
		raw = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(raw)
	}
	return strings.TrimFunc(raw, func(r rune) bool { return r <= ' ' }), long
}

// unescapeMD снимает экранирование markdown: «\» перед знаком ASCII.
func unescapeMD(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] > ' ' && s[i+1] < 0x7F && !alnum(s[i+1]) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unescapeJSON расшифровывает «\/» и «\uXXXX» (ASCII) из строк JSON
// (аргументы tool_calls); остальное оставляет как есть.
func unescapeJSON(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == '/' {
				b.WriteByte('/')
				i++
				continue
			}
			if (s[i+1] == 'u' || s[i+1] == 'U') && i+6 <= len(s) {
				v := 0
				ok := true
				for _, c := range []byte(s[i+2 : i+6]) {
					d := digitVal(c, 16)
					if d < 0 {
						ok = false
						break
					}
					v = v*16 + d
				}
				if ok && v > 0 && v < 0x80 {
					b.WriteByte(byte(v))
					i += 5
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseURL разбирает ссылку. Ошибок нет: непонятное — относительная ссылка
// или схема без адресата.
func parseURL(raw string) urlInfo {
	var u urlInfo
	rest := raw
	if i := schemeEnd(raw); i > 0 {
		u.scheme = strings.ToLower(raw[:i])
		rest = raw[i+1:]
	}
	switch u.scheme {
	case "http", "https", "ftp", "ws", "wss":
		// Особые схемы: любое число косых черт обоих видов перед хостом.
		rest = strings.TrimLeft(rest, `/\`)
	case "":
		if len(rest) < 2 || !slash(rest[0]) || !slash(rest[1]) {
			return u // относительная ссылка — тот же источник
		}
		rest = strings.TrimLeft(rest, `/\`)
	default:
		return u
	}
	u.external = true
	end := strings.IndexAny(rest, `/\?#`)
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	rest = rest[end:]
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		u.userinfo = at > 0
		authority = authority[at+1:]
	}
	host := authority
	if strings.HasPrefix(host, "[") {
		if j := strings.IndexByte(host, ']'); j >= 0 {
			host = host[:j+1]
		}
	} else if j := strings.IndexByte(host, ':'); j >= 0 {
		host = host[:j]
	}
	if strings.IndexByte(host, '%') >= 0 {
		if h, err := url.PathUnescape(host); err == nil {
			host = h
		}
	}
	u.rawHost = strings.TrimSuffix(host, ".")
	u.host = strings.ToLower(u.rawHost)
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		rest = rest[:j] // фрагмент на сервер не уходит
	}
	if j := strings.IndexByte(rest, '?'); j >= 0 {
		u.path, u.query = rest[:j], rest[j+1:]
	} else {
		u.path = rest
	}
	return u
}

func slash(c byte) bool { return c == '/' || c == '\\' }

// schemeEnd — позиция «:» после схемы ([A-Za-z][A-Za-z0-9+.-]*, до 32
// символов); 0 — схемы нет.
func schemeEnd(s string) int {
	for i := 0; i < len(s) && i <= 32; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-'):
		case i > 0 && c == ':':
			return i
		default:
			return 0
		}
	}
	return 0
}

// hasData — в ссылке, похоже, передаются данные: userinfo, закодированные
// значения в поддомене, пути или параметрах (и в склейке соседних частей —
// данные, разложенные по частям), длинный текст в параметрах.
// image — изображение (загружается без участия пользователя): пороги ниже.
func hasData(u urlInfo, image bool) bool {
	if u.userinfo || u.long {
		return true
	}
	// Поддомены (DNS-эксфильтрация: <данные>.attacker.example), кроме двух
	// последних меток. base64 — в исходном регистре: получатель его не
	// расшифрует (браузер приводит хост к нижнему), но намерение видно.
	if len(u.host) > 100 {
		return true
	}
	if strings.Count(u.host, ".") >= 2 {
		labels := strings.Split(u.host, ".")
		raw := strings.Split(u.rawHost, ".")
		if len(raw) != len(labels) {
			raw = labels
		}
		raw = raw[:len(raw)-2]
		for k, l := range labels[:len(labels)-2] {
			if encodedLike(l, 20, true) || hexText(l) || base64Text(raw[k]) {
				return true
			}
		}
		if splitData(raw, 20, true) {
			return true
		}
	}
	minQuery, minValue, minText, minPath, minSegText := 256, 24, 80, 64, 120
	if image {
		minQuery, minValue, minText, minPath, minSegText = 64, 12, 16, 24, 64
	}
	if len(u.query) >= minQuery {
		return true
	}
	if u.query != "" {
		params := strings.FieldsFunc(u.query, func(r rune) bool { return r == '&' || r == ';' })
		if len(params) > maxParams {
			return true
		}
		var vals []string
		for _, p := range params {
			if j := strings.IndexByte(p, '='); j >= 0 {
				p = p[j+1:]
			}
			v, err := url.QueryUnescape(p)
			if err != nil {
				v = p
			}
			v = strings.Trim(v, `'"`)
			if len(v) >= minText || encodedLike(v, minValue, image) || base64Text(v) || hexText(v) {
				return true
			}
			vals = append(vals, v)
		}
		if splitData(vals, minValue, image) {
			return true
		}
	}
	var segs []string
	for _, seg := range strings.FieldsFunc(u.path, func(r rune) bool { return r == '/' || r == '\\' }) {
		v, err := url.PathUnescape(seg)
		if err != nil {
			v = seg
		}
		if k := strings.LastIndexByte(v, '.'); k > 0 && len(v)-k <= 5 {
			v = v[:k] // расширение файла
		}
		if len(v) >= minSegText || encodedLike(v, minPath, image) || base64Text(v) || hexText(v) {
			return true
		}
		segs = append(segs, v)
	}
	return splitData(segs, minPath, image)
}

// splitData — данные, разложенные по частям (метки поддомена, значения
// параметров, сегменты пути: /aXZhbi5w/ZXRyb3ZA/…): склейка частей
// проверяется как одно значение — base64 или hex, которые расшифровываются
// в текст, или закодированные данные (encodedLike с проверкой noisy) от
// удвоенного порога одной части, но не короче 32 символов: два случайных
// идентификатора в одной ссылке (видео и метка отправки) не должны давать
// находку. Первые одна-две части и последняя могут быть не данными
// (/collect/<данные>/pixel.png) — проверяются и склейки без них; в склейке
// не меньше двух частей (одна часть проверена отдельно).
func splitData(parts []string, minEnc int, hexOK bool) bool {
	minEnc = max(2*minEnc, 32)
	for drop := 0; drop <= 2 && drop+1 < len(parts); drop++ {
		for tail := 0; tail <= 1 && drop+tail+1 < len(parts); tail++ {
			j := strings.Join(parts[drop:len(parts)-tail], "")
			if base64Text(j) || hexText(j) || encodedLike(j, minEnc, hexOK) && noisy(j) {
				return true
			}
		}
	}
	return false
}

// noisy — строка похожа на случайную, а не на склейку слов: есть заглавные
// и строчные буквы и цифры, и класс знака меняется не реже чем у 45 %
// соседних пар (у base64 — около 65 %, у слов в CamelCase, номеров версий
// и меток домена — заметно реже). Без этой проверки склейка обычных
// сегментов пути или меток домена («apiv2eu-west-1service») проходит
// encodedLike.
func noisy(s string) bool {
	class := func(c byte) int {
		switch {
		case c >= 'A' && c <= 'Z':
			return 0
		case c >= 'a' && c <= 'z':
			return 1
		case c >= '0' && c <= '9':
			return 2
		}
		return 3
	}
	var seen [4]bool
	changes := 0
	for i := 0; i < len(s); i++ {
		seen[class(s[i])] = true
		if i > 0 && class(s[i]) != class(s[i-1]) {
			changes++
		}
	}
	return seen[0] && seen[1] && seen[2] && len(s) > 1 && changes*100 >= (len(s)-1)*45
}

// encodedLike — строка похожа на закодированные данные (base64, base32,
// hex и т. п.), а не на слово, слаг или число: от min символов из набора
// base64, буквы и цифры вперемешку, мало разделителей, энтропия от 3,5 бита
// на символ. Шестнадцатеричная строка считается только при hexOK: в
// обычных ссылках это хеши коммитов и идентификаторы.
func encodedLike(s string, min int, hexOK bool) bool {
	if len(s) < min {
		return false
	}
	var counts [256]int
	upper, lower, digit, seps := false, false, false, 0
	hex := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		counts[c]++
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
			hex = hex && c <= 'F'
		case c >= 'a' && c <= 'z':
			lower = true
			hex = hex && c <= 'f'
		case c >= '0' && c <= '9':
			digit = true
		case c == '-' || c == '_':
			seps++
			hex = false
		case c == '+' || c == '/' || c == '=' || c == '.':
			hex = false
		default:
			return false
		}
	}
	if hex && digit {
		return hexOK
	}
	classes := 0
	for _, b := range []bool{upper, lower, digit} {
		if b {
			classes++
		}
	}
	if classes < 2 || seps*10 > len(s) {
		return false
	}
	return entropy(counts[:], len(s)) >= 3.5
}

// base64Text — строка от 16 символов в base64 или base64url (с дополнением
// или без) и расшифровывается в текст: так данные отличаются от случайных
// идентификаторов в ссылках (документы, файлы), которые дают двоичные байты.
func base64Text(s string) bool {
	if len(s) < 16 || len(s) > maxURL {
		return false
	}
	raw := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(raw)
		if err == nil && printableText(b) {
			return true
		}
	}
	return false
}

// hexText — строка чётной длины от 16 шестнадцатеричных цифр, которая
// расшифровывается в текст: хеши коммитов и идентификаторы дают двоичные
// байты. Строка из одних цифр (длинный номер в ссылке) считается, только
// если текст после расшифровки — буквы, цифры и пробелы: так номер
// телефона или ИНН в hex находится, а случайный номер — почти никогда.
func hexText(s string) bool {
	if len(s) < 16 || len(s)%2 != 0 || len(s) > maxURL {
		return false
	}
	b, err := hex.DecodeString(s)
	if err != nil || !printableText(b) {
		return false
	}
	if strings.Trim(s, "0123456789") != "" {
		return true
	}
	words := 0
	for _, c := range b {
		if alnum(c) || c == ' ' {
			words++
		}
	}
	return words*10 >= len(b)*9
}

// printableText — не меньше 90 % символов UTF-8 печатные (с переводом
// строки и табуляцией).
func printableText(b []byte) bool {
	printable, total := 0, 0
	for _, r := range string(b) {
		total++
		if r >= ' ' && r != 0x7F && r != 0xFFFD || r == '\n' || r == '\t' {
			printable++
		}
	}
	return printable*10 >= total*9
}

func entropy(counts []int, n int) float64 {
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / float64(n)
			h -= p * math.Log2(p)
		}
	}
	return h
}

// decodeEntities расшифровывает числовые ссылки на символы и несколько
// именованных, которыми прячут схему (&colon;, &Tab;, &NewLine; и т. п.).
// Остальное оставляет как есть.
func decodeEntities(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if r, n := entityAt(s[i:]); n > 0 {
			b.WriteRune(r)
			i += n
			continue
		}
		b.WriteByte('&')
		i++
	}
	return b.String()
}

var namedEntities = map[string]rune{
	"colon": ':', "tab": '\t', "newline": '\n', "sol": '/', "bsol": '\\',
	"quest": '?', "period": '.', "commat": '@', "num": '#', "amp": '&',
	"lpar": '(', "rpar": ')', "equals": '=', "percnt": '%',
}

// entityAt — ссылка на символ в начале s («&#106;», «&#x6A;», «&colon;»;
// точка с запятой необязательна, как у браузеров для числовых).
func entityAt(s string) (rune, int) {
	if len(s) < 3 {
		return 0, 0
	}
	if s[1] == '#' {
		i, base := 2, 10
		if i < len(s) && (s[i] == 'x' || s[i] == 'X') {
			i, base = 3, 16
		}
		start := i
		for i < len(s) && s[i] == '0' {
			i++ // ведущие нули
		}
		sig := i
		v := 0
		for i < len(s) && i-sig < 8 {
			d := digitVal(s[i], base)
			if d < 0 {
				break
			}
			v = v*base + d
			i++
		}
		if i == start {
			return 0, 0
		}
		for i < len(s) && digitVal(s[i], base) >= 0 {
			i, v = i+1, 0x110000 // лишние разряды — вне Unicode
		}
		if i < len(s) && s[i] == ';' {
			i++
		}
		if v == 0 || v > 0x10FFFF || v >= 0xD800 && v <= 0xDFFF {
			v = 0xFFFD
		}
		return rune(v), i
	}
	j := 1
	for j < len(s) && j <= 10 && (s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
		j++
	}
	if j < len(s) && s[j] == ';' {
		if r, ok := namedEntities[strings.ToLower(s[1:j])]; ok {
			return r, j + 1
		}
	}
	return 0, 0
}

func digitVal(c byte, base int) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case base == 16 && c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case base == 16 && c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
