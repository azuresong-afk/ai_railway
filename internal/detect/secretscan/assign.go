package secretscan

// Секреты по контексту: «password=…», «пароль: …», заголовки авторизации,
// высокоэнтропийные строки рядом со словами «token», «ключ».

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// assignKey — ключевое слово присваивания. ru — русское слово: между ним и
// значением допустимы слова («пароль от почты: …»). weak — допустимо
// значение и без «:» или «=» («пароль qwerty12», «password is …»), тогда
// требования к значению строже.
type assignKey struct {
	kw   string // в нижнем регистре
	cat  string
	ru   bool
	weak bool
}

var assignKeys = []assignKey{
	{"password", CatPassword, false, true},
	{"passwd", CatPassword, false, false},
	{"passphrase", CatPassword, false, false},
	{"pwd", CatPassword, false, false},
	{"пароль", CatPassword, true, true},
	{"secret", CatToken, false, false},
	{"token", CatToken, false, false},
	{"api_key", CatAPIKey, false, false},
	{"apikey", CatAPIKey, false, false},
	{"api-key", CatAPIKey, false, false},
	{"access_key", CatAPIKey, false, false},
	{"private_key", CatAPIKey, false, false},
	{"секрет", CatToken, true, false},
	{"токен", CatToken, true, false},
	{"ключ", CatAPIKey, true, false},
}

// identMarkers — имя поля описывает не сам секрет: «password_hash»,
// «token_type», «max_tokens», «PASSWORD_FILE».
var identMarkers = []string{
	"hash", "file", "path", "length", "policy", "type", "reset", "expir", "ttl", "name",
	"url", "uri", "endpoint", "header", "field", "count", "limit", "usage", "tokens",
	"size", "_id", "-id", "prompt", "max", "min_", "_min", "strength", "rule", "hint",
	"label", "placeholder", "required",
}

// dottedIdentRe — значение — обращение к полю или переменной окружения
// («process.env.DB_PASSWORD», «settings.secret»), а не секрет.
var dottedIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)

// assignments — значения после ключевых слов: «DB_PASSWORD=…»,
// «"password": "…"», «пароль от почты: …», «api_key: …». Находка — само
// значение.
func assignments(ctx context.Context, text, low string, c *collector) error {
	for _, k := range assignKeys {
		err := indexAll(ctx, low, k.kw, func(p int) {
			if s, e, score, ok := assignment(text, p, k); ok {
				c.add(k.cat, "assign", s, e, score)
			}
		})
		if err != nil {
			return err
		}
		c.commit()
	}
	return nil
}

// assignment разбирает присваивание с ключевым словом в позиции p.
func assignment(text string, p int, k assignKey) (s, e int, score float64, ok bool) {
	q := p + len(k.kw)
	if k.ru {
		if wordBefore(text, p) {
			return
		}
	} else {
		// Начало слова или граница в camelCase («dbPassword»), «_» и «-»
		// допустимы («DB_PASSWORD», «x-api-key»).
		if wordBefore(text, p) && !camelBoundary(text, p) {
			return
		}
		is := p
		for is > 0 && isTokenByte(text[is-1]) {
			is--
		}
		for q < len(text) && isTokenByte(text[q]) {
			q++
		}
		ident := strings.ToLower(text[is:q])
		for _, m := range identMarkers {
			if strings.Contains(ident, m) {
				return
			}
		}
	}
	if q < len(text) && strings.IndexByte("\"'`", text[q]) >= 0 {
		q++
	}
	sep, phrase := separator(text, &q, k.ru)
	weak := false
	switch {
	case sep:
	case phrase || !k.weak:
		return
	default:
		weak = true
	}
	s, e = value(text, q)
	if s < 0 {
		return
	}
	score, ok = valueScore(text[s:e], k.cat, weak)
	return s, e, score, ok
}

// separator пропускает разделитель между ключевым словом и значением:
// «:», «=», «:=», «=>», для русских слов — ещё тире. phrase — между словом и
// разделителем были слова («пароль от почты:»); без разделителя такая фраза
// не считается. Без «:» и «=» допустимы пробелы и «is», «это».
func separator(text string, q *int, ru bool) (sep, phrase bool) {
	i := *q
	if ru {
		// До 32 байт слов перед разделителем: «пароль от почты: …». Без
		// разделителя после слов фраза не считается — слова могут быть
		// началом значения («пароль Qr3…»).
		j := i
		for j < len(text) && j-i < 32 {
			r, size := utf8.DecodeRuneInString(text[j:])
			if r != ' ' && !isLetterRune(r) {
				break
			}
			j += size
		}
		if strings.TrimSpace(text[i:j]) != "" {
			if k := skipSpaces(text, j); k < len(text) && strings.IndexByte(":=", text[k]) >= 0 || strings.HasPrefix(text[k:], "—") || strings.HasPrefix(text[k:], "–") || strings.HasPrefix(text[k:], "- ") {
				phrase = true
				i = j
			}
		}
	}
	i = skipSpaces(text, i)
	switch {
	case strings.HasPrefix(text[i:], ":="), strings.HasPrefix(text[i:], "=>"):
		*q, sep = skipSpaces(text, i+2), true
	case strings.HasPrefix(text[i:], "=="):
		return false, true // сравнение в коде, а не значение
	case i < len(text) && (text[i] == ':' || text[i] == '='):
		*q, sep = skipSpaces(text, i+1), true
	case ru && (strings.HasPrefix(text[i:], "—") || strings.HasPrefix(text[i:], "–") || strings.HasPrefix(text[i:], "- ")):
		_, size := utf8.DecodeRuneInString(text[i:])
		*q, sep = skipSpaces(text, i+size), true
	default:
		if i == *q && !phrase {
			return false, true // ни разделителя, ни пробела: «passwords»
		}
		for _, w := range []string{"is ", "это "} {
			if strings.HasPrefix(strings.ToLower(text[i:min(i+len(w), len(text))]), w) {
				i = skipSpaces(text, i+len(w))
				break
			}
		}
		*q = i
	}
	return sep, phrase
}

// camelBoundary — в позиции p начинается слово camelCase: прописная после
// строчной или цифры («dbPassword»).
func camelBoundary(text string, p int) bool {
	if p == 0 || text[p] < 'A' || text[p] > 'Z' {
		return false
	}
	b := text[p-1]
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

func isLetterRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= 'а' && r <= 'я' || r >= 'А' && r <= 'Я' || r == 'ё' || r == 'Ё'
}

func skipSpaces(text string, i int) int {
	for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	return i
}

// value — значение в позиции i: в кавычках — до закрывающей кавычки в той
// же строке, без кавычек — до пробела или знака конца («,;)}]>»), не длиннее
// 256 байт. Точка в конце предложения не входит в значение.
func value(text string, i int) (s, e int) {
	if i >= len(text) {
		return -1, -1
	}
	if q := text[i]; q == '"' || q == '\'' || q == '`' {
		j := i + 1
		for j < len(text) && j-i <= 256 && text[j] != q && text[j] != '\n' {
			j++
		}
		if j < len(text) && text[j] == q {
			return i + 1, j
		}
		return -1, -1
	}
	j := i
	for j < len(text) && j-i <= 256 && strings.IndexByte(" \t\r\n,;)}]>\"'`", text[j]) < 0 {
		j++
	}
	if j > i && text[j-1] == '.' && (j == len(text) || text[j] != '.') {
		j--
	}
	return i, j
}

// valueScore — похоже ли значение на секрет. Пароль: не меньше двух классов
// символов (одно слово «required», «буквы» — не пароль); цифры подряд —
// только после «:» или «=» (PIN). Токен и ключ: от 12 символов, энтропия от
// 3 бит на символ. Заглушки — ниже порога, обращения к полям и пути — не
// секреты.
func valueScore(v, cat string, weak bool) (float64, bool) {
	if len(v) < 4 || len(v) > 256 {
		return 0, false
	}
	if isPlaceholder(v) {
		return placeholderScore, true
	}
	if strings.IndexByte("$%{([@&*#/\\.", v[0]) >= 0 || strings.ContainsAny(v, "()") ||
		dottedIdentRe.MatchString(v) || strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return 0, false
	}
	cls := charClasses(v)
	if cat == CatPassword {
		digits := strings.Trim(v, "0123456789") == ""
		switch {
		case digits && !weak:
			return 0.7, true
		case digits, cls < 2:
			return 0, false
		case weak && !strings.ContainsAny(v, "0123456789!@#$%^&*_-+=?"):
			return 0, false
		case weak:
			return 0.8, true
		}
		return 0.9, true
	}
	if len(v) < 12 || cls < 2 || entropy(v) < 3 {
		return 0, false
	}
	if len(v) >= 20 && entropy(v) >= 3.5 {
		return 0.9, true
	}
	return 0.85, true
}

// --- Заголовки авторизации ---

// authHeaders — «Bearer <токен>» и «Basic <base64 логин:пароль>».
func authHeaders(ctx context.Context, text, low string, c *collector) error {
	for _, scheme := range []string{"bearer", "basic"} {
		err := indexAll(ctx, low, scheme, func(p int) {
			q := p + len(scheme)
			if wordBefore(text, p) || q >= len(text) || text[q] != ' ' {
				return
			}
			s := skipSpaces(text, q)
			e := s
			for e < len(text) && e-s < 4096 && (isTokenByte(text[e]) || strings.IndexByte(".~+/=", text[e]) >= 0) {
				e++
			}
			v := text[s:e]
			switch {
			case scheme == "bearer" && len(v) >= 16:
				if isPlaceholder(v) {
					c.add(CatToken, "bearer.example", s, e, placeholderScore)
					return
				}
				c.add(CatToken, "bearer", s, e, 0.9)
			case scheme == "basic" && len(v) >= 8 && basicCredentials(v):
				c.add(CatToken, "basic", s, e, 0.9)
			}
		})
		if err != nil {
			return err
		}
		c.commit()
	}
	return nil
}

// basicCredentials — значение Basic декодируется в «логин:пароль».
func basicCredentials(v string) bool {
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(v); err != nil {
			return false
		}
	}
	s := string(raw)
	return utf8.ValidString(s) && strings.IndexByte(s, ':') > 0 && !strings.ContainsAny(s, "\x00\n\r")
}

// --- Энтропийный анализ ---

// entropyContext — слова, рядом с которыми случайная строка — вероятно
// секрет.
var entropyContext = []string{"token", "key", "secret", "bearer", "auth", "api", "credential", "password", "ключ", "токен", "секрет", "пароль"}

// highEntropy — строки из символов base64 длиной 32–512 с тремя классами
// символов (строчные, прописные, цифры) и энтропией от 4 бит на символ.
// Хеши (только шестнадцатеричные цифры), UUID (энтропия ниже порога), пути
// и данные data:…;base64 не считаются. С ключевым словом в 40 байтах
// перед строкой — 0,75, без него — 0,4 (ниже порога: случайные
// идентификаторы в ссылках и логах встречаются часто).
func highEntropy(ctx context.Context, text, low string, c *collector) error {
	for i, n := 0, 0; i < len(text); n++ {
		if n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if !isEntropyByte(text[i]) {
			i++
			continue
		}
		s := i
		for i < len(text) && isEntropyByte(text[i]) {
			i++
		}
		v := text[s:i]
		if len(v) < 32 || len(v) > 512 || v[0] == '/' || strings.Contains(v, "//") || isHex(v) ||
			charClasses(v) < 3 || entropy(v) < 4 || strings.HasSuffix(low[max(0, s-16):s], "base64,") ||
			sshPublicKey(low, s) {
			continue
		}
		switch {
		case s > 0 && text[s-1] == '/':
			c.add(CatToken, "entropy.url", s, i, placeholderScore)
		case hasContext(low, s):
			c.add(CatToken, "entropy.kw", s, i, 0.75)
		default:
			c.add(CatToken, "entropy", s, i, 0.4)
		}
	}
	return nil
}

// sshPublicKey — строка — тело открытого ключа SSH: «ssh-ed25519 AAAA…».
func sshPublicKey(low string, s int) bool {
	w := low[max(0, s-24):s]
	return strings.Contains(w, "ssh-") || strings.Contains(w, "ecdsa-sha2-") || strings.Contains(w, "sk-ssh-")
}

func isEntropyByte(b byte) bool { return isTokenByte(b) || b == '+' || b == '/' || b == '=' }

func hasContext(low string, s int) bool {
	w := low[max(0, s-40):s]
	for _, k := range entropyContext {
		if strings.Contains(w, k) {
			return true
		}
	}
	return false
}
