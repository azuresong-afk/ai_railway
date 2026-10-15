package secretscan

// Помощники детектора: приведение к нижнему регистру без изменения позиций,
// границы значений, заглушки, энтропия.

import (
	"context"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

// fold — текст в нижнем регистре с теми же байтовыми позициями: меняются
// только латиница A–Z и кириллица А–Я, Ё (строчные той же длины в UTF-8).
// Позиции ключевых слов в результате совпадают с позициями в исходном
// тексте. ctx проверяется каждые 64 КиБ.
func fold(ctx context.Context, text string) (string, error) {
	b := []byte(text)
	for i := 0; i < len(b); i++ {
		if i%(64<<10) == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		c := b[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + 32
		case c == 0xD0 && i+1 < len(b):
			switch n := b[i+1]; {
			case n >= 0x90 && n <= 0x9F: // А–П → а–п
				b[i+1] = n + 0x20
			case n >= 0xA0 && n <= 0xAF: // Р–Я → р–я (D1 80–8F)
				b[i], b[i+1] = 0xD1, n-0x20
			case n == 0x81: // Ё → ё (D1 91)
				b[i], b[i+1] = 0xD1, 0x91
			}
			i++
		}
	}
	return string(b), nil
}

// isTokenByte — символ токена: латиница, цифры, «_» и «-».
func isTokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// wordBefore — перед позицией i буква или цифра: ключевое слово стоит не с
// начала слова («mypassword»). «_», «-», «.» допустимы: «DB_PASSWORD».
func wordBefore(text string, i int) bool {
	if i == 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(text[:i])
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// placeholderParts — признаки значений из документации и шаблонов.
var placeholderParts = []string{
	"example", "sample", "dummy", "placeholder", "redacted", "changeme", "change_me",
	"your_", "your-", "yourpass", "xxxx", "****", "....", "<", ">", "${", "{{", "%s",
	"пример", "ваш_", "ваш-",
}

// placeholderWords — значение целиком — название поля или служебное слово.
var placeholderWords = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pwd": true, "secret": true, "token": true,
	"null": true, "none": true, "nil": true, "true": true, "false": true, "undefined": true,
	"пароль": true, "секрет": true, "токен": true, "ключ": true,
}

// isPlaceholder — значение похоже на заглушку: «<token>», «${DB_PASSWORD}»,
// «YOUR_API_KEY», «AKIA…EXAMPLE», «********», или в нём мало разных символов.
func isPlaceholder(v string) bool {
	l := strings.ToLower(v)
	if placeholderWords[l] {
		return true
	}
	for _, p := range placeholderParts {
		if strings.Contains(l, p) {
			return true
		}
	}
	return len(v) >= 12 && distinct(v) < 6
}

func distinct(v string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(v); i++ {
		if !seen[v[i]] {
			seen[v[i]] = true
			n++
		}
	}
	return n
}

// entropy — энтропия Шеннона по байтам, бит на символ.
func entropy(v string) float64 {
	var cnt [256]int
	for i := 0; i < len(v); i++ {
		cnt[v[i]]++
	}
	e := 0.0
	for _, c := range cnt {
		if c > 0 {
			p := float64(c) / float64(len(v))
			e -= p * math.Log2(p)
		}
	}
	return e
}

// charClasses — сколько классов символов в значении: строчные, прописные,
// цифры, прочие.
func charClasses(v string) int {
	var lower, upper, digit, other bool
	for _, r := range v {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

// isHex — только шестнадцатеричные цифры (хеш, идентификатор коммита).
func isHex(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// indexAll вызывает f для каждого вхождения sub в text слева направо;
// ctx проверяется каждые 256 вхождений.
func indexAll(ctx context.Context, text, sub string, f func(i int)) error {
	for pos, n := 0, 0; ; n++ {
		if n%256 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		i := strings.Index(text[pos:], sub)
		if i < 0 {
			return nil
		}
		f(pos + i)
		pos += i + len(sub)
	}
}
