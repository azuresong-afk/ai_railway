package auth

import (
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxEmailLen — предел длины e-mail учётной записи (RFC 5321).
const MaxEmailLen = 254

// emailRule — правило поля e-mail (текст для пользователя).
const emailRule = "E-mail: до 254 символов, вида user@example.ru, без пробелов и управляющих символов; пустое значение убирает адрес."

// NormalizeEmail проверяет e-mail учётной записи и возвращает его без
// пробелов по краям. Пустое значение допустимо — адрес убирается. Проверка
// простая, без письма-подтверждения: адрес без отображаемого имени, одна «@»,
// без пробелов и управляющих символов (защита от подмены заголовков письма).
func NormalizeEmail(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", true
	}
	if len(s) > MaxEmailLen || !utf8.ValidString(s) || strings.Count(s, "@") != 1 {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", false
		}
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s {
		return "", false
	}
	return s, true
}
