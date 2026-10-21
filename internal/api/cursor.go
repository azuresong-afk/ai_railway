package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// Параметры страницы.
const (
	DefaultPageLimit = 50
	MaxPageLimit     = 200
	// MaxCursorLen — предел длины курсора до разбора.
	MaxCursorLen = 256
	maxCursorID  = 64
)

// Cursor — позиция в упорядоченной выборке: пара (метка времени, идентификатор).
// Курсор непрозрачен для клиента, но не секретен и не подписан: он только
// указывает место в выборке, а права на данные проверяются при каждом запросе.
type Cursor struct {
	// TimeMicro — метка времени строки, микросекунды Unix.
	TimeMicro int64
	// ID — идентификатор строки (UUID или иной ключ), символы [A-Za-z0-9_-].
	ID string
}

var errBadCursor = errors.New("неверный курсор")

// Encode возвращает строку курсора для next_cursor.
func (c Cursor) Encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(c.TimeMicro, 10) + ":" + c.ID))
}

// DecodeCursor разбирает курсор строго: длина, алфавит, форма и значения
// проверяются до использования; ошибка не раскрывает, что именно неверно.
func DecodeCursor(s string) (Cursor, error) {
	if s == "" || len(s) > MaxCursorLen {
		return Cursor{}, errBadCursor
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return Cursor{}, errBadCursor
	}
	// Декодер пропускает переводы строк: неканоническую запись отвергаем.
	if base64.RawURLEncoding.EncodeToString(raw) != s {
		return Cursor{}, errBadCursor
	}
	ts, id, ok := strings.Cut(string(raw), ":")
	if !ok || !validCursorID(id) || !validDecimal(ts) {
		return Cursor{}, errBadCursor
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || n < 0 {
		return Cursor{}, errBadCursor
	}
	return Cursor{TimeMicro: n, ID: id}, nil
}

// validDecimal — только цифры без знака и ведущих нулей (каноническая форма,
// чтобы один и тот же курсор не имел нескольких записей).
func validDecimal(s string) bool {
	if s == "" || len(s) > 19 || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validCursorID(s string) bool {
	if s == "" || len(s) > maxCursorID {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// Page — разобранные параметры страницы.
type Page struct {
	Limit  int
	Cursor *Cursor // nil — первая страница
}

// ParsePage разбирает `limit` и `cursor` из строки запроса. Ошибки — Problem
// с перечнем полей.
func ParsePage(r *http.Request) (Page, *Problem) {
	q := r.URL.Query()
	page := Page{Limit: DefaultPageLimit}
	var bad []FieldError
	if vs, ok := q["limit"]; ok {
		n, err := strconv.Atoi(first(vs))
		if len(vs) != 1 || err != nil || n < 1 || n > MaxPageLimit {
			bad = append(bad, FieldError{"limit", "Укажите целое число от 1 до " + strconv.Itoa(MaxPageLimit) + "."})
		} else {
			page.Limit = n
		}
	}
	if vs, ok := q["cursor"]; ok {
		c, err := DecodeCursor(first(vs))
		if len(vs) != 1 || err != nil {
			bad = append(bad, FieldError{"cursor", "Курсор неверен или устарел: начните выборку сначала."})
		} else {
			page.Cursor = &c
		}
	}
	if len(bad) > 0 {
		return Page{}, Invalid("Параметры страницы заданы неверно.", bad...)
	}
	return page, nil
}

func first(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// PageResponse — конверт страницы списка. NextCursor пуст на последней странице.
type PageResponse[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}
