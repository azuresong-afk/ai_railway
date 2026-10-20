package pseudonym

import (
	"encoding/json"
	"strings"
)

// restorer — обратная подстановка в одном тексте ответа. pend — хвост
// предыдущей части, в котором может начинаться псевдоним (потоковая
// передача); url — контекст адреса на позиции начала pend.
type restorer struct {
	v    *Vault
	pend string
	url  urlState
}

// run обрабатывает pend и chunk и возвращает текст, готовый к выдаче.
// При final = false возможный незавершённый псевдоним в конце остаётся в
// pend (не длиннее MaxTokenLen); при final = true pend пуст.
func (r *restorer) run(chunk string, final bool) string {
	s := r.pend + chunk
	r.pend = ""
	r.v.mu.Lock()
	defer r.v.mu.Unlock()
	var b strings.Builder
	last := 0
	esc := !r.url.json
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '[' || esc && c == '\\' {
			t, res := parseToken(s, i, final, esc)
			switch res {
			case scanMore:
				r.pend = s[i:]
				b.WriteString(s[last:i])
				return b.String()
			case scanMatch:
				if value, ok := r.v.lookup(t, r.url.unsafe()); ok {
					b.WriteString(s[last:i])
					b.WriteString(r.escape(value))
					last = t.end
				}
				// Символы псевдонима не меняют контекст адреса, восстановлен
				// он или нет: так исход не зависит от разбиения на части.
				i = t.end - 1
				continue
			}
		}
		r.url.observe(c)
	}
	b.WriteString(s[last:])
	return b.String()
}

// escape — значение для вставки: в JSON — содержимое строки JSON.
func (r *restorer) escape(value string) string {
	if !r.url.json {
		return value
	}
	q, _ := json.Marshal(value) // строка всегда кодируется; неверный UTF-8 заменяется на U+FFFD
	return string(q[1 : len(q)-1])
}

// urlState — находится ли текущая позиция внутри адреса. Адрес начинается
// с «//» (в том числе «://» и «\/\/» в JSON) и длится до пробельного
// символа ASCII. Внутри «<…>» пробел адрес не завершает: так устроены
// адреса в угловых скобках markdown и атрибуты тегов HTML, а браузер
// выбрасывает из адреса переводы строк. В JSON адрес завершает только конец
// строки JSON: инструмент может взять адрес с пробелом целиком. Правило с запасом: псевдоним после адреса в той же «словоформе» тоже
// не восстанавливается — значение останется замаскированным, но не уйдёт на
// чужой сервер (DM-11). В JSON значение вставляется только внутрь строки:
// вне строки оно стало бы частью структуры аргументов.
type urlState struct {
	json     bool
	inString bool // JSON: позиция внутри строки
	inURL    bool
	angle    bool
	slashes  int
	escaped  bool // JSON: предыдущий символ — неэкранированная «\»
}

// unsafe — восстанавливать значение в этой позиции нельзя.
func (u *urlState) unsafe() bool { return u.inURL || u.json && !u.inString }

func (u *urlState) observe(c byte) {
	esc := u.escaped
	u.escaped = u.json && c == '\\' && !esc
	switch c {
	case '/':
		u.slashes++
		if u.slashes >= 2 {
			u.inURL = true
		}
		return
	case '\\':
		return // «\/» — экранированная «/»: подряд идущие косые не прерываются
	}
	u.slashes = 0
	switch {
	case c == '<':
		u.angle = true
	case c == '>':
		u.angle = false
	case u.json && c == '"' && !esc:
		u.inString = !u.inString
		u.inURL, u.angle = false, false
	case isSpace(c) && !u.angle && !u.inString:
		u.inURL = false
	}
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}
