package pseudonym

import (
	"encoding/json"
	"strings"
)

// restorer — обратная подстановка в одном тексте ответа. pend — хвост
// предыдущей части, в котором может начинаться псевдоним (потоковая
// передача); ctx — контекст на позиции начала pend.
type restorer struct {
	v    *Vault
	pend string
	ctx  ctxState
}

// run обрабатывает pend и chunk и возвращает текст, готовый к выдаче.
// При final = false возможный незавершённый псевдоним в конце остаётся в
// pend (не длиннее MaxPending); при final = true pend пуст.
func (r *restorer) run(chunk string, final bool) string {
	s := r.pend + chunk
	r.pend = ""
	r.v.mu.Lock()
	defer r.v.mu.Unlock()
	issued := len(r.v.next) > 0
	var b strings.Builder
	last := 0
	esc := !r.ctx.json
	hold := func(i int) string {
		r.pend = s[i:]
		b.WriteString(s[last:i])
		return b.String()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '[' || esc && c == '\\' {
			t, res := parseToken(s, i, final, esc)
			if res == scanMore {
				return hold(i)
			}
			if res == scanMatch {
				if value, ok := r.v.lookup(t, r.ctx.unsafe()); ok {
					b.WriteString(s[last:i])
					b.WriteString(r.escape(value))
					last = t.end
				}
				// Символы псевдонима контекст не меняют, восстановлен он или
				// нет: так исход не зависит от разбиения на части.
				i = r.skip(t.end)
				continue
			}
			if c == '[' && issued {
				end, res := parseLoose(s, i, final)
				if res == scanMore {
					return hold(i)
				}
				if res == scanMatch {
					r.v.stats.Mangled++
					i = r.skip(end)
					continue
				}
			}
		}
		if issued && isUpper(c) && !isWord(r.ctx.prev) {
			end, res := parseBare(s, i, final, r.v.issuedType, r.v.typePrefix)
			if res == scanMore {
				return hold(i)
			}
			if res == scanMatch {
				r.v.stats.Mangled++
				i = r.skip(end)
				continue
			}
		}
		r.ctx.observe(c)
	}
	b.WriteString(s[last:])
	return b.String()
}

// skip — переход за разобранный псевдоним (end — его конец). Экранирование
// «\» перед псевдонимом на символ после него не переносится.
func (r *restorer) skip(end int) int {
	r.ctx.backslash = false
	return end - 1
}

// escape — значение для вставки: в JSON — содержимое строки JSON.
func (r *restorer) escape(value string) string {
	if !r.ctx.json {
		return value
	}
	q, _ := json.Marshal(value) // строка всегда кодируется; неверный UTF-8 заменяется на U+FFFD
	return string(q[1 : len(q)-1])
}

// maxJSONDepth — вложенность JSON, которую отслеживает контекст; глубже —
// подстановка до конца текста запрещена.
const maxJSONDepth = 64

// ctxState — можно ли вернуть значение в текущей позиции. Правило
// консервативное (ADR-0005): значение не возвращается туда, где оно может
// стать частью адреса — иначе внедрённая инструкция заставит модель вставить
// псевдоним в ссылку или картинку на чужом сервере, и приложение само
// отправит туда значение (DM-11), — и туда, где оно изменит структуру JSON.
//
// Текст (markdown, HTML):
//   - внутри «<…>» (тег HTML, автоссылка, адрес markdown в угловых скобках);
//     «>» в кавычках атрибута и экранированная «\>» тег не закрывают;
//   - если в текущем отрезке без пробельных символов ASCII перед
//     псевдонимом есть признак адреса: «/ \ % & = ? @», «](», «www.» или
//     «:» после латинской буквы (схема: http:, mailto:, javascript:).
//
// JSON (response_format JSON, аргументы tool_calls):
//   - вне строки, в ключе объекта, сразу после «\»;
//   - если в какой-либо строке до псевдонима был признак адреса: «/ % &»,
//     «\/», «\u», «\\», «www.» или «:» после латинской буквы. Признак
//     действует до конца текста: адрес мог быть в соседнем поле, а
//     псевдоним — в теле запроса инструмента.
type ctxState struct {
	json bool

	prev      byte // предыдущий символ
	backslash bool // предыдущий символ — неэкранированная «\»
	w         int  // подряд идущих «w»

	// Текст.
	angle bool // внутри «<…>»
	quote byte // открытая кавычка атрибута внутри «<…>»
	run   bool // в отрезке без пробелов есть признак адреса

	// JSON.
	inString  bool
	isKey     bool // текущая строка — ключ объекта
	expectKey bool // следующая строка — ключ
	urlSeen   bool // в тексте уже был признак адреса
	broken    bool // вложенность глубже maxJSONDepth
	stack     []byte
}

// unsafe — восстанавливать значение в этой позиции нельзя.
func (u *ctxState) unsafe() bool {
	if u.json {
		return !u.inString || u.isKey || u.backslash || u.urlSeen || u.broken
	}
	return u.angle || u.run
}

func (u *ctxState) observe(c byte) {
	bs := u.backslash
	u.backslash = c == '\\' && !bs
	if u.json {
		u.observeJSON(c, bs)
	} else {
		u.observeText(c, bs)
	}
	if c == '.' && u.w >= 3 {
		u.mark()
	}
	if c == 'w' || c == 'W' {
		u.w++
	} else {
		u.w = 0
	}
	u.prev = c
}

// mark — встретился признак адреса.
func (u *ctxState) mark() {
	if !u.json {
		u.run = true
	} else if u.inString {
		u.urlSeen = true
	}
}

func (u *ctxState) observeText(c byte, bs bool) {
	if u.angle {
		switch {
		case u.quote != 0:
			if c == u.quote {
				u.quote = 0
			}
		case c == '"' || c == '\'':
			u.quote = c
		case c == '>' && !bs:
			u.angle = false
		}
	} else if c == '<' {
		u.angle = true
	}
	switch {
	case isSpace(c):
		if !u.angle {
			u.run = false
		}
	case strings.IndexByte(`/\%&=?@`, c) >= 0,
		c == ':' && isLetter(u.prev),
		c == '(' && u.prev == ']':
		u.mark()
	}
}

func (u *ctxState) observeJSON(c byte, bs bool) {
	if u.inString {
		switch {
		case bs:
			if c == '/' || c == 'u' || c == '\\' {
				u.mark()
			}
		case c == '"':
			u.inString = false
		case c == '/' || c == '%' || c == '&', c == ':' && isLetter(u.prev):
			u.mark()
		}
		return
	}
	top := byte(0)
	if n := len(u.stack); n > 0 {
		top = u.stack[n-1]
	}
	switch c {
	case '"':
		u.inString = true
		u.isKey = u.expectKey && top == '{'
	case '{', '[':
		if len(u.stack) >= maxJSONDepth {
			u.broken = true
		} else {
			u.stack = append(u.stack, c)
		}
		u.expectKey = c == '{'
	case '}', ']':
		if n := len(u.stack); n > 0 {
			u.stack = u.stack[:n-1]
		}
		u.expectKey = false
	case ',':
		u.expectKey = top == '{'
	case ':':
		u.expectKey = false
	}
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

// Stream — обратная подстановка в тексте ответа, который приходит частями
// (потоковая передача, ТЗ, 5.1). Хвост части, в котором может начинаться
// псевдоним, задерживается до следующей части — не больше MaxPending байт;
// остальное отдаётся сразу. Склейка результатов Write и Flush равна Restore
// (RestoreJSON) всего текста при любом разбиении на части. Части с верным
// UTF-8 дают результаты с верным UTF-8: задержка начинается с символа ASCII.
//
// Один Stream — один текст ответа: content или refusal. Не безопасен для
// одновременного вызова.
type Stream struct {
	r restorer
}

// NewStream — потоковая подстановка для текста ответа (content, refusal).
func (v *Vault) NewStream() *Stream { return &Stream{r: restorer{v: v}} }

// NewJSONStream — потоковая подстановка для content в формате JSON
// (response_format json_object или json_schema). Адрес, который придёт
// в тексте позже псевдонима, поток не видит — поэтому аргументы tool_calls
// восстанавливаются только RestoreToolArgs по собранным аргументам.
func (v *Vault) NewJSONStream() *Stream {
	return &Stream{r: restorer{v: v, ctx: ctxState{json: true}}}
}

// Write обрабатывает очередную часть и возвращает текст, который можно
// отдать приложению сейчас (возможно, пустой).
func (s *Stream) Write(chunk string) string { return s.r.run(chunk, false) }

// Flush — конец текста: отдаёт задержанный хвост, восстановив псевдоним,
// если он завершён (например, без второй закрывающей скобки). Вызывается
// при завершении потока, в том числе при обрыве, чтобы хвост не потерялся.
func (s *Stream) Flush() string { return s.r.run("", true) }

// Pending — сколько байт задержано.
func (s *Stream) Pending() int { return len(s.r.pend) }
