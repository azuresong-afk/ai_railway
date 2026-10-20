package pseudonym

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
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
	if r.v.cleared {
		// Запрос завершён (Clear): значений нет, текст отдаётся как есть,
		// без задержки и без учёта в метриках — обрыв потока не должен
		// портить Failed().
		return s
	}
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
				after, more := r.addrAfter(s, t.end, final)
				if more {
					return hold(i)
				}
				if value, ok := r.v.lookup(t, r.ctx.unsafe() || after); ok {
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

// afterLen — сколько байт после конца псевдонима смотрит правило мест:
// знак и следующий символ UTF-8. Входит в MaxPending.
const afterLen = 1 + utf8.UTFMax

// addrAfter — за псевдонимом идёт продолжение адреса, и значение станет его
// частью: поддоменом ([[INN_1]].evil.example — превью ссылки сделает запрос
// DNS и HTTP), именем ящика ([[INN_1]]@evil.example), портом или путём.
// Признаки: «/ @ # %», латинская буква, цифра, «-» и «_» (продолжение
// метки) сразу после псевдонима; «.» перед буквой (любого
// алфавита: IDN) или цифрой; «:» и «?» перед латинской буквой, цифрой или
// «/ \ @ %»; экранирование «\.», «\@», «\/», «\:» (markdown) или «\/»,
// «\u», «\\» (JSON). Конец предложения («[[PERSON_1]]. Далее»,
// «[[PERSON_1]].» в конце текста, «[[PERSON_1]]?», «[[PERSON_1]]: …») —
// не адрес. Решение зависит только от s[end:end+afterLen]; more — этих байт
// ещё нет (final = false).
func (r *restorer) addrAfter(s string, end int, final bool) (unsafe, more bool) {
	if end >= len(s) {
		return false, !final
	}
	c := s[end]
	switch {
	case strings.IndexByte("/@#%", c) >= 0:
		return true, false
	case isLetter(c) || isDigit(c) || c == '-' || c == '_':
		// Продолжение метки домена: «[[INN_1]]x.evil.example» дало бы
		// хост «7707083893x.evil.example». Псевдоним, слитый с латинским
		// словом, — и так искажение; кириллический суффикс («[[PERSON_1]]у»)
		// разрешён.
		return true, false
	case c != '.' && c != ':' && c != '?' && c != '\\':
		return false, false
	case end+1 >= len(s):
		return false, !final
	}
	n := s[end+1]
	switch c {
	case '\\':
		if r.ctx.json {
			return n == '/' || n == 'u' || n == '\\', false
		}
		return strings.IndexByte("./:@", n) >= 0, false
	case '.':
		if n >= utf8.RuneSelf {
			if !final && !utf8.FullRuneInString(s[end+1:]) {
				return false, true
			}
			ch, _ := utf8.DecodeRuneInString(s[end+1:])
			return unicode.IsLetter(ch), false
		}
		return isLetter(n) || isDigit(n), false
	}
	return isLetter(n) || isDigit(n) || strings.IndexByte(`/\@%`, n) >= 0, false
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
//   - если в какой-либо строке до псевдонима был признак адреса: «/ % & @ =»,
//     «\/», «\u», «\\», «www.», «:» после латинской буквы, «?» перед
//     латинской буквой, цифрой или «[ = & %» (знак вопроса в конце фразы —
//     не признак), похожее на домен: латинская буква после «.», перед
//     которой буква или цифра (evil.example; «1.5» — не домен), IPv4
//     (четыре группы цифр через точку), кириллический домен верхнего
//     уровня (пример.рф). Признак действует до конца текста: адрес мог быть
//     в соседнем поле, а псевдоним — в теле запроса инструмента.
//
// В обоих видах — если сразу за псевдонимом идёт продолжение адреса
// (restorer.addrAfter).
type ctxState struct {
	json bool

	prev      byte // предыдущий символ
	prev2     byte // символ перед prev
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
	dots      int  // точек в текущей группе цифр через точку (IPv4)
	labDot    bool // текущая метка не ASCII начата после «буква.»
	labN      int  // её длина в байтах
	lab       [maxTLDLen]byte
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
	u.prev2 = u.prev
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
		case strings.IndexByte("/%&@=", c) >= 0, c == ':' && isLetter(u.prev):
			u.mark()
		}
		u.observeHost(c, bs)
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

// maxTLDLen — длина в байтах самого длинного из cyrTLD.
const maxTLDLen = 16

// cyrTLD — домены верхнего уровня кириллицей: адрес «пример.рф» в JSON без
// схемы и латиницы. Список, а не «буква.буква» любого алфавита: иначе
// сокращения «т.е.», «г.Москва» в аргументах давали бы ложные блокировки.
var cyrTLD = []string{"рф", "рус", "москва", "дети", "сайт", "онлайн", "орг", "ком", "бел", "укр", "срб", "мкд", "мон", "қаз", "бг", "католик"}

// observeHost — признаки адреса без схемы внутри строки JSON: «?» перед
// продолжением запроса, домен «буква.буква», IPv4 и кириллический домен
// верхнего уровня. c — символ строки (не закрывающая кавычка); bs — он
// экранирован.
func (u *ctxState) observeHost(c byte, bs bool) {
	if !u.inString {
		// Закрывающая кавычка завершает метку.
		u.endLabel()
		u.dots = 0
		return
	}
	alnum := func(b byte) bool { return isLetter(b) || isDigit(b) || b >= utf8.RuneSelf }
	switch {
	case bs:
	case isLetter(c) && u.prev == '.' && alnum(u.prev2):
		u.mark() // evil.example, пример.com
	case u.prev == '?' && (isWord(c) || strings.IndexByte("[=&%", c) >= 0):
		u.mark() // ?q=, ?[[INN_1]]
	case isDigit(c) && u.prev == '.' && u.dots >= 3:
		u.mark() // 203.0.113.5
	}
	switch {
	case isDigit(c):
	case c == '.' && isDigit(u.prev):
		u.dots++
	default:
		u.dots = 0
	}
	switch {
	case c >= utf8.RuneSelf:
		if u.labDot {
			if u.labN < len(u.lab) {
				u.lab[u.labN] = c
				u.labN++
			} else {
				u.labDot = false
			}
		}
	case isLetter(c) || isDigit(c) || c == '-':
		u.labDot = false
	default:
		u.endLabel()
		u.labDot = c == '.' && !bs && alnum(u.prev)
		u.labN = 0
	}
}

// observeEnd — конец текста: незакрытая строка завершает метку.
func (u *ctxState) observeEnd() { u.endLabel() }

// endLabel — метка кончилась: если это кириллический домен верхнего уровня
// после «буква.», это признак адреса.
func (u *ctxState) endLabel() {
	if u.labDot && u.labN > 0 {
		label := string(u.lab[:u.labN])
		for _, tld := range cyrTLD {
			// Строчными или прописными целиком, но не с прописной буквы:
			// «г.Москва» — адрес в тексте, а не домен.
			if label == tld || label == strings.ToUpper(tld) {
				u.urlSeen = true
				break
			}
		}
	}
	u.labDot, u.labN = false, 0
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
