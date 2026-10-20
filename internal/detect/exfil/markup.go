package exfil

import (
	"context"
	"strings"
)

// Пределы разбора разметки.
const (
	maxDest   = 1 << 20 // адрес markdown-ссылки
	maxTitle  = 8 << 10 // заголовок markdown-ссылки
	maxLabel  = 999     // метка ссылки-сноски (CommonMark)
	maxDepth  = 32      // вложенность скобок в адресе
	maxTag    = 64 << 10
	maxCSSURL = 8 << 10
	maxName   = 32
	maxAttrs  = 256
)

// codeSpans — блоки кода (``` и ~~~) и встроенный код (`…`) в markdown:
// там разметка не отображается, ссылки не загружаются. Интервалы [s, e)
// по возрастанию, не пересекаются. Встроенный код не выходит за блок, как
// в CommonMark: блок заканчивается пустой строкой, а строки заголовка,
// подчёркивания заголовка, разделителя, пункта списка, цитаты, таблицы и
// HTML — отдельные блоки. Ограда с отступом внутри пункта списка — код
// этого пункта: она кончается вместе с пунктом (строкой с меньшим
// отступом). При сомнении — не код: ошибка в эту сторону даёт лишнюю
// находку, а не пропуск. Код с отступом в четыре пробела не учитывается.
func codeSpans(ctx context.Context, text string) ([][2]int, error) {
	var out [][2]int
	var err error
	var fenceChar byte
	var lists listStack
	fenceLen, fenceStart, fenceBase, para := 0, 0, 0, 0
	// noLazy — следующая строка не может быть ленивым продолжением абзаца
	// пункта списка: перед ней пустая строка, ограда или заголовок.
	inFence, noLazy := false, false
	n := 0
	for ls := 0; ls < len(text); {
		if n++; n&0x3FFF == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		le := strings.IndexByte(text[ls:], '\n')
		next := len(text)
		if le < 0 {
			le = len(text)
		} else {
			le += ls
			next = le + 1
		}
		line := text[ls:le]
		ind, body := indent(line)
		blank := strings.TrimSpace(line) == ""
		if inFence {
			if fenceBase == 0 || blank || ind >= fenceBase {
				ch, run, rest := fence(body)
				if ch == fenceChar && run >= fenceLen && ind-fenceBase <= 3 && strings.TrimSpace(rest) == "" {
					out = append(out, [2]int{fenceStart, le})
					inFence, noLazy = false, true
					para = next
				}
				ls = next
				continue
			}
			// Пункт списка кончился — кончилась и ограда внутри него;
			// строка разбирается как обычная.
			out = append(out, [2]int{fenceStart, ls})
			inFence, noLazy = false, true
			para = ls
		}
		if blank {
			if out, err = inlineCode(ctx, out, text, para, ls); err != nil {
				return nil, err
			}
			para = next
			noLazy = true
			ls = next
			continue
		}
		base := lists.base(ind)
		rel := ind - base
		ch, run, rest := fence(body)
		isFence := rel <= 3 && run >= 3 && (ch == '~' || strings.IndexByte(rest, '`') < 0)
		brk := rel <= 3 && !isFence && breakLine(body)
		w, item := 0, false
		if rel <= 3 && !isFence && !brk {
			w, item = listItem(body)
		}
		block := brk || item
		if isFence || block || noLazy {
			lists.pop(ind) // пункты с отступом больше строки закрыты
		}
		noLazy = false
		switch {
		case isFence:
			if out, err = inlineCode(ctx, out, text, para, ls); err != nil {
				return nil, err
			}
			inFence, fenceChar, fenceLen, fenceStart, fenceBase = true, ch, run, ls, base
		case block:
			if out, err = inlineCode(ctx, out, text, para, ls); err != nil {
				return nil, err
			}
			para = ls
			if item {
				lists.push(ind + w)
			} else if body[0] != '>' && body[0] != '|' {
				noLazy = true // заголовок, разделитель, HTML: абзаца нет
			}
		}
		ls = next
	}
	if inFence {
		return append(out, [2]int{fenceStart, len(text)}), nil
	}
	return inlineCode(ctx, out, text, para, len(text))
}

// maxLists — глубина вложенности списков, которую отслеживает codeSpans;
// более глубокие пункты не учитываются (ограда в них — не код).
const maxLists = 32

// listStack — отступы содержимого открытых пунктов списка, по возрастанию.
type listStack struct {
	w [maxLists]int
	n int
}

// base — отступ содержимого самого глубокого пункта, которому может
// принадлежать строка с отступом ind; 0 — верхний уровень.
func (l *listStack) base(ind int) int {
	for k := l.n - 1; k >= 0; k-- {
		if l.w[k] <= ind {
			return l.w[k]
		}
	}
	return 0
}

// pop закрывает пункты, отступ содержимого которых больше ind.
func (l *listStack) pop(ind int) {
	for l.n > 0 && l.w[l.n-1] > ind {
		l.n--
	}
}

func (l *listStack) push(w int) {
	if l.n < maxLists && (l.n == 0 || w > l.w[l.n-1]) {
		l.w[l.n] = w
		l.n++
	}
}

// indent — ширина отступа строки в колонках (табуляция — до следующей
// кратной 4, как в CommonMark) и строка без отступа.
func indent(line string) (int, string) {
	col, i := 0, 0
	for ; i < len(line); i++ {
		switch line[i] {
		case ' ':
			col++
		case '\t':
			col += 4 - col%4
		default:
			return col, line[i:]
		}
	}
	return col, ""
}

// breakLine — строка без отступа (body) начинает свой блок и это не пункт
// списка: заголовок, цитата, строка таблицы, разделитель (***, ---, ___),
// подчёркивание заголовка (===, ---), HTML-тег или комментарий.
func breakLine(body string) bool {
	if body == "" {
		return false
	}
	switch c := body[0]; {
	case c == '#' || c == '>' || c == '|':
		return true
	case c == '<':
		return len(body) > 1 && (letter(body[1]) || body[1] == '/' || body[1] == '!' || body[1] == '?')
	case c == '*' || c == '-' || c == '_':
		// Разделитель: от трёх одинаковых знаков, между ними пробелы.
		k := 0
		for i := 0; i < len(body); i++ {
			switch body[i] {
			case c:
				k++
			case ' ', '\t', '\r':
			default:
				return false
			}
		}
		// Подчёркивание заголовка «---» — без пробелов между знаками.
		return k >= 3 || c == '-' && strings.Trim(strings.TrimRight(body, " \t\r"), "-") == ""
	case c == '=':
		return strings.Trim(strings.TrimRight(body, " \t\r"), "=") == ""
	}
	return false
}

// listItem — строка без отступа (body) начинается с маркера пункта списка
// («-», «*», «+», «1.», «1)» и пробел или конец строки); w — отступ
// содержимого пункта от начала body.
func listItem(body string) (w int, ok bool) {
	m := 0
	switch {
	case body == "":
		return 0, false
	case body[0] == '-' || body[0] == '*' || body[0] == '+':
		m = 1
	default:
		for m < len(body) && m < 9 && digit(body[m]) {
			m++
		}
		if m == 0 || m == len(body) || body[m] != '.' && body[m] != ')' {
			return 0, false
		}
		m++
	}
	if m < len(body) && body[m] != ' ' && body[m] != '\t' && body[m] != '\r' {
		return 0, false
	}
	sp := 0
	for m+sp < len(body) && (body[m+sp] == ' ' || body[m+sp] == '\t') {
		sp++
	}
	if sp == 0 || sp > 4 || m+sp == len(body) {
		sp = 1 // пустой пункт или код с отступом внутри пункта
	}
	return m + sp, true
}

// fence — начало строки-ограды без отступа: от трёх «`» или «~».
func fence(body string) (ch byte, run int, rest string) {
	if body == "" || body[0] != '`' && body[0] != '~' {
		return 0, 0, ""
	}
	ch = body[0]
	j := 0
	for j < len(body) && body[j] == ch {
		j++
	}
	return ch, j, body[j:]
}

// inlineCode добавляет встроенный код блока [s, e): последовательность из
// k обратных кавычек закрывается ближайшей последовательностью той же
// длины. Последовательность после «\» не открывает код, но закрывает:
// внутри кода обратная косая черта — обычный символ. Время линейно: для
// каждой последовательности заранее известна следующая той же длины.
func inlineCode(ctx context.Context, out [][2]int, text string, s, e int) ([][2]int, error) {
	if s >= e || strings.IndexByte(text[s:e], '`') < 0 {
		return out, nil
	}
	type run struct {
		s, e    int
		escaped bool
	}
	var runs []run
	for i := s; i < e; i++ {
		if (i-s)&0xFFFF == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if text[i] == '`' {
			j := i
			for j < e && text[j] == '`' {
				j++
			}
			runs = append(runs, run{i, j, escapedAt(text, s, i)})
			i = j - 1
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nextSame := make([]int, len(runs))
	last := map[int]int{}
	for k := len(runs) - 1; k >= 0; k-- {
		l := runs[k].e - runs[k].s
		if j, ok := last[l]; ok {
			nextSame[k] = j
		} else {
			nextSame[k] = -1
		}
		last[l] = k
	}
	for k := 0; k < len(runs); k++ {
		if j := nextSame[k]; j > 0 && !runs[k].escaped {
			// Таблица GFM сначала делит строку на ячейки по «|», даже внутри
			// обратных кавычек, и только потом разбирает разметку: код с
			// неэкранированной «|» может не быть кодом при отрисовке. При
			// сомнении — не код. Отрезки не пересекаются — время линейно.
			if !hasPipe(text[runs[k].e:runs[j].s]) {
				out = append(out, [2]int{runs[k].s, runs[j].e})
			}
			k = j
		}
	}
	return out, ctx.Err()
}

// hasPipe — в s есть «|» без «\» перед ней.
func hasPipe(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '|' && (i == 0 || s[i-1] != '\\') {
			return true
		}
	}
	return false
}

// escapedAt — символ в позиции i экранирован: перед ним нечётное число «\\»
// (не дальше начала блока s).
func escapedAt(text string, s, i int) bool {
	n := 0
	for k := i - 1; k >= s && text[k] == '\\'; k-- {
		n++
	}
	return n%2 == 1
}

// dest — адрес ссылки в тексте.
type dest struct {
	raw   string
	end   int // позиция после конструкции
	angle bool
}

// inlineDest разбирает «(адрес "заголовок")» markdown-ссылки с позиции p
// (после «(»). Адрес в <…> или без пробелов со сбалансированными скобками.
func inlineDest(text string, p int, budget *int) (dest, bool) {
	q := skipSpace(text, p)
	d, q, ok := rawDest(text, q, true, budget)
	if !ok {
		return d, false
	}
	q = skipSpace(text, q)
	if q < len(text) && (text[q] == '"' || text[q] == '\'' || text[q] == '(') && q > 0 && (text[q-1] <= ' ') {
		closing := text[q]
		if closing == '(' {
			closing = ')'
		}
		limit := min(len(text), q+1+maxTitle)
		k := strings.IndexByte(text[q+1:limit], closing)
		if k < 0 {
			*budget -= limit - q
			return d, false
		}
		*budget -= k + 1
		q = skipSpace(text, q+1+k+1)
	}
	if q >= len(text) || text[q] != ')' {
		return d, false
	}
	d.end = q + 1
	return d, true
}

// rawDest — адрес с позиции q: в угловых скобках или до пробела. paren —
// скобки внутри адреса должны быть сбалансированы (адрес встроенной ссылки).
func rawDest(text string, q int, paren bool, budget *int) (dest, int, bool) {
	if q < len(text) && text[q] == '<' {
		limit := min(len(text), q+1+maxDest)
		k := strings.IndexAny(text[q+1:limit], ">\n<")
		if k < 0 {
			*budget -= limit - q
			return dest{}, q, false
		}
		*budget -= k + 1
		if text[q+1+k] != '>' {
			return dest{}, q, false
		}
		return dest{raw: text[q+1 : q+1+k], angle: true}, q + 1 + k + 1, true
	}
	start, depth := q, 0
	for q < len(text) && q-start < maxDest {
		c := text[q]
		if c <= ' ' {
			break
		}
		if c == '\\' && q+1 < len(text) && text[q+1] > ' ' {
			q += 2
			continue
		}
		if paren {
			if c == '(' {
				if depth++; depth > maxDepth {
					*budget -= q - start
					return dest{}, q, false
				}
			} else if c == ')' {
				if depth == 0 {
					break
				}
				depth--
			}
		}
		q++
	}
	*budget -= q - start
	if depth != 0 {
		return dest{}, q, false
	}
	return dest{raw: text[start:q]}, q, true
}

// skipSpace пропускает пробелы, табуляцию и не больше одного перевода строки.
func skipSpace(text string, q int) int {
	nl := false
	for q < len(text) {
		switch text[q] {
		case ' ', '\t':
		case '\n':
			if nl {
				return q
			}
			nl = true
		case '\r':
		default:
			return q
		}
		q++
	}
	return q
}

// attr — атрибут тега HTML.
type attr struct {
	name, value string
	hasValue    bool
}

// htmlTag разбирает открывающий тег с позиции i («<»). Имя — латинские
// буквы, цифры, «-», «:»; атрибуты — имя из букв, цифр и «_:.-», значение в
// кавычках или без. Возвращает имя в нижнем регистре и позицию после «>».
func htmlTag(text string, i int, budget *int) (name string, attrs []attr, end int, ok bool) {
	j := i + 1
	if j < len(text) && text[j] == '/' {
		return "", nil, 0, false // закрывающий тег ничего не загружает
	}
	ns := j
	for j < len(text) && j-ns < maxName && (letter(text[j]) || j > ns && (digit(text[j]) || text[j] == '-' || text[j] == ':')) {
		j++
	}
	if j == ns || j == len(text) || text[j] > ' ' && text[j] != '/' && text[j] != '>' {
		return "", nil, 0, false
	}
	name = strings.ToLower(text[ns:j])
	limit := min(len(text), i+maxTag)
	defer func() { *budget -= j - i }()
	for j < limit {
		for j < limit && (text[j] <= ' ' || text[j] == '/') {
			j++
		}
		if j >= limit {
			break
		}
		if text[j] == '>' {
			return name, attrs, j + 1, true
		}
		as := j
		for j < limit && j-as < maxName*2 && attrChar(text[j]) {
			j++
		}
		if j == as || len(attrs) >= maxAttrs {
			return "", nil, 0, false
		}
		a := attr{name: strings.ToLower(text[as:j])}
		k := j
		for k < limit && text[k] <= ' ' {
			k++
		}
		if k < limit && text[k] == '=' {
			k++
			for k < limit && text[k] <= ' ' {
				k++
			}
			if k >= limit {
				break
			}
			a.hasValue = true
			if q := text[k]; q == '"' || q == '\'' {
				e := strings.IndexByte(text[k+1:limit], q)
				if e < 0 {
					j = limit
					break
				}
				a.value = text[k+1 : k+1+e]
				j = k + 1 + e + 1
			} else {
				vs := k
				for k < limit && text[k] > ' ' && text[k] != '>' {
					k++
				}
				a.value = text[vs:k]
				j = k
			}
		}
		attrs = append(attrs, a)
	}
	return "", nil, 0, false
}

func letter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func digit(c byte) bool  { return c >= '0' && c <= '9' }
func alnum(c byte) bool  { return letter(c) || digit(c) }

func attrChar(c byte) bool { return alnum(c) || c == '_' || c == ':' || c == '.' || c == '-' }
