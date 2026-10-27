package argschema

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Строгий разбор JSON (ADR-0023, раздел 3). Шлюз и MCP-сервер должны
// прочесть документ одинаково, поэтому отвергается всё, что разборщики
// понимают по-разному: повторяющиеся ключи, неверный UTF-8, одиночные
// суррогаты в \u, данные после значения. Числа хранятся точно (big.Rat):
// сравнение с minimum и maximum не теряет разрядов, а число, которое нельзя
// представить точно в разумном объёме (экспонента больше maxExponent), —
// отказ.

// Kind — вид значения JSON.
type Kind uint8

// Виды значений.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// Value — разобранное значение JSON. У объекта ключи в порядке документа и
// без повторов.
type Value struct {
	Kind Kind
	Bool bool
	// Num — точное значение числа; Raw — его запись в документе.
	Num *big.Rat
	Raw string
	Str string
	Arr []Value
	// Keys и Vals — пары объекта по порядку.
	Keys []string
	Vals []Value
}

// Get — значение ключа объекта.
func (v *Value) Get(key string) (*Value, bool) {
	for i, k := range v.Keys {
		if k == key {
			return &v.Vals[i], true
		}
	}
	return nil, false
}

// Limits — пределы разбора.
type Limits struct {
	MaxSize   int // байт в документе
	MaxDepth  int // вложенность массивов и объектов
	MaxValues int // значений всего, включая вложенные
	MaxString int // байт в одной строке после раскрытия escape-последовательностей
}

// Пределы аргументов вызова (ADR-0023, раздел 3).
const (
	MaxArgsSize   = 256 << 10
	MaxArgsDepth  = 32
	MaxArgsValues = 10000
	MaxArgsString = 64 << 10
)

// ArgsLimits — пределы аргументов вызова инструмента.
var ArgsLimits = Limits{MaxSize: MaxArgsSize, MaxDepth: MaxArgsDepth, MaxValues: MaxArgsValues, MaxString: MaxArgsString}

// Пределы записи числа: длина и порядок экспоненты. 1e400 и 400 цифр
// хранятся в big.Rat без заметных затрат; больше — отказ, а не округление.
const (
	maxNumberLen = 512
	maxExponent  = 400
)

// ErrTooLarge — документ больше предела MaxSize.
var ErrTooLarge = errors.New("документ JSON больше предела")

// SyntaxError — ошибка разбора: смещение в байтах и причина без фрагмента
// документа (аргументы — содержимое, в журнал не попадают).
type SyntaxError struct {
	Offset int
	Msg    string
}

func (e *SyntaxError) Error() string { return fmt.Sprintf("JSON, байт %d: %s", e.Offset, e.Msg) }

// ParseJSON строго разбирает один документ JSON с пределами lim.
func ParseJSON(data []byte, lim Limits) (Value, error) {
	if len(data) > lim.MaxSize {
		return Value{}, ErrTooLarge
	}
	p := &parser{data: data, lim: lim}
	p.skipSpace()
	v, err := p.value(0)
	if err != nil {
		return Value{}, err
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return Value{}, p.fail("данные после значения JSON")
	}
	return v, nil
}

type parser struct {
	data   []byte
	pos    int
	values int
	lim    Limits
}

func (p *parser) fail(msg string) error { return &SyntaxError{Offset: p.pos, Msg: msg} }

func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (Value, error) {
	p.values++
	if p.values > p.lim.MaxValues {
		return Value{}, p.fail("слишком много значений")
	}
	if p.pos >= len(p.data) {
		return Value{}, p.fail("неожиданный конец документа")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		s, err := p.str()
		return Value{Kind: String, Str: s}, err
	case c == 't':
		return Value{Kind: Bool, Bool: true}, p.literal("true")
	case c == 'f':
		return Value{Kind: Bool}, p.literal("false")
	case c == 'n':
		return Value{Kind: Null}, p.literal("null")
	case c == '-' || c >= '0' && c <= '9':
		return p.number()
	}
	return Value{}, p.fail("недопустимый символ")
}

func (p *parser) literal(word string) error {
	if len(p.data)-p.pos < len(word) || string(p.data[p.pos:p.pos+len(word)]) != word {
		return p.fail("недопустимое значение")
	}
	p.pos += len(word)
	return nil
}

func (p *parser) object(depth int) (Value, error) {
	if depth > p.lim.MaxDepth {
		return Value{}, p.fail("слишком глубокая вложенность")
	}
	p.pos++ // {
	v := Value{Kind: Object, Keys: []string{}, Vals: []Value{}}
	seen := map[string]bool{}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return v, nil
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return Value{}, p.fail("ожидается ключ объекта")
		}
		at := p.pos
		k, err := p.str()
		if err != nil {
			return Value{}, err
		}
		if seen[k] {
			return Value{}, &SyntaxError{Offset: at, Msg: "повторяющийся ключ объекта"}
		}
		seen[k] = true
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return Value{}, p.fail("ожидается «:»")
		}
		p.pos++
		p.skipSpace()
		x, err := p.value(depth)
		if err != nil {
			return Value{}, err
		}
		v.Keys, v.Vals = append(v.Keys, k), append(v.Vals, x)
		p.skipSpace()
		if p.pos >= len(p.data) {
			return Value{}, p.fail("неожиданный конец объекта")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return v, nil
		default:
			return Value{}, p.fail("ожидается «,» или «}»")
		}
	}
}

func (p *parser) array(depth int) (Value, error) {
	if depth > p.lim.MaxDepth {
		return Value{}, p.fail("слишком глубокая вложенность")
	}
	p.pos++ // [
	v := Value{Kind: Array, Arr: []Value{}}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return v, nil
	}
	for {
		p.skipSpace()
		x, err := p.value(depth)
		if err != nil {
			return Value{}, err
		}
		v.Arr = append(v.Arr, x)
		p.skipSpace()
		if p.pos >= len(p.data) {
			return Value{}, p.fail("неожиданный конец массива")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return v, nil
		default:
			return Value{}, p.fail("ожидается «,» или «]»")
		}
	}
}

// str разбирает строку в кавычках: неверный UTF-8, неэкранированные
// управляющие символы и одиночные суррогаты — ошибка.
func (p *parser) str() (string, error) {
	p.pos++ // "
	var out []byte
	start := p.pos
	for {
		if p.pos >= len(p.data) {
			return "", p.fail("незакрытая строка")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			out = append(out, p.data[start:p.pos]...)
			p.pos++
			if len(out) > p.lim.MaxString {
				return "", p.fail("слишком длинная строка")
			}
			return string(out), nil
		case c == '\\':
			out = append(out, p.data[start:p.pos]...)
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			out = utf8.AppendRune(out, r)
			start = p.pos
		case c < 0x20:
			return "", p.fail("управляющий символ в строке")
		case c < utf8.RuneSelf:
			p.pos++
		default:
			r, n := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && n <= 1 {
				return "", p.fail("неверный UTF-8")
			}
			p.pos += n
		}
		if p.pos-start+len(out) > p.lim.MaxString {
			return "", p.fail("слишком длинная строка")
		}
	}
}

// escape разбирает escape-последовательность с «\» в p.pos.
func (p *parser) escape() (rune, error) {
	if p.pos+1 >= len(p.data) {
		return 0, p.fail("незакрытая escape-последовательность")
	}
	c := p.data[p.pos+1]
	p.pos += 2
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
		r, err := p.hex4()
		if err != nil {
			return 0, err
		}
		switch {
		case utf16.IsSurrogate(r) && r < 0xdc00:
			// Старший суррогат — только вместе с младшим.
			if p.pos+1 >= len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
				return 0, p.fail("одиночный суррогат в \\u")
			}
			p.pos += 2
			lo, err := p.hex4()
			if err != nil {
				return 0, err
			}
			if lo < 0xdc00 || lo > 0xdfff {
				return 0, p.fail("одиночный суррогат в \\u")
			}
			return utf16.DecodeRune(r, lo), nil
		case utf16.IsSurrogate(r):
			return 0, p.fail("одиночный суррогат в \\u")
		}
		return r, nil
	}
	return 0, p.fail("недопустимая escape-последовательность")
}

func (p *parser) hex4() (rune, error) {
	if len(p.data)-p.pos < 4 {
		return 0, p.fail("неполная последовательность \\u")
	}
	var r rune
	for _, c := range p.data[p.pos : p.pos+4] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, p.fail("неверная последовательность \\u")
		}
		r = r<<4 | rune(d)
	}
	p.pos += 4
	return r, nil
}

// number разбирает число по грамматике JSON и переводит его в big.Rat.
func (p *parser) number() (Value, error) {
	start := p.pos
	digits := func() int {
		n := 0
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
			n++
		}
		return n
	}
	if p.data[p.pos] == '-' {
		p.pos++
	}
	switch {
	case p.pos < len(p.data) && p.data[p.pos] == '0':
		p.pos++
	case digits() == 0:
		return Value{}, p.fail("неверное число")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if digits() == 0 {
			return Value{}, p.fail("неверное число")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		expStart := p.pos
		if digits() == 0 {
			return Value{}, p.fail("неверное число")
		}
		if e, err := strconv.Atoi(string(p.data[expStart:p.pos])); err != nil || e > maxExponent {
			return Value{}, p.fail("порядок числа вне диапазона точной проверки")
		}
	}
	raw := string(p.data[start:p.pos])
	if len(raw) > maxNumberLen {
		return Value{}, p.fail("слишком длинная запись числа")
	}
	r, ok := new(big.Rat).SetString(raw)
	if !ok {
		return Value{}, p.fail("неверное число")
	}
	return Value{Kind: Number, Num: r, Raw: raw}, nil
}
