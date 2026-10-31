package modelscan

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// Формат .npy (numpy/lib/format.py): сигнатура \x93NUMPY, версия, длина
// заголовка (2 байта в версии 1, 4 — в версиях 2 и 3) и заголовок — словарь
// Python с ключами descr, fortran_order, shape. Массив с типом object
// хранится как pickle: такой файл — находка pickle.

// scanNumpy проверяет поток .npy; entry — имя записи в архиве .npz или пусто.
func (s *Scanner) scanNumpy(r io.Reader, size int64, fr *FileReport, entry string) {
	where := "файл .npy"
	if entry != "" {
		where = "запись " + clean(entry) + " архива .npz"
	}
	obj, err := numpyHasObject(r, size, s.limits.MaxNumpyHeader)
	switch {
	case errors.Is(err, errLimit):
		fr.add(CodeLimitExceeded, SeverityBlock, "%s: заголовок больше %d байт", where, s.limits.MaxNumpyHeader)
	case err != nil:
		fr.add(CodeMalformed, SeverityBlock, "%s: %v", where, err)
	case obj:
		fr.add(CodePickle, SeverityBlock, "%s: массив с типом object хранится как pickle; запрет без исключений (DM-27)", where)
	}
}

var errLimit = errors.New("превышен предел")

// numpyHasObject читает заголовок .npy и отвечает, есть ли в типе object.
// size — размер потока или -1, если неизвестен.
func numpyHasObject(r io.Reader, size int64, maxHeader uint32) (bool, error) {
	var pre [12]byte
	if _, err := io.ReadFull(r, pre[:10]); err != nil {
		return false, errors.New("обрезанная сигнатура")
	}
	if string(pre[:6]) != "\x93NUMPY" {
		return false, errors.New("нет сигнатуры")
	}
	var hlen uint32
	start := int64(10)
	switch pre[6] {
	case 1:
		hlen = uint32(le16(pre[8:]))
	case 2, 3:
		if _, err := io.ReadFull(r, pre[10:12]); err != nil {
			return false, errors.New("обрезанная длина заголовка")
		}
		hlen = le32(pre[8:])
		start = 12
	default:
		return false, fmt.Errorf("версия формата %d не поддерживается", pre[6])
	}
	if hlen > maxHeader {
		return false, errLimit
	}
	if size >= 0 && int64(hlen) > size-start {
		return false, errors.New("заголовок за концом файла")
	}
	header := make([]byte, hlen)
	if _, err := io.ReadFull(r, header); err != nil {
		return false, errors.New("обрезанный заголовок")
	}
	return headerHasObject(header)
}

// headerHasObject разбирает словарь заголовка и проверяет descr.
func headerHasObject(header []byte) (bool, error) {
	p := &pyParser{s: string(header)}
	v, err := p.value(0)
	if err != nil {
		return false, err
	}
	p.skipSpace()
	if p.pos != len(p.s) {
		return false, errors.New("лишние данные после заголовка")
	}
	d, ok := v.(pyDict)
	if !ok {
		return false, errors.New("заголовок — не словарь")
	}
	descr, ok := d["descr"]
	if !ok {
		return false, errors.New("в заголовке нет descr")
	}
	return dtypeHasObject(descr, 0)
}

// dtypeHasObject — тип numpy содержит object: строка «O» (с порядком байт
// и размером) или поле структурного типа с таким типом.
func dtypeHasObject(v any, depth int) (bool, error) {
	if depth > maxPyDepth {
		return false, errors.New("слишком глубокая вложенность типа")
	}
	switch t := v.(type) {
	case string:
		s := strings.TrimLeft(t, "<>|=")
		return strings.HasPrefix(s, "O"), nil
	case pyList:
		for _, f := range t {
			field, ok := f.(pyList)
			if !ok || len(field) < 2 {
				return false, errors.New("поле структурного типа — не кортеж (имя, тип)")
			}
			obj, err := dtypeHasObject(field[1], depth+1)
			if err != nil || obj {
				return obj, err
			}
		}
		return false, nil
	}
	return false, errors.New("descr — не строка и не список полей")
}

// Минимальный разбор литералов Python заголовка .npy: словарь, список,
// кортеж, строка, целое, True, False, None. Ничего не вычисляется.

type (
	pyDict map[string]any
	pyList []any // и список, и кортеж
)

const (
	maxPyDepth = 16
	maxPyItems = 4096
)

type pyParser struct {
	s     string
	pos   int
	items int
}

func (p *pyParser) skipSpace() {
	for p.pos < len(p.s) && strings.IndexByte(" \t\r\n", p.s[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *pyParser) value(depth int) (any, error) {
	if depth > maxPyDepth {
		return nil, errors.New("слишком глубокая вложенность заголовка")
	}
	p.items++
	if p.items > maxPyItems {
		return nil, errors.New("слишком много элементов в заголовке")
	}
	p.skipSpace()
	if p.pos >= len(p.s) {
		return nil, errors.New("заголовок оборван")
	}
	switch c := p.s[p.pos]; c {
	case '{':
		p.pos++
		d := pyDict{}
		for {
			p.skipSpace()
			if p.pos < len(p.s) && p.s[p.pos] == '}' {
				p.pos++
				return d, nil
			}
			k, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, errors.New("ключ словаря — не строка")
			}
			p.skipSpace()
			if p.pos >= len(p.s) || p.s[p.pos] != ':' {
				return nil, errors.New("нет «:» после ключа")
			}
			p.pos++
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, dup := d[key]; dup {
				return nil, errors.New("повтор ключа в заголовке")
			}
			d[key] = v
			if err := p.sep('}'); err != nil {
				return nil, err
			}
		}
	case '[', '(':
		end := byte(']')
		if c == '(' {
			end = ')'
		}
		p.pos++
		var l pyList
		for {
			p.skipSpace()
			if p.pos < len(p.s) && p.s[p.pos] == end {
				p.pos++
				return l, nil
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			l = append(l, v)
			if err := p.sep(end); err != nil {
				return nil, err
			}
		}
	case '\'', '"':
		return p.str(c)
	default:
		start := p.pos
		for p.pos < len(p.s) && (isWordByte(p.s[p.pos])) {
			p.pos++
		}
		w := p.s[start:p.pos]
		switch {
		case w == "True" || w == "False" || w == "None":
			return w == "True", nil
		case w != "" && strings.Trim(w, "+-0123456789L") == "":
			return int64(0), nil
		}
		return nil, errors.New("неизвестное значение в заголовке")
	}
}

func isWordByte(c byte) bool {
	return c == '+' || c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// sep — «,» перед следующим элементом или закрывающая скобка.
func (p *pyParser) sep(end byte) error {
	p.skipSpace()
	if p.pos >= len(p.s) {
		return errors.New("заголовок оборван")
	}
	switch p.s[p.pos] {
	case ',':
		p.pos++
		return nil
	case end:
		return nil
	}
	return errors.New("нет «,» между элементами")
}

func (p *pyParser) str(q byte) (string, error) {
	p.pos++
	var b strings.Builder
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		switch {
		case c == q:
			p.pos++
			return b.String(), nil
		case c == '\\' && p.pos+1 < len(p.s):
			b.WriteByte(p.s[p.pos+1])
			p.pos += 2
		case c == '\n':
			return "", errors.New("перевод строки внутри строки")
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
	return "", errors.New("строка не закрыта")
}
