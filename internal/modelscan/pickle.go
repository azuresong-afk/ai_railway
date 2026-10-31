package modelscan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Просмотр потока pickle по опкодам (протоколы 0–5). Опкоды не исполняются:
// разбираются только их аргументы, чтобы отличить pickle от случайных байт
// (протоколы 0 и 1 не имеют сигнатуры) и показать импортируемые объекты.

const (
	opProto       = 0x80
	opStop        = '.'
	opGlobal      = 'c'
	opInst        = 'i'
	opStackGlobal = 0x93
)

// argKind — вид аргумента опкода.
type argKind uint8

const (
	argNone     argKind = iota
	argLine             // строка до \n
	argLines2           // две строки (модуль и имя)
	argFixed            // n байт
	argLen1             // длина в 1 байте и данные
	argLen4             // длина в 4 байтах и данные
	argLen8             // длина в 8 байтах и данные
	argInt              // строка с целым
	argFloat            // строка с числом
	argQuoted           // строка в кавычках (STRING протокола 0)
	argLongLine         // строка с целым и необязательным L
)

type opInfo struct {
	kind argKind
	n    int  // для argFixed
	str  bool // аргумент — строка, которую может взять STACK_GLOBAL
}

// opcodes — таблица опкодов pickle (Lib/pickletools.py).
var opcodes = map[byte]opInfo{
	// Протокол 0.
	'(': {}, '.': {}, '0': {}, '1': {}, '2': {},
	'F': {kind: argFloat}, 'I': {kind: argInt}, 'L': {kind: argLongLine},
	'N': {}, 'P': {kind: argLine}, 'R': {}, 'S': {kind: argQuoted},
	'V': {kind: argLine, str: true}, 'a': {}, 'b': {}, 'c': {kind: argLines2},
	'd': {}, 'g': {kind: argInt}, 'i': {kind: argLines2}, 'l': {},
	'p': {kind: argInt}, 's': {}, 't': {},
	// Протокол 1.
	'J': {kind: argFixed, n: 4}, 'K': {kind: argFixed, n: 1}, 'M': {kind: argFixed, n: 2},
	'Q': {}, 'T': {kind: argLen4}, 'U': {kind: argLen1}, 'X': {kind: argLen4, str: true},
	'G': {kind: argFixed, n: 8}, '}': {}, ']': {}, ')': {}, 'e': {},
	'h': {kind: argFixed, n: 1}, 'j': {kind: argFixed, n: 4},
	'q': {kind: argFixed, n: 1}, 'r': {kind: argFixed, n: 4}, 'u': {}, 'o': {},
	// Протокол 2.
	0x80: {kind: argFixed, n: 1}, 0x81: {}, 0x82: {kind: argFixed, n: 1},
	0x83: {kind: argFixed, n: 2}, 0x84: {kind: argFixed, n: 4},
	0x85: {}, 0x86: {}, 0x87: {}, 0x88: {}, 0x89: {},
	0x8a: {kind: argLen1}, 0x8b: {kind: argLen4},
	// Протокол 3.
	'B': {kind: argLen4}, 'C': {kind: argLen1},
	// Протокол 4.
	0x8c: {kind: argLen1, str: true}, 0x8d: {kind: argLen8, str: true}, 0x8e: {kind: argLen8},
	0x8f: {}, 0x90: {}, 0x91: {}, 0x92: {}, 0x93: {}, 0x94: {},
	0x95: {kind: argFixed, n: 8},
	// Протокол 5.
	0x96: {kind: argLen8}, 0x97: {}, 0x98: {},
}

// pickleProbe — сколько байт начала потока просматривается.
const pickleProbe = 64 << 10

// maxGlobals — импортируемых объектов в пояснении находки.
const maxGlobals = 8

// pickleWalk — итог просмотра потока.
type pickleWalk struct {
	proto   int // -1 — без опкода PROTO
	ops     int
	stopped bool
	globals []string
	// short — данные кончились посреди опкода (поток длиннее просмотра).
	short bool
	// broken — просмотр остановился на байте не по формату (pickleInfo).
	broken bool
}

// walkPickle просматривает поток в buf; err — байт не опкод или аргумент
// не по формату.
func walkPickle(buf []byte) (pickleWalk, error) {
	w := pickleWalk{proto: -1}
	var lastStr [2]string
	seen := map[string]bool{}
	addGlobal := func(mod, name string) {
		g := clean(mod) + "." + clean(name)
		if !seen[g] && len(w.globals) < maxGlobals {
			seen[g] = true
			w.globals = append(w.globals, g)
		}
	}
	pos := 0
	for pos < len(buf) {
		op := buf[pos]
		info, ok := opcodes[op]
		if !ok {
			return w, fmt.Errorf("байт 0x%02x на смещении %d — не опкод pickle", op, pos)
		}
		pos++
		var arg []byte
		switch info.kind {
		case argNone:
		case argFixed:
			if len(buf)-pos < info.n {
				w.short = true
				return w, nil
			}
			arg = buf[pos : pos+info.n]
			pos += info.n
		case argLen1, argLen4, argLen8:
			width := map[argKind]int{argLen1: 1, argLen4: 4, argLen8: 8}[info.kind]
			if len(buf)-pos < width {
				w.short = true
				return w, nil
			}
			var n uint64
			switch width {
			case 1:
				n = uint64(buf[pos])
			case 4:
				n = uint64(le32(buf[pos:]))
			default:
				n = le64(buf[pos:])
			}
			pos += width
			if n > uint64(len(buf)-pos) { //nolint:gosec // G115: pos ≤ len(buf)
				w.short = true
				return w, nil
			}
			m := int(n) //nolint:gosec // G115: n не больше длины буфера
			arg = buf[pos : pos+m]
			pos += m
		default:
			lines := 1
			if info.kind == argLines2 {
				lines = 2
			}
			var parts [2][]byte
			for i := range lines {
				nl := bytes.IndexByte(buf[pos:], '\n')
				if nl < 0 {
					w.short = true
					return w, nil
				}
				parts[i] = buf[pos : pos+nl]
				pos += nl + 1
			}
			if err := checkLineArg(info.kind, parts[0], parts[1]); err != nil {
				return w, fmt.Errorf("опкод %q: %w", op, err)
			}
			arg = parts[0]
			if info.kind == argLines2 {
				addGlobal(string(parts[0]), string(parts[1]))
			}
		}
		if op == opProto {
			if w.ops > 0 || arg[0] > 5 {
				return w, fmt.Errorf("опкод PROTO с протоколом %d на смещении %d", arg[0], pos-2)
			}
			w.proto = int(arg[0])
		}
		if info.str {
			lastStr[0], lastStr[1] = lastStr[1], string(arg)
		}
		if op == opStackGlobal && lastStr[0] != "" {
			addGlobal(lastStr[0], lastStr[1])
		}
		w.ops++
		if op == opStop {
			w.stopped = true
			return w, nil
		}
	}
	w.short = true
	return w, nil
}

// checkLineArg проверяет строковые аргументы протокола 0. Числа проверяются
// мягко (печатные символы ASCII): Python принимает пробелы, «+» и «_» в
// записи числа, и строгая проверка позволила бы спрятать поток от сканера.
func checkLineArg(kind argKind, line, second []byte) error {
	s := strings.TrimSuffix(string(line), "\r")
	switch kind {
	case argInt, argLongLine, argFloat:
		if s == "" || len(s) > 128 || !printableASCII(s) {
			return fmt.Errorf("не число")
		}
	case argQuoted:
		if len(s) < 2 || s[0] != s[len(s)-1] || s[0] != '\'' && s[0] != '"' {
			return fmt.Errorf("строка не в кавычках")
		}
	case argLines2:
		if !isDotted(strings.TrimSpace(s)) || !isDotted(strings.TrimSpace(strings.TrimSuffix(string(second), "\r"))) {
			return fmt.Errorf("имя модуля или объекта не идентификатор")
		}
	}
	return nil
}

func printableASCII(s string) bool {
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// isDotted — имя Python через точки (модуль или объект).
func isDotted(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for i, c := range []byte(part) {
			letter := c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
			if !letter && (i == 0 || c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

// minPickleOps — сколько опкодов подряд считается pickle без опкода PROTO,
// если поток не кончился STOP в пределах просмотра.
const minPickleOps = 16

// looksLikePickle — поток протокола 0 или 1 (без сигнатуры): опкоды подряд до
// STOP или не меньше minPickleOps, если поток длиннее просмотра.
func looksLikePickle(buf []byte) bool {
	w, err := walkPickle(buf)
	if err != nil {
		return false
	}
	if w.stopped {
		return w.ops >= 2
	}
	return w.ops >= minPickleOps
}

// pickleInfo — итог просмотра для пояснения находки: поток, который
// просмотр не прошёл целиком, остаётся находкой, отмечается признак.
func pickleInfo(buf []byte) pickleWalk {
	w, err := walkPickle(buf)
	w.broken = err != nil
	return w
}

// pickleDetail — пояснение находки pickle.
func pickleDetail(what string, w pickleWalk) string {
	var b strings.Builder
	b.WriteString(what)
	if w.proto >= 0 {
		fmt.Fprintf(&b, ", протокол %d", w.proto)
	}
	if len(w.globals) > 0 {
		b.WriteString("; импортирует: " + strings.Join(w.globals, ", "))
	}
	if w.broken {
		fmt.Fprintf(&b, "; после %d опкодов поток не по формату", w.ops)
	}
	b.WriteString(". pickle выполняет код при загрузке; запрет без исключений (DM-27)")
	return b.String()
}

// scanPickle — файл pickle (в том числе .bin/.pt/.pth/.ckpt PyTorch старого
// формата и joblib без сжатия).
func (s *Scanner) scanPickle(r io.ReaderAt, size int64, fr *FileReport) {
	buf := make([]byte, min(size, pickleProbe))
	n, err := r.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		n = 0
	}
	fr.add(CodePickle, SeverityBlock, "%s", pickleDetail("поток pickle", pickleInfo(buf[:n])))
}
