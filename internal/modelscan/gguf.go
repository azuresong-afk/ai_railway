package modelscan

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"sort"
	"strings"
)

// Формат GGUF (ggml/docs/gguf.md), версии 2 и 3, little-endian: сигнатура
// «GGUF», версия, число тензоров и записей метаданных, метаданные «ключ —
// тип — значение», описания тензоров (имя, размерности, тип ggml,
// смещение), выравнивание и данные. Метаданные читаются потоком; в память
// попадают только ключи, выравнивание и шаблоны чата.

// Типы значений метаданных GGUF.
const (
	ggufUint8 = iota
	ggufInt8
	ggufUint16
	ggufInt16
	ggufUint32
	ggufInt32
	ggufFloat32
	ggufBool
	ggufString
	ggufArray
	ggufUint64
	ggufInt64
	ggufFloat64
)

// ggufFixed — размер значения фиксированной длины, байт.
var ggufFixed = map[uint32]uint64{
	ggufUint8: 1, ggufInt8: 1, ggufUint16: 2, ggufInt16: 2, ggufUint32: 4, ggufInt32: 4,
	ggufFloat32: 4, ggufBool: 1, ggufUint64: 8, ggufInt64: 8, ggufFloat64: 8,
}

// ggmlType — размер блока (элементов) и байт на блок у типов ggml с точно
// известной раскладкой. Для прочих типов проверяются только начало данных
// и выравнивание.
var ggmlType = map[uint32][2]uint64{
	0: {1, 4}, 1: {1, 2}, // F32, F16
	2: {32, 18}, 3: {32, 20}, 6: {32, 22}, 7: {32, 24}, 8: {32, 34}, 9: {32, 36}, // Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q8_1
	10: {256, 84}, 11: {256, 110}, 12: {256, 144}, 13: {256, 176}, 14: {256, 210}, 15: {256, 292}, // Q2_K…Q8_K
	24: {1, 1}, 25: {1, 2}, 26: {1, 4}, 27: {1, 8}, 28: {1, 8}, 30: {1, 2}, // I8, I16, I32, I64, F64, BF16
}

const (
	ggufMaxKey     = 65535
	ggufMaxDims    = 4
	ggufArrayDepth = 2
	ggufDefAlign   = 32
	chatTemplateGG = "tokenizer.chat_template"
)

var errTruncated = errors.New("файл обрезан")

type ggufReader struct {
	r   *bufio.Reader
	pos uint64
	lim Limits
}

func (g *ggufReader) read(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(g.r, b); err != nil {
		return nil, errTruncated
	}
	g.pos += uint64(n)
	return b, nil
}

func (g *ggufReader) u32() (uint32, error) {
	b, err := g.read(4)
	if err != nil {
		return 0, err
	}
	return le32(b), nil
}

func (g *ggufReader) u64() (uint64, error) {
	b, err := g.read(8)
	if err != nil {
		return 0, err
	}
	return le64(b), nil
}

func (g *ggufReader) skip(n uint64) error {
	for n > 0 {
		step := min(n, 1<<30)
		d, err := g.r.Discard(int(step)) //nolint:gosec // G115: шаг не больше 2^30
		g.pos += uint64(d)               //nolint:gosec // G115: d неотрицательно
		if err != nil {
			return errTruncated
		}
		n -= step
	}
	return nil
}

// str читает строку GGUF: max — предел длины, keep — оставить значение.
func (g *ggufReader) str(max uint64, keep bool) (string, error) {
	n, err := g.u64()
	if err != nil {
		return "", err
	}
	if n > max {
		return "", fmt.Errorf("%w: строка %d байт, предел %d", errLimit, n, max)
	}
	if !keep {
		return "", g.skip(n)
	}
	b, err := g.read(int(n)) //nolint:gosec // G115: n не больше предела строки
	return string(b), err
}

// scanGGUF разбирает файл GGUF.
func (s *Scanner) scanGGUF(r io.ReaderAt, size int64, fr *FileReport) {
	err := s.parseGGUF(r, size, fr)
	switch {
	case errors.Is(err, errLimit):
		fr.add(CodeLimitExceeded, SeverityBlock, "GGUF: %v", err)
	case errors.Is(err, errUnsupported):
		fr.add(CodeUnknownFormat, SeverityWarn, "GGUF: %v", err)
	case err != nil:
		fr.add(CodeMalformed, SeverityBlock, "GGUF: %v", err)
	}
}

var errUnsupported = errors.New("не поддерживается")

type ggufTensor struct {
	name          string
	offset, bytes uint64
	sized         bool
}

func (s *Scanner) parseGGUF(r io.ReaderAt, size int64, fr *FileReport) error {
	g := &ggufReader{r: bufio.NewReaderSize(io.NewSectionReader(r, 0, size), 64<<10), lim: s.limits}
	if _, err := g.read(4); err != nil {
		return err
	}
	ver, err := g.u32()
	if err != nil {
		return err
	}
	switch {
	case ver == 2 || ver == 3:
	case ver == 0x02000000 || ver == 0x03000000:
		return fmt.Errorf("%w: GGUF с порядком байт big-endian", errUnsupported)
	case ver > 3:
		return fmt.Errorf("%w: версия %d", errUnsupported, ver)
	default:
		return fmt.Errorf("версия %d устарела и не загружается", ver)
	}
	tensors, err := g.u64()
	if err != nil {
		return err
	}
	kvs, err := g.u64()
	if err != nil {
		return err
	}
	if tensors > s.limits.MaxTensors {
		return fmt.Errorf("%w: тензоров %d, предел %d", errLimit, tensors, s.limits.MaxTensors)
	}
	if kvs > s.limits.MaxGGUFMetadata {
		return fmt.Errorf("%w: записей метаданных %d, предел %d", errLimit, kvs, s.limits.MaxGGUFMetadata)
	}
	align := uint64(ggufDefAlign)
	keys := map[string]bool{}
	for range kvs {
		key, err := g.str(ggufMaxKey, true)
		if err != nil {
			return fmt.Errorf("ключ метаданных: %w", err)
		}
		if keys[key] {
			return fmt.Errorf("повтор ключа %q", clean(key))
		}
		keys[key] = true
		typ, err := g.u32()
		if err != nil {
			return err
		}
		switch {
		case key == "general.alignment":
			if typ != ggufUint32 {
				return errors.New("general.alignment — не uint32")
			}
			v, err := g.u32()
			if err != nil {
				return err
			}
			if v == 0 || v&(v-1) != 0 {
				return fmt.Errorf("выравнивание %d — не степень двойки", v)
			}
			align = uint64(v)
		case key == chatTemplateGG || strings.HasPrefix(key, chatTemplateGG+"."):
			if typ != ggufString {
				return fmt.Errorf("%s — не строка", clean(key))
			}
			n, err := g.u64()
			if err != nil {
				return err
			}
			if n > uint64(s.limits.MaxChatTemplate) { //nolint:gosec // G115: предел положителен
				return fmt.Errorf("%w: шаблон чата %s — %d байт, предел %d", errLimit, clean(key), n, s.limits.MaxChatTemplate)
			}
			b, err := g.read(int(n)) //nolint:gosec // G115: n не больше предела шаблона
			if err != nil {
				return err
			}
			fr.ChatTemplates = append(fr.ChatTemplates, ChatTemplate{
				Source: "gguf", Name: strings.TrimPrefix(strings.TrimPrefix(key, chatTemplateGG), "."), Text: string(b),
			})
		default:
			if err := g.value(typ, 0); err != nil {
				return fmt.Errorf("значение %s: %w", clean(key), err)
			}
		}
	}
	list := make([]ggufTensor, 0, min(tensors, 1<<16))
	names := map[string]bool{}
	for range tensors {
		t, err := g.tensorInfo()
		if err != nil {
			return err
		}
		if names[t.name] {
			return fmt.Errorf("повтор имени тензора %q", clean(t.name))
		}
		names[t.name] = true
		if t.offset%align != 0 {
			return fmt.Errorf("тензор %q: смещение %d не выровнено по %d", clean(t.name), t.offset, align)
		}
		list = append(list, t)
	}
	fr.Tensors = len(list)
	start := (g.pos + align - 1) / align * align
	if start > uint64(size) {
		if len(list) == 0 {
			return nil
		}
		return errors.New("область данных за концом файла")
	}
	dataLen := uint64(size) - start
	sort.Slice(list, func(i, j int) bool { return list[i].offset < list[j].offset })
	var prevEnd uint64
	var prev string
	for _, t := range list {
		if t.offset > dataLen {
			return fmt.Errorf("тензор %q: смещение %d за концом данных (%d байт)", clean(t.name), t.offset, dataLen)
		}
		if t.offset < prevEnd {
			return fmt.Errorf("данные тензоров %q и %q перекрываются", clean(prev), clean(t.name))
		}
		if t.sized {
			if t.bytes > dataLen-t.offset {
				return fmt.Errorf("тензор %q: данные за концом файла", clean(t.name))
			}
			prevEnd, prev = t.offset+t.bytes, t.name
		}
	}
	return nil
}

// value пропускает значение метаданных, проверяя пределы.
func (g *ggufReader) value(typ uint32, depth int) error {
	if n, ok := ggufFixed[typ]; ok {
		return g.skip(n)
	}
	switch typ {
	case ggufString:
		_, err := g.str(g.lim.MaxGGUFString, false)
		return err
	case ggufArray:
		if depth >= ggufArrayDepth {
			return errors.New("слишком глубокая вложенность массивов")
		}
		et, err := g.u32()
		if err != nil {
			return err
		}
		count, err := g.u64()
		if err != nil {
			return err
		}
		if count > g.lim.MaxGGUFArray {
			return fmt.Errorf("%w: элементов массива %d, предел %d", errLimit, count, g.lim.MaxGGUFArray)
		}
		if n, ok := ggufFixed[et]; ok {
			return g.skip(count * n) // count ≤ 2^22, n ≤ 8: без переполнения
		}
		for range count {
			if err := g.value(et, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("неизвестный тип значения %d", typ)
}

func (g *ggufReader) tensorInfo() (ggufTensor, error) {
	name, err := g.str(ggufMaxKey, true)
	if err != nil {
		return ggufTensor{}, fmt.Errorf("имя тензора: %w", err)
	}
	nd, err := g.u32()
	if err != nil {
		return ggufTensor{}, err
	}
	if nd == 0 || nd > ggufMaxDims {
		return ggufTensor{}, fmt.Errorf("тензор %q: размерностей %d", clean(name), nd)
	}
	elems := uint64(1)
	var first uint64
	for i := range nd {
		d, err := g.u64()
		if err != nil {
			return ggufTensor{}, err
		}
		if i == 0 {
			first = d
		}
		hi, lo := bits.Mul64(elems, d)
		if hi != 0 || lo > 1<<62 {
			return ggufTensor{}, fmt.Errorf("тензор %q: переполнение числа элементов", clean(name))
		}
		elems = lo
	}
	typ, err := g.u32()
	if err != nil {
		return ggufTensor{}, err
	}
	off, err := g.u64()
	if err != nil {
		return ggufTensor{}, err
	}
	t := ggufTensor{name: name, offset: off}
	if bt, ok := ggmlType[typ]; ok {
		if first%bt[0] != 0 {
			return ggufTensor{}, fmt.Errorf("тензор %q: первая размерность %d не кратна блоку %d", clean(name), first, bt[0])
		}
		hi, lo := bits.Mul64(elems/bt[0], bt[1])
		if hi != 0 {
			return ggufTensor{}, fmt.Errorf("тензор %q: переполнение размера", clean(name))
		}
		t.bytes, t.sized = lo, true
	}
	return t, nil
}
