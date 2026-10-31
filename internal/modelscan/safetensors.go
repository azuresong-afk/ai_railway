package modelscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"sort"
)

// Формат safetensors: 8 байт длины заголовка (little-endian), заголовок JSON
// и данные. Заголовок — объект «имя тензора → {dtype, shape, data_offsets}»
// и необязательный __metadata__ (строки). Смещения отсчитываются от начала
// данных; каждый тензор — внутри файла, тензоры не перекрываются, размер
// совпадает с типом и формой.

// dtypeBits — размер элемента в битах для известных типов.
var dtypeBits = map[string]uint64{
	"BOOL": 8, "U8": 8, "I8": 8, "F8_E5M2": 8, "F8_E4M3": 8, "F8_E8M0": 8,
	"I16": 16, "U16": 16, "F16": 16, "BF16": 16,
	"I32": 32, "U32": 32, "F32": 32,
	"I64": 64, "U64": 64, "F64": 64, "C64": 64,
	"F4": 4, "F6_E2M3": 6, "F6_E3M2": 6,
}

type tensorSpan struct {
	name       string
	begin, end uint64
}

func (s *Scanner) scanSafetensors(r io.ReaderAt, size int64, fr *FileReport) {
	var pre [8]byte
	if _, err := r.ReadAt(pre[:], 0); err != nil {
		fr.add(CodeMalformed, SeverityBlock, "safetensors: обрезанная длина заголовка")
		return
	}
	n := le64(pre[:])
	if n > s.limits.MaxSafetensorsHeader {
		fr.add(CodeLimitExceeded, SeverityBlock, "safetensors: заголовок %d байт, предел %d", n, s.limits.MaxSafetensorsHeader)
		return
	}
	if n > uint64(size)-8 {
		fr.add(CodeMalformed, SeverityBlock, "safetensors: обрезанный заголовок (%d байт заявлено, в файле %d)", n, size-8)
		return
	}
	header := make([]byte, n)
	if _, err := r.ReadAt(header, 8); err != nil {
		fr.add(CodeMalformed, SeverityBlock, "safetensors: заголовок не прочитан")
		return
	}
	spans, err := parseSafetensorsHeader(header, uint64(size)-8-n, s.limits.MaxTensors)
	switch {
	case errors.Is(err, errLimit):
		fr.add(CodeLimitExceeded, SeverityBlock, "safetensors: тензоров больше %d", s.limits.MaxTensors)
	case err != nil:
		fr.add(CodeMalformed, SeverityBlock, "safetensors: %v", err)
	default:
		fr.Tensors = len(spans)
	}
}

// parseSafetensorsHeader проверяет заголовок; dataLen — размер области данных.
func parseSafetensorsHeader(header []byte, dataLen, maxTensors uint64) ([]tensorSpan, error) {
	dec := json.NewDecoder(bytes.NewReader(header))
	dec.UseNumber()
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var spans []tensorSpan
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("заголовок: %w", err)
		}
		name, _ := tok.(string)
		if seen[name] {
			return nil, fmt.Errorf("повтор имени %q в заголовке", clean(name))
		}
		seen[name] = true
		if name == "__metadata__" {
			var meta map[string]string
			if err := dec.Decode(&meta); err != nil {
				return nil, errors.New("__metadata__ — не объект со строками")
			}
			continue
		}
		if uint64(len(spans)) >= maxTensors {
			return nil, errLimit
		}
		var t struct {
			DType       *string       `json:"dtype"`
			Shape       []json.Number `json:"shape"`
			DataOffsets []json.Number `json:"data_offsets"`
		}
		if err := dec.Decode(&t); err != nil {
			return nil, fmt.Errorf("тензор %q: описание не по формату", clean(name))
		}
		span, err := checkTensor(name, t.DType, t.Shape, t.DataOffsets, dataLen)
		if err != nil {
			return nil, err
		}
		spans = append(spans, span)
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, err
	}
	// После объекта допускаются только пробелы (выравнивание заголовка).
	if len(bytes.Trim(header[dec.InputOffset():], " ")) != 0 {
		return nil, errors.New("данные после заголовка JSON")
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].begin != spans[j].begin {
			return spans[i].begin < spans[j].begin
		}
		return spans[i].end < spans[j].end
	})
	var prev *tensorSpan
	for i := range spans {
		cur := &spans[i]
		if cur.begin == cur.end {
			continue
		}
		if prev != nil && cur.begin < prev.end {
			return nil, fmt.Errorf("данные тензоров %q и %q перекрываются", clean(prev.name), clean(cur.name))
		}
		prev = cur
	}
	return spans, nil
}

func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("заголовок: %w", err)
	}
	if tok != d {
		return fmt.Errorf("заголовок: ожидается %q", d)
	}
	return nil
}

func checkTensor(name string, dtype *string, shape, offsets []json.Number, dataLen uint64) (tensorSpan, error) {
	bad := func(what string) (tensorSpan, error) {
		return tensorSpan{}, fmt.Errorf("тензор %q: %s", clean(name), what)
	}
	if dtype == nil || len(offsets) != 2 || shape == nil {
		return bad("нет dtype, shape или data_offsets")
	}
	begin, err1 := parseUint(offsets[0])
	end, err2 := parseUint(offsets[1])
	if err1 != nil || err2 != nil {
		return bad("смещения — не целые неотрицательные числа")
	}
	if begin > end {
		return bad("начало данных после конца")
	}
	if end > dataLen {
		return bad(fmt.Sprintf("смещение %d за концом данных (%d байт)", end, dataLen))
	}
	elems := uint64(1)
	for _, d := range shape {
		v, err := parseUint(d)
		if err != nil {
			return bad("размерность — не целое неотрицательное число")
		}
		hi, lo := bits.Mul64(elems, v)
		if hi != 0 {
			return bad("переполнение числа элементов")
		}
		elems = lo
	}
	if b, ok := dtypeBits[*dtype]; ok {
		hi, total := bits.Mul64(elems, b)
		if hi != 0 || total%8 == 0 && total/8 != end-begin {
			return bad(fmt.Sprintf("размер данных %d не совпадает с типом %s и формой", end-begin, clean(*dtype)))
		}
	}
	return tensorSpan{name: name, begin: begin, end: end}, nil
}

func parseUint(n json.Number) (uint64, error) {
	s := string(n)
	if s == "" || s[0] == '-' {
		return 0, errors.New("отрицательное")
	}
	var v uint64
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, errors.New("не целое")
		}
		hi, lo := bits.Mul64(v, 10)
		lo2, carry := bits.Add64(lo, uint64(c-'0'), 0)
		if hi != 0 || carry != 0 {
			return 0, errors.New("переполнение")
		}
		v = lo2
	}
	return v, nil
}
