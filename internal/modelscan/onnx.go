package modelscan

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Минимальный разбор ONNX (onnx/onnx.proto) своим кодом, без библиотеки
// protobuf: читаются только поля, нужные проверке, — наборы операторов
// (opset_import), узлы графов и функций (домен и тип оператора), тензоры
// (внешние данные), вложенные графы атрибутов и обучения. Остальные поля,
// в том числе веса raw_data, пропускаются потоком, не попадая в память.

// Номера полей ONNX.
const (
	modelGraph     = 7
	modelOpset     = 8
	modelTraining  = 20
	modelFunctions = 25

	opsetDomain = 1

	graphNode        = 1
	graphInitializer = 5
	graphSparseInit  = 15

	nodeAttribute = 5
	nodeOpType    = 4
	nodeDomain    = 7

	attrT             = 5
	attrG             = 6
	attrTensors       = 10
	attrGraphs        = 11
	attrSparseTensor  = 22
	attrSparseTensors = 23

	tensorExternal = 13
	tensorLocation = 14

	sparseValues  = 1
	sparseIndices = 2

	funcName   = 1
	funcNode   = 7
	funcOpset  = 9
	funcDomain = 10

	trainInit = 1
	trainAlgo = 2

	entryKey   = 1
	entryValue = 2

	locationExternal = 1
)

const (
	wireVarint = 0
	wireI64    = 1
	wireLen    = 2
	wireI32    = 5
	// maxONNXString — строка, которую разбор оставляет в памяти (домен, тип
	// оператора, ключ и значение внешних данных).
	maxONNXString = 4096
	// maxONNXOpsInDetail — типов операторов домена в пояснении.
	maxONNXOpsInDetail = 5
)

// onnxStandard — домены стандартных операторов.
func onnxStandard(domain string) bool {
	return domain == "" || domain == "ai.onnx" || domain == "ai.onnx.ml"
}

type pbReader struct {
	r     *bufio.Reader
	pos   int64
	items int
	lim   Limits
}

func (p *pbReader) readByte() (byte, error) {
	b, err := p.r.ReadByte()
	if err != nil {
		return 0, errTruncated
	}
	p.pos++
	return b, nil
}

func (p *pbReader) varint() (uint64, error) {
	var v uint64
	for shift := uint(0); shift < 64; shift += 7 {
		b, err := p.readByte()
		if err != nil {
			return 0, err
		}
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			if shift == 63 && b > 1 {
				return 0, errors.New("переполнение varint")
			}
			return v, nil
		}
	}
	return 0, errors.New("слишком длинный varint")
}

func (p *pbReader) skip(n int64) error {
	for n > 0 {
		step := min(n, 1<<30)
		d, err := p.r.Discard(int(step))
		p.pos += int64(d)
		if err != nil {
			return errTruncated
		}
		n -= step
	}
	return nil
}

// field читает ключ поля в пределах end: номер, тип и длину (для LEN).
func (p *pbReader) field(end int64) (num uint64, wt uint64, n int64, err error) {
	k, err := p.varint()
	if err != nil {
		return 0, 0, 0, err
	}
	num, wt = k>>3, k&7
	if num == 0 {
		return 0, 0, 0, errors.New("поле с номером 0")
	}
	if wt == wireLen {
		l, err := p.varint()
		if err != nil {
			return 0, 0, 0, err
		}
		if l > uint64(end-p.pos) { //nolint:gosec // G115: end ≥ pos внутри сообщения
			return 0, 0, 0, errors.New("длина поля за границей сообщения")
		}
		n = int64(l) //nolint:gosec // G115: l не больше остатка сообщения
	}
	return num, wt, n, nil
}

// skipValue пропускает значение поля.
func (p *pbReader) skipValue(wt uint64, n int64) error {
	switch wt {
	case wireVarint:
		_, err := p.varint()
		return err
	case wireI64:
		return p.skip(8)
	case wireI32:
		return p.skip(4)
	case wireLen:
		return p.skip(n)
	}
	return fmt.Errorf("тип поля protobuf %d не поддерживается", wt)
}

func (p *pbReader) str(n int64) (string, error) {
	if n > maxONNXString {
		return "", fmt.Errorf("%w: строка %d байт, предел %d", errLimit, n, maxONNXString)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(p.r, b); err != nil {
		return "", errTruncated
	}
	p.pos += n
	return string(b), nil
}

// onnxModel — то, что разбор собрал из модели.
type onnxModel struct {
	opsets   map[string]bool
	ops      map[string]map[string]bool // домен → типы операторов
	funcs    map[[2]string]bool         // (домен, имя) локальных функций
	external []externalRef
	extSeen  map[externalRef]bool
	bad      []string // ошибки внешних данных (запись пути)
}

type onnxParser struct {
	p *pbReader
	m *onnxModel
}

// message читает сообщение длиной n: для каждого поля вызывает fn, которая
// возвращает handled=false для пропуска.
func (o *onnxParser) message(n int64, depth int, fn func(num, wt uint64, n int64, depth int) (bool, error)) error {
	if depth > o.p.lim.MaxONNXDepth {
		return fmt.Errorf("%w: вложенность больше %d", errLimit, o.p.lim.MaxONNXDepth)
	}
	end := o.p.pos + n
	for o.p.pos < end {
		num, wt, ln, err := o.p.field(end)
		if err != nil {
			return err
		}
		handled, err := fn(num, wt, ln, depth)
		if err != nil {
			return err
		}
		if !handled {
			if err := o.p.skipValue(wt, ln); err != nil {
				return err
			}
		}
		if o.p.pos > end {
			return errors.New("поле за границей сообщения")
		}
	}
	return nil
}

func (o *onnxParser) count() error {
	o.p.items++
	if o.p.items > o.p.lim.MaxONNXItems {
		return fmt.Errorf("%w: узлов, тензоров и графов больше %d", errLimit, o.p.lim.MaxONNXItems)
	}
	return nil
}

func wantLen(wt uint64) error {
	if wt != wireLen {
		return errors.New("вложенное сообщение не того типа поля")
	}
	return nil
}

func (o *onnxParser) model(n int64) error {
	return o.message(n, 0, func(num, wt uint64, ln int64, depth int) (bool, error) {
		switch num {
		case modelGraph:
			return true, o.sub(wt, ln, depth, o.graph)
		case modelOpset:
			return true, o.sub(wt, ln, depth, o.opset)
		case modelTraining:
			return true, o.sub(wt, ln, depth, o.training)
		case modelFunctions:
			return true, o.sub(wt, ln, depth, o.function)
		}
		return false, nil
	})
}

func (o *onnxParser) sub(wt uint64, ln int64, depth int, fn func(int64, int) error) error {
	if err := wantLen(wt); err != nil {
		return err
	}
	return fn(ln, depth+1)
}

func (o *onnxParser) opset(n int64, depth int) error {
	return o.message(n, depth, func(num, wt uint64, ln int64, _ int) (bool, error) {
		if num != opsetDomain {
			return false, nil
		}
		if err := wantLen(wt); err != nil {
			return true, err
		}
		d, err := o.p.str(ln)
		if err == nil {
			o.m.opsets[d] = true
		}
		return true, err
	})
}

func (o *onnxParser) graph(n int64, depth int) error {
	if err := o.count(); err != nil {
		return err
	}
	return o.message(n, depth, func(num, wt uint64, ln int64, depth int) (bool, error) {
		switch num {
		case graphNode:
			return true, o.sub(wt, ln, depth, o.node)
		case graphInitializer:
			return true, o.sub(wt, ln, depth, o.tensor)
		case graphSparseInit:
			return true, o.sub(wt, ln, depth, o.sparse)
		}
		return false, nil
	})
}

func (o *onnxParser) training(n int64, depth int) error {
	return o.message(n, depth, func(num, wt uint64, ln int64, depth int) (bool, error) {
		if num == trainInit || num == trainAlgo {
			return true, o.sub(wt, ln, depth, o.graph)
		}
		return false, nil
	})
}

func (o *onnxParser) function(n int64, depth int) error {
	if err := o.count(); err != nil {
		return err
	}
	var domain, name string
	err := o.message(n, depth, func(num, wt uint64, ln int64, depth int) (bool, error) {
		switch num {
		case funcName, funcDomain:
			if err := wantLen(wt); err != nil {
				return true, err
			}
			s, err := o.p.str(ln)
			if num == funcName {
				name = s
			} else {
				domain = s
			}
			return true, err
		case funcNode:
			return true, o.sub(wt, ln, depth, o.node)
		case funcOpset:
			return true, o.sub(wt, ln, depth, o.opset)
		}
		return false, nil
	})
	o.m.funcs[[2]string{domain, name}] = true
	return err
}

func (o *onnxParser) node(n int64, depth int) error {
	if err := o.count(); err != nil {
		return err
	}
	var domain, op string
	err := o.message(n, depth, func(num, wt uint64, ln int64, depth int) (bool, error) {
		switch num {
		case nodeOpType, nodeDomain:
			if err := wantLen(wt); err != nil {
				return true, err
			}
			s, err := o.p.str(ln)
			if num == nodeOpType {
				op = s
			} else {
				domain = s
			}
			return true, err
		case nodeAttribute:
			return true, o.sub(wt, ln, depth, o.attribute)
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	if o.m.ops[domain] == nil {
		o.m.ops[domain] = map[string]bool{}
	}
	o.m.ops[domain][op] = true
	return nil
}

func (o *onnxParser) attribute(n int64, depth int) error {
	return o.message(n, depth, func(num, wt uint64, ln int64, depth int) (bool, error) {
		switch num {
		case attrT, attrTensors:
			return true, o.sub(wt, ln, depth, o.tensor)
		case attrG, attrGraphs:
			return true, o.sub(wt, ln, depth, o.graph)
		case attrSparseTensor, attrSparseTensors:
			return true, o.sub(wt, ln, depth, o.sparse)
		}
		return false, nil
	})
}

func (o *onnxParser) sparse(n int64, depth int) error {
	return o.message(n, depth, func(num, wt uint64, ln int64, depth int) (bool, error) {
		if num == sparseValues || num == sparseIndices {
			return true, o.sub(wt, ln, depth, o.tensor)
		}
		return false, nil
	})
}

func (o *onnxParser) tensor(n int64, depth int) error {
	if err := o.count(); err != nil {
		return err
	}
	var location uint64
	entries := map[string]string{}
	err := o.message(n, depth, func(num, wt uint64, ln int64, depth int) (bool, error) {
		switch num {
		case tensorLocation:
			if wt != wireVarint {
				return true, errors.New("data_location не того типа поля")
			}
			v, err := o.p.varint()
			location = v
			return true, err
		case tensorExternal:
			if err := wantLen(wt); err != nil {
				return true, err
			}
			var key, value string
			err := o.message(ln, depth+1, func(num, wt uint64, ln int64, _ int) (bool, error) {
				if num != entryKey && num != entryValue {
					return false, nil
				}
				if err := wantLen(wt); err != nil {
					return true, err
				}
				s, err := o.p.str(ln)
				if num == entryKey {
					key = s
				} else {
					value = s
				}
				return true, err
			})
			if _, dup := entries[key]; dup && err == nil {
				err = fmt.Errorf("повтор ключа внешних данных %q", clean(key))
			}
			entries[key] = value
			return true, err
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	if location != locationExternal {
		return nil
	}
	return o.m.addExternal(entries)
}

// addExternal проверяет запись пути внешних данных: относительный путь
// через «/» внутри каталога модели, без «..», «\», «:» и управляющих символов.
func (m *onnxModel) addExternal(entries map[string]string) error {
	loc, ok := entries["location"]
	if !ok || loc == "" {
		return errors.New("у тензора с внешними данными нет location")
	}
	ref := externalRef{location: loc}
	var err error
	if v, ok := entries["offset"]; ok {
		if ref.offset, err = strconv.ParseUint(v, 10, 63); err != nil {
			return errors.New("offset внешних данных — не число")
		}
		ref.hasRange = true
	}
	if v, ok := entries["length"]; ok {
		if ref.length, err = strconv.ParseUint(v, 10, 63); err != nil {
			return errors.New("length внешних данных — не число")
		}
		ref.hasRange = true
	}
	if why := badLocation(loc); why != "" {
		if len(m.bad) < maxFindingsPerFile {
			m.bad = append(m.bad, fmt.Sprintf("внешние данные %s: %s", clean(loc), why))
		}
		return nil
	}
	if !m.extSeen[ref] {
		m.extSeen[ref] = true
		m.external = append(m.external, ref)
	}
	return nil
}

// badLocation — причина, по которой путь внешних данных выходит за каталог
// модели, или пусто.
func badLocation(loc string) string {
	switch {
	case strings.HasPrefix(loc, "/") || path.IsAbs(loc):
		return "абсолютный путь"
	case strings.ContainsAny(loc, "\\:"):
		return "путь с «\\» или «:» (имя диска, поток NTFS)"
	}
	for _, r := range loc {
		if r < 0x20 || r == 0x7f {
			return "управляющий символ в пути"
		}
	}
	for _, part := range strings.Split(loc, "/") {
		if part == ".." {
			return "выход за каталог модели через «..»"
		}
		if part == "" {
			return "пустой элемент пути"
		}
	}
	return ""
}

// isONNX — начало ModelProto: поле 1 (ir_version) varint от 1 до 100 и за
// ним поле модели с допустимым типом.
func isONNX(head []byte) bool {
	if len(head) < 3 || head[0] != 0x08 {
		return false
	}
	p := &pbReader{r: bufio.NewReader(strings.NewReader(string(head[1:])))}
	ir, err := p.varint()
	if err != nil || ir == 0 || ir > 100 {
		return false
	}
	k, err := p.varint()
	if err != nil {
		return false
	}
	num, wt := k>>3, k&7
	switch num {
	case 2, 3, 4, 6, 7, 8, 14, 20, 25:
		return wt == wireLen
	case 5:
		return wt == wireVarint
	}
	return false
}

// scanONNX разбирает модель ONNX.
func (s *Scanner) scanONNX(r io.ReaderAt, size int64, fr *FileReport) {
	m := &onnxModel{
		opsets: map[string]bool{}, ops: map[string]map[string]bool{},
		funcs: map[[2]string]bool{}, extSeen: map[externalRef]bool{},
	}
	o := &onnxParser{p: &pbReader{r: bufio.NewReaderSize(io.NewSectionReader(r, 0, size), 64<<10), lim: s.limits}, m: m}
	err := o.model(size)
	switch {
	case errors.Is(err, errLimit):
		fr.add(CodeLimitExceeded, SeverityBlock, "ONNX: %v", err)
		return
	case err != nil:
		fr.add(CodeMalformed, SeverityBlock, "ONNX: %v", err)
		return
	}
	fr.Tensors = o.p.items
	localDomains := map[string]bool{}
	for k := range m.funcs {
		localDomains[k[0]] = true
	}
	domains := map[string]bool{}
	for d := range m.opsets {
		domains[d] = true
	}
	for d := range m.ops {
		domains[d] = true
	}
	sorted := make([]string, 0, len(domains))
	for d := range domains {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)
	for _, d := range sorted {
		if onnxStandard(d) {
			continue
		}
		var foreign []string
		for op := range m.ops[d] {
			if !m.funcs[[2]string{d, op}] {
				foreign = append(foreign, op)
			}
		}
		if len(foreign) == 0 && (localDomains[d] || len(m.ops[d]) > 0) {
			continue // только локальные функции модели
		}
		sort.Strings(foreign)
		detail := fmt.Sprintf("операторы домена %q", clean(d))
		if len(foreign) > 0 {
			shown := foreign[:min(len(foreign), maxONNXOpsInDetail)]
			for i := range shown {
				shown[i] = clean(shown[i])
			}
			detail += ": " + strings.Join(shown, ", ")
			if len(foreign) > maxONNXOpsInDetail {
				detail += fmt.Sprintf(" и ещё %d", len(foreign)-maxONNXOpsInDetail)
			}
		} else {
			detail += " (набор операторов без узлов)"
		}
		fr.add(CodeONNXDomain, SeverityWarn, "%s — вне ai.onnx и ai.onnx.ml; для загрузки нужна библиотека операторов", detail)
	}
	for _, b := range m.bad {
		fr.add(CodeExternalData, SeverityBlock, "%s", b)
	}
	fr.external = m.external
}
