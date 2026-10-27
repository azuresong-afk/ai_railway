// Пакет argschema — ограничения аргументов вызова инструмента агентом
// (ТЗ 5.10; ADR-0023, раздел 3; DM-21): своё подмножество JSON Schema без
// внешних библиотек и без разрешения ссылок, строгий разбор аргументов и
// собственные ключевые слова x-aisec-path-prefix и x-aisec-domains.
//
// Незнакомое ключевое слово — ошибка, а не пропуск: пропуск молча ослабил
// бы проверку. Схема разбирается при сохранении версии политики и при
// чтении пакета в шлюзе. Пакет без сети и без ввода-вывода: его используют
// сервер (проверка политики) и шлюз (вызовы инструментов, задача 4.11).
package argschema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode/utf8"
)

// Пределы схемы (ADR-0023, раздел 3).
const (
	// MaxSchemaSize — байт в схеме одного правила (каноничный JSON).
	MaxSchemaSize = 16 << 10
	// MaxSchemaDepth — вложенность схем (properties, items).
	MaxSchemaDepth = 8
	// MaxSchemaNodes — схем (объектов-узлов) в одной схеме правила.
	MaxSchemaNodes = 256
	// MaxPatternsPerPolicy — выражений pattern во всех правилах политики;
	// считает вызывающий по Schema.Patterns.
	MaxPatternsPerPolicy = 64
	// MaxPathPrefixes — префиксов x-aisec-path-prefix в одной схеме правила.
	MaxPathPrefixes = 32
	// MaxDomains — доменов x-aisec-domains в одной схеме правила.
	MaxDomains = 256
	// MaxEnum — значений в enum.
	MaxEnum = 64
	// MaxPatternLen и MaxPatternInsts — пределы pattern, как у словарей
	// lists (ТЗ 5.2): RE2 работает за линейное время, размер программы
	// ограничен.
	MaxPatternLen   = 512
	MaxPatternInsts = 4000
	// MaxPathPrefixLen — байт в одном префиксе пути.
	MaxPathPrefixLen = 512
	// MaxKeyLen — байт в имени свойства и строковом значении схемы.
	MaxKeyLen = 1024
)

// schemaLimits — пределы разбора документа схемы: глубина JSON больше
// глубины схем (properties — два уровня на одну схему).
var schemaLimits = Limits{MaxSize: MaxSchemaSize, MaxDepth: 2*MaxSchemaDepth + 4, MaxValues: 4096, MaxString: MaxKeyLen}

// Типы JSON Schema — биты маски.
const (
	tObject uint8 = 1 << iota
	tArray
	tString
	tInteger
	tNumber
	tBoolean
	tNull
)

var typeBits = map[string]uint8{"object": tObject, "array": tArray, "string": tString, "integer": tInteger,
	"number": tNumber, "boolean": tBoolean, "null": tNull}

// Schema — проверенная схема. Неизменяема и безопасна для одновременного
// использования.
type Schema struct {
	types      uint8 // 0 — любой тип
	properties map[string]*Schema
	required   []string
	// additional — разрешены свойства вне properties (по умолчанию, как в
	// JSON Schema).
	additional         bool
	items              *Schema
	minItems, maxItems int // -1 — нет ограничения
	enum               []Value
	constant           *Value
	minimum, maximum   *big.Rat
	exMinimum          *big.Rat
	exMaximum          *big.Rat
	minLength          int // -1 — нет ограничения
	maxLength          int
	pattern            *regexp.Regexp
	pathPrefixes       []string
	domains            []string

	// Только у корня: число pattern и узлов во всей схеме.
	patterns, nodes int
}

// Patterns — выражений pattern во всей схеме (предел на политику —
// MaxPatternsPerPolicy).
func (s *Schema) Patterns() int { return s.patterns }

// ErrUnsupported — ключевое слово вне подмножества (ADR-0023, раздел 3).
var ErrUnsupported = errors.New("ключевое слово не поддерживается")

// unsupported — ключевые слова JSON Schema, которые отвергаются с
// объяснением (остальные незнакомые — тоже ошибка).
var unsupported = map[string]string{
	"$ref": "ссылки не поддерживаются", "$defs": "ссылки не поддерживаются", "definitions": "ссылки не поддерживаются",
	"$id": "ссылки не поддерживаются", "$schema": "удалённые схемы не поддерживаются", "$anchor": "ссылки не поддерживаются",
	"$dynamicRef": "ссылки не поддерживаются", "oneOf": "комбинации схем не поддерживаются",
	"anyOf": "комбинации схем не поддерживаются", "allOf": "комбинации схем не поддерживаются",
	"not": "комбинации схем не поддерживаются", "if": "условные схемы не поддерживаются",
	"then": "условные схемы не поддерживаются", "else": "условные схемы не поддерживаются",
	"patternProperties": "patternProperties не поддерживается", "dependentSchemas": "dependentSchemas не поддерживается",
	"dependentRequired": "dependentRequired не поддерживается", "format": "format не поддерживается",
	"unevaluatedProperties": "unevaluated* не поддерживается", "unevaluatedItems": "unevaluated* не поддерживается",
	"prefixItems": "prefixItems не поддерживается", "contains": "contains не поддерживается",
	"propertyNames": "propertyNames не поддерживается",
}

// Parse строго разбирает схему из JSON и проверяет её (FuzzParseArgSchema).
func Parse(data []byte) (*Schema, error) {
	if len(data) > MaxSchemaSize {
		return nil, fmt.Errorf("схема больше %d байт", MaxSchemaSize)
	}
	v, err := ParseJSON(data, schemaLimits)
	if err != nil {
		return nil, fmt.Errorf("схема: %w", err)
	}
	return Compile(v)
}

// CompileAny проверяет схему из дерева значений Go (YAML политики).
func CompileAny(x any) (*Schema, error) {
	v, err := FromAny(x, schemaLimits)
	if err != nil {
		return nil, fmt.Errorf("схема: %w", err)
	}
	return Compile(v)
}

// Compile проверяет схему: только поддерживаемые ключевые слова, пределы
// размера, глубины и числа узлов. Ошибка называет путь в схеме.
func Compile(v Value) (*Schema, error) {
	if v.Kind != Object {
		return nil, errors.New("схема: ожидается объект")
	}
	raw, err := json.Marshal(ToAny(v))
	if err != nil {
		return nil, fmt.Errorf("схема: %w", err)
	}
	if len(raw) > MaxSchemaSize {
		return nil, fmt.Errorf("схема больше %d байт", MaxSchemaSize)
	}
	c := &compiler{}
	s, err := c.schema(v, "", 1)
	if err != nil {
		return nil, err
	}
	if c.prefixes > MaxPathPrefixes {
		return nil, fmt.Errorf("схема: больше %d префиксов x-aisec-path-prefix", MaxPathPrefixes)
	}
	if c.domains > MaxDomains {
		return nil, fmt.Errorf("схема: больше %d доменов x-aisec-domains", MaxDomains)
	}
	s.patterns, s.nodes = c.patterns, c.nodes
	return s, nil
}

type compiler struct {
	nodes, patterns, prefixes, domains int
}

// at — путь в схеме для сообщения об ошибке.
func at(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func (c *compiler) schema(v Value, path string, depth int) (*Schema, error) {
	if v.Kind != Object {
		return nil, fmt.Errorf("схема %s: ожидается объект", at(path))
	}
	if depth > MaxSchemaDepth {
		return nil, fmt.Errorf("схема %s: вложенность больше %d", at(path), MaxSchemaDepth)
	}
	c.nodes++
	if c.nodes > MaxSchemaNodes {
		return nil, fmt.Errorf("схема: больше %d узлов", MaxSchemaNodes)
	}
	s := &Schema{additional: true, minItems: -1, maxItems: -1, minLength: -1, maxLength: -1}
	fail := func(kw, format string, a ...any) error {
		return fmt.Errorf("схема %s: %s — %s", at(path), kw, fmt.Sprintf(format, a...))
	}
	for i, kw := range v.Keys {
		x := v.Vals[i]
		var err error
		switch kw {
		case "type":
			err = s.setType(x)
		case "properties":
			if err := c.properties(s, x, path, depth); err != nil {
				return nil, err
			}
		case "required":
			s.required, err = stringList(x, 1024, false)
		case "additionalProperties":
			if x.Kind != Bool {
				err = errors.New("только true или false")
			}
			s.additional = x.Bool
		case "items":
			s.items, err = c.schema(x, path+"/items", depth+1)
			if err != nil {
				return nil, err
			}
		case "minItems":
			s.minItems, err = count(x)
		case "maxItems":
			s.maxItems, err = count(x)
		case "minLength":
			s.minLength, err = count(x)
		case "maxLength":
			s.maxLength, err = count(x)
		case "enum":
			err = s.setEnum(x)
		case "const":
			if !scalar(x) {
				err = errors.New("только число, строка, true, false или null")
			}
			cv := x
			s.constant = &cv
		case "minimum":
			s.minimum, err = number(x)
		case "maximum":
			s.maximum, err = number(x)
		case "exclusiveMinimum":
			s.exMinimum, err = number(x)
		case "exclusiveMaximum":
			s.exMaximum, err = number(x)
		case "pattern":
			s.pattern, err = compilePattern(x)
			c.patterns++
		case "x-aisec-path-prefix":
			s.pathPrefixes, err = pathPrefixes(x)
			c.prefixes += len(s.pathPrefixes)
		case "x-aisec-domains":
			s.domains, err = domainList(x)
			c.domains += len(s.domains)
		default:
			if why, ok := unsupported[kw]; ok {
				return nil, fmt.Errorf("схема %s: %s — %w: %s", at(path), kw, ErrUnsupported, why)
			}
			return nil, fmt.Errorf("схема %s: %q — %w", at(path), clip(kw), ErrUnsupported)
		}
		if err != nil {
			return nil, fail(kw, "%v", err)
		}
	}
	return s, s.check(path)
}

// check — согласованность ключевых слов одной схемы.
func (s *Schema) check(path string) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("схема %s: %s", at(path), fmt.Sprintf(format, a...))
	}
	if s.minItems >= 0 && s.maxItems >= 0 && s.minItems > s.maxItems {
		return fail("minItems больше maxItems")
	}
	if s.minLength >= 0 && s.maxLength >= 0 && s.minLength > s.maxLength {
		return fail("minLength больше maxLength")
	}
	if s.minimum != nil && s.maximum != nil && s.minimum.Cmp(s.maximum) > 0 {
		return fail("minimum больше maximum")
	}
	// Собственные ключевые слова проверяют только строки: без type: string
	// значение другого типа (массив путей) прошло бы мимо проверки. Поэтому
	// они требуют явного type: string, хотя JSON Schema просто пропустила
	// бы проверку для другого типа.
	if (s.pathPrefixes != nil || s.domains != nil) && s.types != tString {
		return fail("x-aisec-path-prefix и x-aisec-domains — только вместе с type: string")
	}
	if !s.additional && s.properties == nil {
		// Объект без свойств: допускается, разрешён только пустой объект.
		s.properties = map[string]*Schema{}
	}
	return nil
}

func (s *Schema) setType(x Value) error {
	add := func(v Value) error {
		if v.Kind != String {
			return errors.New("имя типа — строка")
		}
		b, ok := typeBits[v.Str]
		if !ok {
			return fmt.Errorf("неизвестный тип %q", clip(v.Str))
		}
		if s.types&b != 0 {
			return fmt.Errorf("тип %s указан дважды", v.Str)
		}
		s.types |= b
		return nil
	}
	switch x.Kind {
	case String:
		return add(x)
	case Array:
		if len(x.Arr) == 0 {
			return errors.New("пустой список типов")
		}
		for _, v := range x.Arr {
			if err := add(v); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("строка или список строк")
}

func (c *compiler) properties(s *Schema, x Value, path string, depth int) error {
	if x.Kind != Object {
		return fmt.Errorf("схема %s: properties — ожидается объект", at(path))
	}
	s.properties = make(map[string]*Schema, len(x.Keys))
	for i, name := range x.Keys {
		if len(name) > MaxKeyLen {
			return fmt.Errorf("схема %s: properties — слишком длинное имя свойства", at(path))
		}
		ps, err := c.schema(x.Vals[i], path+"/properties/"+escapePointer(name), depth+1)
		if err != nil {
			return err
		}
		s.properties[name] = ps
	}
	return nil
}

func (s *Schema) setEnum(x Value) error {
	if x.Kind != Array || len(x.Arr) == 0 || len(x.Arr) > MaxEnum {
		return fmt.Errorf("список от 1 до %d значений", MaxEnum)
	}
	for i, v := range x.Arr {
		if !scalar(v) {
			return errors.New("только числа, строки, true, false и null")
		}
		if slices.ContainsFunc(x.Arr[:i], func(o Value) bool { return Equal(o, v) }) {
			return errors.New("значения без повторов")
		}
	}
	s.enum = x.Arr
	return nil
}

func scalar(v Value) bool { return v.Kind != Array && v.Kind != Object }

// count — неотрицательное целое до 1<<30.
func count(x Value) (int, error) {
	if x.Kind != Number || !x.Num.IsInt() || x.Num.Sign() < 0 || x.Num.Num().Cmp(big.NewInt(1<<30)) > 0 {
		return 0, errors.New("целое от 0")
	}
	return int(x.Num.Num().Int64()), nil
}

func number(x Value) (*big.Rat, error) {
	if x.Kind != Number {
		return nil, errors.New("ожидается число")
	}
	return x.Num, nil
}

// stringList — список строк без повторов не длиннее max.
func stringList(x Value, max int, nonEmpty bool) ([]string, error) {
	if x.Kind != Array || len(x.Arr) > max || nonEmpty && len(x.Arr) == 0 {
		return nil, fmt.Errorf("список до %d строк", max)
	}
	out := make([]string, 0, len(x.Arr))
	for _, v := range x.Arr {
		if v.Kind != String {
			return nil, errors.New("элементы — строки")
		}
		if slices.Contains(out, v.Str) {
			return nil, fmt.Errorf("значение %q указано дважды", clip(v.Str))
		}
		out = append(out, v.Str)
	}
	return out, nil
}

// compilePattern — RE2 не длиннее MaxPatternLen байт и не больше
// MaxPatternInsts инструкций. Смысл как в JSON Schema: без привязки к
// началу и концу строки.
func compilePattern(x Value) (*regexp.Regexp, error) {
	if x.Kind != String || x.Str == "" || len(x.Str) > MaxPatternLen {
		return nil, fmt.Errorf("строка от 1 до %d байт", MaxPatternLen)
	}
	re, err := syntax.Parse(x.Str, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("неверное выражение: %s", syntaxCode(err))
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, fmt.Errorf("неверное выражение: %s", syntaxCode(err))
	}
	if len(prog.Inst) > MaxPatternInsts {
		return nil, fmt.Errorf("слишком большое выражение (%d инструкций, предел %d)", len(prog.Inst), MaxPatternInsts)
	}
	return regexp.Compile(x.Str)
}

// syntaxCode — код ошибки выражения без фрагмента недоверенной строки.
func syntaxCode(err error) string {
	var se *syntax.Error
	if errors.As(err, &se) {
		return string(se.Code)
	}
	return "синтаксис"
}

// clip укорачивает недоверенную строку для сообщения об ошибке.
func clip(s string) string {
	if len(s) <= 64 {
		return s
	}
	cut := 64
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// escapePointer — экранирование части JSON Pointer (RFC 6901).
func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
