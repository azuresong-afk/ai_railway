// Пакет mcp — разбор и сборка сообщений Model Context Protocol для
// MCP-прокси шлюза (ADR-0023, раздел 6; задача 4.11). Пакет без сетевого
// кода: JSON-RPC, заголовки транспорта Streamable HTTP, чтение потока SSE,
// результаты tools/list и tools/call, вырезание возможностей клиента.
//
// Всё, что приходит от клиента и от вышестоящего сервера, — недоверенный
// ввод. Разбор строгий (argschema.ParseJSON): повтор ключа, неверный UTF-8,
// одиночный суррогат и данные после документа — отказ, иначе шлюз и сервер
// прочли бы одно сообщение по-разному. Наружу сообщение уходит собранным
// заново (Encode) из проверенного дерева, а не исходными байтами.
package mcp

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

// Ревизии MCP, которые понимает прокси (ADR-0023, раздел 6). Переводить
// одну в другую шлюз не умеет: вышестоящий сервер должен поддерживать
// версию клиента.
const (
	Version20251125 = "2025-11-25"
	Version20260728 = "2026-07-28"
)

// Versions — поддерживаемые ревизии по порядку.
var Versions = []string{Version20251125, Version20260728}

// Supported — ревизия поддерживается прокси.
func Supported(v string) bool { return slices.Contains(Versions, v) }

// Коды ошибок JSON-RPC и MCP (схема 2026-07-28).
const (
	CodeParseError         = -32700
	CodeInvalidRequest     = -32600
	CodeMethodNotFound     = -32601
	CodeInvalidParams      = -32602
	CodeInternalError      = -32603
	CodeHeaderMismatch     = -32020
	CodeMissingCapability  = -32021
	CodeUnsupportedVersion = -32022
)

// Пределы сообщения JSON-RPC (ADR-0023, раздел 6).
const (
	// MaxDepth — вложенность массивов и объектов.
	MaxDepth = 32
	// MaxMessage — сообщение вышестоящего сервера (JSON или событие SSE).
	MaxMessage = 4 << 20
	// MaxIDLen — строковый id запроса.
	MaxIDLen = 128
	// MaxMethodLen — имя метода.
	MaxMethodLen = 128
	maxValues    = 200000
)

// Limits — пределы разбора сообщения размером до size байт.
func Limits(size int) argschema.Limits {
	return argschema.Limits{MaxSize: size, MaxDepth: MaxDepth, MaxValues: maxValues, MaxString: size}
}

// Kind — вид сообщения JSON-RPC.
type Kind uint8

// Виды сообщений.
const (
	KindRequest Kind = iota + 1
	KindNotification
	KindResult
	KindError
)

func (k Kind) String() string {
	switch k {
	case KindRequest:
		return "request"
	case KindNotification:
		return "notification"
	case KindResult:
		return "result"
	case KindError:
		return "error"
	}
	return "unknown"
}

// Message — одно сообщение JSON-RPC 2.0.
type Message struct {
	Kind Kind
	// ID — строка или целое; у уведомления нет (HasID = false). У ошибки
	// разбора id бывает null — тогда HasID = true и ID.Kind = Null.
	ID     argschema.Value
	HasID  bool
	Method string
	// Params — объект параметров (nil — нет); Result — результат
	// (объект); Error — объект ошибки с code и message.
	Params *argschema.Value
	Result *argschema.Value
	Error  *argschema.Value
}

// ErrBatch — тело — пакет JSON-RPC (массив): прокси пакеты не принимает
// (ADR-0023, раздел 6; в MCP 2025-06-18 пакеты убраны).
var ErrBatch = errors.New("пакеты JSON-RPC (массив сообщений) не поддерживаются")

// ProtocolError — сообщение не подходит под JSON-RPC или MCP: код ошибки
// для ответа и текст без фрагментов сообщения.
type ProtocolError struct {
	Code int
	Msg  string
}

func (e *ProtocolError) Error() string { return e.Msg }

func invalid(format string, a ...any) error {
	return &ProtocolError{Code: CodeInvalidRequest, Msg: fmt.Sprintf(format, a...)}
}

// CodeOf — код ошибки JSON-RPC для err: ProtocolError — его код, ошибка
// синтаксиса JSON и превышение пределов — Parse error.
func CodeOf(err error) int {
	var pe *ProtocolError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return CodeParseError
}

var envelopeKeys = []string{"jsonrpc", "id", "method", "params", "result", "error"}

// Parse строго разбирает одно сообщение JSON-RPC 2.0 с пределами lim:
//   - один объект, массив — ErrBatch;
//   - jsonrpc равно "2.0", других полей, кроме id, method, params, result
//     и error, нет;
//   - id — строка до MaxIDLen байт или целое без дробной части и
//     экспоненты; у ответа с ошибкой допускается null;
//   - method — непустая строка до MaxMethodLen байт, params — объект;
//   - у ответа ровно одно из result (объект) и error (объект с целым code
//     и строкой message).
func Parse(data []byte, lim argschema.Limits) (*Message, error) {
	v, err := argschema.ParseJSON(data, lim)
	if err != nil {
		return nil, err
	}
	return FromValue(v)
}

// FromValue — сообщение из уже разобранного значения (правила Parse).
func FromValue(v argschema.Value) (*Message, error) {
	if v.Kind == argschema.Array {
		return nil, ErrBatch
	}
	if v.Kind != argschema.Object {
		return nil, invalid("сообщение JSON-RPC — объект")
	}
	for _, k := range v.Keys {
		if !slices.Contains(envelopeKeys, k) {
			return nil, invalid("неизвестное поле сообщения JSON-RPC")
		}
	}
	if j, ok := v.Get("jsonrpc"); !ok || j.Kind != argschema.String || j.Str != "2.0" {
		return nil, invalid(`jsonrpc — "2.0"`)
	}
	m := &Message{}
	method, hasMethod := v.Get("method")
	result, hasResult := v.Get("result")
	errv, hasError := v.Get("error")
	if id, ok := v.Get("id"); ok {
		m.ID, m.HasID = *id, true
	}
	switch {
	case hasMethod:
		if hasResult || hasError {
			return nil, invalid("запрос не содержит result и error")
		}
		if method.Kind != argschema.String || method.Str == "" || len(method.Str) > MaxMethodLen {
			return nil, invalid("method — строка от 1 до %d байт", MaxMethodLen)
		}
		m.Method = method.Str
		if p, ok := v.Get("params"); ok {
			if p.Kind != argschema.Object {
				return nil, &ProtocolError{Code: CodeInvalidParams, Msg: "params — объект"}
			}
			m.Params = p
		}
		m.Kind = KindNotification
		if m.HasID {
			if err := checkID(m.ID, false); err != nil {
				return nil, err
			}
			m.Kind = KindRequest
		}
	case hasResult == hasError:
		return nil, invalid("ответ содержит ровно одно из result и error")
	case hasResult:
		if _, ok := v.Get("params"); ok || result.Kind != argschema.Object {
			return nil, invalid("result — объект, params в ответе нет")
		}
		if !m.HasID {
			return nil, invalid("у ответа нет id")
		}
		if err := checkID(m.ID, false); err != nil {
			return nil, err
		}
		m.Kind, m.Result = KindResult, result
	default:
		if _, ok := v.Get("params"); ok || errv.Kind != argschema.Object {
			return nil, invalid("error — объект, params в ответе нет")
		}
		if m.HasID {
			if err := checkID(m.ID, true); err != nil {
				return nil, err
			}
		}
		code, ok := errv.Get("code")
		if !ok || code.Kind != argschema.Number || !code.Num.IsInt() || !code.Num.Num().IsInt64() {
			return nil, invalid("error.code — целое")
		}
		if msg, ok := errv.Get("message"); !ok || msg.Kind != argschema.String {
			return nil, invalid("error.message — строка")
		}
		m.Kind, m.Error = KindError, errv
	}
	return m, nil
}

// checkID — id запроса: строка до MaxIDLen байт или целое в записи без
// дробной части и экспоненты (1.0 и 1e0 разные серверы читают по-разному).
func checkID(id argschema.Value, nullOK bool) error {
	switch id.Kind {
	case argschema.String:
		if len(id.Str) <= MaxIDLen {
			return nil
		}
	case argschema.Number:
		if isPlainInt(id.Raw) && len(id.Raw) <= 20 && id.Num.Num().IsInt64() {
			return nil
		}
	case argschema.Null:
		if nullOK {
			return nil
		}
	}
	return invalid("id — строка до %d байт или целое", MaxIDLen)
}

func isPlainInt(raw string) bool {
	if raw == "" {
		return false
	}
	if raw[0] == '-' {
		raw = raw[1:]
	}
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
	}
	return true
}

// SameID — id ответа совпадает с id запроса (строка со строкой, целое с
// целым).
func SameID(a, b argschema.Value) bool {
	return a.Kind == b.Kind && (a.Kind == argschema.String && a.Str == b.Str ||
		a.Kind == argschema.Number && a.Num != nil && b.Num != nil && a.Num.Cmp(b.Num) == 0)
}

// ErrorCode — code объекта ошибки ответа.
func (m *Message) ErrorCode() int64 {
	if m.Error == nil {
		return 0
	}
	c, _ := m.Error.Get("code")
	return c.Num.Num().Int64()
}

// Value — сообщение как дерево значений для сборки (Encode).
func (m *Message) Value() argschema.Value {
	out := Object()
	Set(&out, "jsonrpc", String("2.0"))
	if m.HasID {
		Set(&out, "id", m.ID)
	}
	switch m.Kind {
	case KindRequest, KindNotification:
		Set(&out, "method", String(m.Method))
		if m.Params != nil {
			Set(&out, "params", *m.Params)
		}
	case KindResult:
		Set(&out, "result", *m.Result)
	case KindError:
		Set(&out, "error", *m.Error)
	}
	return out
}

// Encode собирает сообщение заново из дерева значений.
func (m *Message) Encode() []byte { return AppendJSON(nil, m.Value()) }

// ErrorMessage — ответ с ошибкой на запрос с id (nil — ошибка без id,
// например при неразборном теле). data — дополнительные данные или nil.
func ErrorMessage(id *argschema.Value, code int, msg string, data *argschema.Value) *Message {
	e := Object()
	Set(&e, "code", Int(int64(code)))
	Set(&e, "message", String(msg))
	if data != nil {
		Set(&e, "data", *data)
	}
	m := &Message{Kind: KindError, Error: &e}
	if id != nil {
		m.ID, m.HasID = *id, true
	}
	return m
}

// ResultMessage — ответ с результатом на запрос с id.
func ResultMessage(id argschema.Value, result argschema.Value) *Message {
	return &Message{Kind: KindResult, ID: id, HasID: true, Result: &result}
}

// Конструкторы значений для сборки сообщений.

// Object — пустой объект.
func Object() argschema.Value { return argschema.Value{Kind: argschema.Object} }

// String — строка.
func String(s string) argschema.Value { return argschema.Value{Kind: argschema.String, Str: s} }

// Bool — логическое значение.
func Bool(b bool) argschema.Value { return argschema.Value{Kind: argschema.Bool, Bool: b} }

// Int — целое (запись — десятичная).
func Int(n int64) argschema.Value {
	v, err := argschema.FromAny(n, argschema.Limits{MaxValues: 1})
	if err != nil {
		panic(err) // целое всегда переводится
	}
	return v
}

// Array — массив.
func Array(items ...argschema.Value) argschema.Value {
	return argschema.Value{Kind: argschema.Array, Arr: items}
}

// Set задаёт поле объекта: заменяет прежнее значение или добавляет в конец.
func Set(obj *argschema.Value, key string, v argschema.Value) {
	for i, k := range obj.Keys {
		if k == key {
			obj.Vals[i] = v
			return
		}
	}
	obj.Keys = append(obj.Keys, key)
	obj.Vals = append(obj.Vals, v)
}

// Delete удаляет поле объекта; сообщает, было ли оно.
func Delete(obj *argschema.Value, key string) bool {
	for i, k := range obj.Keys {
		if k == key {
			obj.Keys = slices.Delete(obj.Keys, i, i+1)
			obj.Vals = slices.Delete(obj.Vals, i, i+1)
			return true
		}
	}
	return false
}

// Keep оставляет в объекте только поля keys (порядок документа).
func Keep(obj *argschema.Value, keys ...string) {
	out := Object()
	for i, k := range obj.Keys {
		if slices.Contains(keys, k) {
			out.Keys = append(out.Keys, k)
			out.Vals = append(out.Vals, obj.Vals[i])
		}
	}
	obj.Keys, obj.Vals = out.Keys, out.Vals
}

// Clone — глубокая копия значения: сборка ответа не меняет разобранный
// документ, который ещё нужен событию и проверкам.
func Clone(v argschema.Value) argschema.Value {
	out := v
	if v.Arr != nil {
		out.Arr = make([]argschema.Value, len(v.Arr))
		for i := range v.Arr {
			out.Arr[i] = Clone(v.Arr[i])
		}
	}
	if v.Keys != nil {
		out.Keys = slices.Clone(v.Keys)
		out.Vals = make([]argschema.Value, len(v.Vals))
		for i := range v.Vals {
			out.Vals[i] = Clone(v.Vals[i])
		}
	}
	return out
}

// GetString — строковое поле объекта.
func GetString(obj *argschema.Value, key string) (string, bool) {
	if obj == nil || obj.Kind != argschema.Object {
		return "", false
	}
	v, ok := obj.Get(key)
	if !ok || v.Kind != argschema.String {
		return "", false
	}
	return v.Str, true
}

// GetObject — поле-объект.
func GetObject(obj *argschema.Value, key string) (*argschema.Value, bool) {
	if obj == nil || obj.Kind != argschema.Object {
		return nil, false
	}
	v, ok := obj.Get(key)
	if !ok || v.Kind != argschema.Object {
		return nil, false
	}
	return v, true
}

// AppendJSON дописывает компактную запись значения: ключи в порядке
// дерева, числа — исходной записью, строки в UTF-8 без экранирования HTML
// (экранируются «"», «\» и управляющие символы).
func AppendJSON(b []byte, v argschema.Value) []byte {
	switch v.Kind {
	case argschema.Null:
		return append(b, "null"...)
	case argschema.Bool:
		return strconv.AppendBool(b, v.Bool)
	case argschema.Number:
		if v.Raw == "" && v.Num != nil {
			return append(b, v.Num.RatString()...)
		}
		return append(b, v.Raw...)
	case argschema.String:
		return appendString(b, v.Str)
	case argschema.Array:
		b = append(b, '[')
		for i := range v.Arr {
			if i > 0 {
				b = append(b, ',')
			}
			b = AppendJSON(b, v.Arr[i])
		}
		return append(b, ']')
	}
	b = append(b, '{')
	for i, k := range v.Keys {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendString(b, k)
		b = append(b, ':')
		b = AppendJSON(b, v.Vals[i])
	}
	return append(b, '}')
}

const hexDigits = "0123456789abcdef"

func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c >= utf8.RuneSelf {
			r, n := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && n == 1 {
				// Неверный UTF-8 в дерево из разбора не попадает; строки,
				// собранные шлюзом, заменяются символом U+FFFD.
				b = append(b, "�"...)
			} else {
				b = append(b, s[i:i+n]...)
			}
			i += n
			continue
		}
		switch c {
		case '"', '\\':
			b = append(b, '\\', c)
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if c < 0x20 || c == 0x7f {
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			} else {
				b = append(b, c)
			}
		}
		i++
	}
	return append(b, '"')
}
