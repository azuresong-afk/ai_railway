package mcp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

// Заголовки транспорта Streamable HTTP (ревизии 2025-11-25 и 2026-07-28).
const (
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
	HeaderSessionID       = "Mcp-Session-Id"
	// HeaderParamPrefix — заголовки Mcp-Param-{name} по x-mcp-header
	// в inputSchema инструмента (2026-07-28).
	HeaderParamPrefix = "Mcp-Param-"
)

// Ключи _meta запроса ревизии 2026-07-28.
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfo         = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	MetaProgressToken      = "progressToken"
)

// Пределы заголовков.
const (
	// MaxHeaderValue — значение Mcp-Name и Mcp-Param-* (после base64 — до
	// раскрытия).
	MaxHeaderValue = 8 << 10
	// MaxSessionID — Mcp-Session-Id (2025-11-25: видимый ASCII).
	MaxSessionID = 256
	// MaxParamHeaders — заголовков Mcp-Param-* у одного инструмента.
	MaxParamHeaders = 32
	// maxSafeInt — 2^53−1: целые x-mcp-header в пределах точного double.
	maxSafeInt = 1<<53 - 1
)

// HeaderError — заголовки не совпадают с телом или неверны: ответ 400 с
// ошибкой HeaderMismatch (-32020).
type HeaderError struct{ Msg string }

func (e *HeaderError) Error() string {
	return "несовпадение заголовков: " + e.Msg
}

func mismatch(format string, a ...any) error { return &HeaderError{Msg: fmt.Sprintf(format, a...)} }

const (
	b64Prefix = "=?base64?"
	b64Suffix = "?="
)

// DecodeHeaderValue раскрывает значение Mcp-Name или Mcp-Param-*: обёртку
// =?base64?…?= (base64 от UTF-8) или обычное значение из видимого ASCII,
// пробела и табуляции без пробелов по краям.
func DecodeHeaderValue(s string) (string, error) {
	if len(s) > MaxHeaderValue {
		return "", errors.New("значение заголовка слишком длинное")
	}
	if strings.HasPrefix(s, b64Prefix) && strings.HasSuffix(s, b64Suffix) && len(s) >= len(b64Prefix)+len(b64Suffix) {
		raw, err := base64.StdEncoding.Strict().DecodeString(s[len(b64Prefix) : len(s)-len(b64Suffix)])
		if err != nil || !utf8.Valid(raw) {
			return "", errors.New("неверная запись base64 в заголовке")
		}
		return string(raw), nil
	}
	if !plainHeaderValue(s) {
		return "", errors.New("недопустимые символы в заголовке")
	}
	return s, nil
}

// plainHeaderValue — значение передаётся без обёртки: видимый ASCII,
// пробел и табуляция внутри, не похоже на обёртку base64.
func plainHeaderValue(s string) bool {
	if s == "" || s[0] == ' ' || s[0] == '\t' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t' {
		return s == ""
	}
	if strings.HasPrefix(s, b64Prefix) && strings.HasSuffix(s, b64Suffix) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 || c > 0x7e) && c != '\t' {
			return false
		}
	}
	return true
}

// EncodeHeaderValue — запись значения в заголовок: как есть или в обёртке
// base64, если значение нельзя передать обычным ASCII.
func EncodeHeaderValue(s string) string {
	if s != "" && plainHeaderValue(s) {
		return s
	}
	return b64Prefix + base64.StdEncoding.EncodeToString([]byte(s)) + b64Suffix
}

// single — единственное значение заголовка; повтор — ошибка (разные
// посредники берут разные экземпляры).
func single(h http.Header, name string) (string, bool, error) {
	vals := h.Values(name)
	switch len(vals) {
	case 0:
		return "", false, nil
	case 1:
		return vals[0], true, nil
	}
	return "", false, mismatch("заголовок %s указан несколько раз", name)
}

// ProtocolVersion — версия из MCP-Protocol-Version (пусто — заголовка нет).
func ProtocolVersion(h http.Header) (string, error) {
	v, _, err := single(h, HeaderProtocolVersion)
	if err != nil {
		return "", err
	}
	if len(v) > 64 {
		return "", mismatch("неверный %s", HeaderProtocolVersion)
	}
	return v, nil
}

// NameField — поле params, которое отражает Mcp-Name: name для tools/call и
// prompts/get, uri для resources/read; пусто — у метода нет Mcp-Name.
func NameField(method string) string {
	switch method {
	case "tools/call", "prompts/get":
		return "name"
	case "resources/read":
		return "uri"
	}
	return ""
}

// MetaVersion — версия из params._meta (2026-07-28); пусто — нет.
func MetaVersion(m *Message) string {
	meta, ok := GetObject(m.Params, "_meta")
	if !ok {
		return ""
	}
	v, _ := GetString(meta, MetaProtocolVersion)
	return v
}

// CheckHeaders сверяет заголовки запроса ревизии 2026-07-28 с телом
// (раздел «Server Validation»): MCP-Protocol-Version равен _meta
// protocolVersion, Mcp-Method — method, Mcp-Name — params.name или
// params.uri. Отсутствие обязательного заголовка, повтор, недопустимые
// символы и несовпадение — HeaderError. Заголовки Mcp-Param-* клиента
// шлюз не передаёт: они строятся заново (ParamHeaders), поэтому здесь не
// сверяются.
func CheckHeaders(h http.Header, m *Message) error {
	ver, err := ProtocolVersion(h)
	if err != nil {
		return err
	}
	if ver == "" {
		return mismatch("нет заголовка %s", HeaderProtocolVersion)
	}
	if mv := MetaVersion(m); mv != ver {
		return mismatch("%s не совпадает с _meta %s", HeaderProtocolVersion, MetaProtocolVersion)
	}
	method, ok, err := single(h, HeaderMethod)
	if err != nil {
		return err
	}
	if !ok {
		return mismatch("нет заголовка %s", HeaderMethod)
	}
	if method != m.Method {
		return mismatch("%s не совпадает с method", HeaderMethod)
	}
	field := NameField(m.Method)
	raw, ok, err := single(h, HeaderName)
	if err != nil {
		return err
	}
	if field == "" {
		if ok {
			return mismatch("%s у метода без имени", HeaderName)
		}
		return nil
	}
	if !ok {
		return mismatch("нет заголовка %s", HeaderName)
	}
	name, err := DecodeHeaderValue(raw)
	if err != nil {
		return mismatch("%s: %v", HeaderName, err)
	}
	if body, _ := GetString(m.Params, field); body != name {
		return mismatch("%s не совпадает с params.%s", HeaderName, field)
	}
	return nil
}

// ParamHeader — заголовок Mcp-Param-* инструмента: имя (часть после
// префикса) и путь свойства в аргументах (цепочка ключей properties).
type ParamHeader struct {
	Name string
	Path []string
	// Type — объявленный тип свойства: string, integer или boolean.
	Type string
}

// ErrInvalidToolHeaders — x-mcp-header в inputSchema нарушает правила
// спецификации: по ней инструмент исключается из tools/list.
var ErrInvalidToolHeaders = errors.New("inputSchema: неверная аннотация x-mcp-header")

// ParamHeaders — аннотации x-mcp-header описания инструмента (2026-07-28,
// «Custom Headers from Tool Parameters»): имя — токен RFC 9110, без
// повторов без учёта регистра; свойство примитивного типа (string,
// integer, boolean), достижимое от корня только через properties.
// Аннотация в другом месте схемы (items, oneOf и т. п.) — ошибка.
func ParamHeaders(inputSchema *argschema.Value) ([]ParamHeader, error) {
	if inputSchema == nil || inputSchema.Kind != argschema.Object {
		return nil, nil
	}
	var out []ParamHeader
	seen := map[string]bool{}
	reachable := 0
	var walk func(s *argschema.Value, path []string) error
	walk = func(s *argschema.Value, path []string) error {
		if h, ok := s.Get("x-mcp-header"); ok {
			if len(path) == 0 {
				return ErrInvalidToolHeaders
			}
			if h.Kind != argschema.String || !token(h.Str) || seen[strings.ToLower(h.Str)] {
				return ErrInvalidToolHeaders
			}
			typ, _ := GetString(s, "type")
			if typ != "string" && typ != "integer" && typ != "boolean" {
				return ErrInvalidToolHeaders
			}
			seen[strings.ToLower(h.Str)] = true
			reachable++
			out = append(out, ParamHeader{Name: h.Str, Path: append([]string(nil), path...), Type: typ})
			if len(out) > MaxParamHeaders {
				return ErrInvalidToolHeaders
			}
		}
		props, ok := GetObject(s, "properties")
		if !ok {
			return nil
		}
		for i, k := range props.Keys {
			if p := &props.Vals[i]; p.Kind == argschema.Object {
				if err := walk(p, append(path, k)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(inputSchema, nil); err != nil {
		return nil, err
	}
	// Аннотаций во всей схеме больше, чем достижимых через properties, —
	// какая-то стоит в items, oneOf и т. п.
	if countAnnotations(inputSchema) != reachable {
		return nil, ErrInvalidToolHeaders
	}
	return out, nil
}

func countAnnotations(v *argschema.Value) int {
	n := 0
	switch v.Kind {
	case argschema.Object:
		for i, k := range v.Keys {
			if k == "x-mcp-header" {
				n++
			}
			n += countAnnotations(&v.Vals[i])
		}
	case argschema.Array:
		for i := range v.Arr {
			n += countAnnotations(&v.Arr[i])
		}
	}
	return n
}

// token — имя поля HTTP (RFC 9110, 1*tchar).
func token(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

var (
	safeMax = big.NewRat(maxSafeInt, 1)
	safeMin = big.NewRat(-maxSafeInt, 1)
)

// BuildParamHeaders — заголовки Mcp-Param-* по аннотациям и аргументам
// вызова: значение по пути свойства (нет или null — заголовок не
// ставится), строка как есть, целое десятичной записью, логическое — true
// или false; при необходимости — обёртка base64. Значение не того типа —
// ошибка: сервер отверг бы вызов (заголовок не совпал бы с телом).
func BuildParamHeaders(hs []ParamHeader, args *argschema.Value) (http.Header, error) {
	out := http.Header{}
	for _, ph := range hs {
		v := args
		for _, k := range ph.Path {
			if v == nil || v.Kind != argschema.Object {
				v = nil
				break
			}
			v, _ = v.Get(k)
		}
		if v == nil || v.Kind == argschema.Null {
			continue
		}
		var s string
		switch {
		case ph.Type == "string" && v.Kind == argschema.String:
			s = v.Str
		case ph.Type == "integer" && v.Kind == argschema.Number && v.Num.IsInt() &&
			v.Num.Cmp(safeMax) <= 0 && v.Num.Cmp(safeMin) >= 0:
			s = strconv.FormatInt(v.Num.Num().Int64(), 10)
		case ph.Type == "boolean" && v.Kind == argschema.Bool:
			s = strconv.FormatBool(v.Bool)
		default:
			return nil, fmt.Errorf("аргумент для заголовка %s%s не того типа", HeaderParamPrefix, ph.Name)
		}
		if len(s) > MaxHeaderValue {
			return nil, fmt.Errorf("аргумент для заголовка %s%s слишком длинный", HeaderParamPrefix, ph.Name)
		}
		out.Set(HeaderParamPrefix+ph.Name, EncodeHeaderValue(s))
	}
	return out, nil
}

// SessionID — Mcp-Session-Id запроса (2025-11-25): видимый ASCII до
// MaxSessionID байт; пусто — заголовка нет.
func SessionID(h http.Header) (string, error) {
	v, ok, err := single(h, HeaderSessionID)
	if err != nil || !ok {
		return "", err
	}
	if !ValidSessionID(v) {
		return "", mismatch("неверный %s", HeaderSessionID)
	}
	return v, nil
}

// ValidSessionID — идентификатор сессии 2025-11-25: 1–MaxSessionID
// символов видимого ASCII (0x21–0x7E).
func ValidSessionID(v string) bool {
	if v == "" || len(v) > MaxSessionID {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return false
		}
	}
	return true
}
