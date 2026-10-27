// Package tooldesc — каноническая форма и хеш описания инструмента агента
// (ADR-0023, раздел 1; DM-25). Пакет-лист без зависимостей сервера: его
// используют реестр агентов сервера, шлюз и самотест.
package tooldesc

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

// Хеш описания инструмента (ADR-0023, раздел 1). Одной функцией его считают
// шлюз (по tools/list) и сервер (по tools:observe), поэтому каноническая
// форма зафиксирована здесь и тестами:
//   - строгий разбор (argschema.ParseJSON): повтор ключа, неверный UTF-8,
//     одиночный суррогат, данные после документа — ошибка;
//   - ключи объектов по порядку байтов, без пробелов;
//   - строки в UTF-8 без экранирования HTML: экранируются только «"», «\»
//     и управляющие символы (\b \f \n \r \t, остальные — \u00XX);
//   - числа — исходной записью;
//   - на верхнем уровне не входят icons и _meta: модель их не видит.
// Хешируется Domain и каноническая форма.

// Domain — префикс домена хеша описания.
const Domain = "aisec-tool-descriptor-v1\n"

// Пределы описания инструмента.
const (
	MaxSize       = 64 << 10
	maxDescDepth  = 32
	maxDescValues = 10000
	maxDescString = 32 << 10
)

// descLimits — пределы разбора описания.
var descLimits = argschema.Limits{MaxSize: MaxSize, MaxDepth: maxDescDepth, MaxValues: maxDescValues,
	MaxString: maxDescString}

// excludedKeys — поля верхнего уровня вне хеша.
var excludedKeys = []string{"icons", "_meta"}

// ErrDescriptor — описание инструмента не разбирается или не подходит.
var ErrDescriptor = errors.New("описание инструмента")

// Descriptor — разобранное описание: имя, каноническая форма без icons и
// _meta и подсказки аннотаций.
type Descriptor struct {
	Name      string
	Canonical []byte
	// Destructive — annotations.destructiveHint = true (подсказка сервера,
	// недоверенная: только поднимает предлагаемый уровень риска).
	Destructive bool
}

// Parse разбирает описание инструмента из tools/list. Имя
// обязательно и проверяется по правилам политики вызовов.
func Parse(raw []byte) (Descriptor, error) {
	v, err := argschema.ParseJSON(raw, descLimits)
	if err != nil {
		return Descriptor{}, errors.Join(ErrDescriptor, err)
	}
	if v.Kind != argschema.Object {
		return Descriptor{}, errors.Join(ErrDescriptor, errors.New("ожидается объект"))
	}
	name, ok := v.Get("name")
	if !ok || name.Kind != argschema.String || !ValidName(name.Str) {
		return Descriptor{}, errors.Join(ErrDescriptor, errors.New("name — латиница, цифры, «_», «.», «-», до 128 символов"))
	}
	d := Descriptor{Name: name.Str}
	if a, ok := v.Get("annotations"); ok && a.Kind == argschema.Object {
		if h, ok := a.Get("destructiveHint"); ok && h.Kind == argschema.Bool && h.Bool {
			d.Destructive = true
		}
	}
	top := argschema.Value{Kind: argschema.Object}
	for i, k := range v.Keys {
		if !slices.Contains(excludedKeys, k) {
			top.Keys = append(top.Keys, k)
			top.Vals = append(top.Vals, v.Vals[i])
		}
	}
	d.Canonical = appendCanonical(nil, &top)
	return d, nil
}

// Hash — хеш описания на криптопрофиле: h(Domain || каноническая форма).
func Hash(h aisecCrypto.Hasher, d Descriptor) []byte {
	buf := make([]byte, 0, len(Domain)+len(d.Canonical))
	buf = append(append(buf, Domain...), d.Canonical...)
	return h.Sum(buf)
}

func appendCanonical(b []byte, v *argschema.Value) []byte {
	switch v.Kind {
	case argschema.Null:
		return append(b, "null"...)
	case argschema.Bool:
		return strconv.AppendBool(b, v.Bool)
	case argschema.Number:
		return append(b, v.Raw...)
	case argschema.String:
		return appendString(b, v.Str)
	case argschema.Array:
		b = append(b, '[')
		for i := range v.Arr {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendCanonical(b, &v.Arr[i])
		}
		return append(b, ']')
	}
	idx := make([]int, len(v.Keys))
	for i := range idx {
		idx[i] = i
	}
	slices.SortFunc(idx, func(x, y int) int {
		switch {
		case v.Keys[x] < v.Keys[y]:
			return -1
		case v.Keys[x] > v.Keys[y]:
			return 1
		}
		return 0
	})
	b = append(b, '{')
	for n, i := range idx {
		if n > 0 {
			b = append(b, ',')
		}
		b = appendString(b, v.Keys[i])
		b = append(b, ':')
		b = appendCanonical(b, &v.Vals[i])
	}
	return append(b, '}')
}

const hexDigits = "0123456789abcdef"

func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c >= utf8.RuneSelf {
			// Строка уже проверена разбором: UTF-8 копируется как есть.
			_, n := utf8.DecodeRuneInString(s[i:])
			b = append(b, s[i:i+n]...)
			i += n
			continue
		}
		switch c {
		case '"', '\\':
			b = append(b, '\\', c)
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if c < 0x20 {
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			} else {
				b = append(b, c)
			}
		}
		i++
	}
	return append(b, '"')
}

// nameRe — имя инструмента (как в шаблоне правила tools).
var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// ValidName — имя инструмента подходит для реестра, пакета и правил.
func ValidName(n string) bool { return nameRe.MatchString(n) }
