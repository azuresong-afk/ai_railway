package argschema

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"unicode/utf8"
)

// Перевод между Value и деревом значений Go, которое даёт разбор YAML
// (map[string]any, []any, string, bool, целые, float64, nil). Схема в YAML
// политики хранится деревом Go, проверяется и исполняется как Value.

// FromAny переводит дерево значений Go в Value. Ключи объектов
// упорядочиваются по байтам; бесконечности и NaN, ключи не строками и
// неверный UTF-8 — ошибка.
func FromAny(x any, lim Limits) (Value, error) {
	c := converter{lim: lim}
	return c.from(x, 0)
}

type converter struct {
	lim    Limits
	values int
}

func (c *converter) from(x any, depth int) (Value, error) {
	c.values++
	if c.values > c.lim.MaxValues {
		return Value{}, errors.New("слишком много значений")
	}
	switch v := x.(type) {
	case nil:
		return Value{Kind: Null}, nil
	case bool:
		return Value{Kind: Bool, Bool: v}, nil
	case string:
		if !utf8.ValidString(v) || len(v) > c.lim.MaxString {
			return Value{}, errors.New("неверная или слишком длинная строка")
		}
		return Value{Kind: String, Str: v}, nil
	case int:
		return intValue(int64(v)), nil
	case int64:
		return intValue(v), nil
	case uint64:
		r := new(big.Rat).SetInt(new(big.Int).SetUint64(v))
		return Value{Kind: Number, Num: r, Raw: r.RatString()}, nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return Value{}, errors.New("число должно быть конечным")
		}
		// Кратчайшая десятичная запись: граница 100.05 из YAML — ровно
		// 100.05, а не двоичное приближение float64.
		raw := strconv.FormatFloat(v, 'g', -1, 64)
		r, ok := new(big.Rat).SetString(raw)
		if !ok {
			return Value{}, errors.New("неверное число")
		}
		return Value{Kind: Number, Num: r, Raw: raw}, nil
	case []any:
		if depth+1 > c.lim.MaxDepth {
			return Value{}, errors.New("слишком глубокая вложенность")
		}
		out := Value{Kind: Array, Arr: make([]Value, 0, len(v))}
		for _, e := range v {
			ev, err := c.from(e, depth+1)
			if err != nil {
				return Value{}, err
			}
			out.Arr = append(out.Arr, ev)
		}
		return out, nil
	case map[string]any:
		if depth+1 > c.lim.MaxDepth {
			return Value{}, errors.New("слишком глубокая вложенность")
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			if !utf8.ValidString(k) || len(k) > c.lim.MaxString {
				return Value{}, errors.New("неверный ключ объекта")
			}
			keys = append(keys, k)
		}
		slices.Sort(keys)
		out := Value{Kind: Object, Keys: keys, Vals: make([]Value, 0, len(keys))}
		for _, k := range keys {
			ev, err := c.from(v[k], depth+1)
			if err != nil {
				return Value{}, err
			}
			out.Vals = append(out.Vals, ev)
		}
		return out, nil
	}
	return Value{}, fmt.Errorf("недопустимый тип значения %T: ключи объектов — только строки", x)
}

func intValue(n int64) Value {
	return Value{Kind: Number, Num: new(big.Rat).SetInt64(n), Raw: fmt.Sprint(n)}
}

// ToAny переводит Value в дерево значений Go для YAML и JSON: целое в
// пределах int64 — int64, остальные числа — float64. Число, которое float64
// не передаёт точно, теряет точность: проверяйте Exact.
func ToAny(v Value) any {
	switch v.Kind {
	case Bool:
		return v.Bool
	case Number:
		if v.Num.IsInt() && v.Num.Num().IsInt64() {
			return v.Num.Num().Int64()
		}
		f, _ := v.Num.Float64()
		return f
	case String:
		return v.Str
	case Array:
		out := make([]any, 0, len(v.Arr))
		for _, e := range v.Arr {
			out = append(out, ToAny(e))
		}
		return out
	case Object:
		out := make(map[string]any, len(v.Keys))
		for i, k := range v.Keys {
			out[k] = ToAny(v.Vals[i])
		}
		return out
	}
	return nil
}

// Equal — значения равны по смыслу JSON: числа сравниваются точно, у
// объектов порядок ключей не важен.
func Equal(a, b Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case Null:
		return true
	case Bool:
		return a.Bool == b.Bool
	case Number:
		return a.Num.Cmp(b.Num) == 0
	case String:
		return a.Str == b.Str
	case Array:
		return slices.EqualFunc(a.Arr, b.Arr, Equal)
	case Object:
		if len(a.Keys) != len(b.Keys) {
			return false
		}
		for i, k := range a.Keys {
			bv, ok := b.Get(k)
			if !ok || !Equal(a.Vals[i], *bv) {
				return false
			}
		}
		return true
	}
	return false
}

// Exact — ToAny(v) читается FromAny обратно в то же значение: числа не
// потеряли точности при переводе в float64.
func Exact(v Value, lim Limits) bool {
	back, err := FromAny(ToAny(v), lim)
	return err == nil && Equal(v, back)
}
