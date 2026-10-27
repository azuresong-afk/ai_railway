package argschema

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"
)

// ValidationError — аргументы не проходят схему: путь JSON Pointer и
// причина без значения аргумента (аргументы — содержимое, ТЗ 5.5).
type ValidationError struct {
	Path   string
	Reason string
}

func (e *ValidationError) Error() string { return "аргумент " + at(e.Path) + ": " + e.Reason }

// ValidateArgs строго разбирает аргументы вызова (ArgsLimits) и проверяет
// их схемой s; s = nil — только строгий разбор. Ошибка разбора — тоже отказ
// вызова (DM-21).
func ValidateArgs(s *Schema, raw []byte) (Value, error) {
	v, err := ParseJSON(raw, ArgsLimits)
	if err != nil {
		return Value{}, err
	}
	if s == nil {
		return v, nil
	}
	return v, s.Validate(v)
}

// Validate проверяет значение схемой; первая найденная причина отказа.
func (s *Schema) Validate(v Value) error {
	return s.validate(v, "")
}

func (s *Schema) validate(v Value, path string) error {
	fail := func(format string, a ...any) error {
		return &ValidationError{Path: path, Reason: fmt.Sprintf(format, a...)}
	}
	if s.types != 0 && s.types&typeOf(v) == 0 {
		return fail("тип значения не разрешён")
	}
	if s.constant != nil && !Equal(*s.constant, v) {
		return fail("значение не равно const")
	}
	if s.enum != nil && !containsValue(s.enum, v) {
		return fail("значение не из enum")
	}
	switch v.Kind {
	case Number:
		if s.minimum != nil && v.Num.Cmp(s.minimum) < 0 || s.exMinimum != nil && v.Num.Cmp(s.exMinimum) <= 0 {
			return fail("число меньше допустимого")
		}
		if s.maximum != nil && v.Num.Cmp(s.maximum) > 0 || s.exMaximum != nil && v.Num.Cmp(s.exMaximum) >= 0 {
			return fail("число больше допустимого")
		}
	case String:
		n := utf8.RuneCountInString(v.Str)
		if s.minLength >= 0 && n < s.minLength || s.maxLength >= 0 && n > s.maxLength {
			return fail("длина строки вне допустимой")
		}
		if s.pattern != nil && !s.pattern.MatchString(v.Str) {
			return fail("строка не соответствует pattern")
		}
		if s.pathPrefixes != nil {
			if err := checkPath(v.Str, s.pathPrefixes); err != nil {
				return fail("%v", err)
			}
		}
		if s.domains != nil {
			if err := checkDomain(v.Str, s.domains); err != nil {
				return fail("%v", err)
			}
		}
	case Array:
		if s.minItems >= 0 && len(v.Arr) < s.minItems || s.maxItems >= 0 && len(v.Arr) > s.maxItems {
			return fail("число элементов вне допустимого")
		}
		if s.items != nil {
			for i, e := range v.Arr {
				if err := s.items.validate(e, path+"/"+strconv.Itoa(i)); err != nil {
					return err
				}
			}
		}
	case Object:
		for _, r := range s.required {
			if _, ok := v.Get(r); !ok {
				return &ValidationError{Path: path, Reason: fmt.Sprintf("нет обязательного свойства %q", clip(r))}
			}
		}
		for i, k := range v.Keys {
			ps, ok := s.properties[k]
			switch {
			case ok:
				if err := ps.validate(v.Vals[i], path+"/"+escapePointer(k)); err != nil {
					return err
				}
			case !s.additional:
				// Имя свойства — из аргументов: в сообщение не попадает.
				return fail("свойство вне разрешённых (additionalProperties: false)")
			}
		}
	}
	return nil
}

func typeOf(v Value) uint8 {
	switch v.Kind {
	case Null:
		return tNull
	case Bool:
		return tBoolean
	case Number:
		if v.Num.IsInt() {
			return tNumber | tInteger
		}
		return tNumber
	case String:
		return tString
	case Array:
		return tArray
	case Object:
		return tObject
	}
	return 0
}

func containsValue(list []Value, v Value) bool {
	for _, x := range list {
		if Equal(x, v) {
			return true
		}
	}
	return false
}

// IsValidation — ошибка — несоответствие схеме (а не разбора).
func IsValidation(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}
