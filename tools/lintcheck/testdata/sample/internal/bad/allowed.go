package bad

import (
	"reflect" //nolint:depguard // образец: разрешённое исключение с обоснованием // clean:depguard
)

// Allowed использует reflect по оформленному исключению.
func Allowed() string { return reflect.TypeOf(0).String() }
