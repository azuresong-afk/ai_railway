// Пакет cgouse — файл с cgo: линтеры обязаны его проверять.
package cgouse

// int one(void) { return 1; }
import "C"

import "crypto/md5" // want:depguard

// One вызывает C-функцию.
func One() int { _ = md5.Size; return int(C.one()) }
