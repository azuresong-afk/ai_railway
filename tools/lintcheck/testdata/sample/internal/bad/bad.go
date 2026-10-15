// Пакет bad — образец нарушений правил проекта для make lint-selftest.
// Каждая строка с маркером want:<линтер> обязана дать замечание этого линтера.
package bad

import (
	"crypto/sha256" // want:depguard
	"fmt"
	"log"
	"math/rand"        // want:depguard
	_ "net/http/pprof" // want:depguard
	"os/exec"          // want:depguard
	"reflect"          // want:depguard
	"unsafe"           // want:depguard
)

// Use использует все импорты, чтобы образец компилировался.
func Use() {
	_ = sha256.Sum256(nil)
	_ = rand.Int()
	_ = exec.Command
	_ = reflect.TypeOf(0)
	_ = unsafe.Sizeof(0)
	fmt.Println("x") // want:forbidigo
	log.Printf("x")  // want:forbidigo
	println("x")     // want:forbidigo
}

// Suppressed показывает подавление без указания линтера.
func Suppressed() int {
	return 1 //nolint // want:nolintlint
}
