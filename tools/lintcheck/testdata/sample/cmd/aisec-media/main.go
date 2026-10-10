// Команда aisec-media образца: os/exec и reflect запрещены.
package main

import (
	"os/exec" // want:depguard
	"reflect" // want:depguard
)

func main() {
	_ = exec.Command
	_ = reflect.TypeOf(0)
}
