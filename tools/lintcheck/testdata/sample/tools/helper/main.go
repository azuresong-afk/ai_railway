// Утилита образца: os/exec и reflect в утилитах разрешены.
package main

import (
	"os/exec" // clean:depguard
	"reflect" // clean:depguard
)

func main() {
	_ = exec.Command
	_ = reflect.TypeOf(0)
}
