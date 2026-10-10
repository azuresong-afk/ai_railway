package bad

import (
	f "fmt"                        // clean:depguard
	"golang.org/x/crypto/chacha20" // want:depguard
	"os"                           // clean:depguard
	"plugin"                       // want:depguard
	"syscall"                      // want:depguard
)

// More — обходы запретов, которые тоже должны ловиться.
func More() {
	f.Println("x")                        // want:forbidigo
	_, _ = os.StartProcess("x", nil, nil) // want:forbidigo
	_ = syscall.Exec("x", nil, nil)       // want:forbidigo
	_ = plugin.Open
	_ = chacha20.KeySize
}

// NoReason — подавление с линтером, но без обоснования.
func NoReason() int {
	return 2 //nolint:depguard // want:nolintlint
}
