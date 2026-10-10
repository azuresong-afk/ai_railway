// Команда aisec-server образца: криптография и os/exec запрещены.
package main

import (
	"crypto/tls" // want:depguard
	"os/exec"    // want:depguard
)

func main() {
	_ = tls.VersionTLS13
	_ = exec.Command
}
