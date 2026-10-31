// Команда aisec-server образца: криптография, os/exec и сканер файлов
// моделей запрещены.
package main

import (
	"crypto/tls" // want:depguard
	"os/exec"    // want:depguard

	"github.com/azuresong-afk/ai_railway/internal/modelscan" // want:depguard
)

func main() {
	_ = tls.VersionTLS13
	_ = exec.Command
	_ = modelscan.Formats
}
