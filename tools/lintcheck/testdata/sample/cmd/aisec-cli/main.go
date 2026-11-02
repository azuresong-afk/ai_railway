// Команда aisec-cli образца: не серверный компонент, os/exec разрешён;
// сканер файлов моделей — только здесь (ADR-0029, п. 4).
package main

import (
	"os/exec" // clean:depguard

	"github.com/azuresong-afk/ai_railway/internal/modelscan" // clean:depguard
)

func main() { _, _ = exec.Command, modelscan.Formats }
