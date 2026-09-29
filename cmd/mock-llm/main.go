// Команда mock-llm — OpenAI-совместимый мок провайдера для разработки и e2e. В поставку не входит.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "mock-llm: компонент ещё не реализован (задача 0.11 этапа 0)")
	os.Exit(2)
}
