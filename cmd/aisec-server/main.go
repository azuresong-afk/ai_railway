// Команда aisec-server — сервер управления: API, веб-консоль, оповещёния, инциденты, отчёты, аудит.
package main

import (
	"fmt"
	"os"

	"github.com/azuresong-afk/ai_railway/web"
)

// Статика веб-консоли встроена в бинарник (web/embed.go, ADR-0011);
// раздача — в задачах каркаса консоли этапа 2.
var _ = web.Dist

func main() {
	fmt.Fprintln(os.Stderr, "aisec-server: компонент ещё не реализован (этап 2)")
	os.Exit(2)
}
