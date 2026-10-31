// Команда aisec-media образца: os/exec и reflect запрещены, анализатор
// internal/media — разрешён, декодеры напрямую — нет (ADR-0032).
package main

import (
	"image/png" // want:depguard
	"os/exec"   // want:depguard
	"reflect"   // want:depguard

	"github.com/azuresong-afk/ai_railway/internal/media"      // clean:depguard
	"github.com/azuresong-afk/ai_railway/internal/media/wire" // clean:depguard
)

func main() {
	_ = exec.Command
	_ = reflect.TypeOf(0)
	_ = png.Decode
	_, _ = media.Formats(), wire.Magic
}
