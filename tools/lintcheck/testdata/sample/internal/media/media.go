// Пакет media образца: декодеры изображений здесь разрешены (ADR-0032).
package media

import (
	"image/png" // clean:depguard

	"github.com/makiuchi-d/gozxing" // clean:depguard
	"golang.org/x/image/webp"       // clean:depguard
)

// Formats — форматы с декодером.
func Formats() []string { _ = png.Decode; return []string{webp.Name, gozxing.Name} }
