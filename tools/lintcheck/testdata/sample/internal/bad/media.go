package bad

import (
	"image/jpeg" // want:depguard
	"image/png"  // want:depguard

	"github.com/azuresong-afk/ai_railway/internal/media"       // want:depguard
	"github.com/azuresong-afk/ai_railway/internal/media/inner" // want:depguard
	"github.com/azuresong-afk/ai_railway/internal/media/wire"  // clean:depguard
	"golang.org/x/image/webp"                                  // want:depguard
)

// UseMedia — анализатор и декодеры изображений вне aisec-media запрещены (ADR-0032), протокол кадров — нет.
func UseMedia() []string {
	_, _ = jpeg.Decode, png.Decode
	return append(media.Formats(), inner.Name, wire.Magic, webp.Name)
}
