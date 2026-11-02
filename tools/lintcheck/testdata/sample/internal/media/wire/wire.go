// Пакет wire образца — протокол кадров: шлюзу разрешён, декодеры в нём запрещены.
package wire

import "image/gif" // want:depguard

// Magic — сигнатура кадра.
const Magic = "AIMD"

var _ = gif.Decode
