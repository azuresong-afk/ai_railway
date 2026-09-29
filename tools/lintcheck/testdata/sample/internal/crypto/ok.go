// Пакет crypto образца: здесь криптография разрешена.
package crypto

import "crypto/sha256" // clean:depguard

// Sum считает хеш.
func Sum(b []byte) [32]byte { return sha256.Sum256(b) }
