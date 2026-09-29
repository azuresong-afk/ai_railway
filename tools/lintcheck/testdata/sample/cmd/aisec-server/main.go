// Команда aisec-server образца: криптография вне internal/crypto запрещена.
package main

import "crypto/tls" // want:depguard

func main() { _ = tls.VersionTLS13 }
