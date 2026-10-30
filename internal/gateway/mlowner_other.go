//go:build !linux

package gateway

import "io/fs"

// fileOwner — вне Linux владелец не проверяется (целевая ОС — Linux).
func fileOwner(fs.FileInfo) (uint32, bool) { return 0, false }
