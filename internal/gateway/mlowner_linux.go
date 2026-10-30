//go:build linux

package gateway

import (
	"io/fs"
	"syscall" //nolint:depguard // ADR-0024, дополнение 30.10.2026 (4Н27 ревью 4.r3): только чтение UID владельца из Lstat, без системных вызовов
)

// fileOwner — UID владельца файла из результата os.Lstat; false — ОС не
// сообщила владельца.
func fileOwner(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t) //nolint:forbidigo // ADR-0024, дополнение 30.10.2026: тип результата Lstat, не системный вызов
	if !ok {
		return 0, false
	}
	return st.Uid, true //nolint:forbidigo // поле результата Lstat (см. выше)
}
