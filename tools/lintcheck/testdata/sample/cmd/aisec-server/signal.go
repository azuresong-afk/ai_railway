package main

import (
	"syscall" //nolint:depguard // образец: оформленное исключение ADR-0004 // clean:depguard
)

// Разрешено только SIGTERM.
var term = syscall.SIGTERM // clean:forbidigo

// Прочее из syscall ловит forbidigo даже при открытом импорте.
var pid = syscall.Getpid // want:forbidigo
