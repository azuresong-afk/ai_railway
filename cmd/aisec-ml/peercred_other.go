//go:build !linux

package main

import (
	"errors"
	"net"
)

// peerCredSupported — на других ОС учётные данные собеседника не
// читаются, и aisec-ml не запускается (ADR-0024, дополнение задачи 5.7).
const peerCredSupported = false

func peerCred(net.Conn) (uid, gid uint32, err error) {
	return 0, 0, errors.New("SO_PEERCRED поддерживается только в Linux")
}
