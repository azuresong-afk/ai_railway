//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"syscall" //nolint:depguard // ADR-0032, раздел 2: SO_PEERCRED собеседника по Unix-сокету
)

// peerCredSupported — учётные данные собеседника читаются (Linux).
const peerCredSupported = true

// peerCred — UID и GID процесса на другом конце Unix-сокета (SO_PEERCRED):
// ядро запоминает их при connect, собеседник их не подделает.
func peerCred(c net.Conn) (uid, gid uint32, err error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("соединение не через Unix-сокет")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("SO_PEERCRED: %w", err)
	}
	var cred *syscall.Ucred //nolint:forbidigo // ADR-0032, раздел 2: SO_PEERCRED
	var credErr error
	if err := raw.Control(func(fd uintptr) { //nolint:forbidigo // ADR-0032, раздел 2: SO_PEERCRED
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) //nolint:forbidigo,gosec // ADR-0032, раздел 2: SO_PEERCRED; G115: дескриптор сокета помещается в int
	}); err != nil {
		return 0, 0, fmt.Errorf("SO_PEERCRED: %w", err)
	}
	if credErr != nil {
		return 0, 0, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	return cred.Uid, cred.Gid, nil //nolint:forbidigo // ADR-0032, раздел 2: SO_PEERCRED
}
