package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
)

// socketMode — права сокета: владелец (aisec-ml) и группа шлюза.
const socketMode = 0o660

// listenSocket создаёт Unix-сокет для шлюза (ADR-0024, раздел 2). Каталог
// сокета — общий со шлюзом: обязан быть каталогом, не ссылкой и без прав для
// остальных, иначе отказ. Старый файл на месте сокета удаляется, только если
// это сокет. Права 0660 ставятся сразу после создания: в окне до chmod
// посторонний в каталог не войдёт.
func listenSocket(ctx context.Context, path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir) //nolint:gosec // G703: путь сокета задаёт администратор флагом -socket
	if err != nil {
		return nil, fmt.Errorf("каталог сокета: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("каталог сокета %s: не каталог или символьная ссылка", dir)
	}
	if info.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("каталог сокета %s: права %#o, у остальных не должно быть доступа", dir, info.Mode().Perm())
	}
	old, err := os.Lstat(path) //nolint:gosec // G703: путь сокета задаёт администратор флагом -socket
	switch {
	case err == nil && old.Mode().Type() == fs.ModeSocket:
		if err := os.Remove(path); err != nil { //nolint:gosec // G703: путь сокета задаёт администратор флагом -socket
			return nil, fmt.Errorf("старый сокет: %w", err)
		}
	case err == nil:
		return nil, fmt.Errorf("%s: на месте сокета другой файл", path)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("сокет: %w", err)
	}
	l, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, socketMode); err != nil { //nolint:gosec // G703: путь сокета задаёт администратор флагом -socket
		_ = l.Close() //nolint:gosec // G104: запуск всё равно прерывается
		return nil, fmt.Errorf("права сокета: %w", err)
	}
	return l, nil
}
