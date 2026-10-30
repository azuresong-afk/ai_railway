package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
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

// peerLogEvery — не чаще одной записи об отказе в технический журнал:
// процесс группы шлюза, открывающий соединения в цикле, не заполнит журнал.
// Счётчик отказов в записи — все отказы с запуска.
const peerLogEvery = time.Second

// peerListener пропускает к серверу только соединения шлюза: UID и GID
// собеседника (SO_PEERCRED) совпадают с ожидаемыми (4Н27, ADR-0024,
// раздел 2). Сверяются оба: группа шлюза есть и у самого aisec-ml, и одна
// группа не отличает шлюз от других процессов этой группы. Чужое
// соединение закрывается в Accept — до чтения кадра и до слота сервера
// (ml.ServerConfig.MaxConns).
type peerListener struct {
	net.Listener
	uid, gid uint32
	logger   *slog.Logger
	rejected atomic.Uint64
	mu       sync.Mutex
	lastLog  time.Time
}

func newPeerListener(l net.Listener, uid, gid uint32, logger *slog.Logger) *peerListener {
	return &peerListener{Listener: l, uid: uid, gid: gid, logger: logger}
}

// Accept возвращает следующее соединение шлюза; чужие закрываются, ошибка
// чтения учётных данных — тоже отказ.
func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, gid, err := peerCred(c)
		if err == nil && uid == l.uid && gid == l.gid {
			return c, nil
		}
		_ = c.Close() //nolint:gosec // G104: чужое соединение закрывается без чтения
		l.reject(uid, gid, err)
	}
}

// reject считает отказ и пишет в журнал UID и GID собеседника — без
// содержимого: из соединения ничего не прочитано.
func (l *peerListener) reject(uid, gid uint32, err error) {
	n := l.rejected.Add(1)
	l.mu.Lock()
	now := time.Now()
	write := now.Sub(l.lastLog) >= peerLogEvery
	if write {
		l.lastLog = now
	}
	l.mu.Unlock()
	if !write {
		return
	}
	if err != nil {
		l.logger.Warn("aisec-ml: учётные данные собеседника не прочитаны, соединение закрыто", "error", err, "rejected_total", n)
		return
	}
	l.logger.Warn("aisec-ml: соединение не от шлюза закрыто", "peer_uid", uid, "peer_gid", gid, "rejected_total", n)
}

// Rejected — число отказов с запуска.
func (l *peerListener) Rejected() uint64 { return l.rejected.Load() }
