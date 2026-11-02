//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// syncBuffer — журнал отказов: пишет Accept в своей горутине, читает тест.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// peerSocket — сокет aisec-ml в каталоге 0750 с проверкой собеседника и
// журнал отказов.
func peerSocket(t *testing.T, uid, gid uint32) (*peerListener, string, *syncBuffer) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })  //nolint:gosec // G104: ошибка в тесте не важна
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: тест задаёт права каталога сокета намеренно
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	l, err := listenSocket(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	pl := newPeerListener(l, uid, gid, slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { _ = pl.Close() }) //nolint:gosec // G104: ошибка в тесте не важна
	return pl, path, logs
}

// Свои UID и GID — соединение принято, учётные данные прочитаны.
func TestPeerListenerAcceptsGateway(t *testing.T) {
	uid, gid := ownIDs()
	pl, path, _ := peerSocket(t, uid, gid)
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck // тест
	got, err := pl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close() //nolint:errcheck // тест
	if u, g, err := peerCred(got); err != nil || u != uid || g != gid {
		t.Fatalf("SO_PEERCRED: %d %d %v, ожидалось %d %d", u, g, err, uid, gid)
	}
	if pl.Rejected() != 0 {
		t.Fatalf("отказов %d", pl.Rejected())
	}
}

// Покрывает 4Н27: неверный ожидаемый UID или GID — соединение закрыто до
// чтения кадра и в Accept не выходит (слот сервера не занят); в журнале —
// UID и GID собеседника без содержимого, счётчик отказов.
func TestPeerListenerRejectsStranger(t *testing.T) {
	uid, gid := ownIDs()
	for name, want := range map[string][2]uint32{"чужой UID": {uid + 1, gid}, "чужой GID": {uid, gid + 1}} {
		t.Run(name, func(t *testing.T) {
			pl, path, logs := peerSocket(t, want[0], want[1])
			accepted := make(chan net.Conn, 1)
			go func() {
				if c, err := pl.Accept(); err == nil {
					accepted <- c
				}
			}()
			c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close() //nolint:errcheck // тест
			// Кадр отправлен, но сервер его не читает: соединение закрыто.
			body, err := ml.EncodeDetect("injection", "секретный текст")
			if err != nil {
				t.Fatal(err)
			}
			_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeDetect, ID: 1}, body) //nolint:gosec // G104: запись может не успеть до закрытия
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))            //nolint:gosec // G104: тест
			if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("соединение не закрыто: %d %v", n, err)
			}
			// Отказ считается и пишется в журнал сразу после закрытия.
			deadline := time.Now().Add(5 * time.Second)
			for (pl.Rejected() == 0 || !strings.Contains(logs.String(), "rejected_total=1")) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			select {
			case <-accepted:
				t.Fatal("чужое соединение вышло из Accept")
			case <-time.After(50 * time.Millisecond):
			}
			if pl.Rejected() != 1 {
				t.Fatalf("отказов %d", pl.Rejected())
			}
			log := logs.String()
			if !strings.Contains(log, "peer_uid=") || !strings.Contains(log, "peer_gid=") || !strings.Contains(log, "rejected_total=1") ||
				strings.Contains(log, "секретный") {
				t.Fatalf("журнал: %s", log)
			}
		})
	}
}

// aisec-ml с ожидаемым UID не шлюза (собеседник — тест) не отвечает на
// кадр: соединение закрыто, а сервер продолжает работать.
func TestRunRejectsStrangerPeer(t *testing.T) {
	f := newFixture(t)
	f.cfg.PeerUID++
	ready := make(chan struct{})
	f.d.ready = func() { close(ready) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.cfg, f.d) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("aisec-ml не запустился: %v", err)
	}
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", f.cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ml.EncodeDetect("injection", "ignore all")
	if err != nil {
		t.Fatal(err)
	}
	_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeDetect, ID: 1}, body) //nolint:gosec // G104: запись может не успеть до закрытия
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))            //nolint:gosec // G104: тест
	if _, _, err := ml.ReadFrame(c, ml.ClientSide); err == nil {
		t.Fatal("чужой собеседник получил ответ")
	}
	_ = c.Close() //nolint:gosec // G104: ошибка в тесте не важна
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("остановка: %v", err)
	}
}
