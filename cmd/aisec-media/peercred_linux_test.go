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

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
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

// Чужой UID или GID — соединение закрыто до чтения кадра и в Accept не
// выходит; в журнале — UID и GID собеседника без содержимого и счётчик.
func TestPeerListenerRejectsStranger(t *testing.T) {
	uid, gid := ownIDs()
	for name, want := range map[string][2]uint32{"чужой UID": {uid + 1, gid}, "чужой GID": {uid, gid + 1}} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(sockDir(t), "s")
			l, err := listenSocket(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			logs := &syncBuffer{}
			pl := newPeerListener(l, want[0], want[1], slog.New(slog.NewTextHandler(logs, nil)))
			defer pl.Close() //nolint:errcheck // тест
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
			defer c.Close()                                                                     //nolint:errcheck // тест
			_ = wire.WriteFrame(c, wire.Header{Type: wire.TypeAnalyze, ID: 1}, []byte(tinyPNG)) //nolint:gosec // G104: запись может не успеть до закрытия
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))                              //nolint:gosec // G104: тест
			if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("соединение не закрыто: %d %v", n, err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for (pl.Rejected() == 0 || !strings.Contains(logs.String(), "rejected_total=1")) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			select {
			case <-accepted:
				t.Fatal("чужое соединение вышло из Accept")
			case <-time.After(50 * time.Millisecond):
			}
			log := logs.String()
			if pl.Rejected() != 1 || !strings.Contains(log, "peer_uid=") || !strings.Contains(log, "peer_gid=") || strings.Contains(log, "PNG") {
				t.Fatalf("отказов %d, журнал: %s", pl.Rejected(), log)
			}
		})
	}
}

// aisec-media с ожидаемым UID не шлюза (собеседник — тест) не отвечает:
// соединение закрыто, а анализатор продолжает работать.
func TestRunRejectsStrangerPeer(t *testing.T) {
	cfg := testConfig(t)
	cfg.PeerUID++
	startRun(t, cfg)
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()                                                       //nolint:errcheck // тест
	_ = wire.WriteFrame(c, wire.Header{Type: wire.TypeHello, ID: 1}, nil) //nolint:gosec // G104: запись может не успеть до закрытия
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))                //nolint:gosec // G104: тест
	if _, _, err := wire.ReadFrame(c, wire.ClientSide); err == nil {
		t.Fatal("чужой собеседник получил ответ")
	}
}
