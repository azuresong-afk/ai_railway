package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// События не теряются за время обновления (ОБН.2, ADR-0036 раздел 4 и
// ADR-0037): пока сервер остановлен, а затем слушает внутренний порт
// 127.0.0.1:0 (приём закрыт), настоящий отправитель шлюза получает отказ
// соединения, и буфер на диске принимает события; после открытия приёма
// (сервер снова на своём порту) они досылаются по порядку, без потерь.
func TestUpdateGatewayBufferAcrossServerDowntime(t *testing.T) {
	var mu sync.Mutex
	var got []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b events.Batch
		if err := json.NewDecoder(io.LimitReader(r.Body, events.MaxBatchBytes)).Decode(&b); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		mu.Lock()
		for _, ev := range b.Events {
			got = append(got, ev.ID)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(events.BatchResult{}) //nolint:gosec // G104: тестовый сервер
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = ln
	srv.StartTLS()
	client := srv.Client()
	u, err := url.Parse("https://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	quietLog := slog.New(slog.NewTextHandler(io.Discard, nil))
	fast := func(ctx context.Context, _ time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Millisecond):
			return true
		}
	}
	sink, err := gateway.NewServerSink(gateway.ServerSinkConfig{Client: client, Server: u, Logger: quietLog, Sleep: fast})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := standardProvider(t)
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	state, err := gateway.OpenBundleState(dir, rnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() }) //nolint:gosec // G104: очистка теста
	buf, err := gateway.OpenEventBuffer(gateway.EventBufferConfig{State: state, Provider: p, Sink: sink,
		MaxBytes: gateway.DefaultEventBufferMaxBytes, MaxAge: gateway.DefaultEventBufferMaxAge, Logger: quietLog, Sleep: fast})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = buf.Close() }) //nolint:gosec // G104: очистка теста
	gen := ids.NewGenerator(rnd)
	var want []string
	send := func(n int) {
		t.Helper()
		batch := make([]events.Event, 0, n)
		for range n {
			id, err := gen.New()
			if err != nil {
				t.Fatal(err)
			}
			ev := events.Event{ID: id.String(), Time: time.Now().UTC(), Type: events.TypeGatewayRequest, App: "support-bot", Env: "prod",
				PolicyMode: events.ModeEnforce, Storage: events.StorageNone, Decision: &events.Decision{Action: "allow", Applied: []string{}}}
			batch = append(batch, ev)
			want = append(want, ev.ID)
		}
		if err := buf.Send(context.Background(), batch); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	// До обновления сервер принимает напрямую.
	send(3)
	// Шаг 4: сервер остановлен — отказ соединения, события на диске.
	srv.Close()
	send(20)
	send(20)
	if st := buf.Stats(); st.Records != 40 || st.Spilled != 40 {
		t.Fatalf("за время остановки в буфере: %+v", st)
	}
	// Шаг 8: сервер нового выпуска слушает 127.0.0.1:0 — на прежнем адресе
	// по-прежнему отказ, события идут в буфер.
	gated := httptest.NewUnstartedServer(handler)
	gated.StartTLS()
	send(10)
	gated.Close()
	// Шаг 10: приём открыт — сервер снова на своём порту, буфер досылается.
	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("порт %s занят другим процессом: %v", addr, err)
	}
	srv2 := httptest.NewUnstartedServer(handler)
	srv2.Listener = ln2
	srv2.StartTLS()
	t.Cleanup(srv2.Close)
	buf.Start()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= len(want) && buf.Stats().Records == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("на сервере %d событий из %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("порядок нарушен на %d", i)
		}
	}
	if buf.Dropped() != 0 {
		t.Fatalf("потеряно событий: %d", buf.Dropped())
	}
}
