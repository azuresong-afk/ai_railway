package ml_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/ml"
	"github.com/azuresong-afk/ai_railway/internal/ml/mltest"
)

var injInfo = ml.ModelInfo{ID: "injection", Version: "1.0", Labels: []string{"injection"}, Directions: []string{"input"}}

// startServer запускает сервер протокола на Unix-сокете во временном
// каталоге (короткий путь: предел sun_path — 108 байт).
func startServer(t *testing.T, cfg ml.ServerConfig) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:gosec // G104: ошибка в тесте не важна
	sock := filepath.Join(dir, "s")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ml.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return sock
}

func dial(t *testing.T, sock string) net.Conn {
	t.Helper()
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })                //nolint:gosec // G104: ошибка в тесте не важна
	_ = c.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:gosec // G104: ошибка в тесте не важна
	return c
}

func roundTrip(t *testing.T, c net.Conn, typ ml.FrameType, id uint32, body []byte) (ml.Header, []byte) {
	t.Helper()
	if err := ml.WriteFrame(c, ml.Header{Type: typ, ID: id}, body); err != nil {
		t.Fatal(err)
	}
	h, b, err := ml.ReadFrame(c, ml.ClientSide)
	if err != nil {
		t.Fatal(err)
	}
	return h, b
}

func detectBody(t *testing.T, model, text string) []byte {
	t.Helper()
	b, err := ml.EncodeDetect(model, text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServerHelloAndDetect(t *testing.T) {
	m := mltest.NewModel(injInfo, map[string]string{"ignore": "injection"}, nil)
	sock := startServer(t, ml.ServerConfig{Models: []ml.Model{m}})
	c := dial(t, sock)
	h, b := roundTrip(t, c, ml.TypeHello, 1, nil)
	if h.Type != ml.TypeHelloOK || h.ID != 1 {
		t.Fatalf("ответ на hello: %+v", h)
	}
	hello, err := ml.ParseHelloOK(b)
	if err != nil || len(hello.Models) != 1 || hello.Models[0].ID != "injection" {
		t.Fatalf("hello: %+v %v", hello, err)
	}
	text := "please ignore it"
	h, b = roundTrip(t, c, ml.TypeDetect, 2, detectBody(t, "injection", text))
	if h.Type != ml.TypeResult || h.ID != 2 {
		t.Fatalf("ответ на detect: %+v %s", h, b)
	}
	r, err := ml.ParseResult(b, hello.Models[0], text)
	if err != nil || len(r.Findings) != 1 || text[r.Findings[0].Start:r.Findings[0].End] != "ignore" {
		t.Fatalf("находки: %+v %v", r, err)
	}
}

func expectError(t *testing.T, h ml.Header, b []byte, want ml.ErrorCode) {
	t.Helper()
	if h.Type != ml.TypeError {
		t.Fatalf("ожидалась ошибка %s, получен тип %d", want, h.Type)
	}
	code, err := ml.ParseError(b)
	if err != nil || code != want {
		t.Fatalf("код %q (%v), нужен %q", code, err, want)
	}
}

func TestServerUnknownModel(t *testing.T) {
	sock := startServer(t, ml.ServerConfig{Models: []ml.Model{mltest.NewModel(injInfo, map[string]string{"x": "injection"}, nil)}})
	c := dial(t, sock)
	h, b := roundTrip(t, c, ml.TypeDetect, 3, detectBody(t, "toxicity", "x"))
	expectError(t, h, b, ml.ErrUnknownModel)
	// Соединение продолжает работать.
	h, _ = roundTrip(t, c, ml.TypeHello, 4, nil)
	if h.Type != ml.TypeHelloOK {
		t.Fatalf("после unknown_model соединение не работает: %+v", h)
	}
}

// Кадр сверх предела: ошибка too_large и закрытие соединения без чтения тела.
func TestServerRejectsOversizeFrame(t *testing.T) {
	sock := startServer(t, ml.ServerConfig{Models: []ml.Model{mltest.NewModel(injInfo, map[string]string{"x": "injection"}, nil)}})
	c := dial(t, sock)
	hdr := ml.AppendHeader(nil, ml.Header{Type: ml.TypeDetect, ID: 5, Length: ml.MaxDetectBody + 1})
	if _, err := c.Write(hdr); err != nil {
		t.Fatal(err)
	}
	h, b, err := ml.ReadFrame(c, ml.ClientSide)
	if err != nil {
		t.Fatal(err)
	}
	expectError(t, h, b, ml.ErrTooLarge)
	if _, _, err := ml.ReadFrame(c, ml.ClientSide); !errors.Is(err, io.EOF) {
		t.Fatalf("соединение не закрыто: %v", err)
	}
}

func TestServerRejectsGarbage(t *testing.T) {
	sock := startServer(t, ml.ServerConfig{Models: []ml.Model{mltest.NewModel(injInfo, map[string]string{"x": "injection"}, nil)}})
	c := dial(t, sock)
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	h, b, err := ml.ReadFrame(c, ml.ClientSide)
	if err != nil {
		t.Fatal(err)
	}
	expectError(t, h, b, ml.ErrBadRequest)
}

func TestServerOverloaded(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	m := mltest.NewModel(injInfo, map[string]string{"x": "injection"}, func(ctx context.Context, text string) error {
		if text == "block" {
			started <- struct{}{}
			<-release
		}
		return nil
	})
	sock := startServer(t, ml.ServerConfig{Models: []ml.Model{m}, Workers: 1, QueueWait: 10 * time.Millisecond})
	defer close(release)
	busy := dial(t, sock)
	if err := ml.WriteFrame(busy, ml.Header{Type: ml.TypeDetect, ID: 1}, detectBody(t, "injection", "block")); err != nil {
		t.Fatal(err)
	}
	<-started
	h, b := roundTrip(t, dial(t, sock), ml.TypeDetect, 2, detectBody(t, "injection", "x"))
	expectError(t, h, b, ml.ErrOverloaded)
}

func TestServerExecutorPanicAndBadFindings(t *testing.T) {
	m := mltest.NewModel(injInfo, map[string]string{"x": "injection"}, func(ctx context.Context, text string) error {
		if text == "panic" {
			panic("сбой")
		}
		if text == "fail" {
			return errors.New("сбой исполнителя")
		}
		return nil
	})
	sock := startServer(t, ml.ServerConfig{Models: []ml.Model{m}})
	c := dial(t, sock)
	for _, txt := range []string{"panic", "fail"} {
		h, b := roundTrip(t, c, ml.TypeDetect, 1, detectBody(t, "injection", txt))
		expectError(t, h, b, ml.ErrInternal)
	}
	// Процесс продолжает обслуживать запросы.
	h, _ := roundTrip(t, c, ml.TypeDetect, 2, detectBody(t, "injection", "x"))
	if h.Type != ml.TypeResult {
		t.Fatalf("после паники: %+v", h)
	}
}

func TestServerMaxConns(t *testing.T) {
	sock := startServer(t, ml.ServerConfig{Models: []ml.Model{mltest.NewModel(injInfo, map[string]string{"x": "injection"}, nil)}, MaxConns: 1})
	first := dial(t, sock)
	roundTrip(t, first, ml.TypeHello, 1, nil)
	second := dial(t, sock)
	_ = ml.WriteFrame(second, ml.Header{Type: ml.TypeHello, ID: 2}, nil) //nolint:gosec // G104: ошибка в тесте не важна
	if _, _, err := ml.ReadFrame(second, ml.ClientSide); err == nil {
		t.Fatal("соединение сверх предела обслужено")
	}
}

func TestNewServerRejectsDuplicateModels(t *testing.T) {
	m := mltest.NewModel(injInfo, map[string]string{"x": "injection"}, nil)
	if _, err := ml.NewServer(ml.ServerConfig{Models: []ml.Model{m, m}}); err == nil {
		t.Fatal("повтор модели принят")
	}
	bad := mltest.NewModel(ml.ModelInfo{ID: "Bad", Version: "1", Labels: []string{"x"}, Directions: []string{"input"}}, nil, nil)
	if _, err := ml.NewServer(ml.ServerConfig{Models: []ml.Model{bad}}); err == nil {
		t.Fatal("неверный ID модели принят")
	}
}

func TestServerTextAtLimit(t *testing.T) {
	sock := startServer(t, ml.ServerConfig{Models: []ml.Model{mltest.NewModel(injInfo, map[string]string{"ignore": "injection"}, nil)}})
	c := dial(t, sock)
	text := strings.Repeat("a", ml.MaxText-6) + "ignore"
	h, b := roundTrip(t, c, ml.TypeDetect, 9, detectBody(t, "injection", text))
	if h.Type != ml.TypeResult || !bytes.Contains(b, []byte(`"label":"injection"`)) {
		t.Fatalf("текст на пределе: %+v %s", h, b)
	}
}
