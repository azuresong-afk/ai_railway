package media

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

func newTestServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hasher, err = p.Hasher(); err != nil {
		t.Fatal(err)
	}
	if cfg.Limits == (Limits{}) {
		cfg.Limits = testLimits
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// dial — соединение с обработчиком сервера через net.Pipe.
func dial(t *testing.T, s *Server) net.Conn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srv, cli := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer srv.Close() //nolint:errcheck // тест
		s.handle(ctx, srv)
	}()
	t.Cleanup(func() {
		cancel()
		_ = cli.Close() //nolint:gosec // G104: тест
		<-done
	})
	if err := cli.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return cli
}

func send(t *testing.T, c net.Conn, h wire.Header, body []byte) {
	t.Helper()
	if err := wire.WriteFrame(c, h, body); err != nil {
		t.Fatal(err)
	}
}

// reply читает ответ: итог или код ошибки.
func reply(t *testing.T, c net.Conn, id uint32) (*wire.Result, wire.ErrorCode) {
	t.Helper()
	h, b, err := wire.ReadFrame(c, wire.ClientSide)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != id {
		t.Fatalf("номер ответа %d, ожидался %d", h.ID, id)
	}
	switch h.Type {
	case wire.TypeResult:
		r, err := wire.ParseResult(b)
		if err != nil {
			t.Fatal(err)
		}
		return r, ""
	case wire.TypeError:
		code, err := wire.ParseError(b)
		if err != nil {
			t.Fatal(err)
		}
		return nil, code
	}
	t.Fatalf("тип ответа %d", h.Type)
	return nil, ""
}

// blocking — анализ, который ждёт release; started — анализ начался.
type blocking struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func newBlocking() *blocking {
	return &blocking{started: make(chan struct{}, 16), release: make(chan struct{})}
}

func (b *blocking) analyze(data []byte, l Limits) (wire.Result, error) {
	b.calls.Add(1)
	b.started <- struct{}{}
	<-b.release
	return Analyze(data, l)
}

func TestServerHelloAndAnalyze(t *testing.T) {
	s := newTestServer(t, ServerConfig{})
	c := dial(t, s)
	send(t, c, wire.Header{Type: wire.TypeHello, ID: 1}, nil)
	h, b, err := wire.ReadFrame(c, wire.ClientSide)
	if err != nil || h.Type != wire.TypeHelloOK {
		t.Fatal(h, err)
	}
	hello, err := wire.ParseHelloOK(b)
	if err != nil || hello.MaxBytes != DefaultMaxBytes || hello.MaxPixels != DefaultMaxPixels || len(hello.Formats) != 3 {
		t.Fatalf("%+v %v", hello, err)
	}
	send(t, c, wire.Header{Type: wire.TypeAnalyze, ID: 2}, encodePNG(t, 5, 4))
	if r, code := reply(t, c, 2); code != "" || r.Status != wire.StatusOK || r.Width != 5 || r.Cached {
		t.Fatalf("%+v %s", r, code)
	}
}

// Повтор того же изображения — из кэша, анализ не вызывается повторно.
func TestServerCacheRepeat(t *testing.T) {
	s := newTestServer(t, ServerConfig{})
	var calls atomic.Int32
	s.analyze = func(d []byte, l Limits) (wire.Result, error) { calls.Add(1); return Analyze(d, l) }
	c := dial(t, s)
	img := encodeGIF(t, 2, 6, 6)
	for i := range uint32(3) {
		send(t, c, wire.Header{Type: wire.TypeAnalyze, ID: 10 + i}, img)
		r, code := reply(t, c, 10+i)
		if code != "" || r.Status != wire.StatusOK || r.Cached != (i > 0) {
			t.Fatalf("запрос %d: %+v %s", i, r, code)
		}
	}
	// Отказ по пределам тоже кэшируется: тяжёлый файл не разбирается снова.
	bomb := pngHeader(40_000, 40_000)
	for i := range uint32(2) {
		send(t, c, wire.Header{Type: wire.TypeAnalyze, ID: 20 + i}, bomb)
		if r, _ := reply(t, c, 20+i); r == nil || r.Reason != wire.ReasonTooManyPixels || r.Cached != (i > 0) {
			t.Fatalf("бомба %d: %+v", i, r)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("анализов %d, ожидалось 2", calls.Load())
	}
}

// Длина изображения сверх -max-bytes — too_large по заголовку кадра, тело
// не читается (клиент его и не отправляет), соединение закрывается.
func TestServerTooLargeNotRead(t *testing.T) {
	s := newTestServer(t, ServerConfig{Limits: Limits{MaxBytes: MinMaxBytes, MaxPixels: DefaultMaxPixels}})
	c := dial(t, s)
	if _, err := c.Write(wire.AppendHeader(nil, wire.Header{Type: wire.TypeAnalyze, ID: 5, Length: MinMaxBytes + 1})); err != nil {
		t.Fatal(err)
	}
	if _, code := reply(t, c, 5); code != wire.ErrTooLarge {
		t.Fatalf("код %q", code)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("соединение не закрыто: %v", err)
	}
}

func TestServerProtocolError(t *testing.T) {
	s := newTestServer(t, ServerConfig{})
	c := dial(t, s)
	if _, err := c.Write([]byte("AIML\x01\x03\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00")); err != nil {
		t.Fatal(err)
	}
	if _, code := reply(t, c, 0); code != wire.ErrBadRequest {
		t.Fatalf("код %q", code)
	}
}

// Очередь полна — сразу overloaded (DM-50), занятый исполнитель не ждут.
func TestServerQueueOverflow(t *testing.T) {
	s := newTestServer(t, ServerConfig{Workers: 1, Queue: 1})
	b := newBlocking()
	s.analyze = b.analyze
	defer close(b.release)
	img := encodePNG(t, 2, 2)
	a := dial(t, s)
	send(t, a, wire.Header{Type: wire.TypeAnalyze, ID: 1}, img)
	<-b.started // исполнитель занят
	q := dial(t, s)
	send(t, q, wire.Header{Type: wire.TypeAnalyze, ID: 1}, encodePNG(t, 2, 3)) // ждёт в очереди
	time.Sleep(20 * time.Millisecond)
	o := dial(t, s)
	start := time.Now()
	send(t, o, wire.Header{Type: wire.TypeAnalyze, ID: 7}, encodePNG(t, 3, 3))
	if _, code := reply(t, o, 7); code != wire.ErrOverloaded {
		t.Fatalf("код %q", code)
	}
	if time.Since(start) > time.Second || s.Overloaded() != 1 {
		t.Fatalf("overloaded через %s, счётчик %d", time.Since(start), s.Overloaded())
	}
	// Соединение после overloaded работает дальше.
	send(t, o, wire.Header{Type: wire.TypeHello, ID: 8}, nil)
	if h, _, err := wire.ReadFrame(o, wire.ClientSide); err != nil || h.Type != wire.TypeHelloOK {
		t.Fatal(h, err)
	}
}

// Срок истёк во время анализа — timeout; анализ доделывается и его итог
// попадает в кэш, слот освобождается только по завершении.
func TestServerDeadlineDuringAnalysis(t *testing.T) {
	s := newTestServer(t, ServerConfig{Workers: 1})
	b := newBlocking()
	s.analyze = b.analyze
	c := dial(t, s)
	img := encodePNG(t, 3, 3)
	send(t, c, wire.Header{Type: wire.TypeAnalyze, Timeout: 30, ID: 3}, img)
	<-b.started
	if _, code := reply(t, c, 3); code != wire.ErrTimeout {
		t.Fatalf("код %q", code)
	}
	if s.Timeouts() != 1 || len(s.slots) != 1 {
		t.Fatalf("сроков %d, занятых слотов %d", s.Timeouts(), len(s.slots))
	}
	close(b.release)
	deadline := time.Now().Add(2 * time.Second)
	for len(s.slots) != 0 || s.cache.Len() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("слот не освобождён или итог не в кэше")
		}
		time.Sleep(5 * time.Millisecond)
	}
	send(t, c, wire.Header{Type: wire.TypeAnalyze, ID: 4}, img)
	if r, code := reply(t, c, 4); code != "" || !r.Cached {
		t.Fatalf("%+v %s", r, code)
	}
}

// Срок истёк в очереди — timeout, и анализ этого запроса не выполняется.
func TestServerDeadlineInQueue(t *testing.T) {
	s := newTestServer(t, ServerConfig{Workers: 1, Queue: 4})
	b := newBlocking()
	s.analyze = b.analyze
	a := dial(t, s)
	send(t, a, wire.Header{Type: wire.TypeAnalyze, ID: 1}, encodePNG(t, 2, 2))
	<-b.started
	q := dial(t, s)
	send(t, q, wire.Header{Type: wire.TypeAnalyze, Timeout: 30, ID: 2}, encodePNG(t, 4, 4))
	if _, code := reply(t, q, 2); code != wire.ErrTimeout {
		t.Fatalf("код %q", code)
	}
	close(b.release)
	if r, code := reply(t, a, 1); code != "" || r.Status != wire.StatusOK {
		t.Fatalf("%+v %s", r, code)
	}
	time.Sleep(20 * time.Millisecond)
	if b.calls.Load() != 1 || len(s.queue) != 0 {
		t.Fatalf("анализов %d, в очереди %d", b.calls.Load(), len(s.queue))
	}
}

// Паника анализа — internal для запроса, процесс и соединение работают.
func TestServerAnalyzerPanic(t *testing.T) {
	s := newTestServer(t, ServerConfig{})
	s.analyze = func([]byte, Limits) (wire.Result, error) { panic("декодер") }
	c := dial(t, s)
	send(t, c, wire.Header{Type: wire.TypeAnalyze, ID: 1}, encodePNG(t, 2, 2))
	if _, code := reply(t, c, 1); code != wire.ErrInternal {
		t.Fatalf("код %q", code)
	}
	s.analyze = Analyze
	send(t, c, wire.Header{Type: wire.TypeAnalyze, ID: 2}, encodePNG(t, 2, 2))
	if r, code := reply(t, c, 2); code != "" || r.Status != wire.StatusOK {
		t.Fatalf("%+v %s", r, code)
	}
	if len(s.slots) != 0 || len(s.queue) != 0 {
		t.Fatal("слот не освобождён после паники")
	}
}

// Срок из кадра ограничен MaxRunTimeout, без срока — RunTimeout.
func TestServerRunTimeout(t *testing.T) {
	s := newTestServer(t, ServerConfig{RunTimeout: time.Second, MaxRunTimeout: 3 * time.Second})
	if d := s.runTimeout(wire.Header{}); d != time.Second {
		t.Fatal(d)
	}
	if d := s.runTimeout(wire.Header{Timeout: 500}); d != 500*time.Millisecond {
		t.Fatal(d)
	}
	if d := s.runTimeout(wire.Header{Timeout: 60_000}); d != 3*time.Second {
		t.Fatal(d)
	}
	if _, err := NewServer(ServerConfig{Limits: testLimits}); err == nil {
		t.Fatal("сервер без хеша")
	}
}

// Лишние соединения сверх MaxConns закрываются сразу.
func TestServerMaxConns(t *testing.T) {
	s := newTestServer(t, ServerConfig{MaxConns: 1})
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	defer func() { cancel(); <-done }()
	d := &net.Dialer{}
	first, err := d.DialContext(ctx, "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close() //nolint:errcheck // тест
	send(t, first, wire.Header{Type: wire.TypeHello, ID: 1}, nil)
	if _, _, err := wire.ReadFrame(first, wire.ClientSide); err != nil {
		t.Fatal(err)
	}
	second, err := d.DialContext(ctx, "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()                                        //nolint:errcheck // тест
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:gosec // G104: тест
	if _, err := second.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("второе соединение не закрыто: %v", err)
	}
}
