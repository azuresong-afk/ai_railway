package gateway

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Протокол шлюза с aisec-media (ADR-0032, раздел 4; задача 5.39). Сервер —
// поддельный, на пакете wire: сам анализатор шлюзу импортировать нельзя
// (depguard), его проверяют тесты internal/media.

// fakeMedia — сервер протокола AIMD. analyze решает, что ответить на кадр
// analyze: тип кадра и тело.
type fakeMedia struct {
	hello   wire.HelloOK
	analyze func(h wire.Header, img []byte) (wire.FrameType, any)
	conns   atomic.Int32
	frames  atomic.Int32
}

func defaultHello() wire.HelloOK {
	return wire.HelloOK{Protocol: 1, Formats: []wire.Format{wire.FormatPNG, wire.FormatJPEG},
		Checks: []wire.Check{wire.CheckDecode}, MaxBytes: 1 << 20, MaxPixels: 40_000_000}
}

func okResult(wire.Header, []byte) (wire.FrameType, any) {
	return wire.TypeResult, wire.Result{Status: wire.StatusOK, Format: wire.FormatPNG, Width: 4, Height: 4, Frames: 1,
		Checks: []wire.Check{wire.CheckDecode}}
}

// start поднимает сервер на сокете 0660 и возвращает путь.
func (f *fakeMedia) start(t *testing.T) string {
	t.Helper()
	return startFakeML(t, f.serve)
}

func (f *fakeMedia) serve(c net.Conn) {
	f.conns.Add(1)
	for {
		h, err := wire.ReadHeader(c, wire.ServerSide)
		if err != nil {
			return
		}
		f.frames.Add(1)
		body, err := wire.ReadBody(c, h)
		if err != nil {
			return
		}
		var typ wire.FrameType
		var msg any
		switch h.Type {
		case wire.TypeHello:
			typ, msg = wire.TypeHelloOK, f.hello
		case wire.TypeAnalyze:
			if f.analyze == nil {
				typ, msg = okResult(h, body)
			} else {
				typ, msg = f.analyze(h, body)
			}
		}
		if typ == 0 {
			return // закрыть соединение без ответа
		}
		b, err := wire.MarshalBody(msg)
		if err != nil {
			return
		}
		if err := wire.WriteFrame(c, wire.Header{Type: typ, ID: h.ID}, b); err != nil {
			return
		}
	}
}

func newMediaClient(t *testing.T, sock string, now func() time.Time) *MediaClient {
	t.Helper()
	c, err := NewMediaClient(MediaClientConfig{Socket: sock, MaxInflight: 4, now: now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func mediaReason(t *testing.T, err error) string {
	t.Helper()
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("ожидалась MediaError: %v", err)
	}
	return me.Reason
}

func TestMediaClientAnalyzeAndReuse(t *testing.T) {
	f := &fakeMedia{hello: defaultHello()}
	c := newMediaClient(t, f.start(t), nil)
	if c.MaxBytes() != DefaultMediaMaxBytes {
		t.Fatalf("предел до hello: %d", c.MaxBytes())
	}
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		r, err := c.Analyze(ctx, pngBytes)
		cancel()
		if err != nil || r.Result.Status != wire.StatusOK || r.Result.Format != wire.FormatPNG || len(r.Texts) != 0 {
			t.Fatalf("%+v %v", r, err)
		}
	}
	if c.MaxBytes() != 1<<20 {
		t.Fatalf("предел из hello_ok: %d", c.MaxBytes())
	}
	if n := f.conns.Load(); n != 1 {
		t.Fatalf("соединений: %d, ожидалось одно из пула", n)
	}
}

// Срок шлюза передаётся анализатору в заголовке analyze.
func TestMediaClientSendsDeadline(t *testing.T) {
	var got atomic.Int32
	f := &fakeMedia{hello: defaultHello(), analyze: func(h wire.Header, b []byte) (wire.FrameType, any) {
		got.Store(int32(h.Timeout))
		return okResult(h, b)
	}}
	c := newMediaClient(t, f.start(t), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := c.Analyze(ctx, pngBytes); err != nil {
		t.Fatal(err)
	}
	if ms := got.Load(); ms <= 0 || ms > 1500 {
		t.Fatalf("срок в заголовке: %d мс", ms)
	}
}

func TestMediaClientErrorCodes(t *testing.T) {
	for _, tc := range []struct {
		code    wire.ErrorCode
		reason  string
		failure bool
	}{
		{wire.ErrOverloaded, events.MediaReasonOverloaded, true},
		{wire.ErrTimeout, events.MediaReasonTimeout, true},
		{wire.ErrInternal, events.MediaReasonError, true},
		{wire.ErrTooLarge, events.MediaReasonTooLarge, false},
	} {
		t.Run(string(tc.code), func(t *testing.T) {
			f := &fakeMedia{hello: defaultHello(), analyze: func(wire.Header, []byte) (wire.FrameType, any) {
				return wire.TypeError, wire.ErrorMsg{Code: tc.code}
			}}
			c := newMediaClient(t, f.start(t), nil)
			_, err := c.Analyze(context.Background(), pngBytes)
			var me *MediaError
			if !errors.As(err, &me) || me.Reason != tc.reason || me.Failure() != tc.failure {
				t.Fatalf("%v", err)
			}
			// Ответ с кодом — не сбой процесса: отсрочки нет.
			if c.isDown() {
				t.Fatal("код ошибки анализатора включил отсрочку")
			}
		})
	}
}

// Отказ по свойствам изображения приходит результатом, а не ошибкой.
func TestMediaClientRejectedResult(t *testing.T) {
	f := &fakeMedia{hello: defaultHello(), analyze: func(wire.Header, []byte) (wire.FrameType, any) {
		return wire.TypeResult, wire.Result{Status: wire.StatusRejected, Reason: wire.ReasonTooManyPixels, Format: wire.FormatPNG,
			Checks: []wire.Check{}}
	}}
	c := newMediaClient(t, f.start(t), nil)
	r, err := c.Analyze(context.Background(), pngBytes)
	if err != nil || r.Result.Status != wire.StatusRejected || r.Result.Reason != wire.ReasonTooManyPixels {
		t.Fatalf("%+v %v", r, err)
	}
}

// Изображение больше max_bytes анализатора не отправляется.
func TestMediaClientOversizeNotSent(t *testing.T) {
	h := defaultHello()
	h.MaxBytes = 64
	f := &fakeMedia{hello: h}
	c := newMediaClient(t, f.start(t), nil)
	if _, err := c.Analyze(context.Background(), pngBytes); err != nil {
		t.Fatal(err)
	}
	before := f.frames.Load()
	_, err := c.Analyze(context.Background(), make([]byte, 65))
	if mediaReason(t, err) != events.MediaReasonTooLarge {
		t.Fatalf("%v", err)
	}
	if f.frames.Load() != before {
		t.Fatal("изображение сверх предела ушло анализатору")
	}
}

// Зависший анализатор: ответ — не позже срока, после трёх сроков подряд —
// отсрочка, в которой ответ сразу unavailable.
func TestMediaClientHungBoundedByDeadline(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := &fakeMedia{hello: defaultHello(), analyze: func(wire.Header, []byte) (wire.FrameType, any) {
		<-release
		return 0, nil
	}}
	c := newMediaClient(t, f.start(t), nil)
	for i := range mediaTimeoutsToFail {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		start := time.Now()
		_, err := c.Analyze(ctx, pngBytes)
		cancel()
		if took := time.Since(start); took > time.Second {
			t.Fatalf("попытка %d: ответ через %v при сроке 100 мс", i, took)
		}
		if mediaReason(t, err) != events.MediaReasonTimeout {
			t.Fatalf("попытка %d: %v", i, err)
		}
	}
	start := time.Now()
	_, err := c.Analyze(context.Background(), pngBytes)
	if mediaReason(t, err) != events.MediaReasonUnavailable || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("в отсрочке: %v за %v", err, time.Since(start))
	}
}

// Нет сокета — unavailable и отсрочка с удвоением; после восстановления —
// снова анализ.
func TestMediaClientUnavailableBackoff(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	sock := filepath.Join(mlSocketDir(t), "absent")
	c := newMediaClient(t, sock, clock)
	_, err := c.Analyze(context.Background(), pngBytes)
	if mediaReason(t, err) != events.MediaReasonUnavailable || !c.isDown() {
		t.Fatalf("%v", err)
	}
	advance(DefaultMediaMinBack - time.Millisecond)
	if !c.isDown() {
		t.Fatal("отсрочка короче MinBackoff")
	}
	advance(time.Millisecond)
	if _, err := c.Analyze(context.Background(), pngBytes); mediaReason(t, err) != events.MediaReasonUnavailable {
		t.Fatalf("%v", err)
	}
	if c.backoff != 2*DefaultMediaMinBack {
		t.Fatalf("отсрочка не удвоилась: %v", c.backoff)
	}

	// Анализатор поднялся на том же пути.
	f := &fakeMedia{hello: defaultHello()}
	up := f.start(t)
	if err := os.Rename(up, sock); err != nil {
		t.Fatal(err)
	}
	advance(2 * DefaultMediaMinBack)
	if _, err := c.Analyze(context.Background(), pngBytes); err != nil {
		t.Fatalf("после восстановления: %v", err)
	}
	if c.backoff != 0 || c.isDown() {
		t.Fatal("отсрочка не сброшена после успешного анализа")
	}
}

// Сокет, доступный всем, — не анализатор (как у aisec-ml).
func TestMediaClientRejectsOpenSocket(t *testing.T) {
	f := &fakeMedia{hello: defaultHello()}
	sock := f.start(t)
	if err := os.Chmod(sock, 0o666); err != nil { //nolint:gosec // G302: тест задаёт права сокета намеренно
		t.Fatal(err)
	}
	c := newMediaClient(t, sock, nil)
	if _, err := c.Analyze(context.Background(), pngBytes); mediaReason(t, err) != events.MediaReasonUnavailable {
		t.Fatalf("%v", err)
	}
	if f.conns.Load() != 0 {
		t.Fatal("шлюз подключился к сокету с правами 0666")
	}
}

// hello_ok без разбора растра и неверный ответ — анализатор неисправен.
func TestMediaClientBadHello(t *testing.T) {
	h := defaultHello()
	h.Checks = []wire.Check{wire.CheckOCR}
	c := newMediaClient(t, (&fakeMedia{hello: h}).start(t), nil)
	if _, err := c.Analyze(context.Background(), pngBytes); mediaReason(t, err) != events.MediaReasonUnavailable {
		t.Fatalf("%v", err)
	}
	f := &fakeMedia{hello: defaultHello(), analyze: func(wire.Header, []byte) (wire.FrameType, any) {
		return wire.TypeResult, map[string]any{"status": "ok", "checks": []string{"decode"}, "extra": 1}
	}}
	c = newMediaClient(t, f.start(t), nil)
	if _, err := c.Analyze(context.Background(), pngBytes); mediaReason(t, err) != events.MediaReasonUnavailable {
		t.Fatalf("лишнее поле в result: %v", err)
	}
}

// Свободное соединение, закрытое анализатором, — одна попытка на новом.
func TestMediaClientRetriesClosedIdle(t *testing.T) {
	var n atomic.Int32
	f := &fakeMedia{hello: defaultHello(), analyze: func(h wire.Header, b []byte) (wire.FrameType, any) {
		if n.Add(1) == 2 {
			return 0, nil // второй analyze: соединение закрыто без ответа
		}
		return okResult(h, b)
	}}
	c := newMediaClient(t, f.start(t), nil)
	for i := range 2 {
		if _, err := c.Analyze(context.Background(), pngBytes); err != nil {
			t.Fatalf("вызов %d: %v", i, err)
		}
	}
	if f.conns.Load() != 2 || c.isDown() {
		t.Fatalf("соединений %d, отсрочка %v", f.conns.Load(), c.isDown())
	}
}

// Сверх MaxInflight — сразу overloaded, без ожидания.
func TestMediaClientInflightLimit(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	f := &fakeMedia{hello: defaultHello(), analyze: func(h wire.Header, b []byte) (wire.FrameType, any) {
		started <- struct{}{}
		<-release
		return okResult(h, b)
	}}
	c := newMediaClient(t, f.start(t), nil)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if _, err := c.Analyze(context.Background(), pngBytes); err != nil {
				t.Error(err)
			}
		})
	}
	for range 4 {
		<-started
	}
	_, err := c.Analyze(context.Background(), pngBytes)
	close(release)
	wg.Wait()
	if mediaReason(t, err) != events.MediaReasonOverloaded {
		t.Fatalf("%v", err)
	}
}

func TestNewMediaClientRelativeSocket(t *testing.T) {
	if _, err := NewMediaClient(MediaClientConfig{Socket: "media.sock"}); err == nil {
		t.Fatal("относительный путь принят")
	}
}
