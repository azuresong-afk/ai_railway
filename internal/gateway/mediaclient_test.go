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
	// sanitize — ответ на кадр sanitize: тело []byte уходит как есть
	// (sanitized), иное — JSON (error).
	sanitize func(h wire.Header, img []byte) (wire.FrameType, any)
	conns    atomic.Int32
	frames   atomic.Int32
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
		case wire.TypeSanitize:
			if f.sanitize != nil {
				typ, msg = f.sanitize(h, body)
			}
		}
		if typ == 0 {
			return // закрыть соединение без ответа
		}
		b, ok := msg.([]byte)
		if !ok {
			if b, err = wire.MarshalBody(msg); err != nil {
				return
			}
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

// Тексты итога (задача 5.43) переходят в MediaReply.Texts с источником и
// рамкой; в Result текста не остаётся. Итог с текстом без своей проверки
// в checks — нарушение протокола.
func TestMediaClientTexts(t *testing.T) {
	res := wire.Result{Status: wire.StatusOK, Format: wire.FormatPNG, Width: 40, Height: 40, Frames: 1,
		Checks: []wire.Check{wire.CheckDecode, wire.CheckMetadata, wire.CheckQR},
		Texts:  []wire.Text{{Text: "описание", Source: wire.SourceMetadata}, {Text: "код", Source: wire.SourceQR, Box: &wire.Box{X: 1, Y: 2, W: 30, H: 30}}}}
	f := &fakeMedia{hello: defaultHello(), analyze: func(wire.Header, []byte) (wire.FrameType, any) { return wire.TypeResult, res }}
	c := newMediaClient(t, f.start(t), nil)
	r, err := c.Analyze(context.Background(), pngBytes)
	if err != nil || len(r.Result.Texts) != 0 || len(r.Texts) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if r.Texts[0] != (MediaText{Text: "описание", Origin: "metadata"}) || r.Texts[1].Origin != "qr" || *r.Texts[1].Box != (events.Box{X: 1, Y: 2, W: 30, H: 30}) {
		t.Fatalf("тексты %+v", r.Texts)
	}
	bad := res
	bad.Checks = []wire.Check{wire.CheckDecode, wire.CheckQR}
	f2 := &fakeMedia{hello: defaultHello(), analyze: func(wire.Header, []byte) (wire.FrameType, any) { return wire.TypeResult, bad }}
	c2 := newMediaClient(t, f2.start(t), nil)
	if _, err := c2.Analyze(context.Background(), pngBytes); err == nil {
		t.Fatal("принят текст метаданных без проверки metadata")
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

// Задача 5.44 (DM-50): счётчики клиента для heartbeat — ответы анализатора
// и сбои по причинам, очередь шлюза, отсрочка после сбоя и самотест.
func TestMediaClientStats(t *testing.T) {
	var mode atomic.Int32
	f := &fakeMedia{hello: defaultHello(), analyze: func(h wire.Header, b []byte) (wire.FrameType, any) {
		switch mode.Load() {
		case 1:
			return wire.TypeError, wire.ErrorMsg{Code: wire.ErrOverloaded}
		case 2:
			return wire.TypeError, wire.ErrorMsg{Code: wire.ErrInternal}
		case 3:
			return wire.TypeResult, wire.Result{Status: wire.StatusRejected, Reason: wire.ReasonMalformed, Checks: []wire.Check{}}
		}
		return okResult(h, b)
	}}
	c := newMediaClient(t, f.start(t), nil)
	if st := c.Stats(); st.MaxInflight != 4 || st.Inflight != 0 || st.Down || st.Analyzed != 0 || st.Selftest != nil {
		t.Fatalf("начало: %+v", st)
	}
	analyze := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = c.Analyze(ctx, pngBytes) //nolint:gosec // G104: итог учитывают счётчики
	}
	for _, m := range []int32{0, 3, 1, 1, 2} {
		mode.Store(m)
		analyze()
	}
	st := c.Stats()
	if st.Analyzed != 2 || st.Overloaded != 2 || st.Error != 1 || st.Unavailable != 0 || st.Timeout != 0 || st.Down {
		t.Fatalf("после ответов: %+v", st)
	}
	// Анализатора нет — unavailable и отсрочка; самотест в отчёте.
	c = newMediaClient(t, filepath.Join(t.TempDir(), "none.sock"), nil)
	analyze()
	c.SetSelftest(MediaSelftest{Result: MediaSelftestUnchecked, CheckedAt: time.Unix(10, 0)})
	st = c.Stats()
	if st.Unavailable != 1 || !st.Down || st.Analyzed != 0 || st.Selftest == nil || st.Selftest.Result != MediaSelftestUnchecked {
		t.Fatalf("после пропажи сокета: %+v", st)
	}
	r := NewMediaReport(st)
	if r.Unchecked.Unavailable != 1 || r.Unchecked.Overloaded != 0 || !r.Down || r.Selftest.Result != "unchecked" || !r.Selftest.CheckedAt.Equal(time.Unix(10, 0)) {
		t.Fatalf("отчёт: %+v", r)
	}
}

// Очистка (задача 5.45): очищенные байты и формат по сигнатуре; rejected —
// свойство изображения; анализатор без sanitize в hello_ok — unavailable
// без отправки кадра; ответ не PNG/JPEG или больше max_bytes — нарушение
// протокола (сбой, соединение закрывается).
func TestMediaClientSanitize(t *testing.T) {
	hello := defaultHello()
	hello.Sanitize = true
	clean := []byte("\xff\xd8\xffочищено")
	f := &fakeMedia{hello: hello, sanitize: func(h wire.Header, img []byte) (wire.FrameType, any) {
		switch string(img[len(img)-1:]) {
		case "r":
			return wire.TypeError, wire.ErrorMsg{Code: wire.ErrRejected}
		case "o":
			return wire.TypeError, wire.ErrorMsg{Code: wire.ErrOverloaded}
		case "g":
			return wire.TypeSanitized, []byte("GIF89a")
		case "b":
			return wire.TypeSanitized, append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 2<<20)...)
		}
		if h.Timeout <= 0 {
			return wire.TypeError, wire.ErrorMsg{Code: wire.ErrInternal}
		}
		return wire.TypeSanitized, clean
	}}
	c := newMediaClient(t, f.start(t), nil)
	// До первого hello клиент не знает, умеет ли анализатор очистку:
	// подключение идёт, флаг берётся из hello_ok.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, format, err := c.Sanitize(ctx, append([]byte("img"), 'x'))
	if err != nil || format != wire.FormatJPEG || string(out) != string(clean) {
		t.Fatalf("%q %s %v", out, format, err)
	}
	if _, _, err := c.Sanitize(ctx, []byte("img r")); mediaReason(t, err) != mediaReasonRejected {
		t.Fatal(err)
	}
	if _, _, err := c.Sanitize(ctx, []byte("img o")); mediaReason(t, err) != events.MediaReasonOverloaded {
		t.Fatal(err)
	}
	before := c.Stats()
	for _, img := range []string{"img g", "img b"} {
		_, _, err := c.Sanitize(ctx, []byte(img))
		var me *MediaError
		if !errors.As(err, &me) || !me.Failure() {
			t.Fatalf("%s: %v", img, err)
		}
		c.mu.Lock()
		c.downUntil = time.Time{}
		c.mu.Unlock()
	}
	if after := c.Stats(); after.Analyzed != before.Analyzed || after.Unavailable+after.Error <= before.Unavailable+before.Error {
		t.Fatalf("счётчики: %+v -> %+v", before, after)
	}

	// Анализатор прежней версии: без sanitize в hello_ok кадр не уходит.
	old := &fakeMedia{hello: defaultHello(), sanitize: func(wire.Header, []byte) (wire.FrameType, any) {
		return wire.TypeSanitized, clean
	}}
	c = newMediaClient(t, old.start(t), nil)
	if _, _, err := c.Sanitize(ctx, []byte("img x")); mediaReason(t, err) != events.MediaReasonUnavailable {
		t.Fatal(err)
	}
	if n := old.frames.Load(); n != 1 {
		t.Fatalf("кадров: %d, ожидался только hello", n)
	}
}
