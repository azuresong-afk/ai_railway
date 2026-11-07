package gateway_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
)

// Буфер событий шлюза на диске (задача 6.31, ADR-0037): пока сервер
// недоступен, события пишутся на диск и досылаются по порядку без потерь
// и повторов; сверх предела и срока — отброс со счётчиком; повреждённое —
// пропуск со счётчиком.

// fakeServer — сервер управления для буфера: принимает события, как
// PGStore (повтор по ID — дубликат, не вторая строка), умеет быть
// недоступным, «терять ответ» после записи и зависать после записи
// (остановка шлюза между записью на сервере и сохранением курсора).
type fakeServer struct {
	mu   sync.Mutex
	down bool
	// lostAckOn — номер вызова, который записывает события, но отвечает
	// «недоступен»; hangOn — номер вызова, который записывает и ждёт отмены.
	lostAckOn, hangOn int
	order             []string
	seen              map[string]bool
	dups              int
	calls             int
}

func newFakeServer() *fakeServer { return &fakeServer{seen: map[string]bool{}} }

func (s *fakeServer) Send(ctx context.Context, batch []events.Event) error {
	s.mu.Lock()
	s.calls++
	if s.down {
		s.mu.Unlock()
		return fmt.Errorf("%w: соединение отклонено", events.ErrRetryLater)
	}
	for _, e := range batch {
		if s.seen[e.ID] {
			s.dups++
			continue
		}
		s.seen[e.ID] = true
		s.order = append(s.order, e.ID)
	}
	call := s.calls
	s.mu.Unlock()
	switch call {
	case s.lostAckOn:
		return fmt.Errorf("%w: ответ потерян", events.ErrRetryLater)
	case s.hangOn:
		<-ctx.Done()
		return fmt.Errorf("%w: %w", events.ErrRetryLater, ctx.Err())
	}
	return nil
}

func (s *fakeServer) setDown(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = v
}

func (s *fakeServer) stored() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.order...)
}

// waitStored ждёт, пока на сервере окажется n событий.
func (s *fakeServer) waitStored(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.stored(); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("на сервере %d событий, ждали %d", len(s.stored()), n)
	return nil
}

type bufEnv struct {
	dir   string
	p     aisecCrypto.Provider
	srv   *fakeServer
	clock *testClock
	// sink — отправитель вместо srv; log — куда пишет журнал буфера.
	sink events.Sink
	log  *lockedBuf
}

// lockedBuf — журнал для проверки, что в него не попадает содержимое.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newBufEnv(t *testing.T) *bufEnv {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return &bufEnv{dir: stateDir(t), p: p, srv: newFakeServer(), clock: &testClock{now: time.Now().UTC()}}
}

// open открывает буфер над каталогом (как после запуска шлюза).
func (e *bufEnv) open(t *testing.T, maxBytes int64, maxAge time.Duration) *gateway.EventBuffer {
	t.Helper()
	b, err := e.tryOpen(t, maxBytes, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() }) //nolint:gosec // G104: закрытие буфера в очистке теста
	return b
}

func (e *bufEnv) tryOpen(t *testing.T, maxBytes int64, maxAge time.Duration) (*gateway.EventBuffer, error) {
	t.Helper()
	rnd, err := e.p.Random()
	if err != nil {
		t.Fatal(err)
	}
	st, err := gateway.OpenBundleState(e.dir, rnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() }) //nolint:gosec // G104: закрытие хранилища в очистке теста
	var sink events.Sink = e.srv
	if e.sink != nil {
		sink = e.sink
	}
	logger := quiet()
	if e.log != nil {
		logger = slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return gateway.OpenEventBuffer(gateway.EventBufferConfig{State: st, Provider: e.p, Sink: sink, MaxBytes: maxBytes, MaxAge: maxAge,
		Logger: logger, Clock: e.clock.Now, Sleep: func(ctx context.Context, _ time.Duration) bool {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(5 * time.Millisecond):
				return true
			}
		}})
}

func (e *bufEnv) bufDir() string { return filepath.Join(e.dir, gateway.EventBufferDir) }

func (e *bufEnv) files(t *testing.T, prefix string) []string {
	t.Helper()
	entries, err := os.ReadDir(e.bufDir())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), prefix) {
			out = append(out, en.Name())
		}
	}
	return out
}

func eventsN(t *testing.T, n int) []events.Event {
	t.Helper()
	out := make([]events.Event, n)
	for i := range out {
		out[i] = newEvent(t)
	}
	return out
}

func idsOf(evs []events.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.ID
	}
	return out
}

func sendAll(t *testing.T, b *gateway.EventBuffer, evs []events.Event, size int) {
	t.Helper()
	for i := 0; i < len(evs); i += size {
		if err := b.Send(context.Background(), evs[i:min(i+size, len(evs))]); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
}

func equalIDs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("на сервере %d событий, ждали %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("порядок нарушен на %d: %s вместо %s", i, got[i], want[i])
		}
	}
}

// Сервер недоступен: события пишутся на диск, после восстановления
// досылаются в том же порядке; досланный буфер удаляется вместе с ключом.
// Содержимое full на диске не лежит открытым.
func TestEventBufferSpillAndReplayInOrder(t *testing.T) {
	e := newBufEnv(t)
	e.log = &lockedBuf{}
	e.srv.setDown(true)
	b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	evs := eventsN(t, 250)
	sendAll(t, b, evs, 30)
	if got := e.srv.stored(); len(got) != 0 {
		t.Fatalf("сервер недоступен, а принял %d", len(got))
	}
	st := b.Stats()
	if st.Records != 250 || st.Spilled != 250 || st.Bytes == 0 || st.OldestAt.IsZero() || st.MaxBytes != gateway.DefaultEventBufferMaxBytes {
		t.Fatalf("состояние буфера: %+v", st)
	}
	// Буфер не пуст: следующий пакет — сразу на диск, без попытки сервера.
	calls := e.srv.calls
	sendAll(t, b, evs[:0], 1)
	more := eventsN(t, 5)
	sendAll(t, b, more, 5)
	if e.srv.calls != calls {
		t.Fatal("при непустом буфере пакет ушёл на сервер мимо очереди буфера")
	}
	evs = append(evs, more...)
	for _, name := range e.files(t, "") {
		data, err := os.ReadFile(filepath.Join(e.bufDir(), name)) //nolint:gosec // G304: файл временного каталога теста
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("Привет")) || bytes.Contains(data, []byte(evs[0].ID)) {
			t.Fatalf("%s: содержимое или ID события открытым текстом", name)
		}
	}
	if len(e.files(t, "key-")) != 1 || len(e.files(t, "seg-")) != 1 {
		t.Fatalf("файлы буфера: %v", e.files(t, ""))
	}

	e.srv.setDown(false)
	b.Start()
	got := e.srv.waitStored(t, len(evs))
	equalIDs(t, got, idsOf(evs))
	deadline := time.Now().Add(5 * time.Second)
	for b.Stats().Records != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	st = b.Stats()
	if st.Records != 0 || st.Replayed != uint64(len(evs)) || b.Dropped() != 0 || st.Bytes != 0 {
		t.Fatalf("после досылки: %+v", st)
	}
	if rest := e.files(t, ""); len(rest) != 0 {
		t.Fatalf("после досылки в каталоге остались файлы: %v", rest)
	}
	// Пустой буфер: пакет — прямо на сервер, на диске ничего.
	direct := eventsN(t, 3)
	sendAll(t, b, direct, 3)
	equalIDs(t, e.srv.waitStored(t, len(evs)+3)[len(evs):], idsOf(direct))
	if rest := e.files(t, ""); len(rest) != 0 {
		t.Fatalf("сервер доступен, а на диске: %v", rest)
	}
	// В техническом журнале — только числа: ни содержимого, ни ID событий.
	journal := e.log.String()
	if !strings.Contains(journal, "буфер") {
		t.Fatalf("журнал буфера пуст: %q", journal)
	}
	for _, ev := range evs {
		if strings.Contains(journal, ev.ID) || strings.Contains(journal, "Привет") {
			t.Fatalf("в журнале ID или содержимое события: %q", journal)
		}
	}
}

// Перезапуск шлюза посреди досылки, обрыв между записью на сервере и
// ответом: после запуска досылка продолжается с курсора, повтор порции
// сервер отбрасывает как дубликат — ни потерь, ни второй строки.
func TestEventBufferRestartMidReplay(t *testing.T) {
	e := newBufEnv(t)
	e.srv.setDown(true)
	b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	evs := eventsN(t, 350)
	sendAll(t, b, evs, 50)

	// Вызов 1: порция записана, ответ потерян — повтор (вызов 2) даёт
	// дубликаты. Вызов 3 — вторая порция. Вызов 4: третья порция записана
	// на сервере, но шлюз останавливается до сохранения курсора.
	e.srv.mu.Lock()
	e.srv.down, e.srv.calls, e.srv.lostAckOn, e.srv.hangOn = false, 0, 1, 4
	e.srv.mu.Unlock()
	b.Start()
	e.srv.waitStored(t, 300)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(e.srv.stored()); n != 300 {
		t.Fatalf("до перезапуска на сервере %d, ждали 300", n)
	}
	dups := e.srv.dups
	if dups != 100 {
		t.Fatalf("повтор порции с потерянным ответом: %d дубликатов", dups)
	}

	b2 := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	if st := b2.Stats(); st.Records != int64(len(evs)-200) {
		t.Fatalf("после перезапуска непосланных: %d", st.Records)
	}
	b2.Start()
	got := e.srv.waitStored(t, len(evs))
	equalIDs(t, got, idsOf(evs))
	// Третья порция досылается снова и отбрасывается сервером как дубликат.
	if e.srv.dups != dups+100 {
		t.Fatalf("после перезапуска дубликатов %d, ждали %d", e.srv.dups-dups, 100)
	}
	if b2.Dropped() != 0 {
		t.Fatalf("потеряно: %d", b2.Dropped())
	}
}

// Остановка шлюза при недоступном сервере: остаток очереди в памяти уходит
// на диск, а не отбрасывается; следующий запуск его досылает.
func TestEventBufferQueueShutdownKeepsEvents(t *testing.T) {
	e := newBufEnv(t)
	e.srv.setDown(true)
	b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	q := events.NewQueue(b, events.QueueConfig{Logger: quiet(), FlushEach: time.Hour, BatchSize: 1000})
	evs := eventsN(t, 40)
	for _, ev := range evs {
		if err := q.Enqueue(ev); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if q.Dropped() != 0 || q.Failed() != 0 {
		t.Fatalf("очередь отбросила %d, отказов %d", q.Dropped(), q.Failed())
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	e.srv.setDown(false)
	b2 := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	b2.Start()
	equalIDs(t, e.srv.waitStored(t, len(evs)), idsOf(evs))
}

// bigEvent — событие с содержимым около size байт.
func bigEvent(t *testing.T, size int) events.Event {
	t.Helper()
	ev := newEvent(t)
	ev.Content = &events.Content{Request: strings.Repeat("я", size/2)}
	return ev
}

// Предел размера: при заполнении удаляются самые старые сегменты, их
// события — в dropped_limit и в общем счётчике отброшенного (stats.dropped
// пакета, условие events_dropped); новые события досылаются по порядку.
// Покрывает: DM-44
func TestEventBufferLimitDropsOldest(t *testing.T) {
	e := newBufEnv(t)
	e.srv.setDown(true)
	b := e.open(t, gateway.MinEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	var evs []events.Event
	for range 100 {
		ev := bigEvent(t, 1<<20)
		evs = append(evs, ev)
		sendAll(t, b, []events.Event{ev}, 1)
		// Вытесняется самый старый сегмент, а не весь буфер разом.
		if st := b.Stats(); st.DroppedLimit > 0 && st.Bytes < gateway.MinEventBufferMaxBytes-2*gateway.EventBufferSegmentBytes {
			t.Fatalf("после вытеснения в буфере %d байт при пределе %d", st.Bytes, gateway.MinEventBufferMaxBytes)
		}
	}
	st := b.Stats()
	if st.DroppedLimit == 0 || b.Dropped() != st.DroppedLimit {
		t.Fatalf("сверх предела ничего не отброшено: %+v", st)
	}
	if st.Bytes > gateway.MinEventBufferMaxBytes+(2<<20) {
		t.Fatalf("на диске %d байт при пределе %d", st.Bytes, gateway.MinEventBufferMaxBytes)
	}
	if int64(st.DroppedLimit)+st.Records != int64(len(evs)) { //nolint:gosec // G115: счётчик теста — сотни событий
		t.Fatalf("отброшено %d + в буфере %d ≠ %d", st.DroppedLimit, st.Records, len(evs))
	}
	e.srv.setDown(false)
	b.Start()
	kept := evs[st.DroppedLimit:]
	equalIDs(t, e.srv.waitStored(t, len(kept)), idsOf(kept))
}

// Срок хранения: сегмент, все записи которого старше срока, удаляется;
// старые записи в сегменте со свежими не досылаются; всё — в
// dropped_expired.
// Покрывает: DM-44
func TestEventBufferExpiry(t *testing.T) {
	e := newBufEnv(t)
	e.srv.setDown(true)
	b := e.open(t, gateway.DefaultEventBufferMaxBytes, 3*time.Hour)
	old := eventsN(t, 7)
	sendAll(t, b, old, 7)
	e.clock.Add(2 * time.Hour)
	fresh := eventsN(t, 5)
	sendAll(t, b, fresh, 5)
	e.clock.Add(2 * time.Hour)
	e.srv.setDown(false)
	b.Start()
	equalIDs(t, e.srv.waitStored(t, len(fresh)), idsOf(fresh))
	if st := b.Stats(); st.DroppedExpired != uint64(len(old)) || st.Records != 0 {
		t.Fatalf("просрочено: %+v", st)
	}

	// Весь сегмент старше срока — удаляется целиком при открытии досылки.
	e2 := newBufEnv(t)
	e2.srv.setDown(true)
	b2 := e2.open(t, gateway.DefaultEventBufferMaxBytes, time.Hour)
	sendAll(t, b2, eventsN(t, 9), 3)
	_ = b2.Close() //nolint:gosec // G104: остановка буфера в тесте, итог проверяется по счётчикам
	e2.clock.Add(2 * time.Hour)
	e2.srv.setDown(false)
	b3 := e2.open(t, gateway.DefaultEventBufferMaxBytes, time.Hour)
	b3.Start()
	deadline := time.Now().Add(5 * time.Second)
	for b3.Stats().DroppedExpired < 9 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := b3.Stats(); st.DroppedExpired != 9 || len(e2.srv.stored()) != 0 {
		t.Fatalf("сегмент старше срока: %+v, на сервере %d", st, len(e2.srv.stored()))
	}
}

// Права: каталог буфера 0700, сегменты, ключи и курсор 0600; файл или
// каталог с правами шире — отказ открытия (шлюз не запускается).
func TestEventBufferPermissions(t *testing.T) {
	e := newBufEnv(t)
	e.srv.setDown(true)
	b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	sendAll(t, b, eventsN(t, 120), 60)
	// Одна порция досылки, вторая зависает — появится курсор.
	e.srv.mu.Lock()
	e.srv.down, e.srv.calls, e.srv.hangOn = false, 0, 2
	e.srv.mu.Unlock()
	b.Start()
	e.srv.waitStored(t, 120)
	_ = b.Close() //nolint:gosec // G104: остановка буфера в тесте, итог проверяется по файлам
	info, err := os.Stat(e.bufDir())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("каталог буфера: %04o", info.Mode().Perm())
	}
	names := e.files(t, "")
	if len(names) < 3 {
		t.Fatalf("файлы буфера: %v", names)
	}
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(e.bufDir(), n))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: права %04o", n, fi.Mode().Perm())
		}
	}
	for _, n := range []string{e.files(t, "seg-")[0], e.files(t, "key-")[0], "cursor"} {
		p := filepath.Join(e.bufDir(), n)
		if err := os.Chmod(p, 0o640); err != nil { //nolint:gosec // G302: проверка отказа на широкие права
			t.Fatal(err)
		}
		if _, err := e.tryOpen(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge); err == nil {
			t.Fatalf("%s с правами 0640 принят", n)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(e.bufDir(), 0o750); err != nil { //nolint:gosec // G302: проверка отказа на широкие права
		t.Fatal(err)
	}
	if _, err := e.tryOpen(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge); err == nil {
		t.Fatal("каталог буфера 0750 принят")
	}
	if err := os.Chmod(e.bufDir(), 0o700); err != nil { //nolint:gosec // G302: каталог, 0700 — требуемые права буфера
		t.Fatal(err)
	}
	// Символическая ссылка вместо сегмента — не обычный файл.
	seg := filepath.Join(e.bufDir(), e.files(t, "seg-")[0])
	if err := os.Rename(seg, seg+".bak"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(seg+".bak", seg); err != nil {
		t.Fatal(err)
	}
	if _, err := e.tryOpen(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge); err == nil {
		t.Fatal("ссылка вместо сегмента принята")
	}
}

// Повреждения: обрезанный хвост, подменённый байт, чужой ключ, мусорный
// курсор — пропуск со счётчиком corrupt, досылка не останавливается.
func TestEventBufferCorruption(t *testing.T) {
	spill := func(t *testing.T, n int) (*bufEnv, []events.Event) {
		t.Helper()
		e := newBufEnv(t)
		e.srv.setDown(true)
		b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
		evs := eventsN(t, n)
		for _, ev := range evs {
			sendAll(t, b, []events.Event{ev}, 1)
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		e.srv.setDown(false)
		return e, evs
	}
	replay := func(t *testing.T, e *bufEnv, want int, corrupt uint64) *gateway.EventBuffer {
		t.Helper()
		b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
		b.Start()
		deadline := time.Now().Add(10 * time.Second)
		for (b.Stats().Records != 0 || len(e.srv.stored()) < want) && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if st := b.Stats(); st.Corrupt != corrupt || len(e.srv.stored()) != want || st.Records != 0 || b.Dropped() != corrupt {
			t.Fatalf("досылка: %+v, на сервере %d из %d", st, len(e.srv.stored()), want)
		}
		return b
	}
	segPath := func(t *testing.T, e *bufEnv) string {
		t.Helper()
		segs := e.files(t, "seg-")
		if len(segs) != 1 {
			t.Fatalf("сегменты: %v", segs)
		}
		return filepath.Join(e.bufDir(), segs[0])
	}

	t.Run("обрезанный хвост", func(t *testing.T) {
		e, evs := spill(t, 3)
		p := segPath(t, e)
		fi, _ := os.Stat(p) //nolint:gosec // G104: сегмент только что записан, ошибка всплывёт в Truncate
		if err := os.Truncate(p, fi.Size()-5); err != nil {
			t.Fatal(err)
		}
		replay(t, e, 2, 1)
		equalIDs(t, e.srv.stored(), idsOf(evs[:2]))
	})
	t.Run("подменённый байт", func(t *testing.T) {
		e, evs := spill(t, 3)
		p := segPath(t, e)
		data, err := os.ReadFile(p) //nolint:gosec // G304: файл временного каталога теста
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-10] ^= 0x55                           // шифротекст последней записи
		if err := os.WriteFile(p, data, 0o600); err != nil { //nolint:gosec // G703: путь из временного каталога теста
			t.Fatal(err)
		}
		replay(t, e, 2, 1)
		equalIDs(t, e.srv.stored(), idsOf(evs[:2]))
	})
	t.Run("подменённый байт первой записи — теряется одна", func(t *testing.T) {
		e, evs := spill(t, 3)
		p := segPath(t, e)
		data, err := os.ReadFile(p) //nolint:gosec // G304: файл временного каталога теста
		if err != nil {
			t.Fatal(err)
		}
		data[36+17+20] ^= 0x55                               // шифротекст первой записи (заголовки сегмента и записи — 36 и 17 байт)
		if err := os.WriteFile(p, data, 0o600); err != nil { //nolint:gosec // G703: путь из временного каталога теста
			t.Fatal(err)
		}
		replay(t, e, 2, 1)
		equalIDs(t, e.srv.stored(), idsOf(evs[1:]))
	})
	t.Run("чужой ключ", func(t *testing.T) {
		e, _ := spill(t, 3)
		keys := e.files(t, "key-")
		other, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindEventBuffer, aisecCrypto.ProfileStandard, bytes.Repeat([]byte{7}, aisecCrypto.AEADKeySize))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(e.bufDir(), keys[0]), other, 0o600); err != nil {
			t.Fatal(err)
		}
		replay(t, e, 0, 3)
		if rest := e.files(t, ""); len(rest) != 0 {
			t.Fatalf("после пропуска остались файлы: %v", rest)
		}
	})
	t.Run("нет ключа", func(t *testing.T) {
		e, _ := spill(t, 4)
		if err := os.Remove(filepath.Join(e.bufDir(), e.files(t, "key-")[0])); err != nil {
			t.Fatal(err)
		}
		replay(t, e, 0, 4)
	})
	t.Run("мусорный курсор — с начала, без потерь", func(t *testing.T) {
		e, evs := spill(t, 3)
		if err := os.WriteFile(filepath.Join(e.bufDir(), "cursor"), []byte("мусор"), 0o600); err != nil {
			t.Fatal(err)
		}
		replay(t, e, 3, 0)
		equalIDs(t, e.srv.stored(), idsOf(evs))
	})
	t.Run("заголовок сегмента", func(t *testing.T) {
		e, _ := spill(t, 2)
		p := segPath(t, e)
		data, err := os.ReadFile(p) //nolint:gosec // G304: файл временного каталога теста
		if err != nil {
			t.Fatal(err)
		}
		copy(data, "XXXXXXXX")
		if err := os.WriteFile(p, data, 0o600); err != nil { //nolint:gosec // G703: путь из временного каталога теста
			t.Fatal(err)
		}
		replay(t, e, 0, 1)
	})
}

// Ошибка записи на диск (новый сегмент не создаётся): событие не теряется
// — пакет остаётся в очереди в памяти (ErrRetryLater), счётчик
// write_errors растёт; после устранения запись идёт снова.
func TestEventBufferWriteErrorKeepsInMemory(t *testing.T) {
	e := newBufEnv(t)
	e.srv.setDown(true)
	b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	// Каталог на месте первого сегмента: создать файл нельзя (и root тоже).
	blocker := filepath.Join(e.bufDir(), "seg-0000000000000001.evb")
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	evs := eventsN(t, 2)
	err := b.Send(context.Background(), evs)
	if !errors.Is(err, events.ErrRetryLater) {
		t.Fatalf("ошибка записи: %v", err)
	}
	if st := b.Stats(); st.WriteErrors == 0 || st.Records != 0 || st.Spilled != 0 {
		t.Fatalf("счётчики: %+v", st)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := b.Send(context.Background(), evs); err != nil {
		t.Fatalf("после устранения: %v", err)
	}
	if st := b.Stats(); st.Records != 2 {
		t.Fatalf("после устранения в буфере %d", st.Records)
	}
}

// Отказ сервера в пакете (400–422) — как без буфера: не повторяется и не
// пишется на диск.
func TestEventBufferPermanentRejectNotBuffered(t *testing.T) {
	e := newBufEnv(t)
	rej := errors.New("сервер управления отверг пакет")
	b2, err := gateway.OpenEventBuffer(gateway.EventBufferConfig{State: nil, Provider: e.p, Sink: e.srv})
	if err == nil || b2 != nil {
		t.Fatal("буфер без каталога состояния открыт")
	}
	rejecting := sinkFunc(func(context.Context, []events.Event) error { return rej })
	rnd, _ := e.p.Random() //nolint:gosec // G104: профиль standard, источник случайности не отказывает
	st, err := gateway.OpenBundleState(e.dir, rnd)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close() //nolint:errcheck // закрытие хранилища в конце теста
	b3, err := gateway.OpenEventBuffer(gateway.EventBufferConfig{State: st, Provider: e.p, Sink: rejecting,
		MaxBytes: gateway.DefaultEventBufferMaxBytes, MaxAge: gateway.DefaultEventBufferMaxAge, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	defer b3.Close() //nolint:errcheck // буфер пуст, закрытие в конце теста
	if err := b3.Send(context.Background(), eventsN(t, 2)); !errors.Is(err, rej) {
		t.Fatalf("отказ сервера: %v", err)
	}
	if st := b3.Stats(); st.Records != 0 || st.Spilled != 0 {
		t.Fatalf("отвергнутое записано на диск: %+v", st)
	}
	for _, c := range []gateway.EventBufferConfig{
		{State: st, Provider: e.p, Sink: e.srv, MaxBytes: gateway.MinEventBufferMaxBytes - 1, MaxAge: time.Hour},
		{State: st, Provider: e.p, Sink: e.srv, MaxBytes: gateway.MinEventBufferMaxBytes, MaxAge: time.Minute},
		{State: st, Provider: e.p, Sink: e.srv, MaxBytes: gateway.MinEventBufferMaxBytes, MaxAge: gateway.MaxEventBufferMaxAge + 1},
	} {
		if _, err := gateway.OpenEventBuffer(c); err == nil {
			t.Fatalf("пределы приняты: %d, %s", c.MaxBytes, c.MaxAge)
		}
	}
}

type sinkFunc func(context.Context, []events.Event) error

func (f sinkFunc) Send(ctx context.Context, b []events.Event) error { return f(ctx, b) }

// modeSink — сервер, который недоступен («down»), один раз «зависает» на
// порции досылки до release («block») или доступен.
type modeSink struct {
	mu      sync.Mutex
	mode    string
	entered chan struct{}
	release chan struct{}
	srv     *fakeServer
}

func (s *modeSink) set(m string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

func (s *modeSink) Send(ctx context.Context, batch []events.Event) error {
	s.mu.Lock()
	m := s.mode
	if m == "block" {
		s.mode = "down"
	}
	s.mu.Unlock()
	switch m {
	case "down":
		return fmt.Errorf("%w: недоступен", events.ErrRetryLater)
	case "block":
		close(s.entered)
		<-s.release
		return fmt.Errorf("%w: таймаут", events.ErrRetryLater)
	}
	return s.srv.Send(ctx, batch)
}

// Вытеснение сегмента, порция которого сейчас отправляется, а сервер
// затем ответил «повторить позже»: записи порции — в dropped_limit, ни
// одно событие не теряется без учёта (6В ревью A2).
// Покрывает: DM-44
func TestEventBufferEvictInflightCounted(t *testing.T) {
	e := newBufEnv(t)
	ms := &modeSink{mode: "down", entered: make(chan struct{}), release: make(chan struct{}), srv: e.srv}
	e.sink = ms
	b := e.open(t, gateway.MinEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	var all []events.Event
	put := func(n int) {
		for range n {
			ev := bigEvent(t, 1<<20)
			all = append(all, ev)
			sendAll(t, b, []events.Event{ev}, 1)
		}
	}
	put(20)
	ms.set("block")
	b.Start()
	<-ms.entered
	put(80) // вытесняет сегменты, в том числе отправляемый
	if b.Stats().DroppedLimit == 0 {
		t.Fatal("предел не достигнут")
	}
	ms.set("up")
	close(ms.release)
	deadline := time.Now().Add(20 * time.Second)
	for b.Stats().Records != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := len(e.srv.stored())
	if st := b.Stats(); st.Records != 0 || uint64(got)+b.Dropped() != uint64(len(all)) { //nolint:gosec // G115: счётчик теста
		t.Fatalf("отправлено %d, на сервере %d, отброшено %d: %+v", len(all), got, b.Dropped(), st)
	}
}

// hangSink — сервер не отвечает до срока попытки (таймаут сети).
type hangSink struct{}

func (hangSink) Send(ctx context.Context, _ []events.Event) error {
	<-ctx.Done()
	return fmt.Errorf("%w: %w", events.ErrRetryLater, ctx.Err())
}

// Остановка шлюза, когда буфер пуст, а сервер «висит»: Drain прерывает
// прямую отправку, остаток очереди уходит на диск в срок остановки.
func TestEventBufferDrainOnShutdown(t *testing.T) {
	for range 10 {
		e := newBufEnv(t)
		e.sink = hangSink{}
		b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
		b.Start()
		q := events.NewQueue(b, events.QueueConfig{Logger: quiet(), FlushEach: time.Millisecond, BatchSize: 10, SendTimeout: gateway.SinkSendTimeout})
		evs := eventsN(t, 40)
		for _, ev := range evs {
			if err := q.Enqueue(ev); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(5 * time.Millisecond) // первая порция уже ушла к «висящему» серверу
		b.Drain()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := q.Close(ctx)
		cancel()
		if err != nil || q.Dropped() != 0 || q.Failed() != 0 {
			t.Fatalf("остановка: %v, отброшено %d, отказов %d", err, q.Dropped(), q.Failed())
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		e.sink = nil
		b2 := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
		if st := b2.Stats(); st.Records != int64(len(evs)) {
			t.Fatalf("на диске %d из %d", st.Records, len(evs))
		}
	}
}

// Сегмент удалён при работающем шлюзе: его события — в corrupt, досылка
// идёт дальше и не встаёт.
func TestEventBufferMissingSegment(t *testing.T) {
	e := newBufEnv(t)
	e.srv.setDown(true)
	b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	var evs []events.Event
	for range 18 {
		ev := bigEvent(t, 1<<20)
		evs = append(evs, ev)
		sendAll(t, b, []events.Event{ev}, 1)
	}
	segs := e.files(t, "seg-")
	if len(segs) < 2 {
		t.Fatalf("сегменты: %v", segs)
	}
	if err := os.Remove(filepath.Join(e.bufDir(), segs[0])); err != nil {
		t.Fatal(err)
	}
	inFirst := b.Stats().Records
	e.srv.setDown(false)
	b.Start()
	deadline := time.Now().Add(10 * time.Second)
	for b.Stats().Records != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	st := b.Stats()
	got := e.srv.stored()
	if st.Records != 0 || st.Corrupt == 0 || uint64(len(got))+st.Corrupt != uint64(len(evs)) { //nolint:gosec // G115: счётчик теста
		t.Fatalf("на сервере %d из %d (было %d), %+v", len(got), len(evs), inFirst, st)
	}
	equalIDs(t, got, idsOf(evs[len(evs)-len(got):]))
}

// Предел уменьшили при заполненном буфере: при открытии лишние старые
// сегменты удаляются со счётчиком dropped_limit, буфер укладывается в предел.
// Покрывает: DM-44
func TestEventBufferShrinkOnOpen(t *testing.T) {
	e := newBufEnv(t)
	e.srv.setDown(true)
	b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	for range 100 {
		sendAll(t, b, []events.Event{bigEvent(t, 1<<20)}, 1)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b2 := e.open(t, gateway.MinEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	st := b2.Stats()
	if st.Bytes > gateway.MinEventBufferMaxBytes || st.DroppedLimit == 0 || int64(st.DroppedLimit)+st.Records != 100 { //nolint:gosec // G115: счётчик теста
		t.Fatalf("после уменьшения предела: %+v", st)
	}
}

// Файл сегмента с номером MaxUint64 — посторонний: его нельзя продолжить
// следующим номером, порядок досылки не ломается.
func TestEventBufferMaxSeqIgnored(t *testing.T) {
	e := newBufEnv(t)
	e.srv.setDown(true)
	b := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	evs := eventsN(t, 3)
	sendAll(t, b, evs, 3)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.bufDir(), "seg-ffffffffffffffff.evb"), []byte("AISECEVB"), 0o600); err != nil {
		t.Fatal(err)
	}
	b2 := e.open(t, gateway.DefaultEventBufferMaxBytes, gateway.DefaultEventBufferMaxAge)
	more := eventsN(t, 2)
	sendAll(t, b2, more, 2)
	e.srv.setDown(false)
	b2.Start()
	equalIDs(t, e.srv.waitStored(t, 5), idsOf(append(evs, more...)))
}
