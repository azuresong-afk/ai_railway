package gateway

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Буфер событий шлюза на диске (ADR-0037, ТЗ 4.4): обёртка над
// отправителем на сервер. Пока сервер недоступен, пакеты пишутся в
// сегменты каталога состояния, зашифрованные AEAD криптопрофиля своим
// ключом; фоновая досылка отправляет их по порядку и сдвигает курсор
// только после ответа сервера. Повтор после обрыва сервер принимает как
// дубликат по ID события. Отброшенное сверх предела и срока и
// повреждённое — в счётчиках и в stats.dropped пакета (DM-44).

// Значения по умолчанию и пределы флагов (internal/config сверяет их в тесте).
const (
	DefaultEventBufferMaxBytes = 1 << 30
	DefaultEventBufferMaxAge   = 72 * time.Hour
	// MinEventBufferMaxBytes — с запасом на два сегмента и самую длинную
	// запись: вытеснение всегда находит сегмент старше пишущегося и не
	// сбрасывает весь буфер разом (6В ревью A2).
	MinEventBufferMaxBytes = 4 * EventBufferSegmentBytes
	MaxEventBufferMaxBytes = 1 << 50
	MinEventBufferMaxAge   = time.Hour
	// MaxEventBufferMaxAge — меньше окна приёма сервера (events.MaxEventAge,
	// 7 суток): более старое событие сервер всё равно отвергнет.
	MaxEventBufferMaxAge = events.MaxEventAge - time.Hour
)

// Параметры досылки и ротации.
const (
	evbReplayEvents = 100
	evbReplayBytes  = 4 << 20
	evbRetryMin     = time.Second
	evbRetryMax     = 30 * time.Second
	// evbMaintainEach — период проверки срока, пока досылать нечего.
	evbMaintainEach = time.Minute
	// evbRotateAfter — записей одним ключом до нового ключа (запас к 2^32
	// сообщений AES-GCM со случайным nonce, ADR-0006).
	evbRotateAfter = 1 << 30
	// evbMaxKeys — ключей в каталоге при открытии: каждый процесс шлюза
	// создаёт свой, лишние удаляются, когда на них не ссылаются сегменты.
	evbMaxKeys = 4096
	// evbMaxSegments — сегментов при открытии (1 ТиБ по 16 МиБ — 65 536).
	evbMaxSegments = 1 << 17
	// evbOpenRetries — подряд неудачных открытий сегмента на чтение (не
	// «нет файла»), после которых его непосланные записи считаются потерянными.
	evbOpenRetries = 3
)

// EventBufferConfig — параметры буфера.
type EventBufferConfig struct {
	// State — каталог состояния шлюза: буфер — его подкаталог EventBufferDir.
	State    *BundleState
	Provider aisecCrypto.Provider
	// Sink — отправитель на сервер (ServerSink).
	Sink     events.Sink
	MaxBytes int64
	MaxAge   time.Duration
	Logger   *slog.Logger
	Clock    func() time.Time
	// Sleep ждёт d или отмены ctx (тесты подменяют его).
	Sleep func(ctx context.Context, d time.Duration) bool
}

// EventBufferStats — состояние буфера для heartbeat (ADR-0037, раздел 8).
type EventBufferStats struct {
	Bytes, MaxBytes int64
	// Records — непосланные записи; OldestAt — время первой записи самого
	// старого сегмента с непосланными (нулевое — пусто).
	Records  int64
	OldestAt time.Time
	// Счётчики с запуска процесса шлюза.
	Spilled, Replayed                     uint64
	DroppedLimit, DroppedExpired, Corrupt uint64
	WriteErrors                           uint64
}

type evbSegment struct {
	seq     uint64
	key     evbKeyID
	size    int64 // конец последней разобранной записи
	disk    int64 // размер файла на диске
	records int64
	oldest  time.Time
	newest  time.Time
	broken  bool // после size — неразборчивый хвост
}

// EventBuffer — events.Sink с буфером на диске.
type EventBuffer struct {
	inner    events.Sink
	p        aisecCrypto.Provider
	rnd      aisecCrypto.Random
	logger   *slog.Logger
	clock    func() time.Time
	sleep    func(ctx context.Context, d time.Duration) bool
	maxBytes int64
	maxAge   time.Duration

	mu    sync.Mutex
	root  *os.Root
	segs  []*evbSegment // по возрастанию номера
	keys  map[evbKeyID]aisecCrypto.AEAD
	cur   evbCursor
	total int64 // байт в сегментах на диске
	next  uint64
	// w — открытый на запись последний сегмент; wkey — ключ записи.
	w      *os.File
	wseg   *evbSegment
	wkey   evbKeyID
	waead  aisecCrypto.AEAD
	wcount int64
	// r — открытый на чтение сегмент досылки.
	r    *os.File
	rseq uint64
	// inflight — конец порции, отправляемой досылкой. Вытеснение и срок
	// откладывают её записи в flyLimit и flyExpired: при ответе сервера их
	// учтёт commit, при «повторить позже» они — потеря (сегмента больше нет).
	inflight             *evbCursor
	flyLimit, flyExpired uint64
	// openFails — подряд неудачных открытий сегмента досылки.
	openFails int
	// draining — шлюз останавливается: Send пишет только на диск.
	draining  atomic.Bool
	drainCtx  context.Context
	drainStop context.CancelFunc

	spilled, replayed, droppedLimit, droppedExpired, corrupt, writeErrors atomic.Uint64

	notify    chan struct{}
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
}

// OpenEventBuffer открывает буфер в каталоге состояния: создаёт подкаталог
// 0700, проверяет права файлов, читает ключи, обходит сегменты и курсор.
// Файл с правами шире 0600, не обычный файл или каталог с правами шире 0700
// — ошибка: шлюз не запускается (ADR-0037, раздел 1). Повреждённые сегменты
// и курсор не мешают открытию: их записи считаются при досылке.
func OpenEventBuffer(c EventBufferConfig) (*EventBuffer, error) {
	if c.State == nil || c.Provider == nil || c.Sink == nil {
		return nil, errors.New("буфер событий: нет каталога состояния, криптопрофиля или отправителя")
	}
	if c.MaxBytes < MinEventBufferMaxBytes || c.MaxBytes > MaxEventBufferMaxBytes || c.MaxAge < MinEventBufferMaxAge || c.MaxAge > MaxEventBufferMaxAge {
		return nil, errors.New("буфер событий: предел размера или срок вне допустимого")
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = sleepCtx
	}
	rnd, err := c.Provider.Random()
	if err != nil {
		return nil, err
	}
	root, err := c.State.eventBufferRoot()
	if err != nil {
		return nil, err
	}
	b := &EventBuffer{inner: c.Sink, p: c.Provider, rnd: rnd, logger: c.Logger, clock: c.Clock, sleep: c.Sleep,
		maxBytes: c.MaxBytes, maxAge: c.MaxAge, root: root, keys: map[evbKeyID]aisecCrypto.AEAD{}, next: 1,
		notify: make(chan struct{}, 1)}
	b.drainCtx, b.drainStop = context.WithCancel(context.Background())
	if err := b.load(); err != nil {
		b.drainStop()
		return nil, errors.Join(err, b.closeFiles())
	}
	return b, nil
}

// eventBufferRoot создаёт (0700) и открывает подкаталог буфера.
func (s *BundleState) eventBufferRoot() (*os.Root, error) {
	if err := s.root.Mkdir(EventBufferDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("буфер событий: %w", err)
	}
	info, err := s.root.Lstat(EventBufferDir)
	if err != nil {
		return nil, fmt.Errorf("буфер событий: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("буфер событий: %s/%s — не каталог или доступен группе и остальным (права %04o); нужно 0700",
			s.dir, EventBufferDir, info.Mode().Perm())
	}
	if err := s.syncDir(); err != nil {
		return nil, err
	}
	return s.root.OpenRoot(EventBufferDir)
}

// load читает каталог буфера при открытии.
func (b *EventBuffer) load() error {
	d, err := b.root.Open(".")
	if err != nil {
		return fmt.Errorf("буфер событий: %w", err)
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close() //nolint:gosec // G104: каталог открыт только для чтения, важна ошибка ReadDir
	if err != nil {
		return fmt.Errorf("буфер событий: %w", err)
	}
	var segSeqs []uint64
	var keyIDs []evbKeyID
	for _, e := range entries {
		name := e.Name()
		if seq, ok := parseHexName(name, evbSegPrefix, evbSegSuffix); ok && seq < math.MaxUint64 {
			// Номер MaxUint64 не продолжить следующим: такой файл шлюз
			// не создаёт, он посторонний.
			segSeqs = append(segSeqs, seq)
			continue
		}
		if v, ok := parseHexName(name, evbKeyPrefix, evbKeySuffix); ok {
			var id evbKeyID
			binary.BigEndian.PutUint64(id[:], v)
			keyIDs = append(keyIDs, id)
			continue
		}
		if len(name) > 2 && name[0] == '.' && len(name) > len(".tmp") && name[len(name)-len(".tmp"):] == ".tmp" {
			// Недописанный курсор прежнего процесса.
			_ = b.root.Remove(name) //nolint:gosec // G104: уборка; файл всё равно не читается
			continue
		}
		if name != evbCursorFile {
			b.logger.Warn("буфер событий: посторонний файл в каталоге не используется", "file", name)
		}
	}
	if len(segSeqs) > evbMaxSegments || len(keyIDs) > evbMaxKeys {
		return fmt.Errorf("буфер событий: в каталоге больше %d сегментов или %d ключей", evbMaxSegments, evbMaxKeys)
	}
	for _, id := range keyIDs {
		if err := b.loadKey(id); err != nil {
			return err
		}
	}
	slices.Sort(segSeqs)
	for _, seq := range segSeqs {
		if err := b.loadSegment(seq); err != nil {
			return err
		}
		b.next = max(b.next, seq+1)
	}
	if err := b.loadCursor(); err != nil {
		return err
	}
	if b.pendingLocked() == 0 {
		// Всё досланное — удаляется вместе с ключами.
		return b.resetLocked()
	}
	// Предел уменьшили при заполненном буфере — старые сегменты сверх него
	// удаляются сразу, со счётчиком dropped_limit.
	b.evictLocked(0)
	b.logger.Info("буфер событий: на диске есть непосланные события, досылка после связи с сервером",
		"records", b.pendingLocked(), "bytes", b.total)
	return nil
}

// checkFile — обычный файл с правами 0600 или строже.
func (b *EventBuffer) checkFile(name string) (fs.FileInfo, error) {
	info, err := b.root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("буфер событий: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("буфер событий: %s — не обычный файл", name)
	}
	if !aisecCrypto.KeyFilePermsOK(info) {
		return nil, fmt.Errorf("буфер событий: %s доступен группе или остальным (права %04o); нужно 0600", name, info.Mode().Perm())
	}
	return info, nil
}

func (b *EventBuffer) loadKey(id evbKeyID) error {
	name := keyName(id)
	info, err := b.checkFile(name)
	if err != nil {
		return err
	}
	if info.Size() > maxKeyFile {
		b.logger.Warn("буфер событий: файл ключа не разобран, сегменты на нём не будут досланы", "key_id", id.String())
		return nil
	}
	data, err := b.root.ReadFile(name)
	if err != nil {
		return fmt.Errorf("буфер событий: %w", err)
	}
	defer clear(data)
	profile, key, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindEventBuffer)
	if err != nil || profile != b.p.Name() {
		b.logger.Warn("буфер событий: ключ не разобран или другого криптопрофиля, сегменты на нём не будут досланы", "key_id", id.String())
		return nil
	}
	defer clear(key)
	a, err := b.p.NewAEAD(key)
	if err != nil {
		return fmt.Errorf("буфер событий: %w", err)
	}
	b.keys[id] = a
	return nil
}

func (b *EventBuffer) loadSegment(seq uint64) error {
	name := segName(seq)
	info, err := b.checkFile(name)
	if err != nil {
		return err
	}
	seg := &evbSegment{seq: seq, broken: true, size: info.Size(), disk: info.Size()}
	f, err := b.root.Open(name)
	if err != nil {
		return fmt.Errorf("буфер событий: %w", err)
	}
	sc, serr := scanSegment(f, info.Size())
	_ = f.Close() //nolint:gosec // G104: открыт только для чтения
	switch {
	case serr != nil || sc.header.seq != seq:
		// Заголовок не разобран: весь сегмент — одна потерянная запись.
		seg.size, seg.records = evbSegHeaderSize, 0
	default:
		seg.key, seg.size, seg.records, seg.oldest, seg.newest, seg.broken = sc.header.key, sc.end, sc.records, sc.oldest, sc.newest, sc.broken
		if seg.oldest.IsZero() {
			seg.oldest = sc.header.created
		}
	}
	b.segs = append(b.segs, seg)
	b.total += info.Size()
	return nil
}

func (b *EventBuffer) loadCursor() error {
	info, err := b.root.Lstat(evbCursorFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if _, err := b.checkFile(evbCursorFile); err != nil {
		return err
	}
	if info.Size() != evbCursorSize {
		b.logger.Warn("буфер событий: курсор не разобран, досылка с начала буфера (повтор сервер отбросит)")
		return nil
	}
	data, err := b.root.ReadFile(evbCursorFile)
	if err != nil {
		return fmt.Errorf("буфер событий: %w", err)
	}
	if c, perr := parseCursor(data); perr == nil {
		b.cur = c
		return nil
	}
	// С начала: повтор досланного сервер примет как дубликат, а пропуск
	// был бы потерей (ADR-0037, раздел 4).
	b.logger.Warn("буфер событий: курсор не разобран, досылка с начала буфера (повтор сервер отбросит)")
	return nil
}

// segAt — первый сегмент с номером не меньше seq.
func (b *EventBuffer) segAt(seq uint64) (int, *evbSegment) {
	for i, s := range b.segs {
		if s.seq >= seq {
			return i, s
		}
	}
	return -1, nil
}

// pendingLocked — непосланные записи.
func (b *EventBuffer) pendingLocked() int64 {
	var n int64
	for _, s := range b.segs {
		switch {
		case s.seq < b.cur.seq:
		case s.seq == b.cur.seq:
			n += max(s.records-b.cur.idx, 0)
			if s.broken && b.cur.off <= s.size {
				n++
			}
		default:
			n += s.records
			if s.broken {
				n++
			}
		}
	}
	return n
}

// Send — events.Sink: буфер пуст — пакет уходит на сервер, а при временной
// недоступности сервера записывается на диск; буфер не пуст — пакет сразу
// дописывается в конец (порядок «старые раньше новых»). Не удалась запись
// на диск — ErrRetryLater: пакет остаётся в очереди в памяти.
func (b *EventBuffer) Send(ctx context.Context, batch []events.Event) error {
	if len(batch) == 0 {
		return nil
	}
	b.mu.Lock()
	empty := b.pendingLocked() == 0
	b.mu.Unlock()
	if empty && !b.draining.Load() {
		// Drain прерывает прямую отправку: при остановке остаток очереди
		// уходит на диск, а не ждёт срока попытки.
		sctx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(b.drainCtx, cancel)
		err := b.inner.Send(sctx, batch)
		stop()
		cancel()
		if err == nil || (!errors.Is(err, events.ErrRetryLater) && !b.draining.Load()) {
			return err
		}
		if werr := b.append(batch); werr != nil {
			b.logger.Error("сервер управления недоступен, а буфер событий на диске не записан: события ждут в памяти",
				"count", len(batch), "error", werr)
			return err
		}
		b.logger.Warn("сервер управления недоступен: события записаны в буфер на диске", "count", len(batch))
		return nil
	}
	if err := b.append(batch); err != nil {
		b.logger.Error("буфер событий на диске не записан: события ждут в памяти", "count", len(batch), "error", err)
		return fmt.Errorf("%w: буфер событий: %w", events.ErrRetryLater, err)
	}
	return nil
}

// Drain переводит буфер в режим остановки: прямая отправка на сервер
// прерывается, Send дальше только пишет на диск. Вызывается перед закрытием
// очереди, чтобы её остаток попал в буфер в срок остановки (ADR-0037, раздел 2).
func (b *EventBuffer) Drain() {
	b.draining.Store(true)
	b.drainStop()
}

// append дописывает события в буфер по одному на запись и сбрасывает
// сегмент на диск.
func (b *EventBuffer) append(batch []events.Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.root == nil {
		return errors.New("буфер событий закрыт")
	}
	now := b.clock().UTC()
	written := 0
	defer func() {
		if written > 0 {
			b.spilled.Add(uint64(written)) //nolint:gosec // G115: written ≥ 0
			select {
			case b.notify <- struct{}{}:
			default:
			}
		}
	}()
	for i := range batch {
		plain, err := json.Marshal(&batch[i])
		if err != nil {
			return err
		}
		if len(plain) > events.MaxBatchBytes {
			// Сервер такое событие всё равно не примет (ServerSink — rejected).
			b.droppedLimit.Add(1)
			continue
		}
		err = b.writeRecord(plain, now)
		clear(plain)
		if err != nil {
			b.writeErrors.Add(1)
			return err
		}
		written++
	}
	if b.w == nil {
		return nil
	}
	if err := b.w.Sync(); err != nil {
		b.writeErrors.Add(1)
		return fmt.Errorf("буфер событий: сброс на диск: %w", err)
	}
	return nil
}

// writeRecord шифрует и дописывает одну запись: при необходимости
// вытесняет старые сегменты, открывает новый сегмент и ключ.
func (b *EventBuffer) writeRecord(plain []byte, now time.Time) error {
	need := int64(evbRecHeaderSize + len(plain) + evbAEADOverhead)
	b.evictLocked(need)
	if b.w == nil || b.wseg.size >= EventBufferSegmentBytes || b.wcount >= evbRotateAfter {
		if err := b.rollLocked(now); err != nil {
			return err
		}
	}
	off := b.wseg.size
	sealed, err := b.waead.Seal(plain, recordAAD(b.wkey, b.wseg.seq, off, now))
	if err != nil {
		return err
	}
	rec := encodeRecord(now, sealed)
	if _, err := b.w.WriteAt(rec, off); err != nil {
		// Недописанная запись срезается; не вышло — сегмент закрывается,
		// хвост при досылке — одна потерянная запись.
		if terr := b.w.Truncate(off); terr != nil {
			b.wseg.broken = true
			b.closeWriterLocked()
		}
		return fmt.Errorf("буфер событий: запись: %w", err)
	}
	b.wcount++
	b.wseg.size += int64(len(rec))
	b.wseg.disk = b.wseg.size
	b.total += int64(len(rec))
	b.wseg.records++
	if b.wseg.oldest.IsZero() {
		b.wseg.oldest = now
	}
	b.wseg.newest = now
	return nil
}

// rollLocked закрывает сегмент записи и открывает новый; ключ — новый,
// если его ещё нет в этом процессе или им записано evbRotateAfter записей.
func (b *EventBuffer) rollLocked(now time.Time) error {
	b.closeWriterLocked()
	if b.waead == nil || b.wcount >= evbRotateAfter {
		if err := b.newKeyLocked(); err != nil {
			return err
		}
	}
	seq := b.next
	name := segName(seq)
	f, err := b.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("буфер событий: новый сегмент: %w", err)
	}
	b.next++
	hdr := evbSegHeader{key: b.wkey, seq: seq, created: now}.encode()
	if _, err := f.Write(hdr); err != nil {
		_ = f.Close()           //nolint:gosec // G104: важна ошибка записи
		_ = b.root.Remove(name) //nolint:gosec // G104: уборка неудавшегося сегмента
		return fmt.Errorf("буфер событий: новый сегмент: %w", err)
	}
	if err := errors.Join(f.Sync(), b.syncDir()); err != nil {
		_ = f.Close()           //nolint:gosec // G104: важна ошибка сброса
		_ = b.root.Remove(name) //nolint:gosec // G104: уборка неудавшегося сегмента
		return fmt.Errorf("буфер событий: новый сегмент: %w", err)
	}
	seg := &evbSegment{seq: seq, key: b.wkey, size: evbSegHeaderSize, disk: evbSegHeaderSize}
	b.segs = append(b.segs, seg)
	b.total += evbSegHeaderSize
	b.w, b.wseg = f, seg
	return nil
}

// newKeyLocked создаёт ключ записи: файл 0600 с O_EXCL и сброс каталога.
func (b *EventBuffer) newKeyLocked() error {
	key, err := aisecCrypto.RandomBytes(b.rnd, aisecCrypto.AEADKeySize)
	if err != nil {
		return err
	}
	defer clear(key)
	idb, err := aisecCrypto.RandomBytes(b.rnd, evbKeyIDSize)
	if err != nil {
		return err
	}
	var id evbKeyID
	copy(id[:], idb)
	a, err := b.p.NewAEAD(key)
	if err != nil {
		return err
	}
	pemData, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindEventBuffer, b.p.Name(), key)
	if err != nil {
		return err
	}
	defer clear(pemData)
	if err := writeSynced(b.root, keyName(id), pemData, os.O_EXCL); err != nil {
		_ = b.root.Remove(keyName(id)) //nolint:gosec // G104: уборка неудавшейся записи
		return fmt.Errorf("буфер событий: ключ: %w", err)
	}
	if err := b.syncDir(); err != nil {
		return err
	}
	b.keys[id], b.wkey, b.waead, b.wcount = a, id, a, 0
	return nil
}

func (b *EventBuffer) closeWriterLocked() {
	if b.w != nil {
		_ = b.w.Close() //nolint:gosec // G104: данные уже сброшены Sync после каждой порции
		b.w, b.wseg = nil, nil
	}
}

func (b *EventBuffer) closeReaderLocked() {
	if b.r != nil {
		_ = b.r.Close() //nolint:gosec // G104: открыт только для чтения
		b.r = nil
	}
}

func (b *EventBuffer) syncDir() error {
	d, err := b.root.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	_ = d.Close() //nolint:gosec // G104: важна ошибка Sync
	if err != nil {
		return fmt.Errorf("буфер событий: сброс каталога: %w", err)
	}
	return nil
}

// unitsFrom — сколько учётных единиц сегмента s (записи и оборванный
// хвост) досылка от курсора c ещё отправит или посчитает потерянными.
// Хвост считается, когда курсор уходит за конец сегмента (readLocked).
func unitsFrom(s *evbSegment, c *evbCursor) int64 {
	var tail int64
	if s.broken {
		tail = 1
	}
	switch {
	case c.seq < s.seq:
		return s.records + tail
	case c.seq > s.seq:
		return 0
	default:
		return max(s.records-c.idx, 0) + tail
	}
}

// splitLocked делит единицы удаляемого сегмента: lost — не учтённые никем,
// fly — уже взятые отправляемой порцией (их судьбу решит её итог).
func (b *EventBuffer) splitLocked(s *evbSegment) (lost, fly uint64) {
	fromCur := unitsFrom(s, &b.cur)
	rest := fromCur
	if b.inflight != nil {
		rest = min(unitsFrom(s, b.inflight), fromCur)
	}
	return uint64(rest), uint64(fromCur - rest) //nolint:gosec // G115: 0 ≤ rest ≤ fromCur
}

// evictLocked удаляет самые старые сегменты, пока буфер с need байтами не
// уложится в предел (ADR-0037, раздел 6).
func (b *EventBuffer) evictLocked(need int64) {
	for len(b.segs) > 0 && b.total+need > b.maxBytes {
		lost, fly := b.splitLocked(b.segs[0])
		b.droppedLimit.Add(lost)
		b.flyLimit += fly
		b.removeSegmentLocked(0)
		b.logger.Warn("буфер событий заполнен: самый старый сегмент удалён, события отброшены", "count", lost)
	}
}

// expireLocked удаляет сегменты, все записи которых старше срока.
func (b *EventBuffer) expireLocked(now time.Time) {
	cutoff := now.Add(-b.maxAge)
	for len(b.segs) > 0 {
		s := b.segs[0]
		last := s.newest
		if last.IsZero() {
			last = s.oldest
		}
		if last.IsZero() || !last.Before(cutoff) {
			return
		}
		lost, fly := b.splitLocked(s)
		b.droppedExpired.Add(lost)
		b.flyExpired += fly
		b.removeSegmentLocked(0)
		if lost > 0 {
			b.logger.Warn("буфер событий: истёк срок хранения, события отброшены", "count", lost)
		}
	}
}

// removeSegmentLocked удаляет файл сегмента i и неиспользуемые ключи.
func (b *EventBuffer) removeSegmentLocked(i int) {
	s := b.segs[i]
	if b.wseg == s {
		b.closeWriterLocked()
	}
	if b.r != nil && b.rseq == s.seq {
		b.closeReaderLocked()
	}
	if err := b.root.Remove(segName(s.seq)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		b.logger.Error("буфер событий: сегмент не удалён", "error", err)
	}
	b.total = max(b.total-s.disk, 0)
	b.segs = slices.Delete(b.segs, i, i+1)
	b.dropUnusedKeysLocked()
	_ = b.syncDir() //nolint:gosec // G104: удаление не критично — следующий запуск увидит то же
}

// dropUnusedKeysLocked удаляет ключи, на которые не ссылается ни один
// сегмент, кроме ключа записи.
func (b *EventBuffer) dropUnusedKeysLocked() {
	used := map[evbKeyID]bool{}
	for _, s := range b.segs {
		used[s.key] = true
	}
	for id := range b.keys {
		if used[id] || (b.waead != nil && id == b.wkey) {
			continue
		}
		if err := b.root.Remove(keyName(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			b.logger.Error("буфер событий: ключ не удалён", "error", err)
			continue
		}
		delete(b.keys, id)
	}
}

// resetLocked — буфер пуст: удаляются все сегменты, курсор и ключи, ключ
// записи сбрасывается (следующая запись — новый ключ, ADR-0037, раздел 5).
func (b *EventBuffer) resetLocked() error {
	b.closeWriterLocked()
	b.closeReaderLocked()
	var errs []error
	for _, s := range b.segs {
		if err := b.root.Remove(segName(s.seq)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	b.segs, b.total = nil, 0
	if err := b.root.Remove(evbCursorFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	b.cur = evbCursor{}
	b.waead, b.wkey, b.wcount = nil, evbKeyID{}, 0
	// Ключи без сегментов — тоже: и прежних процессов, и неразобранные.
	d, err := b.root.Open(".")
	if err == nil {
		entries, rerr := d.ReadDir(-1)
		_ = d.Close() //nolint:gosec // G104: открыт только для чтения
		if rerr != nil {
			errs = append(errs, rerr)
		}
		for _, e := range entries {
			if _, ok := parseHexName(e.Name(), evbKeyPrefix, evbKeySuffix); ok {
				if err := b.root.Remove(e.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
					errs = append(errs, err)
				}
			}
		}
	} else {
		errs = append(errs, err)
	}
	clear(b.keys)
	errs = append(errs, b.syncDir())
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("буфер событий: очистка: %w", err)
	}
	return nil
}

// evbChunk — порция досылки: события, курсор после неё и что пропущено.
type evbChunk struct {
	events           []events.Event
	next             evbCursor
	corrupt, expired uint64
}

// readerLocked — открытый на чтение сегмент seq.
func (b *EventBuffer) readerLocked(seq uint64) (io.ReaderAt, error) {
	if b.r != nil && b.rseq == seq {
		return b.r, nil
	}
	b.closeReaderLocked()
	f, err := b.root.Open(segName(seq))
	if err != nil {
		return nil, err
	}
	b.r, b.rseq = f, seq
	return f, nil
}

// readLocked читает порцию от курсора: до evbReplayEvents событий и
// evbReplayBytes байт. Повреждённое и просроченное пропускается и
// считается в порции; счётчики применяет commit.
func (b *EventBuffer) readLocked(now time.Time) evbChunk {
	ch := evbChunk{next: b.cur}
	pos := &ch.next
	cutoff := now.Add(-b.maxAge)
	var size int
	for len(ch.events) < evbReplayEvents && size < evbReplayBytes {
		i, s := b.segAt(pos.seq)
		if s == nil {
			break
		}
		if s.seq != pos.seq || pos.off < evbSegHeaderSize {
			*pos = evbCursor{seq: s.seq, off: evbSegHeaderSize}
		}
		if pos.off >= s.size {
			if s == b.wseg {
				break // дальше пишет Send
			}
			if s.broken {
				ch.corrupt++
			}
			if i+1 >= len(b.segs) {
				// Последний сегмент дочитан: курсор за ним.
				*pos = evbCursor{seq: s.seq + 1, off: evbSegHeaderSize}
				break
			}
			*pos = evbCursor{seq: b.segs[i+1].seq, off: evbSegHeaderSize}
			continue
		}
		a, ok := b.keys[s.key]
		if !ok {
			// Чужой или неразобранный ключ: все записи сегмента потеряны.
			ch.corrupt += uint64(max(s.records-pos.idx, 0)) //nolint:gosec // G115: неотрицательно
			pos.off, pos.idx = s.size, s.records
			continue
		}
		r, err := b.readerLocked(s.seq)
		if err != nil {
			b.openFails++
			b.logger.Error("буфер событий: сегмент не открыт", "error", err)
			if !errors.Is(err, fs.ErrNotExist) && b.openFails < evbOpenRetries {
				break
			}
			// Файла нет (удалён при работающем шлюзе) или он не открывается
			// раз за разом: непосланное в нём потеряно, досылка идёт дальше.
			b.openFails = 0
			ch.corrupt += uint64(max(s.records-pos.idx, 0)) //nolint:gosec // G115: неотрицательно
			pos.off, pos.idx = s.size, s.records
			continue
		}
		b.openFails = 0
		h, sealed, err := readRecord(r, pos.off, s.size)
		off := pos.off
		switch {
		case errors.Is(err, errEVBRecordCRC):
			// Заголовок цел и укладывается в сегмент (его длины проверил
			// обход), не сошлась CRC: теряется одна запись.
			ch.corrupt++
			pos.off += evbRecHeaderSize + int64(h.n)
			pos.idx++
			continue
		case err != nil:
			// Заголовок не разобран или не прочитан: дальше по сегменту не
			// пройти, остаток потерян (оборванный хвост посчитается сам).
			lost := s.records - pos.idx
			if lost < 1 && !s.broken {
				lost = 1
			}
			ch.corrupt += uint64(max(lost, 0)) //nolint:gosec // G115: неотрицательно
			pos.off, pos.idx = s.size, s.records
			continue
		}
		pos.off += evbRecHeaderSize + int64(h.n)
		pos.idx++
		if h.at.Before(cutoff) {
			ch.expired++
			continue
		}
		plain, err := a.Open(sealed, recordAAD(s.key, s.seq, off, h.at))
		if err != nil {
			ch.corrupt++
			continue
		}
		var e events.Event
		err = json.Unmarshal(plain, &e)
		clear(plain)
		if err != nil || e.Validate() != nil {
			ch.corrupt++
			continue
		}
		if e.Time.Before(now.Add(-events.MaxEventAge + events.MaxClockSkew)) {
			// Событие, попавшее в буфер с опозданием, сервер уже не примет.
			ch.expired++
			continue
		}
		ch.events = append(ch.events, e)
		size += len(sealed)
	}
	return ch
}

// commit применяет итог порции: курсор вперёд (только вперёд), счётчики,
// удаление дочитанных сегментов, запись курсора; пустой буфер очищается.
func (b *EventBuffer) commit(ch evbChunk, sent int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Порция учтена целиком (отправлена или в счётчиках порции): записи
	// удалённых за время отправки сегментов — уже в ней.
	b.inflight, b.flyLimit, b.flyExpired = nil, 0, 0
	b.corrupt.Add(ch.corrupt)
	b.droppedExpired.Add(ch.expired)
	b.replayed.Add(uint64(sent)) //nolint:gosec // G115: sent ≥ 0
	if b.cur.before(ch.next) {
		b.cur = ch.next
	}
	for len(b.segs) > 0 && b.segs[0].seq < b.cur.seq && b.segs[0] != b.wseg {
		b.removeSegmentLocked(0)
	}
	if b.pendingLocked() == 0 {
		return b.resetLocked()
	}
	return b.saveCursorLocked()
}

// saveCursorLocked пишет курсор атомарно: временный файл, сброс,
// переименование, сброс каталога.
func (b *EventBuffer) saveCursorLocked() error {
	rb, err := aisecCrypto.RandomBytes(b.rnd, 8)
	if err != nil {
		return err
	}
	tmp := "." + evbCursorFile + "." + hex.EncodeToString(rb) + ".tmp"
	if err := writeSynced(b.root, tmp, b.cur.encode(), os.O_EXCL); err != nil {
		_ = b.root.Remove(tmp) //nolint:gosec // G104: уборка; важна исходная ошибка
		return fmt.Errorf("буфер событий: курсор: %w", err)
	}
	if err := b.root.Rename(tmp, evbCursorFile); err != nil {
		_ = b.root.Remove(tmp) //nolint:gosec // G104: уборка; важна исходная ошибка
		return fmt.Errorf("буфер событий: курсор: %w", err)
	}
	return b.syncDir()
}

// Start запускает досылку; Close её останавливает.
func (b *EventBuffer) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel, b.done = cancel, make(chan struct{})
	go func() {
		defer close(b.done)
		b.run(ctx)
	}()
}

// run — цикл досылки: порция от курсора, отправка на сервер, курсор после
// ответа. Сервер недоступен — пауза от evbRetryMin до evbRetryMax.
func (b *EventBuffer) run(ctx context.Context) {
	var backoff time.Duration
	t := time.NewTicker(evbMaintainEach)
	defer t.Stop()
	for ctx.Err() == nil {
		b.mu.Lock()
		now := b.clock().UTC()
		b.expireLocked(now)
		ch := b.readLocked(now)
		if len(ch.events) > 0 {
			next := ch.next
			b.inflight = &next
		}
		b.mu.Unlock()
		if len(ch.events) == 0 {
			if ch.next != b.curSnapshot() || ch.corrupt > 0 || ch.expired > 0 {
				if err := b.commit(ch, 0); err != nil {
					b.logger.Error("буфер событий: курсор не сохранён", "error", err)
				}
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-b.notify:
			case <-t.C:
			}
			continue
		}
		err := b.inner.Send(ctx, ch.events)
		if errors.Is(err, events.ErrRetryLater) {
			b.mu.Lock()
			// Сегменты порции, удалённые за время отправки, уже не перечитать:
			// их записи — потеря по пределу или сроку.
			b.droppedLimit.Add(b.flyLimit)
			b.droppedExpired.Add(b.flyExpired)
			b.inflight, b.flyLimit, b.flyExpired = nil, 0, 0
			b.mu.Unlock()
			backoff = min(max(2*backoff, evbRetryMin), evbRetryMax)
			if !b.sleep(ctx, backoff) {
				return
			}
			continue
		}
		backoff = 0
		if err != nil {
			// Отказ сервера в порции: повтор бесполезен, события — в rejected
			// отправителя (как без буфера).
			b.logger.Error("сервер управления отверг события из буфера на диске", "count", len(ch.events), "error", err)
		}
		if err := b.commit(ch, len(ch.events)); err != nil {
			b.logger.Error("буфер событий: курсор не сохранён", "error", err)
		}
	}
}

func (b *EventBuffer) curSnapshot() evbCursor {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cur
}

// Dropped — события, потерянные буфером: сверх предела, сверх срока,
// повреждённые. Прибавляется к stats.dropped пакета (DM-44).
func (b *EventBuffer) Dropped() uint64 {
	return b.droppedLimit.Load() + b.droppedExpired.Load() + b.corrupt.Load()
}

// Stats — состояние буфера для heartbeat.
func (b *EventBuffer) Stats() EventBufferStats {
	b.mu.Lock()
	st := EventBufferStats{Bytes: b.total, MaxBytes: b.maxBytes, Records: b.pendingLocked()}
	for _, s := range b.segs {
		if s.seq >= b.cur.seq && !s.oldest.IsZero() {
			st.OldestAt = s.oldest
			break
		}
	}
	b.mu.Unlock()
	st.Spilled, st.Replayed = b.spilled.Load(), b.replayed.Load()
	st.DroppedLimit, st.DroppedExpired, st.Corrupt = b.droppedLimit.Load(), b.droppedExpired.Load(), b.corrupt.Load()
	st.WriteErrors = b.writeErrors.Load()
	return st
}

// Close останавливает досылку и закрывает файлы. Вызывается после закрытия
// очереди: её остаток к этому времени уже записан Send.
func (b *EventBuffer) Close() error {
	b.closeOnce.Do(func() {
		b.drainStop()
		if b.cancel != nil {
			b.cancel()
			<-b.done
		}
	})
	b.mu.Lock()
	defer b.mu.Unlock()
	if n := b.pendingLocked(); n > 0 {
		b.logger.Info("буфер событий: непосланные события остаются на диске до следующего запуска", "records", n)
	}
	return b.closeFiles()
}

func (b *EventBuffer) closeFiles() error {
	b.closeWriterLocked()
	b.closeReaderLocked()
	if b.root == nil {
		return nil
	}
	err := b.root.Close()
	b.root = nil
	return err
}
