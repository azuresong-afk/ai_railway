package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Клиент изолированного анализатора изображений aisec-media (ADR-0032,
// разделы 4 и 8; задача 5.39). Шлюз изображения не декодирует: он передаёт
// байты из base64 и получает итог разбора. Любой сбой — изображение «не
// проверено» (MediaError с причиной), а не ошибка запроса; что делать с
// непроверенным, решают политика (non_text) и режим при отказе (sync).

// MediaAnalyzer — анализатор изображений для шлюза: MediaClient или
// заглушка в тестах.
type MediaAnalyzer interface {
	// MaxBytes — предел изображения у анализатора (max_bytes из hello_ok;
	// до первого подключения — DefaultMediaMaxBytes). Больше — не
	// отправляется.
	MaxBytes() int64
	// Analyze разбирает изображение не дольше срока ctx. Ошибка —
	// *MediaError.
	Analyze(ctx context.Context, img []byte) (*MediaReply, error)
}

// MediaReply — итог анализа: результат протокола и извлечённые тексты.
type MediaReply struct {
	Result wire.Result
	// Texts — фрагменты текста с изображения. Протокол передаёт их с задачи
	// 5.42 (OCR); до неё список пуст, и изображение без ocr в Checks
	// проверенным не считается.
	Texts []MediaText
}

// MediaText — фрагмент текста на изображении.
type MediaText struct {
	Text string
	// Origin — откуда текст: ocr, ocr_contrast, metadata, qr.
	Origin string
	// Box — рамка на изображении; nil — у текста нет места (метаданные).
	Box *events.Box
}

// MediaError — изображение не проанализировано; Reason — причина для
// события (events.MediaReason*).
type MediaError struct {
	Reason string
	Err    error
}

func (e *MediaError) Error() string {
	if e.Err == nil {
		return "aisec-media: " + e.Reason
	}
	return "aisec-media: " + e.Reason + ": " + e.Err.Error()
}

func (e *MediaError) Unwrap() error { return e.Err }

// Failure — причина — сбой анализатора (а не свойство изображения): в
// режиме sync к ней применяется режим приложения при отказе (ТЗ, 4.4).
func (e *MediaError) Failure() bool {
	switch e.Reason {
	case events.MediaReasonUnavailable, events.MediaReasonOverloaded, events.MediaReasonTimeout, events.MediaReasonError:
		return true
	}
	return false
}

func mediaErr(reason string, err error) error { return &MediaError{Reason: reason, Err: err} }

// Умолчания клиента.
const (
	// DefaultMediaMaxBytes — предел изображения до первого hello_ok:
	// умолчание -max-bytes анализатора (ADR-0032, раздел 6).
	DefaultMediaMaxBytes = 10 << 20
	DefaultMediaInflight = 16
	DefaultMediaMinBack  = time.Second
	DefaultMediaMaxBack  = 30 * time.Second
	// mediaIdleMax — свободное соединение старше этого не берётся:
	// aisec-media закрывает простаивающие через 60 с.
	mediaIdleMax = 30 * time.Second
	// mediaTimeoutsToFail — сроков подряд до отсрочки: одиночное тяжёлое
	// изображение — не сбой процесса (как у aisec-ml, 4В22).
	mediaTimeoutsToFail = 3
)

// MediaClientConfig — параметры клиента aisec-media.
type MediaClientConfig struct {
	// Socket — абсолютный путь к Unix-сокету aisec-media.
	Socket string
	// MaxInflight — предел одновременных анализов от шлюза; сверх — сразу
	// overloaded без ожидания.
	MaxInflight int
	// MinBackoff, MaxBackoff — отсрочка после сбоя: всё это время анализ
	// сразу отвечает unavailable и не задерживает запрос.
	MinBackoff, MaxBackoff time.Duration
	Logger                 *slog.Logger
	now                    func() time.Time
}

// MediaClient — пул соединений с aisec-media. Безопасен для одновременного
// вызова.
type MediaClient struct {
	cfg      MediaClientConfig
	sem      chan struct{}
	nextID   atomic.Uint32
	maxBytes atomic.Int64

	mu        sync.Mutex
	idle      []*mediaConn
	downUntil time.Time
	backoff   time.Duration
	down      bool
	timeouts  int
	closed    bool
}

type mediaConn struct {
	c    net.Conn
	used time.Time
}

// NewMediaClient проверяет параметры; соединения открываются при вызовах.
func NewMediaClient(cfg MediaClientConfig) (*MediaClient, error) {
	if !filepath.IsAbs(cfg.Socket) {
		return nil, errors.New("aisec-media: путь к сокету должен быть абсолютным")
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = DefaultMediaInflight
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = DefaultMediaMinBack
	}
	if cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = max(DefaultMediaMaxBack, cfg.MinBackoff)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	c := &MediaClient{cfg: cfg, sem: make(chan struct{}, cfg.MaxInflight)}
	c.maxBytes.Store(DefaultMediaMaxBytes)
	return c, nil
}

// MaxBytes — предел изображения по последнему hello_ok.
func (c *MediaClient) MaxBytes() int64 { return c.maxBytes.Load() }

// Close закрывает свободные соединения.
func (c *MediaClient) Close() {
	c.mu.Lock()
	idle := c.idle
	c.idle, c.closed = nil, true
	c.mu.Unlock()
	for _, mc := range idle {
		_ = mc.c.Close() //nolint:gosec // G104: соединение больше не нужно
	}
}

// Analyze отправляет изображение анализатору. Срок — срок ctx (его же
// получает анализатор в заголовке analyze); без срока ctx — срок
// анализатора по умолчанию.
func (c *MediaClient) Analyze(ctx context.Context, img []byte) (*MediaReply, error) {
	if int64(len(img)) > c.MaxBytes() {
		return nil, mediaErr(events.MediaReasonTooLarge, nil)
	}
	if c.isDown() {
		return nil, mediaErr(events.MediaReasonUnavailable, errors.New("отсрочка после сбоя"))
	}
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	default:
		return nil, mediaErr(events.MediaReasonOverloaded, errors.New("предел одновременных анализов шлюза"))
	}
	if ctx.Err() != nil {
		return nil, mediaErr(events.MediaReasonTimeout, ctx.Err())
	}
	for attempt := 0; ; attempt++ {
		mc, reused, err := c.conn(ctx)
		if err != nil {
			if ctx.Err() != nil {
				c.timedOut(err)
				return nil, mediaErr(events.MediaReasonTimeout, err)
			}
			c.fail(err)
			return nil, mediaErr(events.MediaReasonUnavailable, err)
		}
		res, keep, err := c.roundTrip(ctx, mc, img)
		if keep {
			c.put(mc)
		} else {
			_ = mc.c.Close() //nolint:gosec // G104: соединение после сбоя не используется
		}
		if err == nil {
			c.ok()
			return &MediaReply{Result: *res}, nil
		}
		var me *MediaError
		if errors.As(err, &me) {
			// Ответ анализатора с кодом: соединение исправно или закрыто
			// им самим (too_large), сбоем процесса это не считается.
			if me.Reason == events.MediaReasonTimeout {
				c.timedOut(err)
			}
			return nil, err
		}
		timeout := ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded)
		if !timeout && reused && attempt == 0 && !errors.Is(err, wire.ErrProtocol) && !errors.Is(err, wire.ErrBadBody) {
			// Свободное соединение мог закрыть сам анализатор (простой,
			// перезапуск): одна попытка на новом.
			continue
		}
		if timeout {
			c.timedOut(err)
			return nil, mediaErr(events.MediaReasonTimeout, err)
		}
		c.fail(err)
		return nil, mediaErr(events.MediaReasonUnavailable, err)
	}
}

// roundTrip — один запрос analyze. keep — соединение можно вернуть в пул.
func (c *MediaClient) roundTrip(ctx context.Context, mc *mediaConn, img []byte) (_ *wire.Result, keep bool, _ error) {
	id := c.nextID.Add(1)
	stop := bindDeadline(ctx, mc.c)
	defer func() {
		if !stop() {
			keep = false
		}
	}()
	if err := wire.WriteFrame(mc.c, wire.Header{Type: wire.TypeAnalyze, ID: id, Timeout: msUntil(ctx)}, img); err != nil {
		return nil, false, err
	}
	h, b, err := wire.ReadFrame(mc.c, wire.ClientSide)
	if err != nil {
		return nil, false, err
	}
	if h.ID != id {
		return nil, false, fmt.Errorf("%w: номер ответа", wire.ErrProtocol)
	}
	switch h.Type {
	case wire.TypeResult:
		r, err := wire.ParseResult(b)
		if err != nil {
			return nil, false, err
		}
		return r, true, nil
	case wire.TypeError:
		code, err := wire.ParseError(b)
		if err != nil {
			return nil, false, err
		}
		switch code {
		case wire.ErrOverloaded:
			return nil, true, mediaErr(events.MediaReasonOverloaded, nil)
		case wire.ErrTimeout:
			return nil, true, mediaErr(events.MediaReasonTimeout, nil)
		case wire.ErrInternal:
			return nil, true, mediaErr(events.MediaReasonError, nil)
		case wire.ErrTooLarge:
			// Анализатор закрывает соединение без чтения тела.
			return nil, false, mediaErr(events.MediaReasonTooLarge, nil)
		}
		// bad_request — нарушение протокола одной из сторон.
		return nil, false, fmt.Errorf("%w: aisec-media ответил %s", wire.ErrProtocol, code)
	}
	return nil, false, fmt.Errorf("%w: тип ответа %d", wire.ErrProtocol, h.Type)
}

// conn — свободное соединение или новое: проверка сокета, подключение,
// hello.
func (c *MediaClient) conn(ctx context.Context) (_ *mediaConn, reused bool, _ error) {
	var stale []*mediaConn
	defer func() {
		for _, mc := range stale {
			_ = mc.c.Close() //nolint:gosec // G104: устаревшее соединение
		}
	}()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false, errors.New("клиент закрыт")
	}
	now := c.cfg.now()
	for n := len(c.idle); n > 0; n-- {
		mc := c.idle[n-1]
		c.idle = c.idle[:n-1]
		if now.Sub(mc.used) < mediaIdleMax {
			c.mu.Unlock()
			return mc, true, nil
		}
		stale = append(stale, mc)
	}
	c.mu.Unlock()
	if err := checkPeerSocket(c.cfg.Socket, "aisec-media"); err != nil {
		return nil, false, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.cfg.Socket)
	if err != nil {
		return nil, false, err
	}
	if err := c.hello(ctx, conn); err != nil {
		_ = conn.Close() //nolint:gosec // G104: соединение после сбоя не используется
		return nil, false, err
	}
	return &mediaConn{c: conn}, false, nil
}

// hello узнаёт пределы анализатора. Анализатор, который не умеет разбирать
// ни одного формата, считается неисправным.
func (c *MediaClient) hello(ctx context.Context, conn net.Conn) (err error) {
	stop := bindDeadline(ctx, conn)
	defer func() {
		if !stop() && err == nil {
			err = context.Cause(ctx)
		}
	}()
	id := c.nextID.Add(1)
	if err := wire.WriteFrame(conn, wire.Header{Type: wire.TypeHello, ID: id}, nil); err != nil {
		return err
	}
	h, b, err := wire.ReadFrame(conn, wire.ClientSide)
	if err != nil {
		return err
	}
	if h.Type != wire.TypeHelloOK || h.ID != id {
		return fmt.Errorf("%w: ответ на hello", wire.ErrProtocol)
	}
	hello, err := wire.ParseHelloOK(b)
	if err != nil {
		return err
	}
	if len(hello.Formats) == 0 || !slices.Contains(hello.Checks, wire.CheckDecode) {
		return fmt.Errorf("%w: анализатор без форматов или без разбора растра", wire.ErrProtocol)
	}
	c.maxBytes.Store(hello.MaxBytes)
	return nil
}

func (c *MediaClient) put(mc *mediaConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed && len(c.idle) < c.cfg.MaxInflight {
		mc.used = c.cfg.now()
		c.idle = append(c.idle, mc)
		return
	}
	_ = mc.c.Close() //nolint:gosec // G104: лишнее свободное соединение
}

func (c *MediaClient) isDown() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.now().Before(c.downUntil)
}

// timedOut — срок истёк: отсрочка — только после mediaTimeoutsToFail
// сроков подряд.
func (c *MediaClient) timedOut(err error) {
	c.mu.Lock()
	c.timeouts++
	n := c.timeouts
	c.mu.Unlock()
	if n >= mediaTimeoutsToFail {
		c.fail(err)
	}
}

// fail — сбой aisec-media: отсрочка удваивается до MaxBackoff, свободные
// соединения закрываются. Переход в «недоступен» пишется в журнал один
// раз, без содержимого запроса.
func (c *MediaClient) fail(err error) {
	c.mu.Lock()
	if c.cfg.now().Before(c.downUntil) {
		c.mu.Unlock()
		return
	}
	c.timeouts = 0
	if c.backoff == 0 {
		c.backoff = c.cfg.MinBackoff
	} else {
		c.backoff = min(c.backoff*2, c.cfg.MaxBackoff)
	}
	c.downUntil = c.cfg.now().Add(c.backoff)
	wasDown := c.down
	c.down = true
	idle := c.idle
	c.idle = nil
	backoff := c.backoff
	c.mu.Unlock()
	for _, mc := range idle {
		_ = mc.c.Close() //nolint:gosec // G104: соединения после сбоя не используются
	}
	if !wasDown {
		c.cfg.Logger.Warn("aisec-media недоступен: изображения не проверяются (media_unchecked)", "error", err, "retry_in", backoff.String())
	}
}

func (c *MediaClient) ok() {
	c.mu.Lock()
	wasDown := c.down
	c.down, c.backoff, c.timeouts = false, 0, 0
	c.mu.Unlock()
	if wasDown {
		c.cfg.Logger.Info("aisec-media снова доступен")
	}
}
