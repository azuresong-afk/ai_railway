package media

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Умолчания сервера (ADR-0032, разделы 4 и 5).
const (
	DefaultMaxConns    = 16
	DefaultWorkers     = 2
	DefaultQueue       = 16
	DefaultBodyTimeout = 10 * time.Second
	DefaultIdleTimeout = 60 * time.Second
	// DefaultRunTimeout — срок анализа, если шлюз не передал свой: цель
	// p95 ТЗ 5.17 для 2 Мпикс с OCR.
	DefaultRunTimeout = 2 * time.Second
	// DefaultMaxRunTimeout — предел срока, назначенного шлюзом.
	DefaultMaxRunTimeout = 10 * time.Second
	acceptRetry          = 100 * time.Millisecond
)

// ServerConfig — параметры сервера протокола aisec-media.
type ServerConfig struct {
	Limits Limits
	// Hasher — хеш содержимого для кэша (криптопрофиль).
	Hasher aisecCrypto.Hasher
	// MaxConns — предел соединений; лишние закрываются сразу.
	MaxConns int
	// Workers — предел одновременных анализов.
	Workers int
	// Queue — сколько запросов ждут сверх Workers; дальше — overloaded.
	Queue int
	// CacheEntries — предел записей кэша; 0 — DefaultCacheEntries, < 0 —
	// кэш выключен.
	CacheEntries  int
	BodyTimeout   time.Duration
	IdleTimeout   time.Duration
	RunTimeout    time.Duration
	MaxRunTimeout time.Duration
	Logger        *slog.Logger
}

// Server — сервер протокола aisec-media: очередь с пределом, срок на
// запрос, кэш по хешу содержимого (ADR-0032).
type Server struct {
	cfg   ServerConfig
	hello []byte
	cache *Cache
	// queue — допуск: занятых и ждущих анализов не больше Workers+Queue.
	queue chan struct{}
	// slots — исполнители: одновременных анализов не больше Workers.
	slots chan struct{}
	conns atomic.Int64
	wg    sync.WaitGroup
	// analyze — анализ изображения (тесты подменяют медленным).
	analyze func([]byte, Limits) (wire.Result, error)

	overloaded, timeouts atomic.Uint64
}

// NewServer проверяет параметры и готовит ответ hello.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.Limits.Validate(); err != nil {
		return nil, err
	}
	if cfg.Hasher == nil {
		return nil, errors.New("aisec-media: нет хеша для кэша")
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.Queue < 0 {
		cfg.Queue = 0
	}
	if cfg.CacheEntries == 0 {
		cfg.CacheEntries = DefaultCacheEntries
	}
	if cfg.BodyTimeout <= 0 {
		cfg.BodyTimeout = DefaultBodyTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.RunTimeout <= 0 {
		cfg.RunTimeout = DefaultRunTimeout
	}
	if cfg.MaxRunTimeout <= 0 {
		cfg.MaxRunTimeout = DefaultMaxRunTimeout
	}
	cfg.MaxRunTimeout = max(cfg.MaxRunTimeout, cfg.RunTimeout)
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	hello, err := wire.MarshalBody(wire.HelloOK{Protocol: wire.ProtocolVersion, Formats: Decodable(),
		Checks: []wire.Check{wire.CheckDecode}, MaxBytes: cfg.Limits.MaxBytes, MaxPixels: cfg.Limits.MaxPixels})
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, hello: hello, cache: NewCache(cfg.CacheEntries),
		queue: make(chan struct{}, cfg.Workers+cfg.Queue), slots: make(chan struct{}, cfg.Workers), analyze: Analyze}, nil
}

// Overloaded — отказов overloaded с запуска (DM-50).
func (s *Server) Overloaded() uint64 { return s.overloaded.Load() }

// Timeouts — истёкших сроков анализа с запуска (DM-50).
func (s *Server) Timeouts() uint64 { return s.timeouts.Load() }

// Serve принимает соединения до отмены ctx, затем закрывает слушатель и
// ждёт завершения обработчиков соединений. Анализы, которые доделываются
// после истёкшего срока, процесс не ждёт.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() }) //nolint:gosec // G104: слушатель закрывается при остановке
	defer stop()
	defer s.wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			s.cfg.Logger.Warn("aisec-media: ошибка приёма соединения", "error", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(acceptRetry):
			}
			continue
		}
		if s.conns.Add(1) > int64(s.cfg.MaxConns) {
			s.conns.Add(-1)
			_ = c.Close() //nolint:gosec // G104: лишнее соединение закрывается сразу
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.conns.Add(-1)
			defer c.Close() //nolint:errcheck // соединение закрывается после обработки
			s.handle(ctx, c)
		}()
	}
}

// handle обслуживает соединение: по одному запросу за раз.
func (s *Server) handle(ctx context.Context, c net.Conn) {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() }) //nolint:gosec // G104: остановка закрывает соединение
	defer stop()
	for ctx.Err() == nil {
		h, body, err := s.readRequest(c)
		if err != nil {
			switch {
			case errors.Is(err, wire.ErrFrameTooLarge):
				s.writeError(c, h.ID, wire.ErrTooLarge)
			case errors.Is(err, wire.ErrProtocol):
				s.writeError(c, 0, wire.ErrBadRequest)
			}
			return
		}
		switch h.Type {
		case wire.TypeHello:
			if !s.write(c, wire.Header{Type: wire.TypeHelloOK, ID: h.ID}, s.hello) {
				return
			}
		case wire.TypeAnalyze:
			if !s.serveAnalyze(ctx, c, h, body) {
				return
			}
		}
	}
}

// readRequest читает кадр: заголовок — со сроком простоя, тело — со сроком
// чтения тела. Изображение длиннее рабочего предела (-max-bytes) не
// читается: ErrFrameTooLarge с номером запроса.
func (s *Server) readRequest(c net.Conn) (wire.Header, []byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout)); err != nil {
		return wire.Header{}, nil, err
	}
	h, err := wire.ReadHeader(c, wire.ServerSide)
	if err != nil {
		return wire.Header{}, nil, err
	}
	if int64(h.Length) > s.cfg.Limits.MaxBytes {
		return h, nil, wire.ErrFrameTooLarge
	}
	if h.Length == 0 {
		return h, nil, nil
	}
	if err := c.SetReadDeadline(time.Now().Add(s.cfg.BodyTimeout)); err != nil {
		return wire.Header{}, nil, err
	}
	body, err := wire.ReadBody(c, h)
	if err != nil {
		return wire.Header{}, nil, err
	}
	return h, body, nil
}

// runTimeout — срок анализа: срок шлюза из заголовка (не больше
// MaxRunTimeout) или RunTimeout.
func (s *Server) runTimeout(h wire.Header) time.Duration {
	if h.Timeout == 0 {
		return s.cfg.RunTimeout
	}
	return min(time.Duration(h.Timeout)*time.Millisecond, s.cfg.MaxRunTimeout)
}

// outcome — итог анализа из исполнителя.
type outcome struct {
	res wire.Result
	err error
}

// serveAnalyze отвечает на analyze; false — соединение закрыть. Срок
// отсчитывается с получения кадра и покрывает очередь. Повтор из кэша не
// занимает очередь и исполнитель.
func (s *Server) serveAnalyze(ctx context.Context, c net.Conn, h wire.Header, body []byte) bool {
	deadline := time.Now().Add(s.runTimeout(h))
	key := s.cfg.Hasher.Sum(body)
	if res, ok := s.cache.Get(key); ok {
		return s.writeResult(c, h.ID, res)
	}
	select {
	case s.queue <- struct{}{}:
	default:
		s.overloaded.Add(1)
		return s.writeError(c, h.ID, wire.ErrOverloaded)
	}
	jctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	done := make(chan outcome, 1)
	go s.runJob(jctx, key, body, done)
	select {
	case o := <-done:
		if o.err != nil {
			if errors.Is(o.err, context.DeadlineExceeded) {
				s.timeouts.Add(1)
				return s.writeError(c, h.ID, wire.ErrTimeout)
			}
			if ctx.Err() != nil {
				return false
			}
			s.cfg.Logger.Warn("aisec-media: сбой анализа", "error", o.err)
			return s.writeError(c, h.ID, wire.ErrInternal)
		}
		return s.writeResult(c, h.ID, o.res)
	case <-jctx.Done():
		if ctx.Err() != nil {
			return false
		}
		s.timeouts.Add(1)
		return s.writeError(c, h.ID, wire.ErrTimeout)
	}
}

// runJob ждёт исполнителя до срока и анализирует. Начатый анализ не
// прерывается (декодеры не принимают контекст): слот освобождается только
// по его завершении, а итог попадает в кэш, даже если срок уже истёк.
func (s *Server) runJob(ctx context.Context, key, body []byte, done chan<- outcome) {
	defer func() { <-s.queue }()
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		done <- outcome{err: ctx.Err()}
		return
	}
	defer func() { <-s.slots }()
	res, err := s.safeAnalyze(body)
	if err == nil {
		if verr := res.Validate(); verr != nil {
			err = fmt.Errorf("aisec-media: неверный итог анализа: %w", verr)
		} else {
			s.cache.Put(key, res)
		}
	}
	done <- outcome{res: res, err: err}
}

// safeAnalyze — анализ с перехватом паники: сбой одного изображения не
// останавливает процесс.
func (s *Server) safeAnalyze(body []byte) (res wire.Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = errDecoderPanic
		}
	}()
	return s.analyze(body, s.cfg.Limits)
}

// writeResult отправляет итог; true — соединение можно продолжать.
func (s *Server) writeResult(c net.Conn, id uint32, res wire.Result) bool {
	b, err := wire.MarshalBody(res)
	if err != nil || len(b) > wire.MaxResultBody {
		return s.writeError(c, id, wire.ErrInternal)
	}
	return s.write(c, wire.Header{Type: wire.TypeResult, ID: id}, b)
}

// writeError отправляет кадр error; true — соединение можно продолжать.
// После too_large и bad_request соединение закрывается: тело не прочитано
// или поток кадров сбит.
func (s *Server) writeError(c net.Conn, id uint32, code wire.ErrorCode) bool {
	b, err := wire.MarshalBody(wire.ErrorMsg{Code: code})
	if err != nil {
		return false
	}
	return s.write(c, wire.Header{Type: wire.TypeError, ID: id}, b) && code != wire.ErrTooLarge && code != wire.ErrBadRequest
}

func (s *Server) write(c net.Conn, h wire.Header, body []byte) bool {
	if err := c.SetWriteDeadline(time.Now().Add(s.cfg.BodyTimeout)); err != nil {
		return false
	}
	return wire.WriteFrame(c, h, body) == nil
}
