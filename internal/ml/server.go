package ml

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Executor — исполнитель моделей (ADR-0024, раздел 6): ONNX Runtime в
// cmd/aisec-ml (тег aisec_onnx) или тестовый исполнитель internal/ml/mltest.
type Executor interface {
	// Load готовит модель из проверенных байтов пакета. Байты уже сверены с
	// подписанным манифестом; повторно с диска исполнитель их не читает.
	Load(m LoadedModel) (Model, error)
}

// Model — загруженная модель. Run безопасен для одновременного вызова.
type Model interface {
	Info() ModelInfo
	// Run выполняет модель на тексте (корректный UTF-8 не длиннее MaxText).
	// Находки — с метками из Info().Labels и позициями в text.
	Run(ctx context.Context, text string) (Result, error)
	Close() error
}

// ServerConfig — параметры сервера протокола.
type ServerConfig struct {
	Models []Model
	// MaxConns — предел соединений; лишние закрываются сразу.
	MaxConns int
	// Workers — предел одновременных выводов.
	Workers int
	// QueueWait — сколько запрос ждёт свободного исполнителя, затем overloaded.
	QueueWait time.Duration
	// BodyTimeout — срок чтения тела кадра после заголовка.
	BodyTimeout time.Duration
	// IdleTimeout — простой соединения между запросами.
	IdleTimeout time.Duration
	// RunTimeout — срок одного вывода.
	RunTimeout time.Duration
	Logger     *slog.Logger
}

// Умолчания сервера (ADR-0024, раздел 3).
const (
	DefaultMaxConns    = 64
	DefaultQueueWait   = 20 * time.Millisecond
	DefaultBodyTimeout = 5 * time.Second
	DefaultIdleTimeout = 60 * time.Second
	// DefaultRunTimeout — срок вывода: шлюз ждёт ответа не дольше
	// 300 мс, дольше занимать исполнитель нет смысла.
	DefaultRunTimeout = 500 * time.Millisecond
	// acceptRetry — пауза после ошибки приёма соединения.
	acceptRetry = 100 * time.Millisecond
)

// Server — сервер протокола aisec-ml.
type Server struct {
	cfg    ServerConfig
	models map[string]Model
	hello  []byte
	slots  chan struct{}
	conns  atomic.Int64
	wg     sync.WaitGroup
}

// NewServer проверяет параметры и готовит ответ hello.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.GOMAXPROCS(0)
	}
	if cfg.QueueWait <= 0 {
		cfg.QueueWait = DefaultQueueWait
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
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if len(cfg.Models) > MaxModels {
		return nil, fmt.Errorf("aisec-ml: моделей больше %d", MaxModels)
	}
	s := &Server{cfg: cfg, models: make(map[string]Model, len(cfg.Models)), slots: make(chan struct{}, cfg.Workers)}
	hello := HelloOK{Protocol: ProtocolVersion, Models: []ModelInfo{}}
	for _, m := range cfg.Models {
		info := m.Info()
		if err := info.Validate(); err != nil {
			return nil, err
		}
		if _, dup := s.models[info.ID]; dup {
			return nil, fmt.Errorf("aisec-ml: модель %s повторяется", info.ID)
		}
		s.models[info.ID] = m
		hello.Models = append(hello.Models, info)
	}
	b, err := MarshalBody(hello)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxHelloOKBody {
		return nil, errors.New("aisec-ml: описание моделей больше предела кадра")
	}
	s.hello = b
	return s, nil
}

// Serve принимает соединения до отмены ctx, затем закрывает слушатель и
// ждёт завершения обработчиков.
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
			// Временная нехватка дескрипторов и подобное — пауза и повтор:
			// процесс не должен завершаться из-за одного неудачного accept.
			s.cfg.Logger.Warn("aisec-ml: ошибка приёма соединения", "error", err)
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
			case errors.Is(err, ErrFrameTooLarge):
				s.writeError(c, 0, ErrTooLarge)
			case errors.Is(err, ErrProtocol):
				s.writeError(c, 0, ErrBadRequest)
			}
			return
		}
		if err := c.SetWriteDeadline(time.Now().Add(s.cfg.BodyTimeout)); err != nil {
			return
		}
		switch h.Type {
		case TypeHello:
			if WriteFrame(c, Header{Type: TypeHelloOK, ID: h.ID}, s.hello) != nil {
				return
			}
		case TypeDetect:
			if !s.detect(ctx, c, h.ID, body) {
				return
			}
		}
	}
}

// readRequest читает кадр: заголовок — со сроком простоя, тело — со сроком
// чтения тела. Тело кадра сверх предела не читается.
func (s *Server) readRequest(c net.Conn) (Header, []byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout)); err != nil {
		return Header{}, nil, err
	}
	// Тот же разбор, что в ReadFrame (FuzzServerReadFrame), но срок на
	// тело — свой: простой и медленная передача тела различаются.
	h, err := readHeader(c, ServerSide)
	if err != nil {
		return Header{}, nil, err
	}
	if h.Length == 0 {
		return h, nil, nil
	}
	if err := c.SetReadDeadline(time.Now().Add(s.cfg.BodyTimeout)); err != nil {
		return Header{}, nil, err
	}
	body, err := readBody(c, h)
	if err != nil {
		return Header{}, nil, err
	}
	return h, body, nil
}

// detect выполняет запрос; false — соединение закрыть.
func (s *Server) detect(ctx context.Context, c net.Conn, id uint32, body []byte) bool {
	model, text, err := ParseDetect(body)
	if err != nil {
		return s.writeError(c, id, ErrBadRequest)
	}
	m, ok := s.models[model]
	if !ok {
		return s.writeError(c, id, ErrUnknownModel)
	}
	t := time.NewTimer(s.cfg.QueueWait)
	select {
	case s.slots <- struct{}{}:
		t.Stop()
	case <-t.C:
		return s.writeError(c, id, ErrOverloaded)
	case <-ctx.Done():
		t.Stop()
		return false
	}
	res, err := s.run(ctx, m, text)
	<-s.slots
	if err != nil {
		s.cfg.Logger.Warn("сбой вывода модели", "model", model, "error", err)
		return s.writeError(c, id, ErrInternal)
	}
	out, err := MarshalBody(res)
	if err != nil || len(out) > MaxResultBody {
		s.cfg.Logger.Warn("ответ модели не помещается в кадр", "model", model, "findings", len(res.Findings))
		return s.writeError(c, id, ErrInternal)
	}
	return WriteFrame(c, Header{Type: TypeResult, ID: id}, out) == nil
}

// run выполняет модель со сроком и проверяет результат тем же правилом, что
// и шлюз. Паника исполнителя — ошибка запроса, а не остановка процесса
// (сбой нативного кода всё равно остановит процесс — это граница ADR-0024).
func (s *Server) run(ctx context.Context, m Model, text string) (res Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = errors.New("исполнитель завершился аварийно")
		}
	}()
	rctx, cancel := context.WithTimeout(ctx, s.cfg.RunTimeout)
	defer cancel()
	res, err = m.Run(rctx, text)
	if err != nil {
		return Result{}, err
	}
	info := m.Info()
	res.Model, res.Version = info.ID, info.Version
	if res.Findings == nil {
		res.Findings = []Score{}
	}
	if len(res.Findings) > MaxFindings {
		return Result{}, fmt.Errorf("находок больше %d", MaxFindings)
	}
	for _, f := range res.Findings {
		if f.validate(info, text) != nil {
			return Result{}, errors.New("исполнитель вернул неверную находку")
		}
	}
	return res, nil
}

// writeError отправляет кадр error; true — соединение можно продолжать.
func (s *Server) writeError(c net.Conn, id uint32, code ErrorCode) bool {
	b, err := MarshalBody(ErrorMsg{Code: code})
	if err != nil {
		return false
	}
	if err := c.SetWriteDeadline(time.Now().Add(s.cfg.BodyTimeout)); err != nil {
		return false
	}
	return WriteFrame(c, Header{Type: TypeError, ID: id}, b) == nil && code != ErrTooLarge && code != ErrBadRequest
}
