// Пакет httpserver — HTTPS-сервер компонентов с безопасными настройками по
// умолчанию (ТЗ, ЗИ.4): только TLS (настройки из internal/crypto), таймауты
// на чтение заголовков и простой соединения, лимит заголовков, корректное
// завершение с ожиданием активных запросов (ТЗ, 4.4).
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Настройки по умолчанию.
const (
	ReadHeaderTimeout = 10 * time.Second
	IdleTimeout       = 120 * time.Second
	MaxHeaderBytes    = 64 << 10
	ShutdownTimeout   = 30 * time.Second
)

// Config — параметры сервера.
type Config struct {
	Addr    string
	Handler http.Handler
	TLS     aisecCrypto.TLSProvider
	CertPEM []byte
	KeyPEM  []byte
	Logger  *slog.Logger
	// ReadTimeout — предел на чтение всего запроса. Ноль — без предела:
	// потоковым ответам нужен долгий ответ, а тело ограничивают обработчики.
	ReadTimeout time.Duration
}

// Server — запущенный или готовый к запуску сервер.
type Server struct {
	srv    *http.Server
	ln     net.Listener
	logger *slog.Logger
}

// New проверяет параметры, готовит TLS и открывает порт. Без сертификата
// сервер не создаётся: перехода на HTTP нет.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Handler == nil || cfg.TLS == nil {
		return nil, errors.New("httpserver: не заданы обработчик или TLS")
	}
	if len(cfg.CertPEM) == 0 || len(cfg.KeyPEM) == 0 {
		return nil, errors.New("httpserver: не заданы сертификат и ключ TLS; работа без TLS не поддерживается")
	}
	tlsCfg, err := cfg.TLS.ServerConfig(cfg.CertPEM, cfg.KeyPEM)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("httpserver: порт %s: %w", cfg.Addr, err)
	}
	srv := &http.Server{
		Handler:           cfg.Handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	return &Server{srv: srv, ln: ln, logger: logger}, nil
}

// Addr — фактический адрес (полезно при порте 0 в тестах).
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Run обслуживает запросы до отмены ctx, затем завершает работу: новые
// соединения не принимаются, активные запросы дорабатывают до ShutdownTimeout.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		// Сертификат уже в TLSConfig, поэтому пути к файлам пустые.
		errCh <- s.srv.ServeTLS(s.ln, "", "")
	}()
	s.logger.Info("сервер запущен", "addr", s.Addr())
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ShutdownTimeout)
	defer cancel()
	s.logger.Info("завершение работы: ожидание активных запросов")
	if err := s.srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("httpserver: завершение: %w", err)
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	s.logger.Info("сервер остановлен")
	return nil
}
