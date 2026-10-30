// Команда aisec-media — изолированный анализатор изображений рядом со
// шлюзом (ТЗ 5.17, ADR-0032): принимает изображения по Unix-сокету
// протоколом internal/media/wire, проверяет формат и размеры по заголовку
// до декодирования и декодирует стандартной библиотекой. Декодеры есть
// только здесь (internal/media); шлюз и сервер их не содержат.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall" //nolint:depguard // ADR-0004: только syscall.SIGTERM для корректного завершения; прочее syscall.* запрещает forbidigo

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/media"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "aisec-media", "version", version)
	cfg, err := loadConfig(os.Args[1:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		logger.Error("неверная конфигурация", "error", err)
		os.Exit(2)
	}
	// От root анализатор недоверенных изображений не запускается: свой
	// пользователь aisec-media создаёт prepare-host.sh (ADR-0032, раздел 1;
	// задача 5.38).
	if os.Getuid() == 0 {
		logger.Error("aisec-media не запускается от root: нужен отдельный непривилегированный пользователь aisec-media")
		os.Exit(2)
	}
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancelCause(sigCtx)
	defer cancel(nil)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		logger.Error("криптопрофиль", "error", err)
		os.Exit(1)
	}
	// Целостность бинарника — до приёма первого изображения (ОЦЛ.2).
	if err := startIntegrity(ctx, cfg, p, logger, cancel); err != nil {
		logger.Error("контроль целостности", "error", err)
		os.Exit(1)
	}
	err = run(ctx, cfg, deps{provider: p, logger: logger})
	if cause := context.Cause(ctx); errors.Is(cause, integrity.ErrViolation) {
		err = errors.Join(err, cause)
	}
	if err != nil {
		logger.Error("остановка с ошибкой", "error", err)
		os.Exit(1)
	}
}

// deps — то, что тесты подменяют.
type deps struct {
	provider aisecCrypto.Provider
	logger   *slog.Logger
	// ready вызывается, когда сокет готов (для тестов).
	ready func(*media.Server)
}

// run обслуживает сокет до отмены ctx.
func run(ctx context.Context, cfg *config, d deps) error {
	if !peerCredSupported {
		return errors.New("проверка собеседника по сокету (SO_PEERCRED) есть только в Linux: aisec-media не запускается")
	}
	h, err := d.provider.Hasher()
	if err != nil {
		return err
	}
	srv, err := media.NewServer(media.ServerConfig{Limits: cfg.Limits, Hasher: h, MaxConns: cfg.MaxConns, Workers: cfg.Workers,
		Queue: cfg.Queue, CacheEntries: cfg.CacheEntries, RunTimeout: cfg.RunTimeout, MaxRunTimeout: cfg.MaxRunTimeout, Logger: d.logger})
	if err != nil {
		return err
	}
	sock, err := listenSocket(ctx, cfg.Socket)
	if err != nil {
		return err
	}
	l := newPeerListener(sock, cfg.PeerUID, cfg.PeerGID, d.logger)
	d.logger.Info("aisec-media готов", "socket", cfg.Socket, "formats", media.Decodable(), "max_bytes", cfg.Limits.MaxBytes,
		"max_pixels", cfg.Limits.MaxPixels, "workers", cfg.Workers, "queue", cfg.Queue, "peer_uid", cfg.PeerUID, "peer_gid", cfg.PeerGID)
	if d.ready != nil {
		d.ready(srv)
	}
	return srv.Serve(ctx, l)
}
