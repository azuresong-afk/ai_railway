// Команда aisec-server — сервер управления: API, веб-консоль, оповещения, инциденты, отчёты, аудит.
// Сейчас (задача 2.6 этапа 2) — каркас: HTTPS, маршрутизатор с проверкой прав,
// Problem Details, ограничение частоты; ресурсы API добавляются следующими задачами.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/azuresong-afk/ai_railway/internal/api"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

var version = "dev"

// dbPoolSize — число соединений с PostgreSQL.
const dbPoolSize = 10

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "aisec-server", "version", version)
	cfg, err := loadConfig(os.Args[1:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		logger.Error("неверная конфигурация", "error", err)
		os.Exit(2)
	}
	ctx, stop := shutdownContext()
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("остановка с ошибкой", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *serverConfig, logger *slog.Logger) error {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	// Самотест криптопрофиля до приёма запросов (ТЗ, ОЦЛ.4).
	if err := aisecCrypto.SelfTest(p); err != nil {
		return fmt.Errorf("самотест: %w", err)
	}
	tp, err := p.TLS()
	if err != nil {
		return err
	}
	hasher, err := p.Hasher()
	if err != nil {
		return err
	}
	certPEM, err := aisecCrypto.ReadPEMFile(cfg.TLSCertFile)
	if err != nil {
		return fmt.Errorf("сертификат сервера: %w", err)
	}
	keyPEM, err := aisecCrypto.ReadKeyFile(cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("ключ сервера: %w", err)
	}
	db, err := store.Open(ctx, cfg.DatabaseURL, dbPoolSize)
	if err != nil {
		return err
	}
	defer db.Close()

	handler, _, err := api.New(api.Options{
		Logger: logger, Version: version, Hasher: hasher,
		Ready:    db.Ping,
		Fallback: staticFallback(),
	})
	if err != nil {
		return err
	}
	srv, err := httpserver.New(ctx, httpserver.Config{
		Addr: cfg.Listen, Handler: handler, TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM, Logger: logger,
	})
	if err != nil {
		return err
	}
	logger.Info("сервер управления запущен")
	return srv.Run(ctx)
}
