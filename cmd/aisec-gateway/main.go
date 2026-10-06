// Команда aisec-gateway — шлюз между приложениями и провайдерами LLM (ТЗ, 5.1).
// Этап 1 в работе: приложения аутентифицируются ключами из файла конфигурации,
// запросы пока передаются провайдеру без проверок (см. internal/gateway).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "aisec-gateway", "version", version)
	cfg, err := config.LoadGateway(os.Args[1:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return // справка уже напечатана
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

func run(ctx context.Context, cfg *config.Gateway, logger *slog.Logger) (err error) {
	file, err := config.LoadGatewayFile(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("файл конфигурации: %w", err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	// Самотест криптопрофиля до приёма трафика (ТЗ, ОЦЛ.4).
	if err := aisecCrypto.SelfTest(p); err != nil {
		return fmt.Errorf("самотест: %w", err)
	}
	tp, err := p.TLS()
	if err != nil {
		return err
	}
	certPEM, err := aisecCrypto.ReadPEMFile(cfg.TLSCertFile)
	if err != nil {
		return fmt.Errorf("сертификат шлюза: %w", err)
	}
	keyPEM, err := aisecCrypto.ReadKeyFile(cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("ключ шлюза: %w", err)
	}
	proxy, err := newProxy(cfg, tp, logger)
	if err != nil {
		return err
	}
	authCfg, queue, closeEvents, err := newAuth(p, file, logger)
	if err != nil {
		return err
	}
	// События, принятые до остановки, отправляются до выхода (ТЗ, 4.4).
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = errors.Join(err, queue.Close(cctx), closeEvents())
		if n := queue.Dropped(); n > 0 {
			logger.Warn("события отброшены из-за переполнения очереди", "count", n)
		}
	}()
	handler, err := gateway.New(gateway.Options{Logger: logger, Proxy: proxy, Auth: authCfg})
	if err != nil {
		return err
	}
	srv, err := httpserver.New(ctx, httpserver.Config{
		Addr: cfg.Listen, Handler: handler,
		TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM, Logger: logger,
	})
	if err != nil {
		return err
	}
	logger.Info("шлюз этапа 1 (в работе): аутентификация приложений включена, проверки содержимого ещё нет",
		"upstream", cfg.UpstreamURL.Redacted(), "max_body_bytes", cfg.MaxBodyBytes, "applications", len(file.Applications))
	return srv.Run(ctx)
}

// newAuth собирает аутентификацию приложений и очередь событий с приёмником
// JSONL из файла конфигурации.
func newAuth(p aisecCrypto.Provider, file *config.GatewayFile, logger *slog.Logger) (*gateway.AuthConfig, *events.Queue, func() error, error) {
	h, err := p.Hasher()
	if err != nil {
		return nil, nil, nil, err
	}
	rnd, err := p.Random()
	if err != nil {
		return nil, nil, nil, err
	}
	recs, err := gateway.KeyRecords(file.Applications)
	if err != nil {
		return nil, nil, nil, err
	}
	a, err := auth.NewAuthenticator(h, recs)
	if err != nil {
		return nil, nil, nil, err
	}
	sink, err := events.NewFileSink(file.Gateway.EventsFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("файл событий: %w", err)
	}
	queue := events.NewQueue(sink, events.QueueConfig{Logger: logger})
	return &gateway.AuthConfig{
		Authenticator: a, Limiter: auth.NewFailureLimiter(auth.LimiterConfig{}),
		Events: queue, IDs: ids.NewGenerator(rnd), Logger: logger,
	}, queue, sink.Close, nil
}

// newProxy собирает прозрачный прокси на upstream из конфигурации.
func newProxy(cfg *config.Gateway, tp aisecCrypto.TLSProvider, logger *slog.Logger) (*gateway.Proxy, error) {
	rootsPEM, err := aisecCrypto.ReadPEMFile(cfg.UpstreamCAFile)
	if err != nil {
		return nil, fmt.Errorf("корневые сертификаты провайдера: %w", err)
	}
	transport, err := gateway.NewTransport(tp, rootsPEM, cfg.UpstreamConnectTimeout, cfg.UpstreamHeaderTimeout)
	if err != nil {
		return nil, err
	}
	key := ""
	if cfg.UpstreamKeyFile != "" {
		b, err := aisecCrypto.ReadKeyFile(cfg.UpstreamKeyFile)
		if err != nil {
			return nil, fmt.Errorf("ключ провайдера: %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	return gateway.NewProxy(gateway.ProxyConfig{
		Upstream: cfg.UpstreamURL, Transport: transport, UpstreamKey: key,
		MaxBodyBytes: cfg.MaxBodyBytes, ForwardHeaders: cfg.ForwardHeaders, Logger: logger,
	})
}
