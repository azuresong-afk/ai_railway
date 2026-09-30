// Команда aisec-gateway — шлюз между приложениями и провайдерами LLM (ТЗ, 5.1).
// На этапе 0 — прозрачный прокси для разработки (см. internal/gateway).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall" //nolint:depguard // только константа SIGTERM: корректное завершение по сигналу оркестратора (ТЗ, 4.4)

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "aisec-gateway", "version", version)
	cfg, err := config.LoadGateway(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		logger.Error("неверная конфигурация", "error", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("остановка с ошибкой", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config.Gateway, logger *slog.Logger) error {
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
	srv, err := httpserver.New(ctx, httpserver.Config{
		Addr: cfg.Listen, Handler: gateway.New(gateway.Options{Logger: logger, Proxy: proxy}),
		TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM, Logger: logger,
	})
	if err != nil {
		return err
	}
	logger.Info("шлюз этапа 0: прозрачный прокси без проверок и аутентификации приложений, только для разработки",
		"upstream", cfg.UpstreamURL.Redacted(), "max_body_bytes", cfg.MaxBodyBytes)
	return srv.Run(ctx)
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
