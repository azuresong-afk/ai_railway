// Команда mock-mcp — мок MCP-сервера (Streamable HTTP, ревизии 2025-11-25 и
// 2026-07-28) для разработки и e2e-тестов MCP-прокси шлюза (задача 4.11).
// В поставку не входит. Работает только по TLS.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
	"github.com/azuresong-afk/ai_railway/internal/mockmcp"
)

var version = "dev"

func main() {
	addr := flag.String("listen", "127.0.0.1:9444", "адрес и порт")
	certFile := flag.String("cert", ".dev-keys/server.pem", "сертификат TLS (PEM)")
	keyFile := flag.String("key", ".dev-keys/server-key.pem", "закрытый ключ TLS (PEM, права 0600)")
	tokenFile := flag.String("token-file", "", "файл с ожидаемым токеном Bearer (по умолчанию без проверки)")
	var opts mockmcp.Options
	flag.BoolVar(&opts.Poisoned, "poisoned", false, "описание add_numbers с внедрёнными инструкциями (DM-24)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "mock-mcp", "version", version)
	if err := run(*addr, *certFile, *keyFile, *tokenFile, opts, logger); err != nil {
		logger.Error("остановка с ошибкой", "error", err)
		os.Exit(1)
	}
}

func run(addr, certFile, keyFile, tokenFile string, opts mockmcp.Options, logger *slog.Logger) error {
	if tokenFile != "" {
		tok, err := aisecCrypto.ReadKeyFile(tokenFile)
		if err != nil {
			return fmt.Errorf("токен: %w", err)
		}
		opts.Token = strings.TrimSpace(string(tok))
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return err
	}
	tp, err := p.TLS()
	if err != nil {
		return err
	}
	certPEM, err := aisecCrypto.ReadPEMFile(certFile)
	if err != nil {
		return fmt.Errorf("сертификат: %w", err)
	}
	keyPEM, err := aisecCrypto.ReadKeyFile(keyFile)
	if err != nil {
		return fmt.Errorf("ключ: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := httpserver.New(ctx, httpserver.Config{
		Addr: addr, Handler: mockmcp.New(opts, logger).Handler(),
		TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM, Logger: logger,
	})
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}
