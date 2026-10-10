// Команда mock-llm — OpenAI-совместимый мок провайдера LLM для разработки и
// e2e-тестов (ТЗ, 11.5). В поставку не входит. Работает только по TLS.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
	"github.com/azuresong-afk/ai_railway/internal/mockllm"
)

var version = "dev"

func main() {
	addr := flag.String("listen", "127.0.0.1:9443", "адрес и порт")
	certFile := flag.String("cert", ".dev-keys/server.pem", "сертификат TLS (PEM)")
	keyFile := flag.String("key", ".dev-keys/server-key.pem", "закрытый ключ TLS (PEM, права 0600)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "mock-llm", "version", version)
	if err := run(*addr, *certFile, *keyFile, logger); err != nil {
		logger.Error("остановка с ошибкой", "error", err)
		os.Exit(1)
	}
}

func run(addr, certFile, keyFile string, logger *slog.Logger) error {
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
		Addr: addr, Handler: mockllm.New(logger).Handler(),
		TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM, Logger: logger,
	})
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}
