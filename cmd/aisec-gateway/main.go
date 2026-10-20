// Команда aisec-gateway — шлюз между приложениями и провайдерами LLM (ТЗ, 5.1).
// Этап 1: приложения аутентифицируются ключами из файла конфигурации, запрос
// и ответ проверяются конвейером по политике приложения (см. internal/gateway).
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
	"github.com/azuresong-afk/ai_railway/internal/providers"
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
	for _, w := range file.Warnings() {
		logger.Warn("опасная настройка", "detail", w)
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
	rnd, err := p.Random()
	if err != nil {
		return err
	}
	provs, err := newProviders(file, tp, rnd, logger)
	if err != nil {
		return err
	}
	// Политики компилируются по детекторам приложения при запуске:
	// незарегистрированный детектор в политике заказчика — отказ запуска.
	router, err := gateway.NewRouter(file.Applications, provs, file.Policies)
	if err != nil {
		return err
	}
	userMAC, err := newUserMAC(p, file)
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
	// Квоты общие для всех маршрутов приложений: счётчики — один набор.
	handlerCfg := gateway.ChatConfig{
		Router: router, MaxBodyBytes: cfg.MaxBodyBytes, Logger: logger,
		Events: queue, IDs: authCfg.IDs, Quotas: gateway.NewLimiter(file.Applications), UserMAC: userMAC,
	}
	chatHandler, err := gateway.NewChatHandler(handlerCfg)
	if err != nil {
		return err
	}
	embeddingsHandler, err := gateway.NewEmbeddingsHandler(handlerCfg)
	if err != nil {
		return err
	}
	checkHandler, err := gateway.NewCheckHandler(handlerCfg)
	if err != nil {
		return err
	}
	handler, err := gateway.New(gateway.Options{Logger: logger, Chat: chatHandler, Embeddings: embeddingsHandler,
		Check: checkHandler, Router: router, Auth: authCfg})
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
	logger.Info("шлюз запущен: проверка запроса и ответа включена",
		"max_body_bytes", cfg.MaxBodyBytes, "applications", len(file.Applications), "providers", len(provs))
	return srv.Run(ctx)
}

// newUserMAC — имитовставка для псевдонимов пользователей (ТЗ, 5.5). Ключ
// нужен, если хотя бы одно приложение передаёт идентификатор пользователя:
// исходный идентификатор в события не пишется.
func newUserMAC(p aisecCrypto.Provider, file *config.GatewayFile) (aisecCrypto.MAC, error) {
	path := file.Gateway.UserHMACKeyFile
	if path == "" {
		for _, a := range file.Applications {
			if a.UserFrom != "" && a.UserFrom != "none" {
				return nil, fmt.Errorf("приложение %s: user_from %s требует gateway.user_hmac_key_file", a.ID, a.UserFrom)
			}
		}
		return nil, nil
	}
	key, err := aisecCrypto.ReadKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("ключ псевдонимов пользователей: %w", err)
	}
	return p.NewMAC(key)
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

// newProviders создаёт провайдеров из файла конфигурации. Ключи провайдеров
// читаются из файлов с правами 0600 и в журнал не попадают.
func newProviders(file *config.GatewayFile, tp aisecCrypto.TLSProvider, rnd aisecCrypto.Random, logger *slog.Logger) (map[string]providers.Provider, error) {
	out := map[string]providers.Provider{}
	for _, pc := range file.Providers {
		rootsPEM, err := aisecCrypto.ReadPEMFile(pc.CAFile)
		if err != nil {
			return nil, fmt.Errorf("провайдер %s: корневые сертификаты: %w", pc.ID, err)
		}
		connect, header := time.Duration(pc.ConnectTimeout), time.Duration(pc.HeaderTimeout)
		if connect == 0 {
			connect = config.DefaultConnectTimeout
		}
		if header == 0 {
			header = config.DefaultHeaderTimeout
		}
		transport, err := providers.NewTransport(tp, rootsPEM, connect, header)
		if err != nil {
			return nil, fmt.Errorf("провайдер %s: %w", pc.ID, err)
		}
		key := ""
		if pc.KeyFile != "" {
			b, err := aisecCrypto.ReadKeyFile(pc.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("провайдер %s: ключ: %w", pc.ID, err)
			}
			key = strings.TrimSpace(string(b))
		}
		u, err := config.ParseUpstreamURL(pc.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("провайдер %s: %w", pc.ID, err)
		}
		bc := providers.BaseConfig{
			ID: pc.ID, External: pc.IsExternal(), Transport: transport, Logger: logger,
			ResponseTimeout: time.Duration(pc.ResponseTimeout), StreamIdleTimeout: time.Duration(pc.StreamIdleTimeout),
		}
		var prov providers.Provider
		switch pc.Type {
		case config.ProviderGigaChat:
			gc := providers.GigaChatConfig{BaseConfig: bc, BaseURL: u, AuthKey: key, Scope: pc.Scope, Random: rnd}
			if pc.AuthURL != "" {
				if gc.AuthURL, err = config.ParseUpstreamURL(pc.AuthURL); err != nil {
					return nil, fmt.Errorf("провайдер %s: auth_url: %w", pc.ID, err)
				}
			}
			prov, err = providers.NewGigaChat(gc)
		case config.ProviderYandexGPT:
			prov, err = providers.NewYandexGPT(providers.YandexGPTConfig{BaseConfig: bc, BaseURL: u, APIKey: key, FolderID: pc.FolderID, Random: rnd})
		default:
			prov, err = providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: bc, BaseURL: u, Key: key})
		}
		if err != nil {
			return nil, err
		}
		out[pc.ID] = prov
	}
	return out, nil
}
