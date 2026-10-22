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
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/integrity/selftest"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "aisec-gateway", "version", version)
	if len(os.Args) > 1 && os.Args[1] == "register" {
		mainRegister(logger)
		return
	}
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

// mainRegister — подкоманда register: получение сертификата шлюза по токену.
func mainRegister(logger *slog.Logger) {
	cfg, err := loadRegConfig(os.Args[2:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		logger.Error("неверные параметры регистрации", "error", err)
		os.Exit(2)
	}
	ctx, stop := shutdownContext()
	defer stop()
	if err := runRegister(ctx, cfg, os.Stdout); err != nil {
		logger.Error("регистрация не выполнена", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config.Gateway, logger *slog.Logger) (err error) {
	// Без сервера — файл конфигурации этапа 1; с сервером — подписанный
	// пакет (задача 2.13), файла нет.
	var file *config.GatewayFile
	if cfg.ConfigFile != "" {
		if file, err = config.LoadGatewayFile(cfg.ConfigFile); err != nil {
			return fmt.Errorf("файл конфигурации: %w", err)
		}
		for _, w := range file.Warnings() {
			logger.Warn("опасная настройка", "detail", w)
		}
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	// Самотест до приёма трафика (ТЗ, ОЦЛ.4–5): криптопрофиль и все
	// встроенные детекторы на эталонах. Своей БД у шлюза нет — итог в
	// техническом журнале и в heartbeat на сервер (2.20).
	reports := &gateway.Reports{}
	if res, err := selftest.Startup(ctx, selftest.StartupConfig{
		Config: selftest.Config{Component: "gateway", Provider: p, Detectors: builtin.All()},
		Action: integrity.Action(cfg.SelftestAction), Logger: logger,
	}); err != nil {
		return err
	} else {
		failed := len(res.Failures)
		if !res.CryptoOK {
			failed++
		}
		reports.SetSelftest(res.OK(), res.At, failed)
	}
	// Контроль целостности до приёма трафика (ОЦЛ.2–3): нарушение с
	// реакцией stop после запуска отменяет контекст с причиной ErrViolation.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	if err := startIntegrity(ctx, cfg, p, logger, cancel, reports); err != nil {
		return err
	}
	defer func() {
		if cause := context.Cause(ctx); errors.Is(cause, integrity.ErrViolation) {
			err = errors.Join(err, cause)
		}
	}()
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
	// Сервер управления (ИАФ.10): heartbeat, события и пакеты конфигурации
	// по mTLS. Без него — автономный режим этапа 1 с файлом событий JSONL.
	var control *http.Client
	gatewayID := ""
	if cfg.Server != nil {
		if control, gatewayID, err = newControlClient(cfg, tp, logger); err != nil {
			return err
		}
	} else if err := file.CheckEventsSink(false); err != nil {
		return fmt.Errorf("файл конфигурации: %w", err)
	}
	userMAC, err := newUserMAC(p, cfg, file)
	if err != nil {
		return err
	}
	authBase, queue, closeEvents, err := newAuth(p, file, cfg, control, logger)
	if err != nil {
		return err
	}
	// События, принятые до остановки, отправляются до выхода (ТЗ, 4.4).
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = errors.Join(err, queue.Close(cctx), closeEvents())
		if n := queue.Dropped(); n > 0 {
			logger.Warn("события отброшены: очередь переполнена или сервер недоступен при остановке", "count", n)
		}
	}()
	h, err := p.Hasher()
	if err != nil {
		return err
	}
	// Квоты общие для всех маршрутов приложений и переживают смену пакета.
	hb := &handlerBuilder{cfg: cfg, logger: logger, hasher: h, auth: authBase, events: queue,
		quotas: gateway.NewLimiter(nil), userMAC: userMAC}
	var handler http.Handler
	var bundles *gateway.BundleClient
	if file != nil {
		provs, err := newProviders(file, tp, rnd, logger)
		if err != nil {
			return err
		}
		recs, err := gateway.KeyRecords(file.Applications)
		if err != nil {
			return err
		}
		// Политики компилируются по детекторам приложения при запуске:
		// незарегистрированный детектор в политике заказчика — отказ запуска.
		if handler, err = hb.build(file.Applications, provs, file.Policies, recs); err != nil {
			return err
		}
		logger.Info("конфигурация из файла", "applications", len(file.Applications), "providers", len(provs))
	} else {
		sw := gateway.NewSwitch(gateway.NewUnavailable(logger))
		if bundles, err = newBundleClient(cfg, p, tp, rnd, gatewayID, control, hb, sw, logger); err != nil {
			return err
		}
		handler = sw
	}
	srv, err := httpserver.New(ctx, httpserver.Config{
		Addr: cfg.Listen, Handler: handler,
		TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM, Logger: logger,
	})
	if err != nil {
		return err
	}
	if control != nil {
		if !bundles.LoadSaved() {
			logger.Warn("пакета конфигурации ещё нет: приложения получат 503 до первого пакета от сервера")
		}
		go bundles.Run(ctx)
		startHeartbeat(ctx, cfg, control, logger, reports, bundles.ETag)
	} else {
		logger.Info("сервер управления не задан (-server): шлюз работает без регистрации, события пишутся в файл")
	}
	logger.Info("шлюз запущен: проверка запроса и ответа включена", "max_body_bytes", cfg.MaxBodyBytes)
	return srv.Run(ctx)
}

// handlerBuilder собирает обработчик шлюза по набору приложений: из файла
// при запуске или из каждого нового пакета конфигурации.
type handlerBuilder struct {
	cfg     *config.Gateway
	logger  *slog.Logger
	hasher  aisecCrypto.Hasher
	auth    *gateway.AuthConfig
	events  *events.Queue
	quotas  *gateway.Limiter
	userMAC aisecCrypto.MAC
}

func (hb *handlerBuilder) build(apps []config.Application, provs map[string]providers.Provider, specs []policy.Spec,
	recs []auth.KeyRecord) (http.Handler, error) {
	for _, a := range apps {
		if hb.userMAC == nil && a.UserFrom != "" && a.UserFrom != "none" {
			return nil, fmt.Errorf("приложение %s: user_from %s требует ключ псевдонимов пользователей (user-hmac-key)", a.ID, a.UserFrom)
		}
	}
	router, err := gateway.NewRouter(apps, provs, specs)
	if err != nil {
		return nil, err
	}
	a, err := auth.NewAuthenticator(hb.hasher, recs)
	if err != nil {
		return nil, err
	}
	authCfg := *hb.auth
	authCfg.Authenticator = a
	handlerCfg := gateway.ChatConfig{
		Router: router, MaxBodyBytes: hb.cfg.MaxBodyBytes, Logger: hb.logger,
		Events: hb.events, IDs: authCfg.IDs, Quotas: hb.quotas, UserMAC: hb.userMAC,
	}
	chatHandler, err := gateway.NewChatHandler(handlerCfg)
	if err != nil {
		return nil, err
	}
	embeddingsHandler, err := gateway.NewEmbeddingsHandler(handlerCfg)
	if err != nil {
		return nil, err
	}
	checkHandler, err := gateway.NewCheckHandler(handlerCfg)
	if err != nil {
		return nil, err
	}
	h, err := gateway.New(gateway.Options{Logger: hb.logger, Chat: chatHandler, Embeddings: embeddingsHandler,
		Check: checkHandler, Router: router, Auth: &authCfg})
	if err != nil {
		return nil, err
	}
	// Счётчики квот — последним шагом: сборка не удалась — квоты прежние.
	hb.quotas.Reconfigure(apps)
	return h, nil
}

// startIntegrity проверяет целостность шлюза при запуске и запускает
// периодическую проверку: исполняемый файл и файл конфигурации, изменённый
// после запуска (ОЦЛ.3). Своей БД у шлюза нет — итоги идут в технический
// журнал; передача на сервер — вместе с каналом шлюз — сервер (2.14, 2.20).
func startIntegrity(ctx context.Context, cfg *config.Gateway, p aisecCrypto.Provider, logger *slog.Logger, stop context.CancelCauseFunc, reports *gateway.Reports) error {
	exe, err := os.Executable()
	if err != nil {
		exe = "" // проверка отметит исполняемый файл как нечитаемый
	}
	manifest := cfg.Manifest
	if manifest == "" {
		manifest = integrity.DefaultManifestPath(exe)
	}
	// Файл конфигурации — только без сервера; пакет с сервера защищён
	// подписью и проверяется при каждой загрузке (ОЦЛ.3, задача 2.13).
	var watch []string
	if cfg.ConfigFile != "" {
		watch = []string{cfg.ConfigFile}
	}
	checker, err := integrity.NewChecker(integrity.Config{
		Component: "gateway", Provider: p, ManifestPath: manifest,
		Executable: exe, BinaryName: "bin/aisec-gateway", Watch: watch,
	})
	if err != nil {
		return err
	}
	mon, err := integrity.NewMonitor(integrity.MonitorConfig{
		Checker: checker, Action: integrity.Action(cfg.IntegrityAction), Interval: cfg.IntegrityInterval,
		Logger: logger, OnStop: stop,
		// Итог каждой проверки — в heartbeat на сервер (2.20); БД у шлюза нет.
		Record: func(_ context.Context, res integrity.Result, _ audit.Actor, _ netip.Addr) error {
			reports.SetIntegrity(res.OK(), res.At, string(res.Reason), len(res.Failures)+res.Omitted)
			return nil
		},
	})
	if err != nil {
		return err
	}
	if _, err := mon.Startup(ctx); err != nil {
		return err
	}
	go mon.Run(ctx)
	return nil
}

// newControlClient — HTTP-клиент к внутреннему API сервера по mTLS
// (ИАФ.10): сертификат и ключ шлюза — от aisec-gateway register.
// Возвращает и ID шлюза — CN сертификата: пакет конфигурации собирается
// на этот ID.
func newControlClient(cfg *config.Gateway, tp aisecCrypto.TLSProvider, logger *slog.Logger) (*http.Client, string, error) {
	rootsPEM, err := aisecCrypto.ReadPEMFile(cfg.ServerCAFile)
	if err != nil {
		return nil, "", fmt.Errorf("корневой сертификат сервера: %w", err)
	}
	certPEM, err := aisecCrypto.ReadPEMFile(cfg.ClientCertFile)
	if err != nil {
		return nil, "", fmt.Errorf("сертификат шлюза для сервера: %w", err)
	}
	keyPEM, err := aisecCrypto.ReadKeyFile(cfg.ClientKeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("ключ шлюза для сервера: %w", err)
	}
	id, err := aisecCrypto.ParseCertInfo(certPEM)
	if err != nil {
		return nil, "", fmt.Errorf("сертификат шлюза для сервера: %w", err)
	}
	if time.Until(id.NotAfter) < 30*24*time.Hour {
		logger.Warn("сертификат шлюза скоро истекает: нужна повторная регистрация", "not_after", id.NotAfter.UTC())
	}
	transport, err := gateway.ControlTransport(tp, rootsPEM, certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}
	logger.Info("связь с сервером управления по mTLS: heartbeat, события и пакеты конфигурации", "gateway_id", id.CommonName, "server", cfg.Server.Host)
	return &http.Client{Transport: transport}, id.CommonName, nil
}

// startHeartbeat запускает heartbeat на внутренний API сервера. Сервер
// недоступен — шлюз всё равно работает (ТЗ, 4.2).
func startHeartbeat(ctx context.Context, cfg *config.Gateway, client *http.Client, logger *slog.Logger, reports *gateway.Reports, etag func() string) {
	v := version
	if !gateway.ValidVersion(v) {
		v = "unknown"
	}
	go gateway.RunHeartbeat(ctx, gateway.HeartbeatConfig{
		Client: client, Server: cfg.Server, Version: v, Logger: logger, Reports: reports, BundleETag: etag,
	})
}

// newUserMAC — имитовставка для псевдонимов пользователей (ТЗ, 5.5). Ключ
// нужен, если хотя бы одно приложение передаёт идентификатор пользователя:
// исходный идентификатор в события не пишется. Без сервера ключ задаёт файл
// конфигурации, с сервером — флаг -user-hmac-key; приложение с user_from
// без ключа отклоняется при сборке обработчика.
func newUserMAC(p aisecCrypto.Provider, cfg *config.Gateway, file *config.GatewayFile) (aisecCrypto.MAC, error) {
	path := cfg.UserHMACKeyFile
	if file != nil {
		path = file.Gateway.UserHMACKeyFile
		if path == "" {
			for _, a := range file.Applications {
				if a.UserFrom != "" && a.UserFrom != "none" {
					return nil, fmt.Errorf("приложение %s: user_from %s требует gateway.user_hmac_key_file", a.ID, a.UserFrom)
				}
			}
		}
	}
	if path == "" {
		return nil, nil
	}
	key, err := aisecCrypto.ReadKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("ключ псевдонимов пользователей: %w", err)
	}
	return p.NewMAC(key)
}

// newAuth собирает общую часть аутентификации приложений (счётчик неудач,
// события) и очередь событий: с сервером управления (control) — отправитель
// на сервер по mTLS, без него — файл JSONL. Проверку ключей (Authenticator)
// добавляет сборка обработчика.
func newAuth(p aisecCrypto.Provider, file *config.GatewayFile, cfg *config.Gateway, control *http.Client,
	logger *slog.Logger) (*gateway.AuthConfig, *events.Queue, func() error, error) {
	rnd, err := p.Random()
	if err != nil {
		return nil, nil, nil, err
	}
	var queue *events.Queue
	var closeSink func() error
	if control != nil {
		sink, err := gateway.NewServerSink(gateway.ServerSinkConfig{Client: control, Server: cfg.Server, Logger: logger})
		if err != nil {
			return nil, nil, nil, err
		}
		queue = events.NewQueue(sink, events.QueueConfig{Logger: logger, SendTimeout: gateway.SinkSendTimeout})
		sink.CountDropped(queue.Dropped)
		closeSink = func() error {
			if n := sink.Rejected(); n > 0 {
				logger.Warn("сервер управления отклонил события", "count", n)
			}
			return nil
		}
	} else {
		sink, err := events.NewFileSink(file.Gateway.EventsFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("файл событий: %w", err)
		}
		queue = events.NewQueue(sink, events.QueueConfig{Logger: logger})
		closeSink = sink.Close
	}
	return &gateway.AuthConfig{
		Limiter: auth.NewFailureLimiter(auth.LimiterConfig{}),
		Events:  queue, IDs: ids.NewGenerator(rnd), Logger: logger,
	}, queue, closeSink, nil
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
		key := ""
		if pc.KeyFile != "" {
			b, err := aisecCrypto.ReadKeyFile(pc.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("провайдер %s: ключ: %w", pc.ID, err)
			}
			key = strings.TrimSpace(string(b))
		}
		if out[pc.ID], err = newProvider(pc, rootsPEM, key, tp, rnd, logger); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// newProvider создаёт провайдера: rootsPEM — корневые сертификаты, key —
// учётные данные (из файла или из пакета конфигурации).
func newProvider(pc config.Provider, rootsPEM []byte, key string, tp aisecCrypto.TLSProvider, rnd aisecCrypto.Random, logger *slog.Logger) (providers.Provider, error) {
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
	u, err := config.ParseUpstreamURL(pc.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("провайдер %s: %w", pc.ID, err)
	}
	bc := providers.BaseConfig{
		ID: pc.ID, External: pc.IsExternal(), Transport: transport, Logger: logger,
		ResponseTimeout: time.Duration(pc.ResponseTimeout), StreamIdleTimeout: time.Duration(pc.StreamIdleTimeout),
	}
	switch pc.Type {
	case config.ProviderGigaChat:
		gc := providers.GigaChatConfig{BaseConfig: bc, BaseURL: u, AuthKey: key, Scope: pc.Scope, Random: rnd}
		if pc.AuthURL != "" {
			if gc.AuthURL, err = config.ParseUpstreamURL(pc.AuthURL); err != nil {
				return nil, fmt.Errorf("провайдер %s: auth_url: %w", pc.ID, err)
			}
		}
		return providers.NewGigaChat(gc)
	case config.ProviderYandexGPT:
		return providers.NewYandexGPT(providers.YandexGPTConfig{BaseConfig: bc, BaseURL: u, APIKey: key, FolderID: pc.FolderID, Random: rnd})
	default:
		return providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: bc, BaseURL: u, Key: key})
	}
}
