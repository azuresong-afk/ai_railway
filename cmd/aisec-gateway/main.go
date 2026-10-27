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
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
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
	// Время запуска процесса — для записи запуска и остановки на сервере
	// (В27 ревью 2.r5).
	started := time.Now().UTC()
	// Без сервера — файл конфигурации этапа 1; с сервером — подписанный
	// пакет (задача 2.13), файла нет.
	var file *config.GatewayFile
	var configData []byte
	if cfg.ConfigFile != "" {
		if file, configData, err = config.ReadGatewayFile(cfg.ConfigFile); err != nil {
			return fmt.Errorf("файл конфигурации: %w", err)
		}
		for _, w := range file.Warnings() {
			logger.Warn("опасная настройка", "detail", w)
		}
	}
	// Корни доверия читаются один раз: шлюз работает с этими байтами, а
	// эталон контроля целостности — их хеш (В19, Н37 ревью 2.r4).
	trust, err := readTrustFiles(cfg, file)
	if err != nil {
		return err
	}
	if cfg.ConfigFile != "" {
		trust.watch = append([]integrity.WatchFile{{Path: cfg.ConfigFile, Data: configData}}, trust.watch...)
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
	verify, err := startIntegrity(ctx, cfg, p, logger, cancel, reports, trust.watch)
	if err != nil {
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
	// Сертификат адреса приложений меняется без перезапуска: сертификат
	// заказчика приходит в пакете конфигурации (задача 3.27).
	certSw, err := aisecCrypto.NewServerCertSwitch(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("сертификат шлюза: %w", err)
	}
	appTLS, err := gateway.NewTLSSwitch(certSw, logger)
	if err != nil {
		return err
	}
	rnd, err := p.Random()
	if err != nil {
		return err
	}
	// Сервер управления (ИАФ.10): heartbeat, события и пакеты конфигурации
	// по mTLS. Без него — автономный режим этапа 1 с файлом событий JSONL.
	var control *controlClient
	var state *gateway.BundleState
	if cfg.Server != nil {
		// Каталог состояния открыт до остановки процесса: os.Root держит
		// дескриптор. В нём ключ получателя, пакет, заявления о доверии и
		// перевыпущенный сертификат.
		if state, err = gateway.OpenBundleState(cfg.StateDir, rnd); err != nil {
			return err
		}
		if control, err = newControlClient(cfg, tp, trust.serverCA, state, logger); err != nil {
			return err
		}
	} else if err := file.CheckEventsSink(false); err != nil {
		return fmt.Errorf("файл конфигурации: %w", err)
	}
	userMAC, err := newUserMAC(p, trust.userHMACKey, file)
	if err != nil {
		return err
	}
	// Сессии чата (задачи 4.13, 4.14 этапа 4): на ключе псевдонимов, без
	// него — на случайном ключе процесса; переживают смену пакета.
	sessions, err := gateway.NewSessions(gateway.SessionConfig{Provider: p, MAC: userMAC})
	if err != nil {
		return err
	}
	authBase, queue, closeEvents, err := newAuth(p, file, cfg, control.httpClient(), logger)
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
		quotas: gateway.NewLimiter(nil), budget: gateway.NewBudget(nil), userMAC: userMAC, clock: &gateway.ServerClock{},
		sessions: sessions}
	hb.budget.SetLogger(logger)
	// Очередь подтверждений вызовов (require_approval, задача 4.10) — только
	// с сервером управления; без него такие вызовы отклоняются.
	if control != nil {
		if hb.approvals, err = gateway.NewApprovalClient(gateway.ApprovalClientConfig{Client: control.client, Server: cfg.Server,
			Hasher: h, Logger: logger}); err != nil {
			return err
		}
	}
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
		if handler, err = hb.build(file.Applications, provs, file.Policies, recs, nil, nil, nil, nil); err != nil {
			return err
		}
		logger.Info("конфигурация из файла", "applications", len(file.Applications), "providers", len(provs))
	} else {
		sw := gateway.NewSwitch(gateway.NewUnavailable(logger))
		var keyIDs []string
		if bundles, keyIDs, err = newBundleClient(cfg, p, tp, rnd, state, control, hb, sw, appTLS, trust.bundlePubs, logger); err != nil {
			return err
		}
		reports.SetBundleKeys(keyIDs)
		handler = sw
	}
	srv, err := httpserver.New(ctx, httpserver.Config{
		Addr: cfg.Listen, Handler: handler,
		TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM, CertSwitch: certSw, Logger: logger,
	})
	if err != nil {
		return err
	}
	if control != nil {
		if !bundles.LoadSaved() {
			logger.Warn("пакета конфигурации ещё нет: приложения получат 503 до первого пакета от сервера")
		}
		go bundles.Run(ctx)
		// Heartbeat остановки уходит после отмены: выход ждёт его (не
		// дольше stopHeartbeatTimeout). Отмена своя — сервер может
		// завершиться с ошибкой и без отмены ctx.
		hbCtx, hbCancel := context.WithCancel(ctx)
		reissue, err := gateway.NewReissuer(gateway.ReissueConfig{Client: control.client, Transport: control.transport,
			Server: cfg.Server, GatewayID: control.gatewayID, Switch: control.cert, State: state, Roots: bundles.TrustRoots,
			Logger: logger})
		if err != nil {
			hbCancel()
			return err
		}
		hbDone := startHeartbeat(hbCtx, cfg, control.client, logger, reports, bundles.ETag, verify, started, reissue.Reissue, hb.budget, hb.clock, appTLS.Current,
			hb.approvals.Pending)
		defer func() {
			hbCancel()
			<-hbDone
		}()
	} else {
		logger.Info("сервер управления не задан (-server): шлюз работает без регистрации, события пишутся в файл")
	}
	logger.Info("шлюз запущен: проверка запроса и ответа включена", "max_body_bytes", cfg.MaxBodyBytes)
	return srv.Run(ctx)
}

// handlerBuilder собирает обработчик шлюза по набору приложений: из файла
// при запуске или из каждого нового пакета конфигурации.
type handlerBuilder struct {
	cfg    *config.Gateway
	logger *slog.Logger
	hasher aisecCrypto.Hasher
	auth   *gateway.AuthConfig
	events *events.Queue
	quotas *gateway.Limiter
	// budget — счётчики расхода процесса (задача 3.18): переживают смену
	// пакета.
	budget  *gateway.Budget
	userMAC aisecCrypto.MAC
	// clock — сроки исключений не раньше времени сервера управления (3Н40).
	clock *gateway.ServerClock
	// sessions — сессии чата и session.risk (задача 4.13): переживают
	// смену пакета.
	sessions *gateway.Sessions
	// approvals — очередь подтверждений на сервере управления (задача
	// 4.10); nil — без сервера.
	approvals *gateway.ApprovalClient
}

func (hb *handlerBuilder) build(apps []config.Application, provs map[string]providers.Provider, specs []policy.Spec,
	recs []auth.KeyRecord, unavailable []string, budgets *bundle.Budgets, baselines []bundle.PromptBaseline,
	agents *gateway.Agents) (http.Handler, error) {
	for _, a := range apps {
		if hb.userMAC == nil && a.UserFrom != "" && a.UserFrom != "none" {
			return nil, fmt.Errorf("приложение %s: user_from %s требует ключ псевдонимов пользователей (user-hmac-key)", a.ID, a.UserFrom)
		}
	}
	router, err := gateway.NewRouter(apps, provs, specs)
	if err != nil {
		return nil, err
	}
	router.SetUnavailable(unavailable)
	// Хеши фрагментов находок для исключений — на ключе псевдонимов (задача 3.22).
	router.SetFragmentMAC(hb.userMAC)
	router.SetClock(hb.clock.Now)
	// Реестр агентов и очередь подтверждений (задачи 4.10, 4.11).
	router.SetAgents(agents)
	if hb.approvals != nil {
		router.SetApprover(hb.approvals)
	}
	// Эталоны системного промпта (задача 4.14): неверный раздел — пакет
	// отклоняется.
	bl := make(map[string]gateway.PromptBaseline, len(baselines))
	for _, b := range baselines {
		bl[b.App] = gateway.PromptBaseline{Hash: b.Hash, Mode: b.Mode}
	}
	if err := router.SetPromptBaselines(hb.hasher, bl); err != nil {
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
		Events: hb.events, IDs: authCfg.IDs, Quotas: hb.quotas, Budget: hb.budget, UserMAC: hb.userMAC,
		Sessions: hb.sessions,
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
	// Бюджеты и счётчики квот — последним шагом: сборка не удалась — они
	// прежние. Неверный раздел budgets (часовой пояс) — пакет отклоняется.
	ids := make([]string, 0, len(apps))
	for _, a := range apps {
		ids = append(ids, a.ID)
	}
	if err := hb.budget.Reconfigure(budgets, ids...); err != nil {
		return nil, err
	}
	hb.quotas.Reconfigure(apps)
	return h, nil
}

// trustFiles — файлы, от которых зависит доверие к конфигурации и серверу,
// прочитанные при запуске, и они же под контролем целостности.
type trustFiles struct {
	serverCA    []byte
	bundlePubs  [][]byte
	userHMACKey []byte
	watch       []integrity.WatchFile
}

// readTrustFiles читает корень доверия сервера (-server-ca), ключи проверки
// пакетов (-bundle-pub) и ключ псевдонимов пользователей. Подмена
// -bundle-pub после запуска — нарушение целостности (В19 ревью 2.r4).
// Сертификаты и ключи TLS не наблюдаются: их меняют при продлении.
func readTrustFiles(cfg *config.Gateway, file *config.GatewayFile) (trustFiles, error) {
	var t trustFiles
	var err error
	if cfg.Server != nil {
		if t.serverCA, err = aisecCrypto.ReadPEMFile(cfg.ServerCAFile); err != nil {
			return t, fmt.Errorf("корневой сертификат сервера: %w", err)
		}
		t.watch = append(t.watch, integrity.WatchFile{Path: cfg.ServerCAFile, Data: t.serverCA})
		for _, path := range cfg.BundlePubFiles {
			data, err := aisecCrypto.ReadPEMFile(path)
			if err != nil {
				return t, fmt.Errorf("ключ проверки пакетов конфигурации: %w", err)
			}
			t.bundlePubs = append(t.bundlePubs, data)
			t.watch = append(t.watch, integrity.WatchFile{Path: path, Data: data})
		}
	}
	path := cfg.UserHMACKeyFile
	if file != nil {
		path = file.Gateway.UserHMACKeyFile
	}
	if path != "" {
		if t.userHMACKey, err = aisecCrypto.ReadKeyFile(path); err != nil {
			return t, fmt.Errorf("ключ псевдонимов пользователей: %w", err)
		}
		t.watch = append(t.watch, integrity.WatchFile{Path: path, Data: t.userHMACKey})
	}
	return t, nil
}

// startIntegrity проверяет целостность шлюза при запуске и запускает
// периодическую проверку: исполняемый файл и файлы watch — конфигурация
// без сервера, корни доверия с сервером (ОЦЛ.3, В19 ревью 2.r4). Своей БД
// у шлюза нет — итоги идут в технический журнал и в heartbeat (2.20).
func startIntegrity(ctx context.Context, cfg *config.Gateway, p aisecCrypto.Provider, logger *slog.Logger, stop context.CancelCauseFunc,
	reports *gateway.Reports, watch []integrity.WatchFile) (verify func(context.Context), err error) {
	exe, exeErr := os.Executable()
	if exeErr != nil {
		exe = "" // проверка отметит исполняемый файл как нечитаемый
	}
	manifest := cfg.Manifest
	if manifest == "" {
		manifest = integrity.DefaultManifestPath(exe)
	}
	// Сверяется образ запущенного процесса, а не файл по пути (Н37).
	running := ""
	if exe != "" {
		running = integrity.RunningExecutable(exe)
	}
	checker, err := integrity.NewChecker(integrity.Config{
		Component: "gateway", Provider: p, ManifestPath: manifest,
		Executable: running, BinaryName: "bin/aisec-gateway", Watch: watch,
	})
	if err != nil {
		return nil, err
	}
	mon, err := integrity.NewMonitor(integrity.MonitorConfig{
		Checker: checker, Action: integrity.Action(cfg.IntegrityAction), Interval: cfg.IntegrityInterval,
		Logger: logger, OnStop: stop,
		// Итог каждой проверки — в heartbeat на сервер (2.20); БД у шлюза нет,
		// откат выпуска определяет сервер по манифесту (В20 ревью 2.r4).
		Record: func(_ context.Context, res integrity.Result, _ audit.Actor, _ netip.Addr) (integrity.Result, error) {
			reports.SetIntegrity(res.OK(), res.At, string(res.Reason), len(res.Failures)+res.Omitted,
				gateway.Manifest{Version: res.ManifestVersion, Created: res.ManifestCreated, TestSigned: res.TestSigned})
			return res, nil
		},
	})
	if err != nil {
		return nil, err
	}
	if _, err := mon.Startup(ctx); err != nil {
		return nil, err
	}
	go mon.Run(ctx)
	// Проверка по запросу из консоли (Н38 ревью 2.r4): реакция та же, что
	// у периодической; итог уходит в heartbeat.
	verify = func(ctx context.Context) {
		if _, err := mon.CheckBy(ctx, audit.Actor{Type: audit.ActorSystem, ID: "gateway", Name: "Запрос из консоли"}, netip.Addr{}); err != nil {
			logger.Error("проверка целостности по запросу не выполнена", "class", "integrity", "error", err)
		}
	}
	return verify, nil
}

// controlClient — связь с внутренним API сервера по mTLS (ИАФ.10):
// клиент, его транспорт и переключатель сертификата для перевыпуска.
type controlClient struct {
	client    *http.Client
	transport *http.Transport
	cert      *aisecCrypto.ClientCertSwitch
	// gatewayID — CN сертификата: пакет конфигурации собирается на этот ID.
	gatewayID string
}

// httpClient — клиент или nil без сервера управления.
func (c *controlClient) httpClient() *http.Client {
	if c == nil {
		return nil
	}
	return c.client
}

// newControlClient — HTTP-клиент к внутреннему API сервера по mTLS:
// сертификат и ключ шлюза — от aisec-gateway register или перевыпущенные в
// client.pem каталога состояния (ADR-0018, п. 6.3), если они новее.
func newControlClient(cfg *config.Gateway, tp aisecCrypto.TLSProvider, rootsPEM []byte, state *gateway.BundleState,
	logger *slog.Logger) (*controlClient, error) {
	certPEM, err := aisecCrypto.ReadPEMFile(cfg.ClientCertFile)
	if err != nil {
		return nil, fmt.Errorf("сертификат шлюза для сервера: %w", err)
	}
	keyPEM, err := aisecCrypto.ReadKeyFile(cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("ключ шлюза для сервера: %w", err)
	}
	id, err := aisecCrypto.ParseCertInfo(certPEM)
	if err != nil {
		return nil, fmt.Errorf("сертификат шлюза для сервера: %w", err)
	}
	if pc, pk, perr := state.LoadClientPair(); perr != nil {
		logger.Warn("перевыпущенный сертификат шлюза не прочитан; используется -client-cert", "file", gateway.ClientPairFile, "error", perr)
	} else if pc != nil {
		next, err := aisecCrypto.ParseCertInfo(pc)
		switch {
		case err != nil || aisecCrypto.VerifyClientCert(pc, pk, id.CommonName, nil, time.Now()) != nil:
			logger.Warn("перевыпущенный сертификат шлюза не подходит; используется -client-cert", "file", gateway.ClientPairFile)
		case next.NotAfter.After(id.NotAfter):
			certPEM, keyPEM, id = pc, pk, next
			logger.Info("используется перевыпущенный сертификат шлюза", "file", gateway.ClientPairFile, "not_after", next.NotAfter.UTC())
		}
	}
	if time.Until(id.NotAfter) < gwReissueWarn {
		logger.Warn("сертификат шлюза скоро истекает: сервер перевыпустит его при heartbeat, иначе нужна повторная регистрация",
			"not_after", id.NotAfter.UTC())
	}
	sw, err := aisecCrypto.NewClientCertSwitch(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("сертификат шлюза для сервера: %w", err)
	}
	transport, err := gateway.ControlTransportSwitch(tp, rootsPEM, sw)
	if err != nil {
		return nil, err
	}
	logger.Info("связь с сервером управления по mTLS: heartbeat, события и пакеты конфигурации", "gateway_id", id.CommonName, "server", cfg.Server.Host)
	return &controlClient{client: &http.Client{Transport: transport}, transport: transport, cert: sw, gatewayID: id.CommonName}, nil
}

// gwReissueWarn — за сколько до истечения сертификата предупреждать.
const gwReissueWarn = 30 * 24 * time.Hour

// startHeartbeat запускает heartbeat на внутренний API сервера. Сервер
// недоступен — шлюз всё равно работает (ТЗ, 4.2).
func startHeartbeat(ctx context.Context, cfg *config.Gateway, client *http.Client, logger *slog.Logger, reports *gateway.Reports, etag func() string,
	verify func(context.Context), started time.Time, reissue func(context.Context) error, budget *gateway.Budget,
	clock *gateway.ServerClock, tlsFingerprint func() string, pendingApprovals func() []string) <-chan struct{} {
	v := version
	if !gateway.ValidVersion(v) {
		v = "unknown"
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		gateway.RunHeartbeat(ctx, gateway.HeartbeatConfig{
			Client: client, Server: cfg.Server, Version: v, Logger: logger, Reports: reports, BundleETag: etag, Verify: verify,
			StartedAt: started, Reissue: reissue, Budget: budget, ServerTime: clock, TLSFingerprint: tlsFingerprint,
			PendingApprovals: pendingApprovals,
		})
	}()
	return done
}

// newUserMAC — имитовставка для псевдонимов пользователей (ТЗ, 5.5). Ключ
// нужен, если хотя бы одно приложение передаёт идентификатор пользователя:
// исходный идентификатор в события не пишется. Без сервера ключ задаёт файл
// конфигурации, с сервером — флаг -user-hmac-key; key — его содержимое,
// прочитанное readTrustFiles. Приложение с user_from без ключа отклоняется
// при сборке обработчика.
func newUserMAC(p aisecCrypto.Provider, key []byte, file *config.GatewayFile) (aisecCrypto.MAC, error) {
	if file != nil && key == nil {
		for _, a := range file.Applications {
			if a.UserFrom != "" && a.UserFrom != "none" {
				return nil, fmt.Errorf("приложение %s: user_from %s требует gateway.user_hmac_key_file", a.ID, a.UserFrom)
			}
		}
	}
	if key == nil {
		return nil, nil
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
