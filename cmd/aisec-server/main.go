// Команда aisec-server — сервер управления: API, веб-консоль, оповещения, инциденты, отчёты, аудит.
// Сейчас (задачи 2.6–2.10, 2.14, 2.15, 2.17 этапа 2): HTTPS, маршрутизатор с
// проверкой прав, Problem Details, ограничение частоты, вход в консоль,
// второй фактор, учётные записи и роли, токены API, регистрация шлюзов и внутренний API на
// отдельном порту с mTLS, приём событий шлюзов, контроль целостности.
// Статика веб-консоли встроена в бинарник (web/embed.go, ADR-0011) и
// сверяется с манифестом; раздача — в задачах каркаса консоли;
// остальные ресурсы API добавляются следующими задачами.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/api"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/integrity/selftest"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
	"github.com/azuresong-afk/ai_railway/web"
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
	// Самотест криптопрофиля до приёма запросов (ТЗ, ОЦЛ.4). Детекторов у
	// сервера нет; провал криптопрофиля останавливает запуск всегда (ОЦЛ.5).
	selftestRes, err := selftest.Startup(ctx, selftest.StartupConfig{
		Config: selftest.Config{Component: "server", Provider: p}, Action: integrity.ActionStop, Logger: logger,
	})
	if err != nil {
		return err
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

	// Контрольные точки архивации (ADR-0008): без них после архивации
	// начало хранимой цепочки не подтверждается. С открытым ключом аудита
	// проверяются и подписи точек, без него — только связность.
	var auditVerifier aisecCrypto.Verifier
	if cfg.AuditSigningPub != "" {
		if auditVerifier, err = aisecCrypto.LoadVerifierFile(p, cfg.AuditSigningPub, aisecCrypto.KeyKindAuditSigningPublic); err != nil {
			return fmt.Errorf("ключ проверки аудита: %w", err)
		}
	}
	checkpoints, err := audit.NewPGCheckpoints(db.Pool(), p, auditVerifier)
	if err != nil {
		return err
	}
	auditLog, err := audit.New(db.Pool(), p, audit.WithCheckpoints(checkpoints))
	if err != nil {
		return err
	}
	// Итог самотеста — в журнал аудита (selftest.result); до открытия БД
	// он есть только в техническом журнале.
	if err := selftest.RecordAudit(ctx, auditLog, selftestRes); err != nil {
		logger.Error("итог самотестирования не сохранён в журнал аудита", "class", "db", "error", err)
	}
	users, err := auth.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	// Ключ данных обязателен: без него не расшифровать секреты TOTP, а
	// роли с обязательным вторым фактором не смогли бы войти (ИАФ.5).
	box, err := keyring.Load(ctx, db.Pool(), p, cfg.KeysDir, audit.DefaultOrgID)
	if err != nil {
		return err
	}
	roles, err := auth.NewPGRoles(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	tokens, err := auth.NewPGAPITokens(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	authSvc, err := auth.NewService(ctx, users, auditLog, p, auth.WithSecretBox(box), auth.WithRoleStore(roles),
		auth.WithAPITokenStore(tokens))
	if err != nil {
		return err
	}
	// Контроль целостности при запуске, раз в Interval и по команде (ОЦЛ.2).
	// Нарушение с реакцией stop после запуска останавливает сервер штатно:
	// контекст отменяется с причиной integrity.ErrViolation.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	integritySvc, err := startIntegrity(ctx, cfg, p, db, auditLog, logger, cancel)
	if err != nil {
		return err
	}

	// Реестр шлюзов и внутренний УЦ (ИАФ.10, Р8): без -ca-cert
	// регистрация отвечает 503, а внутренний порт не открывается.
	var gateways *gwregistry.Service
	var ca *aisecCrypto.CA
	if cfg.CACert != "" {
		if ca, err = loadCA(cfg.CACert, cfg.CAKey); err != nil {
			return err
		}
		gwStore, err := gwregistry.NewPGStore(db.Pool(), auditLog)
		if err != nil {
			return err
		}
		if gateways, err = gwregistry.New(gwregistry.Options{
			Store: gwStore, Provider: p, CA: ca, Audit: auditLog, Logger: logger,
		}); err != nil {
			return err
		}
	} else {
		logger.Warn("внутренний УЦ не задан (-ca-cert, -ca-key): регистрация шлюзов и внутренний API выключены")
	}

	// События шлюзов (ТЗ 5.5, задача 2.15): секции создаются до приёма,
	// дальше фоновое задание раз в час держит их на неделю вперёд и удаляет
	// просроченные.
	rnd, err := p.Random()
	if err != nil {
		return err
	}
	eventStore, err := events.NewPGStore(db.Pool(), box, auditLog, audit.DefaultOrgID, events.WithRandom(rnd))
	if err != nil {
		return err
	}
	if err := events.Maintain(ctx, eventStore, logger); err != nil {
		return fmt.Errorf("секции событий: %w", err)
	}
	go events.RunMaintenance(ctx, eventStore, events.MaintainEvery, logger)
	// Агрегаты для дашбордов (задача 2.16) — фоновым заданием раз в минуту.
	go events.RunAggregates(ctx, eventStore, events.AggregateEvery, logger)

	// «Состояние системы» (задача 2.20): шлюзы читаются из реестра и без
	// внутреннего УЦ; уведомления ВРМ.1, РСБ.5, ОЦЛ.5 пишутся в аудит при
	// смене состояния, раз в минуту.
	statusSvc, err := newStatus(ctx, cfg, db, auditLog, integritySvc, selftestRes, logger)
	if err != nil {
		return err
	}

	// Приложения, ключи и провайдеры (ТЗ 5.4, задача 2.11): учётные данные
	// провайдеров — под ключом данных (ЗИ.1); владелец приложения —
	// действующая учётная запись консоли.
	appStore, err := apps.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	appsSvc, err := apps.New(apps.Options{Store: appStore, Provider: p, Box: box,
		OwnerCheck: func(ctx context.Context, id string) error {
			u, err := authSvc.User(ctx, id)
			if err != nil {
				return err
			}
			if u.Status != auth.StatusActive {
				return errors.New("учётная запись не активна")
			}
			return nil
		}})
	if err != nil {
		return err
	}

	handler, _, err := api.New(api.Options{
		Logger: logger, Version: version, Hasher: hasher,
		Apps:      appsSvc,
		Ready:     db.Ping,
		Auth:      authSvc,
		Gateways:  gateways,
		Integrity: integritySvc,
		Status:    statusSvc,
		Events:    eventStore,
		Audit:     auditLog,
		Fallback:  staticFallback(),
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
	servers := []*httpserver.Server{srv}
	if gateways != nil {
		internal, err := newInternalServer(ctx, cfg, tp, hasher, gateways, eventStore, ca, certPEM, keyPEM, logger)
		if err != nil {
			return err
		}
		servers = append(servers, internal)
	}
	logger.Info("сервер управления запущен")
	err = runAll(ctx, servers...)
	if cause := context.Cause(ctx); errors.Is(cause, integrity.ErrViolation) {
		return errors.Join(err, cause)
	}
	return err
}

// newStatus собирает «Состояние системы» и запускает фоновую проверку
// условий уведомлений раздела 7.
func newStatus(ctx context.Context, cfg *serverConfig, db *store.DB, auditLog *audit.Log, integritySvc integrity.Service,
	selftestRes selftest.Result, logger *slog.Logger) (*sysstatus.Service, error) {
	gwStore, err := gwregistry.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return nil, err
	}
	pg, err := sysstatus.NewPGStore(db.Pool(), auditLog, audit.DefaultOrgID)
	if err != nil {
		return nil, err
	}
	failed := len(selftestRes.Failures)
	if !selftestRes.CryptoOK {
		failed++
	}
	svc, err := sysstatus.New(sysstatus.Options{
		Version: version, StartedAt: time.Now(),
		Selftest:  &sysstatus.SelftestSummary{OK: selftestRes.OK(), At: selftestRes.At, Failed: failed},
		Gateways:  sysstatus.GatewayLister{Store: gwStore},
		Integrity: integritySvc.Store, Store: pg,
		Timezone: cfg.Timezone, StorageLimit: cfg.AuditStorageLimit, WarnPercent: cfg.AuditStorageWarnPercent,
		Logger: logger,
	})
	if err != nil {
		return nil, err
	}
	go svc.Run(ctx, sysstatus.DefaultEvalInterval)
	return svc, nil
}

// startIntegrity проверяет целостность сервера при запуске и запускает
// периодическую проверку. Сверяются исполняемый файл и встроенная статика
// веб-консоли.
func startIntegrity(ctx context.Context, cfg *serverConfig, p aisecCrypto.Provider, db *store.DB, auditLog *audit.Log,
	logger *slog.Logger, stop context.CancelCauseFunc) (integrity.Service, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = "" // проверка отметит исполняемый файл как нечитаемый
	}
	manifest := cfg.Manifest
	if manifest == "" {
		manifest = integrity.DefaultManifestPath(exe)
	}
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		return integrity.Service{}, err
	}
	checker, err := integrity.NewChecker(integrity.Config{
		Component: "server", Provider: p, ManifestPath: manifest,
		Executable: exe, BinaryName: "bin/aisec-server",
		Embedded: map[string]fs.FS{"web/dist": dist},
	})
	if err != nil {
		return integrity.Service{}, err
	}
	pg, err := integrity.NewPGStore(db.Pool(), auditLog, p)
	if err != nil {
		return integrity.Service{}, err
	}
	mon, err := integrity.NewMonitor(integrity.MonitorConfig{
		Checker: checker, Action: cfg.IntegrityAction, Interval: cfg.IntegrityInterval, Logger: logger,
		Record: pg.Record, OnStop: stop,
	})
	if err != nil {
		return integrity.Service{}, err
	}
	if _, err := mon.Startup(ctx); err != nil {
		return integrity.Service{}, err
	}
	go mon.Run(ctx)
	return integrity.Service{Monitor: mon, Store: pg}, nil
}

// loadCA читает внутренний УЦ: сертификат и ключ (права 0400 или 0600).
func loadCA(certFile, keyFile string) (*aisecCrypto.CA, error) {
	certPEM, err := aisecCrypto.ReadPEMFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("сертификат УЦ: %w", err)
	}
	keyPEM, err := aisecCrypto.ReadKeyFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("ключ УЦ: %w", err)
	}
	ca, err := aisecCrypto.LoadCA(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("внутренний УЦ: %w", err)
	}
	return ca, nil
}

// newInternalServer — внутренний API шлюзов на отдельном порту: TLS с
// обязательным клиентским сертификатом внутреннего УЦ (mTLS, ИАФ.10).
func newInternalServer(ctx context.Context, cfg *serverConfig, tp aisecCrypto.TLSProvider, hasher aisecCrypto.Hasher,
	gateways *gwregistry.Service, eventStore events.Store, ca *aisecCrypto.CA, certPEM, keyPEM []byte,
	logger *slog.Logger) (*httpserver.Server, error) {
	if cfg.InternalTLSCertFile != "" {
		var err error
		if certPEM, err = aisecCrypto.ReadPEMFile(cfg.InternalTLSCertFile); err != nil {
			return nil, fmt.Errorf("сертификат внутреннего порта: %w", err)
		}
		if keyPEM, err = aisecCrypto.ReadKeyFile(cfg.InternalTLSKeyFile); err != nil {
			return nil, fmt.Errorf("ключ внутреннего порта: %w", err)
		}
	}
	ilog := logger.With("listener", "internal")
	handler, _, err := api.NewInternal(api.InternalOptions{Logger: ilog, Hasher: hasher, Gateways: gateways, Events: eventStore})
	if err != nil {
		return nil, err
	}
	return httpserver.New(ctx, httpserver.Config{
		Addr: cfg.InternalListen, Handler: handler, TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM,
		ClientCAPEM: ca.CertPEM(), Logger: ilog,
	})
}

// runAll обслуживает все порты; ошибка одного останавливает остальные.
func runAll(ctx context.Context, servers ...*httpserver.Server) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(servers))
	for _, s := range servers {
		go func() { errs <- s.Run(ctx) }()
	}
	var all []error
	for range servers {
		if err := <-errs; err != nil {
			all = append(all, err)
			cancel()
		}
	}
	return errors.Join(all...)
}
