// Команда aisec-server — сервер управления: API, веб-консоль, оповещения, инциденты, отчёты, аудит.
// Сейчас (задачи 2.6–2.8, 2.17 этапа 2): HTTPS, маршрутизатор с проверкой прав,
// Problem Details, ограничение частоты, вход в консоль, второй фактор,
// учётные записи и контроль целостности. Статика веб-консоли встроена в
// бинарник (web/embed.go, ADR-0011) и сверяется с манифестом; раздача — в
// задачах каркаса консоли;
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

	"github.com/azuresong-afk/ai_railway/internal/api"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/store"
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
	authSvc, err := auth.NewService(ctx, users, auditLog, p, auth.WithSecretBox(box))
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

	handler, _, err := api.New(api.Options{
		Logger: logger, Version: version, Hasher: hasher,
		Ready:     db.Ping,
		Auth:      authSvc,
		Integrity: integritySvc,
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
	logger.Info("сервер управления запущен")
	err = srv.Run(ctx)
	if cause := context.Cause(ctx); errors.Is(cause, integrity.ErrViolation) {
		return errors.Join(err, cause)
	}
	return err
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
