// Команда aisec-ml — изолированный процесс ML-детекторов рядом со шлюзом
// (ADR-0024): проверяет подписанный пакет моделей, загружает модели в
// исполнитель и отвечает шлюзу по Unix-сокету протоколом internal/ml.
// ONNX Runtime подключается только здесь и только со сборочным тегом
// aisec_onnx; шлюз и сервер остаются без cgo.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall" //nolint:depguard // ADR-0004: только syscall.SIGTERM для корректного завершения; прочее syscall.* запрещает forbidigo

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/ml"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "aisec-ml", "version", version)
	cfg, err := loadConfig(os.Args[1:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		logger.Error("неверная конфигурация", "error", err)
		os.Exit(2)
	}
	// Телеметрия ONNX Runtime выключается до его инициализации при любой
	// сборке библиотеки (ADR-0024, раздел 1); основная защита — сборка без неё.
	if err := os.Setenv("ORT_DISABLE_TELEMETRY", "1"); err != nil {
		logger.Error("окружение", "error", err)
		os.Exit(1)
	}
	// От root aisec-ml не запускается: в compose пилота пользователь
	// aisec-ml появляется после prepare-host.sh (ADR-0024, раздел 9).
	if os.Getuid() == 0 {
		logger.Error("aisec-ml не запускается от root: запустите prepare-host.sh — он создаст пользователя aisec-ml и запишет AISEC_ML_UID в .env")
		os.Exit(2)
	}
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancelCause(sigCtx)
	defer cancel(nil)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		logger.Error("криптопрофиль", "error", err)
		os.Exit(1)
	}
	// Целостность бинарника, библиотек и моделей — до загрузки ONNX Runtime
	// и моделей (ОЦЛ.2).
	if err := startIntegrity(ctx, cfg, p, logger, cancel); err != nil {
		logger.Error("контроль целостности", "error", err)
		os.Exit(1)
	}
	v, testKey, err := integrity.EmbeddedVerifier(p)
	if err != nil {
		logger.Error("ключ производителя", "error", err)
		os.Exit(1)
	}
	if testKey {
		logger.Warn("сборка с тестовым ключом: пакет моделей проверяется тестовым ключом репозитория, не для поставки")
	}
	err = run(ctx, cfg, deps{provider: p, verifier: v, newExecutor: newExecutor, logger: logger})
	if cause := context.Cause(ctx); errors.Is(cause, integrity.ErrViolation) {
		err = errors.Join(err, cause)
	}
	if err != nil {
		logger.Error("остановка с ошибкой", "error", err)
		os.Exit(1)
	}
}

// deps — то, что тесты подменяют: ключ проверки пакета и исполнитель.
type deps struct {
	provider    aisecCrypto.Provider
	verifier    aisecCrypto.Verifier
	newExecutor func(*config, aisecCrypto.Provider) (ml.Executor, error)
	logger      *slog.Logger
	// ready вызывается, когда сокет готов (для тестов).
	ready func()
}

// run проверяет пакет моделей до загрузки, загружает модели из проверенных
// байтов и обслуживает сокет до отмены ctx. Любое несовпадение пакета —
// ошибка запуска без частичной загрузки.
func run(ctx context.Context, cfg *config, d deps) error {
	loaded, m, err := ml.LoadModels(cfg.Models, ml.LoadOptions{Provider: d.provider, Verifier: d.verifier, MaxTotal: cfg.MaxModelBytes})
	if err != nil {
		return fmt.Errorf("пакет моделей отвергнут: %w", err)
	}
	exec, err := d.newExecutor(cfg, d.provider)
	if err != nil {
		return err
	}
	models := make([]ml.Model, 0, len(loaded))
	defer func() {
		for _, mdl := range models {
			_ = mdl.Close() //nolint:gosec // G104: остановка процесса
		}
	}()
	for _, lm := range loaded {
		mdl, err := exec.Load(lm)
		if err != nil {
			return fmt.Errorf("модель %s: %w", lm.Spec.ID, err)
		}
		models = append(models, mdl)
	}
	srv, err := ml.NewServer(ml.ServerConfig{Models: models, MaxConns: cfg.MaxConns, Workers: cfg.Workers, QueueWait: cfg.QueueWait, Logger: d.logger})
	if err != nil {
		return err
	}
	l, err := listenSocket(ctx, cfg.Socket)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(models))
	for _, mdl := range models {
		ids = append(ids, mdl.Info().ID+"@"+mdl.Info().Version)
	}
	d.logger.Info("aisec-ml готов", "socket", cfg.Socket, "package", m.Version, "models", ids)
	if d.ready != nil {
		d.ready()
	}
	return srv.Serve(ctx, l)
}
