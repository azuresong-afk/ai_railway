package main

import (
	"context"
	"log/slog"
	"os"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// Самопроверка целостности aisec-ml при запуске и периодически (ОЦЛ.2,
// ADR-0024, раздел 8): свой бинарник, библиотеки lib/ (ONNX Runtime и
// системные библиотеки образа) и пакет моделей models/ по манифесту
// выпуска. Остальных файлов выпуска в образе aisec-ml нет — они не
// сверяются. Своей БД и связи с сервером у aisec-ml нет: итог — в
// техническом журнале; при реакции stop нарушение останавливает процесс, и
// шлюз работает на эвристиках с признаком ml_unavailable.

// mlBinary — путь aisec-ml в манифесте выпуска.
const mlBinary = "bin/aisec-ml"

// mlDiskPrefixes — каталоги манифеста, которые сверяет aisec-ml.
var mlDiskPrefixes = []string{"lib/", "models/"}

// startIntegrity проверяет целостность до загрузки библиотеки и моделей и
// запускает периодическую проверку до отмены ctx. Нарушение при запуске с
// реакцией stop — ошибка; после запуска — вызов stop.
func startIntegrity(ctx context.Context, cfg *config, p aisecCrypto.Provider, logger *slog.Logger, stop func(error)) error {
	exe, err := os.Executable()
	if err != nil {
		exe = "" // проверка отметит исполняемый файл как нечитаемый
	}
	manifest := cfg.Manifest
	if manifest == "" {
		manifest = integrity.DefaultManifestPath(exe)
	}
	running := ""
	if exe != "" {
		running = integrity.RunningExecutable(exe)
	}
	checker, err := integrity.NewChecker(integrity.Config{
		Component: "ml", Provider: p, ManifestPath: manifest,
		Executable: running, BinaryName: mlBinary, DiskPrefixes: mlDiskPrefixes,
	})
	if err != nil {
		return err
	}
	mon, err := integrity.NewMonitor(integrity.MonitorConfig{
		Checker: checker, Action: cfg.IntegrityAction, Interval: cfg.IntegrityInterval, Logger: logger, OnStop: stop,
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
