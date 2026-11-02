package main

import (
	"context"
	"log/slog"
	"os"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// Самопроверка целостности aisec-media при запуске и периодически (ОЦЛ.2,
// ADR-0032, раздел 1): свой бинарник по манифесту выпуска. Других файлов
// выпуска в образе aisec-media пока нет; модели OCR (ADR-0033) добавят
// каталоги в mediaDiskPrefixes. Своей БД и связи с сервером нет: итог — в
// техническом журнале; при реакции stop нарушение останавливает процесс, и
// шлюз ставит отметку «не проверено».

// mediaBinary — путь aisec-media в манифесте выпуска.
const mediaBinary = "bin/aisec-media"

// mediaDiskPrefixes — каталоги манифеста, которые сверяет aisec-media.
var mediaDiskPrefixes []string

// startIntegrity проверяет целостность до приёма изображений и запускает
// периодическую проверку до отмены ctx. Нарушение при запуске с реакцией
// stop — ошибка; после запуска — вызов stop.
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
		Component: "media", Provider: p, ManifestPath: manifest,
		Executable: running, BinaryName: mediaBinary, DiskPrefixes: mediaDiskPrefixes,
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
