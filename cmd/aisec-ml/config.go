package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// Умолчания aisec-ml (ADR-0024).
const (
	DefaultSocket = "/run/aisec-ml/aisec-ml.sock"
	DefaultModels = "/opt/aisec/models"
	// DefaultORTLib — библиотека ONNX Runtime в образе aisec-ml (ADR-0024, раздел 8).
	DefaultORTLib = "/opt/aisec/lib/libonnxruntime.so.1.31.0"
	maxSocketPath = 100 // предел sun_path (108 байт) с запасом
	maxWorkers    = 256
	maxConnsLimit = 1024
)

// config — параметры запуска aisec-ml.
type config struct {
	Socket    string
	Models    string
	MaxConns  int
	Workers   int
	QueueWait time.Duration
	// RunTimeout — срок вывода, если шлюз не передал свой; MaxRunTimeout —
	// предел срока, который назначает шлюз (4В30).
	RunTimeout    time.Duration
	MaxRunTimeout time.Duration
	MaxModelBytes int64
	ORTLib        string
	// Manifest — манифест целостности выпуска; пусто — над каталогом bin/
	// бинарника (integrity.DefaultManifestPath).
	Manifest          string
	IntegrityAction   integrity.Action
	IntegrityInterval time.Duration
}

func envName(flagName string) string {
	return "AISEC_ML_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// loadConfig разбирает флаги; у каждого флага есть переменная окружения
// AISEC_ML_<ИМЯ>, флаг важнее. Справка не печатает значения окружения.
func loadConfig(args []string, getenv func(string) string, errOut io.Writer) (*config, error) {
	fs := flag.NewFlagSet("aisec-ml", flag.ContinueOnError)
	fs.SetOutput(errOut)
	socket := fs.String("socket", DefaultSocket, "Unix-сокет для шлюза; каталог — без прав для остальных (AISEC_ML_SOCKET)")
	models := fs.String("models", DefaultModels, "каталог подписанного пакета моделей (AISEC_ML_MODELS)")
	maxConns := fs.String("max-conns", strconv.Itoa(ml.DefaultMaxConns), "предел соединений (AISEC_ML_MAX_CONNS)")
	workers := fs.String("workers", "0", "предел одновременных выводов; 0 — число процессоров (AISEC_ML_WORKERS)")
	queueWait := fs.String("queue-wait", ml.DefaultQueueWait.String(), "ожидание свободного исполнителя, затем overloaded (AISEC_ML_QUEUE_WAIT)")
	runTimeout := fs.String("run-timeout", ml.DefaultRunTimeout.String(), "срок вывода, если шлюз не передал свой (AISEC_ML_RUN_TIMEOUT)")
	maxRunTimeout := fs.String("max-run-timeout", ml.DefaultMaxRunTimeout.String(), "предел срока вывода, назначенного шлюзом по длине текста (AISEC_ML_MAX_RUN_TIMEOUT)")
	ortLib := fs.String("ort-lib", DefaultORTLib, "библиотека ONNX Runtime; хеш сверяется со встроенным при сборке (AISEC_ML_ORT_LIB)")
	maxModel := fs.String("max-model-bytes", strconv.Itoa(ml.DefaultMaxModelBytes), "предел суммарного размера моделей в памяти, байт (AISEC_ML_MAX_MODEL_BYTES)")
	manifest := fs.String("manifest", "", "манифест целостности; по умолчанию ../aisec-manifest.json от каталога бинарника (AISEC_ML_MANIFEST)")
	// stop по умолчанию: остановка aisec-ml не останавливает трафик — шлюз
	// работает на эвристиках с признаком ml_unavailable (ADR-0024, раздел 4).
	action := fs.String("integrity-action", string(integrity.ActionStop), "реакция на нарушение целостности: alert или stop (AISEC_ML_INTEGRITY_ACTION)")
	interval := fs.String("integrity-interval", integrity.DefaultInterval.String(), "период проверки целостности, не меньше 1m (AISEC_ML_INTEGRITY_INTERVAL)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, dst := range map[string]*string{
		"socket": socket, "models": models, "max-conns": maxConns, "workers": workers,
		"queue-wait": queueWait, "run-timeout": runTimeout, "max-run-timeout": maxRunTimeout, "max-model-bytes": maxModel, "ort-lib": ortLib,
		"manifest": manifest, "integrity-action": action, "integrity-interval": interval,
	} {
		if !set[name] {
			if v := getenv(envName(name)); v != "" {
				*dst = v
			}
		}
	}
	cfg := &config{Socket: *socket, Models: *models, ORTLib: *ortLib, Manifest: *manifest}
	var errs []error
	if cfg.Manifest != "" && !filepath.IsAbs(cfg.Manifest) {
		errs = append(errs, errors.New("manifest: абсолютный путь"))
	}
	if a, err := integrity.ParseAction(*action); err != nil {
		errs = append(errs, fmt.Errorf("integrity-action: %w", err))
	} else {
		cfg.IntegrityAction = a
	}
	if !filepath.IsAbs(cfg.Socket) || filepath.Clean(cfg.Socket) != cfg.Socket || len(cfg.Socket) > maxSocketPath {
		errs = append(errs, fmt.Errorf("socket: абсолютный путь без «..» не длиннее %d байт", maxSocketPath))
	}
	if !filepath.IsAbs(cfg.Models) {
		errs = append(errs, errors.New("models: абсолютный путь"))
	}
	if !filepath.IsAbs(cfg.ORTLib) || filepath.Clean(cfg.ORTLib) != cfg.ORTLib {
		errs = append(errs, errors.New("ort-lib: абсолютный путь без «..»"))
	}
	var err error
	if cfg.MaxConns, err = strconv.Atoi(*maxConns); err != nil || cfg.MaxConns < 1 || cfg.MaxConns > maxConnsLimit {
		errs = append(errs, fmt.Errorf("max-conns: число от 1 до %d", maxConnsLimit))
	}
	if cfg.Workers, err = strconv.Atoi(*workers); err != nil || cfg.Workers < 0 || cfg.Workers > maxWorkers {
		errs = append(errs, fmt.Errorf("workers: число от 0 до %d", maxWorkers))
	}
	if cfg.QueueWait, err = time.ParseDuration(*queueWait); err != nil || cfg.QueueWait < time.Millisecond || cfg.QueueWait > time.Second {
		errs = append(errs, errors.New("queue-wait: длительность от 1ms до 1s"))
	}
	if cfg.RunTimeout, err = time.ParseDuration(*runTimeout); err != nil || cfg.RunTimeout < 10*time.Millisecond || cfg.RunTimeout > 10*time.Second {
		errs = append(errs, errors.New("run-timeout: длительность от 10ms до 10s"))
	}
	if cfg.MaxRunTimeout, err = time.ParseDuration(*maxRunTimeout); err != nil || cfg.MaxRunTimeout < cfg.RunTimeout || cfg.MaxRunTimeout > 10*time.Second {
		errs = append(errs, errors.New("max-run-timeout: длительность не меньше run-timeout и не больше 10s"))
	}
	if cfg.IntegrityInterval, err = time.ParseDuration(*interval); err != nil || cfg.IntegrityInterval < integrity.MinInterval {
		errs = append(errs, fmt.Errorf("integrity-interval: длительность не меньше %s", integrity.MinInterval))
	}
	if cfg.MaxModelBytes, err = strconv.ParseInt(*maxModel, 10, 64); err != nil || cfg.MaxModelBytes < 1<<20 || cfg.MaxModelBytes > 16<<30 {
		errs = append(errs, errors.New("max-model-bytes: число от 1 МиБ до 16 ГиБ"))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}
