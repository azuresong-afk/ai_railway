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
	Socket        string
	Models        string
	MaxConns      int
	Workers       int
	QueueWait     time.Duration
	MaxModelBytes int64
	ORTLib        string
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
	ortLib := fs.String("ort-lib", DefaultORTLib, "библиотека ONNX Runtime; хеш сверяется со встроенным при сборке (AISEC_ML_ORT_LIB)")
	maxModel := fs.String("max-model-bytes", strconv.Itoa(ml.DefaultMaxModelBytes), "предел суммарного размера моделей в памяти, байт (AISEC_ML_MAX_MODEL_BYTES)")
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
		"queue-wait": queueWait, "max-model-bytes": maxModel, "ort-lib": ortLib,
	} {
		if !set[name] {
			if v := getenv(envName(name)); v != "" {
				*dst = v
			}
		}
	}
	cfg := &config{Socket: *socket, Models: *models, ORTLib: *ortLib}
	var errs []error
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
	if cfg.MaxModelBytes, err = strconv.ParseInt(*maxModel, 10, 64); err != nil || cfg.MaxModelBytes < 1<<20 || cfg.MaxModelBytes > 16<<30 {
		errs = append(errs, errors.New("max-model-bytes: число от 1 МиБ до 16 ГиБ"))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}
