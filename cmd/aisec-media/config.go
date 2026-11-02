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
	"github.com/azuresong-afk/ai_railway/internal/media"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Умолчания aisec-media (ADR-0032).
const (
	DefaultSocket     = "/run/aisec-media/aisec-media.sock"
	maxSocketPath     = 100 // предел sun_path (108 байт) с запасом
	maxWorkers        = 64
	maxQueue          = 1024
	maxConnsLimit     = 256
	maxCacheEntries   = 1 << 20
	maxRunTimeoutHard = time.Minute // срок в кадре — до 65 с (uint16, мс)
)

// config — параметры запуска aisec-media.
type config struct {
	Socket       string
	Limits       media.Limits
	MaxConns     int
	Workers      int
	Queue        int
	CacheEntries int
	// RunTimeout — срок анализа, если шлюз не передал свой; MaxRunTimeout —
	// предел срока, который назначает шлюз.
	RunTimeout    time.Duration
	MaxRunTimeout time.Duration
	// Manifest — манифест целостности выпуска; пусто — над каталогом bin/
	// бинарника (integrity.DefaultManifestPath).
	Manifest          string
	IntegrityAction   integrity.Action
	IntegrityInterval time.Duration
	// PeerUID и PeerGID — UID и GID шлюза: соединение принимается, только
	// если SO_PEERCRED собеседника совпадает с обоими (ADR-0032, раздел 2).
	PeerUID, PeerGID uint32
}

func envName(flagName string) string {
	return "AISEC_MEDIA_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// loadConfig разбирает флаги; у каждого флага есть переменная окружения
// AISEC_MEDIA_<ИМЯ>, флаг важнее. Справка не печатает значения окружения.
func loadConfig(args []string, getenv func(string) string, errOut io.Writer) (*config, error) {
	fs := flag.NewFlagSet("aisec-media", flag.ContinueOnError)
	fs.SetOutput(errOut)
	socket := fs.String("socket", DefaultSocket, "Unix-сокет для шлюза; каталог — без прав для остальных (AISEC_MEDIA_SOCKET)")
	maxBytes := fs.String("max-bytes", strconv.Itoa(media.DefaultMaxBytes), "предел размера изображения, байт; больше — отказ без чтения (AISEC_MEDIA_MAX_BYTES)")
	maxPixels := fs.String("max-pixels", strconv.Itoa(media.DefaultMaxPixels), "предел пикселей по заголовку до декодирования; у GIF — сумма кадров (AISEC_MEDIA_MAX_PIXELS)")
	maxConns := fs.String("max-conns", strconv.Itoa(media.DefaultMaxConns), "предел соединений (AISEC_MEDIA_MAX_CONNS)")
	workers := fs.String("workers", strconv.Itoa(media.DefaultWorkers), "одновременных анализов; память — до 250 МиБ на исполнитель (AISEC_MEDIA_WORKERS)")
	queue := fs.String("queue", strconv.Itoa(media.DefaultQueue), "запросов в очереди сверх workers, дальше — overloaded (AISEC_MEDIA_QUEUE)")
	cache := fs.String("cache-entries", strconv.Itoa(media.DefaultCacheEntries), "предел записей кэша итогов; 0 — кэш выключен (AISEC_MEDIA_CACHE_ENTRIES)")
	runTimeout := fs.String("run-timeout", media.DefaultRunTimeout.String(), "срок анализа, если шлюз не передал свой (AISEC_MEDIA_RUN_TIMEOUT)")
	maxRunTimeout := fs.String("max-run-timeout", media.DefaultMaxRunTimeout.String(), "предел срока анализа, назначенного шлюзом (AISEC_MEDIA_MAX_RUN_TIMEOUT)")
	manifest := fs.String("manifest", "", "манифест целостности; по умолчанию ../aisec-manifest.json от каталога бинарника (AISEC_MEDIA_MANIFEST)")
	// stop по умолчанию: остановка aisec-media не останавливает трафик —
	// шлюз ставит отметку «не проверено» (ADR-0032, раздел 8).
	action := fs.String("integrity-action", string(integrity.ActionStop), "реакция на нарушение целостности: alert или stop (AISEC_MEDIA_INTEGRITY_ACTION)")
	interval := fs.String("integrity-interval", integrity.DefaultInterval.String(), "период проверки целостности, не меньше 1m (AISEC_MEDIA_INTEGRITY_INTERVAL)")
	peerUID := fs.String("peer-uid", "", "UID шлюза, обязателен: соединения других пользователей закрываются (AISEC_MEDIA_PEER_UID)")
	peerGID := fs.String("peer-gid", "", "GID шлюза, обязателен: соединения других групп закрываются (AISEC_MEDIA_PEER_GID)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, dst := range map[string]*string{
		"socket": socket, "max-bytes": maxBytes, "max-pixels": maxPixels, "max-conns": maxConns, "workers": workers,
		"queue": queue, "cache-entries": cache, "run-timeout": runTimeout, "max-run-timeout": maxRunTimeout,
		"manifest": manifest, "integrity-action": action, "integrity-interval": interval,
		"peer-uid": peerUID, "peer-gid": peerGID,
	} {
		if !set[name] {
			if v := getenv(envName(name)); v != "" {
				*dst = v
			}
		}
	}
	cfg := &config{Socket: *socket, Manifest: *manifest}
	var errs []error
	if !filepath.IsAbs(cfg.Socket) || filepath.Clean(cfg.Socket) != cfg.Socket || len(cfg.Socket) > maxSocketPath {
		errs = append(errs, fmt.Errorf("socket: абсолютный путь без «..» не длиннее %d байт", maxSocketPath))
	}
	if cfg.Manifest != "" && !filepath.IsAbs(cfg.Manifest) {
		errs = append(errs, errors.New("manifest: абсолютный путь"))
	}
	if a, err := integrity.ParseAction(*action); err != nil {
		errs = append(errs, fmt.Errorf("integrity-action: %w", err))
	} else {
		cfg.IntegrityAction = a
	}
	var err error
	if cfg.Limits.MaxBytes, err = strconv.ParseInt(*maxBytes, 10, 64); err != nil || cfg.Limits.MaxBytes < media.MinMaxBytes || cfg.Limits.MaxBytes > wire.MaxContent {
		errs = append(errs, fmt.Errorf("max-bytes: число от %d до %d", media.MinMaxBytes, wire.MaxContent))
	}
	if cfg.Limits.MaxPixels, err = strconv.ParseInt(*maxPixels, 10, 64); err != nil || cfg.Limits.MaxPixels < 1 || cfg.Limits.MaxPixels > wire.MaxPixelsLimit {
		errs = append(errs, fmt.Errorf("max-pixels: число от 1 до %d", wire.MaxPixelsLimit))
	}
	if cfg.MaxConns, err = strconv.Atoi(*maxConns); err != nil || cfg.MaxConns < 1 || cfg.MaxConns > maxConnsLimit {
		errs = append(errs, fmt.Errorf("max-conns: число от 1 до %d", maxConnsLimit))
	}
	if cfg.Workers, err = strconv.Atoi(*workers); err != nil || cfg.Workers < 1 || cfg.Workers > maxWorkers {
		errs = append(errs, fmt.Errorf("workers: число от 1 до %d", maxWorkers))
	}
	if cfg.Queue, err = strconv.Atoi(*queue); err != nil || cfg.Queue < 0 || cfg.Queue > maxQueue {
		errs = append(errs, fmt.Errorf("queue: число от 0 до %d", maxQueue))
	}
	if cfg.CacheEntries, err = strconv.Atoi(*cache); err != nil || cfg.CacheEntries < 0 || cfg.CacheEntries > maxCacheEntries {
		errs = append(errs, fmt.Errorf("cache-entries: число от 0 до %d", maxCacheEntries))
	} else if cfg.CacheEntries == 0 {
		cfg.CacheEntries = -1 // выключен (media.ServerConfig)
	}
	if cfg.RunTimeout, err = time.ParseDuration(*runTimeout); err != nil || cfg.RunTimeout < 100*time.Millisecond || cfg.RunTimeout > maxRunTimeoutHard {
		errs = append(errs, errors.New("run-timeout: длительность от 100ms до 1m"))
	}
	if cfg.MaxRunTimeout, err = time.ParseDuration(*maxRunTimeout); err != nil || cfg.MaxRunTimeout < cfg.RunTimeout || cfg.MaxRunTimeout > maxRunTimeoutHard {
		errs = append(errs, errors.New("max-run-timeout: длительность не меньше run-timeout и не больше 1m"))
	}
	if cfg.IntegrityInterval, err = time.ParseDuration(*interval); err != nil || cfg.IntegrityInterval < integrity.MinInterval {
		errs = append(errs, fmt.Errorf("integrity-interval: длительность не меньше %s", integrity.MinInterval))
	}
	if cfg.PeerUID, err = parseID(*peerUID); err != nil {
		errs = append(errs, fmt.Errorf("peer-uid: %w (UID шлюза)", err))
	}
	if cfg.PeerGID, err = parseID(*peerGID); err != nil {
		errs = append(errs, fmt.Errorf("peer-gid: %w (GID шлюза)", err))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

// parseID разбирает UID или GID шлюза: обязателен, от 1 (шлюз не работает
// от root) до 2^31-1.
func parseID(v string) (uint32, error) {
	if v == "" {
		return 0, errors.New("обязателен")
	}
	n, err := strconv.ParseUint(v, 10, 31)
	if err != nil || n == 0 {
		return 0, errors.New("число от 1 до 2147483647")
	}
	return uint32(n), nil
}
