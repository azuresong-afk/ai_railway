package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/media"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// tinyPNG — PNG 2 × 1 в оттенках серого. Декодеров в cmd/aisec-media нет
// (depguard media-decoders), поэтому образец — готовые байты.
const tinyPNG = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x02\x00\x00\x00\x01\b\x00\x00\x00\x00\xd1I V\x00\x00\x00\x0fIDATx\x9cbb`\x00\x04\x00\x00\xff\xff\x00\t\x00\x03'\x89=\xe3\x00\x00\x00\x00IEND\xaeB`\x82"

func ownIDs() (uid, gid uint32) {
	return uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: UID и GID в Linux — 32 бита без знака
}

// sockDir — каталог сокета 0750 с коротким путём (предел sun_path — 108 байт).
func sockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "media")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })  //nolint:gosec // G104: ошибка в тесте не важна
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: тест задаёт права каталога сокета намеренно
		t.Fatal(err)
	}
	return dir
}

func testConfig(t *testing.T) *config {
	t.Helper()
	cfg, err := loadConfig([]string{"-socket", filepath.Join(sockDir(t), "s.sock"), "-peer-uid=991", "-peer-gid=992"},
		func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	// Собеседник — сам тест (в облачной среде — и от root, которого флаги не
	// допускают): ожидаемые UID и GID — свои.
	cfg.PeerUID, cfg.PeerGID = ownIDs()
	return cfg
}

// startRun запускает run и ждёт готовности сокета.
func startRun(t *testing.T, cfg *config) *media.Server {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan *media.Server, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, deps{provider: p, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), ready: func(s *media.Server) { ready <- s }})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	select {
	case s := <-ready:
		return s
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("сокет не готов")
	}
	return nil
}

func exchange(t *testing.T, c net.Conn, h wire.Header, body []byte) (wire.Header, []byte) {
	t.Helper()
	if err := wire.WriteFrame(c, h, body); err != nil {
		t.Fatal(err)
	}
	rh, rb, err := wire.ReadFrame(c, wire.ClientSide)
	if err != nil {
		t.Fatal(err)
	}
	return rh, rb
}

// Запуск: сокет 0660, hello и анализ PNG через настоящий Unix-сокет.
func TestRunServesSocket(t *testing.T) {
	cfg := testConfig(t)
	startRun(t, cfg)
	info, err := os.Lstat(cfg.Socket)
	if err != nil || info.Mode().Perm() != socketMode {
		t.Fatalf("сокет: %v %v", info.Mode(), err)
	}
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()                                    //nolint:errcheck // тест
	_ = c.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:gosec // G104: тест
	h, b := exchange(t, c, wire.Header{Type: wire.TypeHello, ID: 1}, nil)
	if hello, err := wire.ParseHelloOK(b); h.Type != wire.TypeHelloOK || err != nil || hello.MaxBytes != media.DefaultMaxBytes {
		t.Fatalf("%+v %v", hello, err)
	}
	h, b = exchange(t, c, wire.Header{Type: wire.TypeAnalyze, Timeout: 1000, ID: 2}, []byte(tinyPNG))
	r, err := wire.ParseResult(b)
	if h.Type != wire.TypeResult || err != nil || r.Status != wire.StatusOK || r.Format != wire.FormatPNG || r.Width != 2 || r.Height != 1 {
		t.Fatalf("%+v %v", r, err)
	}
}

// Каталог сокета с правами для остальных — отказ запуска.
func TestRunRejectsOpenSocketDir(t *testing.T) {
	cfg := testConfig(t)
	if err := os.Chmod(filepath.Dir(cfg.Socket), 0o755); err != nil { //nolint:gosec // G302: тест проверяет отказ на открытом каталоге
		t.Fatal(err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	err = run(context.Background(), cfg, deps{provider: p, logger: slog.New(slog.DiscardHandler)})
	if err == nil || !strings.Contains(err.Error(), "у остальных не должно быть доступа") {
		t.Fatal(err)
	}
}

func TestLoadConfig(t *testing.T) {
	env := map[string]string{"AISEC_MEDIA_WORKERS": "3", "AISEC_MEDIA_PEER_GID": "992", "AISEC_MEDIA_MAX_PIXELS": "1000"}
	cfg, err := loadConfig([]string{"-workers=2", "-peer-uid=991", "-cache-entries=0"}, func(k string) string { return env[k] }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workers != 2 || cfg.PeerUID != 991 || cfg.PeerGID != 992 || cfg.Limits.MaxPixels != 1000 ||
		cfg.Limits.MaxBytes != media.DefaultMaxBytes || cfg.Socket != DefaultSocket || cfg.CacheEntries != -1 ||
		cfg.Queue != media.DefaultQueue || cfg.RunTimeout != media.DefaultRunTimeout {
		t.Fatalf("%+v", cfg)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	base := []string{"-peer-uid=991", "-peer-gid=992"}
	cases := map[string][]string{
		"нет peer-uid":           {"-peer-gid=992"},
		"peer-gid 0":             {"-peer-uid=991", "-peer-gid=0"},
		"относительный сокет":    append([]string{"-socket=run/s.sock"}, base...),
		"сокет с ..":             append([]string{"-socket=/run/../s.sock"}, base...),
		"max-bytes мал":          append([]string{"-max-bytes=1000"}, base...),
		"max-bytes сверх 32 МиБ": append([]string{"-max-bytes=33554433"}, base...),
		"max-pixels 0":           append([]string{"-max-pixels=0"}, base...),
		"max-pixels сверх":       append([]string{"-max-pixels=100000001"}, base...),
		"workers 0":              append([]string{"-workers=0"}, base...),
		"queue отрицательная":    append([]string{"-queue=-1"}, base...),
		"срок мал":               append([]string{"-run-timeout=10ms"}, base...),
		"предел срока < срока":   append([]string{"-run-timeout=5s", "-max-run-timeout=1s"}, base...),
		"реакция":                append([]string{"-integrity-action=ignore"}, base...),
		"интервал":               append([]string{"-integrity-interval=1s"}, base...),
		"лишний аргумент":        append(append([]string{}, base...), "x"),
	}
	for name, args := range cases {
		if _, err := loadConfig(args, func(string) string { return "" }, io.Discard); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}
