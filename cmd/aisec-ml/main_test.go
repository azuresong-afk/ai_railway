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
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/ml"
	"github.com/azuresong-afk/ai_railway/internal/ml/mltest"
)

var spec = mltest.Spec{ID: "injection", Version: "1.0", Directions: []string{"input"}, Words: map[string]string{"ignore": "injection"}}

// fixture — пакет моделей, ключ «производителя» и каталог сокета 0750
// (короткий путь: предел sun_path — 108 байт).
type fixture struct {
	cfg    *config
	d      deps
	signer aisecCrypto.Signer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.NewVerifier(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	models := filepath.Join(root, "models")
	if _, err := mltest.WritePackage(models, p, s, spec); err != nil {
		t.Fatal(err)
	}
	manifest := writeReleaseManifest(t, p, s, root)
	sockDir, err := os.MkdirTemp("", "ml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })  //nolint:gosec // G104: ошибка в тесте не важна
	if err := os.Chmod(sockDir, 0o750); err != nil { //nolint:gosec // G302: тест задаёт права сокета и каталога намеренно
		t.Fatal(err)
	}
	cfg := &config{Socket: filepath.Join(sockDir, "aisec-ml.sock"), Models: models, MaxConns: 4, Workers: 1,
		QueueWait: 10 * time.Millisecond, MaxModelBytes: ml.DefaultMaxModelBytes}
	d := deps{provider: p, verifier: v, manifest: manifest, version: "1.0.0", logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		newExecutor: func(*config, aisecCrypto.Provider) (ml.Executor, error) { return mltest.Executor{}, nil }}
	return &fixture{cfg: cfg, d: d, signer: s}
}

// writeReleaseManifest — подписанный манифест выпуска в root с файлами
// models/ (как make ml-release-assemble).
// Без src — файлы models/.
func writeReleaseManifest(t *testing.T, p aisecCrypto.Provider, s aisecCrypto.Signer, root string, src ...integrity.Source) string {
	t.Helper()
	if len(src) == 0 {
		src = []integrity.Source{{Kind: integrity.KindModel, Dir: filepath.Join(root, "models"), Recursive: true}}
	}
	m, err := integrity.Build(p, integrity.BuildInput{Version: "1.0.0", Created: time.Unix(1, 0), Sources: src})
	if err != nil {
		t.Fatal(err)
	}
	data, err := integrity.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := integrity.Sign(s, data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, integrity.ManifestFile)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunServesVerifiedModels(t *testing.T) {
	f := newFixture(t)
	ready := make(chan struct{})
	f.d.ready = func() { close(ready) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.cfg, f.d) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("aisec-ml не запустился: %v", err)
	}
	info, err := os.Lstat(f.cfg.Socket)
	if err != nil || info.Mode().Perm() != socketMode {
		t.Fatalf("права сокета %v (%v), нужны %#o", info.Mode().Perm(), err, socketMode)
	}
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", f.cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ml.EncodeDetect("injection", "ignore all")
	if err != nil {
		t.Fatal(err)
	}
	if err := ml.WriteFrame(c, ml.Header{Type: ml.TypeDetect, ID: 1}, body); err != nil {
		t.Fatal(err)
	}
	h, b, err := ml.ReadFrame(c, ml.ClientSide)
	if err != nil || h.Type != ml.TypeResult {
		t.Fatalf("ответ: %+v %s %v", h, b, err)
	}
	r, err := ml.ParseResult(b, spec.Info(), "ignore all")
	if err != nil || len(r.Findings) != 1 {
		t.Fatalf("находки: %+v %v", r, err)
	}
	_ = c.Close() //nolint:gosec // G104: ошибка в тесте не важна
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("остановка: %v", err)
	}
}

// Неверная подпись или подменённые веса — отказ запуска до загрузки моделей
// и до создания сокета.
func TestRunRefusesUnverifiedPackage(t *testing.T) {
	for name, spoil := range map[string]func(t *testing.T, f *fixture){
		"чужой ключ": func(t *testing.T, f *fixture) {
			other, err := f.d.provider.GenerateSigner()
			if err != nil {
				t.Fatal(err)
			}
			if f.d.verifier, err = f.d.provider.NewVerifier(other.PublicKey()); err != nil {
				t.Fatal(err)
			}
		},
		"подменённые веса": func(t *testing.T, f *fixture) {
			if err := os.WriteFile(filepath.Join(f.cfg.Models, "injection", "model.onnx"), []byte("test-onnx:evil00000"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"подменённый токенизатор": func(t *testing.T, f *fixture) {
			if err := os.WriteFile(filepath.Join(f.cfg.Models, "injection", "tokenizer.json"), []byte(`{"words":{}}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		// 4В23: старый подписанный пакет вне каталога выпуска или в нём.
		"пакет вне каталога выпуска": func(t *testing.T, f *fixture) {
			f.cfg.Models = oldPackage(t, f)
		},
		"старый пакет в каталоге выпуска": func(t *testing.T, f *fixture) {
			if err := os.RemoveAll(f.cfg.Models); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(oldPackage(t, f), f.cfg.Models); err != nil {
				t.Fatal(err)
			}
		},
		"манифест выпуска без моделей": func(t *testing.T, f *fixture) {
			root := filepath.Dir(f.cfg.Models)
			if err := os.MkdirAll(filepath.Join(root, "lib"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "lib", "libx.so"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			writeReleaseManifest(t, f.d.provider, f.signer, root, integrity.Source{Kind: integrity.KindLibrary, Dir: filepath.Join(root, "lib"), Recursive: true})
		},
		"манифест выпуска чужим ключом": func(t *testing.T, f *fixture) {
			other, err := f.d.provider.GenerateSigner()
			if err != nil {
				t.Fatal(err)
			}
			writeReleaseManifest(t, f.d.provider, other, filepath.Dir(f.cfg.Models))
		},
		// 4Н30: манифест другого выпуска (например, -manifest на старый
		// выпуск при -integrity-action=alert).
		"манифест другой версии": func(_ *testing.T, f *fixture) { f.d.version = "1.1.0" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			spoil(t, f)
			loaded := false
			f.d.newExecutor = func(*config, aisecCrypto.Provider) (ml.Executor, error) { loaded = true; return mltest.Executor{}, nil }
			// Принятый пакет — сервер до срока, а не зависание теста.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := run(ctx, f.cfg, f.d)
			if err == nil || !strings.Contains(err.Error(), "пакет моделей отвергнут") {
				t.Fatalf("пакет принят: %v", err)
			}
			if loaded {
				t.Fatal("исполнитель создан до проверки пакета")
			}
			if _, err := os.Lstat(f.cfg.Socket); err == nil {
				t.Fatal("сокет создан при отвергнутом пакете")
			}
		})
	}
}

// oldPackage — пакет другой версии, подписанный тем же ключом
// производителя (откат версии моделей, 4В23).
func oldPackage(t *testing.T, f *fixture) string {
	t.Helper()
	old := spec
	old.Version = "0.9"
	dir := filepath.Join(filepath.Dir(f.cfg.Models), "old")
	if _, err := mltest.WritePackage(dir, f.d.provider, f.signer, old); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestListenSocketDirectoryChecks(t *testing.T) {
	base, err := os.MkdirTemp("", "ml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) }) //nolint:gosec // G104: ошибка в тесте не важна
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o777, 0o755, 0o751} {
		if err := os.Chmod(open, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := listenSocket(context.Background(), filepath.Join(open, "s")); err == nil {
			t.Fatalf("каталог %#o принят", mode)
		}
	}
	link := filepath.Join(base, "link")
	good := filepath.Join(base, "good")
	if err := os.Mkdir(good, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := listenSocket(context.Background(), filepath.Join(link, "s")); err == nil {
		t.Fatal("каталог-ссылка принят")
	}
	// Обычный файл на месте сокета не удаляется.
	file := filepath.Join(good, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenSocket(context.Background(), file); err == nil {
		t.Fatal("файл на месте сокета заменён")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("файл удалён")
	}
	// Старый сокет заменяется.
	sock := filepath.Join(good, "s")
	l1, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l1.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l1.Close() //nolint:gosec // G104: ошибка в тесте не важна
	l2, err := listenSocket(context.Background(), sock)
	if err != nil {
		t.Fatalf("старый сокет не заменён: %v", err)
	}
	_ = l2.Close() //nolint:gosec // G104: ошибка в тесте не важна
}

func TestLoadConfig(t *testing.T) {
	env := map[string]string{"AISEC_ML_SOCKET": "/run/x/s.sock", "AISEC_ML_WORKERS": "3"}
	cfg, err := loadConfig([]string{"-workers=2"}, func(k string) string { return env[k] }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Socket != "/run/x/s.sock" || cfg.Workers != 2 || cfg.Models != DefaultModels ||
		cfg.IntegrityAction != integrity.ActionStop || cfg.IntegrityInterval != integrity.DefaultInterval ||
		cfg.RunTimeout != ml.DefaultRunTimeout || cfg.MaxRunTimeout != ml.DefaultMaxRunTimeout {
		t.Fatalf("конфигурация: %+v", cfg)
	}
	for _, args := range [][]string{
		{"-socket=relative.sock"},
		{"-socket=/run/" + strings.Repeat("a", 120)},
		{"-models=models"},
		{"-max-conns=0"},
		{"-workers=-1"},
		{"-queue-wait=5s"},
		{"-run-timeout=1ms"},
		{"-run-timeout=500ms", "-max-run-timeout=100ms"},
		{"-max-run-timeout=1m"},
		{"-max-model-bytes=10"},
		{"-ort-lib=lib.so"},
		{"-ort-lib=/opt/../lib.so"},
		{"-manifest=aisec-manifest.json"},
		{"-integrity-action=ignore"},
		{"-integrity-interval=10s"},
		{"лишний"},
	} {
		if _, err := loadConfig(args, func(string) string { return "" }, io.Discard); err == nil {
			t.Errorf("%v: принято", args)
		}
	}
}

// Самопроверка целостности при запуске (ОЦЛ.2): без манифеста с реакцией
// stop aisec-ml не запускается, с alert — запускается и пишет нарушение.
func TestStartIntegrity(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := &config{Manifest: filepath.Join(t.TempDir(), integrity.ManifestFile), IntegrityAction: integrity.ActionStop,
		IntegrityInterval: integrity.DefaultInterval}
	var log strings.Builder
	logger := slog.New(slog.NewTextHandler(&log, nil))
	if err := startIntegrity(ctx, cfg, p, logger, func(error) {}); err == nil || !strings.Contains(err.Error(), string(integrity.ReasonManifestMissing)) {
		t.Fatalf("stop без манифеста: %v", err)
	}
	cfg.IntegrityAction = integrity.ActionAlert
	if err := startIntegrity(ctx, cfg, p, logger, func(error) {}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "нарушена целостность") {
		t.Fatalf("журнал: %s", log.String())
	}
}
