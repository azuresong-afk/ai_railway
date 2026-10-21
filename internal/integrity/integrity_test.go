package integrity

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func provider(t testing.TB) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// install — установка в каталоге теста: bin/ с «исполняемым файлом»,
// статика (встроенный набор) и подписанный манифест.
type install struct {
	root     string
	exe      string
	static   fstest.MapFS
	signer   aisecCrypto.Signer
	manifest string
}

var (
	binaryBody = []byte("\x7fELF синтетический исполняемый файл")
	staticBody = map[string]string{"index.html": "<!doctype html><title>AISec</title>", "assets/app.js": "console.log(1)"}
)

func newInstall(t *testing.T) *install {
	t.Helper()
	p := provider(t)
	root := t.TempDir()
	write := func(rel string, data []byte) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("bin/aisec-test", binaryBody)
	write("bin/aisec-other", []byte("другой компонент"))
	static := fstest.MapFS{}
	for name, body := range staticBody {
		write("src/static/"+name, []byte(body))
		static[name] = &fstest.MapFile{Data: []byte(body), Mode: 0o444}
	}
	write("src/migrations/0001_init.sql", []byte("SELECT 1;"))
	signer, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	in := &install{root: root, exe: filepath.Join(root, "bin", "aisec-test"), static: static, signer: signer,
		manifest: filepath.Join(root, ManifestFile)}
	m, err := Build(p, BuildInput{Version: "1.0.0-test", Created: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), Sources: []Source{
		{Kind: KindBinary, Dir: filepath.Join(root, "bin"), Files: []string{"aisec-test", "aisec-other"}},
		{Kind: KindStatic, Dir: filepath.Join(root, "src", "static"), Recursive: true},
		{Kind: KindMigration, Dir: filepath.Join(root, "src", "migrations"), Glob: "*.sql"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	in.writeManifest(t, data, signer)
	return in
}

func (in *install) writeManifest(t *testing.T, data []byte, s aisecCrypto.Signer) {
	t.Helper()
	sig, err := Sign(s, data)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, in.manifest, data)
	writeFile(t, in.manifest+".sig", sig)
}

func (in *install) config(t *testing.T) Config {
	t.Helper()
	v, err := provider(t).NewVerifier(in.signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Component: "test", Provider: provider(t), ManifestPath: in.manifest,
		Executable: in.exe, BinaryName: "bin/aisec-test",
		Embedded: map[string]fs.FS{"web/dist": in.static},
		AllFiles: true, Verifier: v,
	}
}

func check(t *testing.T, cfg Config) Result {
	t.Helper()
	c, err := NewChecker(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Check(context.Background(), TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hasFailure(res Result, path string, p Problem) bool {
	for _, f := range res.Failures {
		if f.Path == path && f.Problem == p {
			return true
		}
	}
	return false
}

func TestCheckOK(t *testing.T) {
	in := newInstall(t)
	res := check(t, in.config(t))
	// Свой файл, два бинарника на диске, два файла статики.
	if !res.OK() || res.Checked != 5 || res.ManifestVersion != "1.0.0-test" || res.TestSigned {
		t.Fatalf("%+v", res)
	}
	if res.Component != "test" || res.Trigger != TriggerManual || res.At.IsZero() {
		t.Fatalf("%+v", res)
	}
}

// TestDM42_ManifestTampered — подмена исполняемого файла и статики
// веб-консоли обнаруживается (DM-42, ОЦЛ.2).
func TestDM42_ManifestTampered(t *testing.T) {
	t.Run("подмена бинарника того же размера", func(t *testing.T) {
		in := newInstall(t)
		forged := bytes.Clone(binaryBody)
		forged[len(forged)-1] ^= 1
		if err := os.WriteFile(in.exe, forged, 0o600); err != nil {
			t.Fatal(err)
		}
		res := check(t, in.config(t))
		if res.OK() || res.Reason != ReasonFilesMismatch || !hasFailure(res, "bin/aisec-test", ProblemModified) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("подмена бинарника другого размера", func(t *testing.T) {
		in := newInstall(t)
		if err := os.WriteFile(filepath.Join(in.root, "bin", "aisec-other"), []byte("троян"), 0o600); err != nil {
			t.Fatal(err)
		}
		res := check(t, in.config(t))
		if res.OK() || !hasFailure(res, "bin/aisec-other", ProblemSize) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("бинарник заменён ссылкой", func(t *testing.T) {
		in := newInstall(t)
		other := filepath.Join(in.root, "bin", "aisec-other")
		if err := os.Remove(other); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(in.exe, other); err != nil {
			t.Fatal(err)
		}
		res := check(t, in.config(t))
		if res.OK() || !hasFailure(res, "bin/aisec-other", ProblemNotRegular) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("бинарник удалён", func(t *testing.T) {
		in := newInstall(t)
		if err := os.Remove(filepath.Join(in.root, "bin", "aisec-other")); err != nil {
			t.Fatal(err)
		}
		res := check(t, in.config(t))
		if res.OK() || !hasFailure(res, "bin/aisec-other", ProblemMissing) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("подмена файла статики", func(t *testing.T) {
		in := newInstall(t)
		cfg := in.config(t)
		forged := fstest.MapFS{}
		for k, v := range in.static {
			forged[k] = v
		}
		forged["assets/app.js"] = &fstest.MapFile{Data: []byte("console.log(2)")}
		cfg.Embedded = map[string]fs.FS{"web/dist": forged}
		res := check(t, cfg)
		if res.OK() || !hasFailure(res, "web/dist/assets/app.js", ProblemModified) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("лишний и пропавший файл статики", func(t *testing.T) {
		in := newInstall(t)
		cfg := in.config(t)
		cfg.Embedded = map[string]fs.FS{"web/dist": fstest.MapFS{
			"index.html":     in.static["index.html"],
			"assets/evil.js": &fstest.MapFile{Data: []byte("fetch('//evil')")},
		}}
		res := check(t, cfg)
		if res.OK() || !hasFailure(res, "web/dist/assets/evil.js", ProblemExtra) || !hasFailure(res, "web/dist/assets/app.js", ProblemMissing) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("исполняемого файла нет в манифесте", func(t *testing.T) {
		in := newInstall(t)
		cfg := in.config(t)
		cfg.BinaryName = "bin/aisec-unknown"
		res := check(t, cfg)
		if res.OK() || !hasFailure(res, "bin/aisec-unknown", ProblemNoEntry) {
			t.Fatalf("%+v", res)
		}
	})
}

// TestManifestSignatureRejected — неверная подпись манифеста — нарушение:
// чужой ключ, подпись без контекста манифеста, изменённый манифест,
// испорченный или пропавший файл подписи.
func TestManifestSignatureRejected(t *testing.T) {
	p := provider(t)
	other, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	for name, tamper := range map[string]func(t *testing.T, in *install, data []byte){
		"чужой ключ": func(t *testing.T, in *install, data []byte) { in.writeManifest(t, data, other) },
		"подпись без контекста": func(t *testing.T, in *install, data []byte) {
			sig, err := in.signer.Sign(data)
			if err != nil {
				t.Fatal(err)
			}
			// Файл подписи того же формата, но подпись — без контекста манифеста.
			file, err := Sign(rawSigner{sig}, nil)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, in.manifest+".sig", file)
		},
		"манифест изменён после подписи": func(t *testing.T, in *install, data []byte) {
			writeFile(t, in.manifest, bytes.Replace(data, []byte("1.0.0-test"), []byte("1.0.1-test"), 1))
		},
		"подпись испорчена": func(t *testing.T, in *install, _ []byte) { writeFile(t, in.manifest+".sig", []byte("не base64\n")) },
		"пустая подпись":    func(t *testing.T, in *install, _ []byte) { writeFile(t, in.manifest+".sig", nil) },
		"нет файла подписи": func(t *testing.T, in *install, _ []byte) { removeFile(t, in.manifest+".sig") },
		"подпись — каталог": func(t *testing.T, in *install, _ []byte) {
			removeFile(t, in.manifest+".sig")
			mkdir(t, in.manifest+".sig")
		},
		"слишком большая подпись": func(t *testing.T, in *install, _ []byte) {
			writeFile(t, in.manifest+".sig", bytes.Repeat([]byte("A"), maxSignatureFile+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := newInstall(t)
			data, err := os.ReadFile(in.manifest)
			if err != nil {
				t.Fatal(err)
			}
			tamper(t, in, data)
			res := check(t, in.config(t))
			if res.OK() || res.Reason != ReasonSignatureInvalid {
				t.Fatalf("%+v", res)
			}
		})
	}
	t.Run("нет манифеста", func(t *testing.T) {
		in := newInstall(t)
		removeFile(t, in.manifest)
		if res := check(t, in.config(t)); res.Reason != ReasonManifestMissing {
			t.Fatalf("%+v", res)
		}
	})
}

// rawSigner возвращает заданную подпись: проверка файла подписи без контекста.
type rawSigner struct{ sig []byte }

func (s rawSigner) Name() string                { return "raw" }
func (s rawSigner) Sign([]byte) ([]byte, error) { return s.sig, nil }
func (s rawSigner) PublicKey() []byte           { return nil }
func (s rawSigner) Seed() []byte                { return nil }

func writeFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.WriteFile(p, data, 0o600); err != nil { //nolint:gosec // G703: путь во временном каталоге теста
		t.Fatal(err)
	}
}

func removeFile(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.Mkdir(p, 0o750); err != nil {
		t.Fatal(err)
	}
}

// Подписанный, но неподходящий манифест: другой профиль или алгоритм хеша.
func TestManifestWrongProfileOrHash(t *testing.T) {
	for name, edit := range map[string]func(m *Manifest){
		"алгоритм хеша": func(m *Manifest) { m.HashAlg = "SHA-512" },
		"профиль":       func(m *Manifest) { m.Profile = aisecCrypto.ProfileGOST },
	} {
		t.Run(name, func(t *testing.T) {
			in := newInstall(t)
			data, err := os.ReadFile(in.manifest)
			if err != nil {
				t.Fatal(err)
			}
			m, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			edit(m)
			if data, err = Marshal(m); err != nil {
				t.Fatal(err)
			}
			in.writeManifest(t, data, in.signer)
			if res := check(t, in.config(t)); res.Reason != ReasonManifestInvalid {
				t.Fatalf("%+v", res)
			}
		})
	}
}

func validManifest() *Manifest {
	h := strings.Repeat("ab", 32)
	return &Manifest{Format: FormatV1, Version: "1", Profile: aisecCrypto.ProfileStandard, HashAlg: "SHA-256",
		Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Files: []Entry{
			{Path: "bin/aisec-server", Kind: KindBinary, Size: 1, Hash: h},
			{Path: "migrations/0001_init.sql", Kind: KindMigration, Size: 1, Hash: h},
			{Path: "web/dist/index.html", Kind: KindStatic, Size: 1, Hash: h},
		}}
}

func TestParseRoundTrip(t *testing.T) {
	data, err := Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(data)
	if err != nil || len(m.Files) != 3 || m.Files[2].Path != "web/dist/index.html" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestParseRejects(t *testing.T) {
	good, err := Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	h := strings.Repeat("ab", 32)
	edits := map[string]func(m *Manifest){
		"формат":               func(m *Manifest) { m.Format = "aisec-manifest-v0" },
		"пустая версия":        func(m *Manifest) { m.Version = "" },
		"версия с переводом":   func(m *Manifest) { m.Version = "1\n2" },
		"профиль":              func(m *Manifest) { m.Profile = "fips" },
		"нет алгоритма":        func(m *Manifest) { m.HashAlg = "" },
		"нет времени":          func(m *Manifest) { m.Created = time.Time{} },
		"нет файлов":           func(m *Manifest) { m.Files = nil },
		"путь с ..":            func(m *Manifest) { m.Files[0].Path = "bin/../etc/passwd" },
		"абсолютный путь":      func(m *Manifest) { m.Files[0].Path = "/bin/aisec-server" },
		"обратная черта":       func(m *Manifest) { m.Files[0].Path = `bin\aisec-server` },
		"пустая часть":         func(m *Manifest) { m.Files[0].Path = "bin//aisec-server" },
		"вид не по каталогу":   func(m *Manifest) { m.Files[0].Kind = KindStatic },
		"неизвестный вид":      func(m *Manifest) { m.Files[0].Kind = "plugin" },
		"отрицательный размер": func(m *Manifest) { m.Files[0].Size = -1 },
		"короткий хеш":         func(m *Manifest) { m.Files[0].Hash = "abcd" },
		"заглавный хеш":        func(m *Manifest) { m.Files[0].Hash = strings.ToUpper(h) },
		"не шестнадцатеричный": func(m *Manifest) { m.Files[0].Hash = strings.Repeat("zz", 32) },
		"разная длина хешей":   func(m *Manifest) { m.Files[1].Hash = strings.Repeat("ab", 48) },
		"повтор пути":          func(m *Manifest) { m.Files[1] = m.Files[0] },
		"не по порядку":        func(m *Manifest) { m.Files[0], m.Files[2] = m.Files[2], m.Files[0] },
	}
	for name, edit := range edits {
		m := validManifest()
		edit(m)
		if _, err := Marshal(m); err == nil {
			t.Errorf("%s: Marshal принял", name)
		}
	}
	for name, data := range map[string][]byte{
		"неизвестное поле": bytes.Replace(good, []byte(`"format"`), []byte(`"extra": 1, "format"`), 1),
		"данные после":     append(bytes.Clone(good), []byte(`{}`)...),
		"не JSON":          []byte("format: v1"),
		"слишком большой":  bytes.Repeat([]byte(" "), MaxManifestSize+1),
	} {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: Parse принял", name)
		}
	}
}

func TestBuildRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.sql"), []byte("SELECT 1;"))
	if err := os.Symlink(filepath.Join(dir, "a.sql"), filepath.Join(dir, "b.sql")); err != nil {
		t.Fatal(err)
	}
	_, err := Build(provider(t), BuildInput{Version: "1", Created: time.Now(), Sources: []Source{{Kind: KindMigration, Dir: dir, Glob: "*.sql"}}})
	if err == nil {
		t.Fatal("ссылка принята")
	}
}

// ОЦЛ.3: файл конфигурации, изменённый после запуска, — нарушение.
func TestWatchedConfigChanged(t *testing.T) {
	in := newInstall(t)
	conf := filepath.Join(in.root, "gateway.yaml")
	writeFile(t, conf, []byte("listen: 127.0.0.1:8443\n"))
	cfg := in.config(t)
	cfg.Watch = []string{conf}
	c, err := NewChecker(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Check(context.Background(), TriggerPeriodic); err != nil || !res.OK() {
		t.Fatalf("%+v %v", res, err)
	}
	writeFile(t, conf, []byte("listen: 0.0.0.0:8443\n"))
	res, err := c.Check(context.Background(), TriggerPeriodic)
	if err != nil || res.OK() || !hasFailure(res, conf, ProblemChanged) {
		t.Fatalf("%+v %v", res, err)
	}
	// Конфигурация проверяется и без манифеста.
	removeFile(t, in.manifest)
	res, err = c.Check(context.Background(), TriggerPeriodic)
	if err != nil || res.Reason != ReasonManifestMissing || !hasFailure(res, conf, ProblemChanged) {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestCheckInterrupted(t *testing.T) {
	in := newInstall(t)
	c, err := NewChecker(in.config(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Check(ctx, TriggerManual); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("ошибка %v", err)
	}
}

func TestFailuresLimited(t *testing.T) {
	var r Result
	for range MaxFailures + 5 {
		r.fail("x", ProblemMissing)
	}
	if len(r.Failures) != MaxFailures || r.Omitted != 5 {
		t.Fatalf("%d %d", len(r.Failures), r.Omitted)
	}
}

// Тестовая пара ключей репозитория: закрытый ключ testdata/integrity/
// соответствует встроенному открытому, и сборка без aisec_release помечает
// это (Р10, «не для поставки»).
func TestEmbeddedTestKeyPair(t *testing.T) {
	p := provider(t)
	v, testKey, err := EmbeddedVerifier(p)
	if err != nil || !testKey {
		t.Fatalf("%v %v", testKey, err)
	}
	data, err := os.ReadFile("../../testdata/integrity/manifest-test.signkey")
	if err != nil {
		t.Fatal(err)
	}
	profile, seed, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindManifestSigning)
	if err != nil || profile != aisecCrypto.ProfileStandard {
		t.Fatal(profile, err)
	}
	s, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.PublicKey(), v.PublicKey()) {
		t.Fatal("тестовый закрытый ключ не соответствует встроенному открытому")
	}
	// Без Verifier в Config используется встроенный ключ, результат помечен.
	in := newInstall(t)
	raw, err := os.ReadFile(in.manifest)
	if err != nil {
		t.Fatal(err)
	}
	in.writeManifest(t, raw, s)
	cfg := in.config(t)
	cfg.Verifier = nil
	if res := check(t, cfg); !res.OK() || !res.TestSigned {
		t.Fatalf("%+v", res)
	}
	// Ключ другого вида встроенным не считается.
	if _, _, err := aisecCrypto.DecodeKeyPEM(embeddedKeyPEM, aisecCrypto.KeyKindAuditSigningPublic); err == nil {
		t.Fatal("ключ манифеста принят как ключ аудита")
	}
}

func TestDefaultManifestPath(t *testing.T) {
	if got := DefaultManifestPath("/opt/aisec/bin/aisec-server"); got != "/opt/aisec/aisec-manifest.json" {
		t.Fatal(got)
	}
}

func TestParseAction(t *testing.T) {
	for _, s := range []string{"alert", "stop"} {
		if a, err := ParseAction(s); err != nil || string(a) != s {
			t.Fatal(s, err)
		}
	}
	for _, s := range []string{"", "Stop", "ignore"} {
		if _, err := ParseAction(s); err == nil {
			t.Fatal(s)
		}
	}
	// Значения в internal/config (флаги шлюза) совпадают с этим пакетом.
	if config.IntegrityAlert != string(ActionAlert) || config.IntegrityStop != string(ActionStop) ||
		config.DefaultIntegrityInterval != DefaultInterval || config.MinIntegrityInterval != MinInterval {
		t.Fatal("значения контроля целостности в internal/config разошлись с internal/integrity")
	}
}

type recorded struct {
	mu   sync.Mutex
	runs []Result
	by   []audit.Actor
	ip   []netip.Addr
}

func (r *recorded) record(_ context.Context, res Result, by audit.Actor, ip netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs, r.by, r.ip = append(r.runs, res), append(r.by, by), append(r.ip, ip)
	return nil
}

func TestMonitorReactions(t *testing.T) {
	in := newInstall(t)
	cfg := in.config(t)
	c, err := NewChecker(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewMonitor(MonitorConfig{Checker: c, Action: "ignore", Interval: time.Hour}); err == nil {
		t.Fatal("неизвестная реакция принята")
	}
	if _, err := NewMonitor(MonitorConfig{Checker: c, Action: ActionAlert, Interval: time.Second}); err == nil {
		t.Fatal("период меньше минуты принят")
	}
	// Нарушение: подменён бинарник.
	writeFile(t, in.exe, []byte("подмена"))
	for _, action := range []Action{ActionAlert, ActionStop} {
		rec := &recorded{}
		stopped := make(chan error, 1)
		m, err := NewMonitor(MonitorConfig{Checker: c, Action: action, Interval: time.Hour, Record: rec.record,
			OnStop: func(err error) { stopped <- err }, Logger: discardLogger()})
		if err != nil {
			t.Fatal(err)
		}
		res, err := m.Startup(context.Background())
		if res.OK() || len(rec.runs) != 1 || rec.by[0].Type != audit.ActorSystem || rec.runs[0].Trigger != TriggerStartup {
			t.Fatalf("%s: %+v %+v", action, res, rec)
		}
		if (action == ActionStop) != errors.Is(err, ErrViolation) {
			t.Fatalf("%s: запуск: %v", action, err)
		}
		user := audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "admin"}
		ip := netip.MustParseAddr("192.0.2.10")
		if _, err := m.CheckBy(context.Background(), user, ip); err != nil {
			t.Fatal(err)
		}
		if rec.by[1] != user || rec.ip[1] != ip || rec.runs[1].Trigger != TriggerManual {
			t.Fatalf("%s: %+v", action, rec)
		}
		select {
		case err := <-stopped:
			if action != ActionStop || !errors.Is(err, ErrViolation) {
				t.Fatalf("%s: остановка %v", action, err)
			}
		default:
			if action == ActionStop {
				t.Fatal("stop: компонент не остановлен")
			}
		}
	}
}

func TestMonitorRunPeriodic(t *testing.T) {
	in := newInstall(t)
	c, err := NewChecker(in.config(t))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, in.exe, []byte("подмена"))
	rec := &recorded{}
	stopped := make(chan error, 1)
	// Период меньше минуты — только в тесте, в обход NewMonitor.
	m := &Monitor{cfg: MonitorConfig{Checker: c, Action: ActionStop, Interval: 10 * time.Millisecond, Record: rec.record,
		OnStop: func(err error) { stopped <- err }, Logger: discardLogger()}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	select {
	case err := <-stopped:
		if !errors.Is(err, ErrViolation) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("периодическая проверка не сработала")
	}
	cancel()
	<-done
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.runs) == 0 || rec.runs[0].Trigger != TriggerPeriodic {
		t.Fatalf("%+v", rec.runs)
	}
}
