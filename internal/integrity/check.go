package integrity

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Trigger — повод проверки (ОЦЛ.2).
type Trigger string

// Поводы.
const (
	TriggerStartup  Trigger = "startup"
	TriggerPeriodic Trigger = "periodic"
	TriggerManual   Trigger = "manual"
)

// Reason — итог проверки.
type Reason string

// Итоги. Всё, кроме ReasonOK, — нарушение целостности (DM-42).
const (
	ReasonOK               Reason = "ok"
	ReasonManifestMissing  Reason = "manifest_missing"
	ReasonManifestInvalid  Reason = "manifest_invalid"
	ReasonSignatureInvalid Reason = "signature_invalid"
	ReasonFilesMismatch    Reason = "files_mismatch"
	// ReasonManifestRollback — манифест подписан верно, но собран раньше
	// манифеста последней успешной проверки: установлен более старый выпуск
	// (В20 ревью 2.r4). Определяется по истории проверок в БД (PGStore).
	ReasonManifestRollback Reason = "manifest_rollback"
)

// Problem — что не так с файлом.
type Problem string

// Проблемы файлов.
const (
	ProblemModified   Problem = "modified"    // хеш не совпал
	ProblemSize       Problem = "size"        // размер не совпал
	ProblemMissing    Problem = "missing"     // в манифесте есть, файла нет
	ProblemExtra      Problem = "extra"       // во встроенном наборе есть, в манифесте нет
	ProblemNotRegular Problem = "not_regular" // ссылка, каталог, устройство
	ProblemUnreadable Problem = "unreadable"  // не прочитать
	ProblemNoEntry    Problem = "no_entry"    // исполняемого файла компонента нет в манифесте
	ProblemChanged    Problem = "changed"     // конфигурация изменилась после запуска (ОЦЛ.3)
)

// MaxFailures — сколько файлов с нарушением сохраняется в результате.
const MaxFailures = 100

// Failure — файл с нарушением.
type Failure struct {
	Path    string  `json:"path"`
	Problem Problem `json:"problem"`
}

// Result — итог проверки.
type Result struct {
	Component       string
	Trigger         Trigger
	At              time.Time
	Reason          Reason
	ManifestVersion string
	// ManifestCreated — время сборки манифеста (поле created): по нему
	// упорядочены выпуски и обнаруживается откат. Нулевое — манифест не
	// прочитан.
	ManifestCreated time.Time
	// TestSigned — проверка встроенным тестовым ключом: сборка не для поставки.
	TestSigned bool
	Checked    int       // проверено файлов
	Failures   []Failure // не больше MaxFailures
	// Omitted — сколько нарушений не вошло в Failures.
	Omitted int
}

// OK — целостность не нарушена.
func (r Result) OK() bool { return r.Reason == ReasonOK }

func (r *Result) fail(p string, pr Problem) {
	if len(r.Failures) >= MaxFailures {
		r.Omitted++
		return
	}
	r.Failures = append(r.Failures, Failure{Path: p, Problem: pr})
}

// Config — что проверяет компонент.
type Config struct {
	// Component — имя для журналов: server, gateway, cli.
	Component string
	Provider  aisecCrypto.Provider
	// ManifestPath — файл манифеста; подпись — рядом (SignatureFile). Корень
	// путей манифеста — каталог этого файла.
	ManifestPath string
	// Executable — запущенный исполняемый файл компонента
	// (RunningExecutable), BinaryName — его путь в манифесте, например bin/aisec-server.
	Executable string
	BinaryName string
	// Embedded — встроенные наборы файлов: префикс в манифесте (web/dist,
	// migrations) → содержимое go:embed. Набор и записи манифеста с этим
	// префиксом совпадают ровно.
	Embedded map[string]fs.FS
	// AllFiles — сверить с диском все невстроенные файлы манифеста
	// (aisec-cli verify).
	AllFiles bool
	// DiskPrefixes — сверить с диском только невстроенные файлы манифеста с
	// этими каталогами (lib/, models/ у aisec-ml: в его образе нет остальных
	// файлов выпуска). При AllFiles не нужен.
	DiskPrefixes []string
	// Watch — файлы конфигурации и корни доверия: изменение после запуска —
	// нарушение (ОЦЛ.3, В19 ревью 2.r4).
	Watch []WatchFile
	// Verifier и TestSigned заменяют встроенный ключ (тесты).
	Verifier   aisecCrypto.Verifier
	TestSigned bool
	Now        func() time.Time
}

// WatchFile — файл под наблюдением. Data — байты, которые компонент
// прочитал при запуске и с которыми работает: эталон — их хеш, поэтому
// изменение между чтением и началом наблюдения тоже видно (Н37 ревью
// 2.r4). nil — эталон снимается чтением файла в NewChecker.
type WatchFile struct {
	Path string
	Data []byte
}

// Checker проверяет целостность компонента. Безопасен для одновременного
// использования; проверки сериализует Monitor.
type Checker struct {
	cfg     Config
	hasher  aisecCrypto.Hasher
	watched map[string][]byte
}

// NewChecker запоминает хеши файлов конфигурации на момент запуска.
func NewChecker(cfg Config) (*Checker, error) {
	if cfg.Provider == nil || cfg.Component == "" || cfg.ManifestPath == "" {
		return nil, errors.New("контроль целостности: нет профиля, имени компонента или пути манифеста")
	}
	h, err := cfg.Provider.Hasher()
	if err != nil {
		return nil, err
	}
	if cfg.Verifier == nil {
		if cfg.Verifier, cfg.TestSigned, err = EmbeddedVerifier(cfg.Provider); err != nil {
			return nil, err
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	for prefix := range cfg.Embedded {
		if err := ValidPath(prefix); err != nil {
			return nil, fmt.Errorf("контроль целостности: префикс %q: %w", prefix, err)
		}
	}
	for _, prefix := range cfg.DiskPrefixes {
		if !strings.HasSuffix(prefix, "/") || ValidPath(strings.TrimSuffix(prefix, "/")) != nil {
			return nil, fmt.Errorf("контроль целостности: каталог %q: путь с «/» в конце", prefix)
		}
	}
	c := &Checker{cfg: cfg, hasher: h, watched: map[string][]byte{}}
	for _, w := range cfg.Watch {
		if _, dup := c.watched[w.Path]; dup || w.Path == "" {
			return nil, fmt.Errorf("контроль целостности: файл конфигурации %q пустой или указан дважды", w.Path)
		}
		var sum []byte
		if w.Data != nil {
			sum = c.hasher.Sum(w.Data)
		} else if sum, err = c.hashPath(w.Path); err != nil {
			return nil, fmt.Errorf("контроль целостности: файл конфигурации %s: %w", w.Path, err)
		}
		c.watched[w.Path] = sum
	}
	return c, nil
}

// Component — имя проверяемого компонента.
func (c *Checker) Component() string { return c.cfg.Component }

// selfExe — запущенный образ процесса в Linux: открывается тот файл, с
// которым работает процесс, даже если путь os.Executable() уже указывает
// на подменённый переименованием файл (Н37 ревью 2.r4).
const selfExe = "/proc/self/exe"

// RunningExecutable — что читать для сверки исполняемого файла: в Linux
// /proc/self/exe, иначе путь path (os.Executable()).
func RunningExecutable(path string) string {
	if runtime.GOOS == "linux" {
		if _, err := os.Stat(selfExe); err == nil {
			return selfExe
		}
	}
	return path
}

// DefaultManifestPath — манифест по умолчанию: в корне установки, над
// каталогом bin/ с исполняемым файлом.
func DefaultManifestPath(executable string) string {
	return filepath.Join(filepath.Dir(filepath.Dir(executable)), ManifestFile)
}

// ErrInterrupted — проверка прервана отменой контекста (остановка компонента).
var ErrInterrupted = errors.New("проверка целостности прервана")

// Check выполняет проверку. Ошибка — только отмена контекста; любое
// нарушение, в том числе отсутствие манифеста, — Result с Reason.
func (c *Checker) Check(ctx context.Context, trig Trigger) (Result, error) {
	res := Result{Component: c.cfg.Component, Trigger: trig, At: c.cfg.Now().UTC().Truncate(time.Microsecond), TestSigned: c.cfg.TestSigned}
	m, reason := c.loadManifest()
	if reason != ReasonOK {
		res.Reason = reason
		c.checkWatched(&res)
		return res, nil
	}
	res.ManifestVersion, res.ManifestCreated = m.Version, m.Created.UTC()
	entries := make(map[string]Entry, len(m.Files))
	for _, e := range m.Files {
		entries[e.Path] = e
	}
	if err := c.checkExecutable(ctx, &res, entries); err != nil {
		return Result{}, err
	}
	if err := c.checkEmbedded(ctx, &res, m); err != nil {
		return Result{}, err
	}
	if err := c.checkDisk(ctx, &res, m); err != nil {
		return Result{}, err
	}
	c.checkWatched(&res)
	res.Reason = ReasonOK
	if len(res.Failures) > 0 {
		res.Reason = ReasonFilesMismatch
	}
	return res, nil
}

func (c *Checker) loadManifest() (*Manifest, Reason) {
	data, err := readLimited(c.cfg.ManifestPath, MaxManifestSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ReasonManifestMissing
	}
	if err != nil {
		return nil, ReasonManifestInvalid
	}
	sig, err := readLimited(c.cfg.ManifestPath+".sig", maxSignatureFile)
	if err != nil {
		return nil, ReasonSignatureInvalid
	}
	if err := VerifySignature(c.cfg.Verifier, data, sig); err != nil {
		return nil, ReasonSignatureInvalid
	}
	m, err := Parse(data)
	if err != nil || m.Profile != c.cfg.Provider.Name() || m.HashAlg != c.hasher.Name() {
		return nil, ReasonManifestInvalid
	}
	return m, ReasonOK
}

func (c *Checker) checkExecutable(ctx context.Context, res *Result, entries map[string]Entry) error {
	if c.cfg.BinaryName == "" {
		return nil
	}
	e, ok := entries[c.cfg.BinaryName]
	if !ok || e.Kind != KindBinary {
		res.fail(c.cfg.BinaryName, ProblemNoEntry)
		return nil
	}
	if c.cfg.Executable == "" {
		res.fail(c.cfg.BinaryName, ProblemUnreadable)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return ErrInterrupted
	}
	f, err := os.Open(c.cfg.Executable) //nolint:gosec // G304: путь — /proc/self/exe или os.Executable() самого компонента, не ввод
	if err != nil {
		res.fail(c.cfg.BinaryName, ProblemUnreadable)
		return nil
	}
	defer f.Close() //nolint:errcheck // файл только читается
	c.compare(res, e, f)
	return nil
}

func (c *Checker) checkEmbedded(ctx context.Context, res *Result, m *Manifest) error {
	prefixes := make([]string, 0, len(c.cfg.Embedded))
	for p := range c.cfg.Embedded {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		fsys := c.cfg.Embedded[prefix]
		want := map[string]Entry{}
		for _, e := range m.Files {
			if strings.HasPrefix(e.Path, prefix+"/") {
				want[e.Path] = e
			}
		}
		var have []string
		err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				have = append(have, p)
			}
			return nil
		})
		if err != nil {
			res.fail(prefix, ProblemUnreadable)
			continue
		}
		for _, p := range have {
			if err := ctx.Err(); err != nil {
				return ErrInterrupted
			}
			full := path.Join(prefix, p)
			e, ok := want[full]
			if !ok {
				res.fail(full, ProblemExtra)
				continue
			}
			delete(want, full)
			f, err := fsys.Open(p)
			if err != nil {
				res.fail(full, ProblemUnreadable)
				continue
			}
			c.compare(res, e, f)
			_ = f.Close() //nolint:gosec // G104: файл встроенного набора только читался
		}
		missing := make([]string, 0, len(want))
		for p := range want {
			missing = append(missing, p)
		}
		sort.Strings(missing)
		for _, p := range missing {
			res.fail(p, ProblemMissing)
		}
	}
	return nil
}

// onDisk — файл манифеста сверяется с диском: все невстроенные при
// AllFiles, иначе — из каталогов DiskPrefixes.
func (c *Checker) onDisk(e Entry) bool {
	if e.Kind.Embedded() {
		return false
	}
	if c.cfg.AllFiles {
		return true
	}
	for _, p := range c.cfg.DiskPrefixes {
		if strings.HasPrefix(e.Path, p) {
			return true
		}
	}
	return false
}

// checkDisk сверяет невстроенные файлы манифеста с каталогом установки.
// Файлы читаются через os.Root: ссылка за пределы корня не открывается.
func (c *Checker) checkDisk(ctx context.Context, res *Result, m *Manifest) error {
	if !c.cfg.AllFiles && len(c.cfg.DiskPrefixes) == 0 {
		return nil
	}
	root, err := os.OpenRoot(filepath.Dir(c.cfg.ManifestPath))
	if err != nil {
		for _, e := range m.Files {
			if c.onDisk(e) {
				res.fail(e.Path, ProblemUnreadable)
			}
		}
		return nil
	}
	defer root.Close() //nolint:errcheck // каталог только читается
	for _, e := range m.Files {
		if !c.onDisk(e) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return ErrInterrupted
		}
		info, err := root.Lstat(e.Path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			res.fail(e.Path, ProblemMissing)
			continue
		case err != nil:
			res.fail(e.Path, ProblemUnreadable)
			continue
		case !info.Mode().IsRegular():
			res.fail(e.Path, ProblemNotRegular)
			continue
		}
		f, err := root.Open(e.Path)
		if err != nil {
			res.fail(e.Path, ProblemUnreadable)
			continue
		}
		c.compare(res, e, f)
		_ = f.Close() //nolint:gosec // G104: файл только читался
	}
	return nil
}

func (c *Checker) checkWatched(res *Result) {
	paths := make([]string, 0, len(c.watched))
	for p := range c.watched {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		sum, err := c.hashPath(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			res.fail(p, ProblemMissing)
		case err != nil:
			res.fail(p, ProblemUnreadable)
		case !bytes.Equal(sum, c.watched[p]):
			res.fail(p, ProblemChanged)
		}
	}
}

// compare сверяет размер и хеш файла с записью; размер — до хеширования.
func (c *Checker) compare(res *Result, e Entry, f fs.File) {
	info, err := f.Stat()
	if err != nil {
		res.fail(e.Path, ProblemUnreadable)
		return
	}
	if !info.Mode().IsRegular() {
		res.fail(e.Path, ProblemNotRegular)
		return
	}
	if info.Size() != e.Size {
		res.fail(e.Path, ProblemSize)
		return
	}
	sum, n, err := hashReader(f, e.Size, c.hasher)
	if err != nil || n != e.Size {
		// Файл меняется во время чтения или длиннее заявленного.
		res.fail(e.Path, ProblemModified)
		return
	}
	res.Checked++
	if hex.EncodeToString(sum) != e.Hash {
		res.fail(e.Path, ProblemModified)
	}
}

func (c *Checker) hashPath(p string) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // G304: путь к конфигурации задаёт администратор параметром запуска
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // файл только читается
	sum, _, err := hashReader(f, MaxFileSize, c.hasher)
	return sum, err
}

// readLimited читает обычный файл не больше limit байт.
func readLimited(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // G304: путь к манифесту задаёт администратор или он рядом с бинарником
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // файл только читается
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: не обычный файл", p)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: файл больше %d байт", p, limit)
	}
	return data, nil
}
