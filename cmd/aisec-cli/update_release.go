package main

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
	"regexp"
	"strings"
	"syscall"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Выпуск для обновления (ADR-0036, раздел 2): проверка подписи и состава
// до любых действий, копия в каталог версии со сверкой хеша при
// копировании, атомарное переключение ссылки.

const (
	// maxReleaseBytes — предел суммы размеров файлов выпуска.
	maxReleaseBytes = 16 << 30
	// spaceMargin — запас места сверх размера выпуска и копии БД.
	spaceMargin = 64 << 20
	// installLink и releasesDir — внутри <корень>/opt.
	installLink = "aisec"
	releasesDir = "aisec-releases"
	stagingPref = ".staging-"
)

// Типы сетевых файловых систем (statfs f_type): источник обновления на них
// отвергается (ОБН.3 — только локальный каталог или носитель).
var networkFS = map[int64]string{
	0x6969:     "NFS",
	0xFF534D42: "CIFS",
	0xFE534D42: "SMB2",
	0x517B:     "SMB",
	0x65735546: "FUSE",
	0x01021997: "9p",
	0x00C36400: "Ceph",
	0x5346414F: "AFS",
	0x47504653: "GPFS",
	0x0BD00BD0: "Lustre",
}

// releaseInfo — проверенный выпуск: байты манифеста и подписи держатся в
// памяти и копируются в установку как есть, файлы сверяются с ними.
type releaseInfo struct {
	Dir        string
	Manifest   *integrity.Manifest
	Data, Sig  []byte
	SHA256     string
	ID         string
	Component  string
	TestSigned bool
	Bytes      int64
}

// versionRe — символы версии, допустимые в имени каталога версии.
var versionRe = regexp.MustCompile(`^[0-9A-Za-z._+~-]{1,64}$`)

// releaseID — имя каталога версии: версия и 12 знаков SHA-256 манифеста.
func releaseID(version, sum string) string {
	if versionRe.MatchString(version) {
		return version + "-" + sum[:12]
	}
	return sum[:12]
}

// readManifestPair читает манифест и подпись (обычные файлы, не ссылки) и
// проверяет подпись ключом, встроенным в этот aisec-cli.
func readManifestPair(p aisecCrypto.Provider, dir string) (*releaseInfo, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("каталог выпуска: %w", err)
	}
	defer root.Close() //nolint:errcheck // каталог только читается
	read := func(name string, limit int64) ([]byte, error) {
		info, err := root.Lstat(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s — не обычный файл (ссылка или каталог)", name)
		}
		if info.Size() > limit {
			return nil, fmt.Errorf("%s больше %d байт", name, limit)
		}
		return root.ReadFile(name)
	}
	data, err := read(integrity.ManifestFile, integrity.MaxManifestSize)
	if err != nil {
		return nil, err
	}
	sig, err := read(integrity.SignatureFile, 64<<10)
	if err != nil {
		return nil, err
	}
	v, testKey, err := integrity.EmbeddedVerifier(p)
	if err != nil {
		return nil, err
	}
	if err := integrity.VerifySignature(v, data, sig); err != nil {
		return nil, errors.New("подпись манифеста неверна: выпуск подписан не ключом производителя этой версии")
	}
	m, err := integrity.Parse(data)
	if err != nil {
		return nil, err
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	if m.Profile != p.Name() || m.HashAlg != h.Name() {
		return nil, errors.New("манифест другого криптопрофиля")
	}
	sum := hex.EncodeToString(sha256Of(p, data))
	return &releaseInfo{Dir: dir, Manifest: m, Data: data, Sig: sig, SHA256: sum, ID: releaseID(m.Version, sum), TestSigned: testKey}, nil
}

// sha256Of — хеш профиля (SHA-256 в standard): им же считается ID каталога.
func sha256Of(p aisecCrypto.Provider, data []byte) []byte {
	h, err := p.Hasher()
	if err != nil {
		return make([]byte, 32)
	}
	return h.Sum(data)
}

// componentOf — компонент по исполняемым файлам манифеста.
func componentOf(m *integrity.Manifest) (string, error) {
	bins := map[string]bool{}
	for _, e := range m.Files {
		if e.Kind == integrity.KindBinary {
			bins[path.Base(e.Path)] = true
		}
	}
	switch {
	case bins["aisec-server"] && bins["aisec-gateway"] && bins["aisec-cli"]:
		return componentMain, nil
	case len(bins) == 1 && bins["aisec-ml"]:
		return componentML, nil
	case len(bins) == 1 && bins["aisec-media"]:
		return componentMedia, nil
	}
	return "", errors.New("в манифесте нет набора исполняемых файлов основного выпуска, aisec-ml или aisec-media")
}

// checkSourceDir — источник только локальный (ОБН.3).
func checkSourceDir(dir string) error {
	if strings.Contains(dir, "://") {
		return errors.New("источник — только локальный каталог или носитель: загрузка по сети не поддерживается (ОБН.3)")
	}
	if !filepath.IsAbs(dir) {
		return errors.New("каталог выпуска — абсолютный путь")
	}
	info, err := os.Lstat(dir) //nolint:gosec // G703: каталог выпуска указал root в аргументе команды
	if err != nil {
		return fmt.Errorf("каталог выпуска: %w", err)
	}
	if !info.IsDir() {
		return errors.New("каталог выпуска — не каталог (ссылка или файл)")
	}
	var st syscall.Statfs_t                          //nolint:forbidigo // ADR-0036, раздел 2: тип файловой системы источника (ОБН.3)
	if err := syscall.Statfs(dir, &st); err != nil { //nolint:forbidigo // ADR-0036, раздел 2: тип файловой системы источника (ОБН.3)
		return fmt.Errorf("каталог выпуска: %w", err)
	}
	if name, ok := networkFS[st.Type]; ok { //nolint:forbidigo // ADR-0036, раздел 2: поле результата statfs
		return fmt.Errorf("каталог выпуска на сетевой файловой системе (%s): скопируйте выпуск на носитель или локальный диск (ОБН.3)", name)
	}
	return nil
}

// freeBytes — свободное место для root в каталоге.
func freeBytes(dir string) (int64, error) {
	var st syscall.Statfs_t                          //nolint:forbidigo // ADR-0036, раздел 2: свободное место до действий
	if err := syscall.Statfs(dir, &st); err != nil { //nolint:forbidigo // ADR-0036, раздел 2: свободное место до действий
		return 0, err
	}
	free := st.Bavail * uint64(st.Bsize) //nolint:forbidigo,gosec // ADR-0036, раздел 2: поля результата statfs; G115: размер блока положителен
	if free > 1<<62 {
		free = 1 << 62
	}
	return int64(free), nil //nolint:gosec // G115: ограничено выше
}

// releaseBytes — сумма размеров невстроенных файлов; превышение предела —
// отказ.
func releaseBytes(m *integrity.Manifest) (int64, error) {
	var total int64
	for _, e := range m.Files {
		if e.Kind.Embedded() {
			continue
		}
		total += e.Size
		if total > maxReleaseBytes {
			return 0, fmt.Errorf("выпуск больше %d ГиБ", maxReleaseBytes>>30)
		}
	}
	return total, nil
}

// copyRelease сверяет файлы выпуска с манифестом и, если dst не пуст,
// копирует их туда; хеш считается по тем же байтам, что пишутся, поэтому
// подмена файла на носителе между проверкой и копированием обнаруживается
// (ADR-0036, раздел 3, шаг 5).
func copyRelease(ctx context.Context, p aisecCrypto.Provider, rel *releaseInfo, dst string) error {
	h, err := p.Hasher()
	if err != nil {
		return err
	}
	src, err := os.OpenRoot(rel.Dir)
	if err != nil {
		return err
	}
	defer src.Close() //nolint:errcheck // каталог только читается
	var out *os.Root
	if dst != "" {
		if out, err = os.OpenRoot(dst); err != nil {
			return err
		}
		defer out.Close() //nolint:errcheck // закрывается после записи всех файлов
	}
	files := 0
	for _, e := range rel.Manifest.Files {
		if e.Kind.Embedded() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := integrity.ValidPath(e.Path); err != nil {
			return err
		}
		if err := copyEntry(src, out, h, e); err != nil {
			return err
		}
		files++
	}
	if files == 0 {
		return errors.New("в манифесте нет ни одного файла на диске")
	}
	if out == nil {
		return nil
	}
	for name, data := range map[string][]byte{integrity.ManifestFile: rel.Data, integrity.SignatureFile: rel.Sig} {
		if err := writeNew(out, name, bytes.NewReader(data), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func copyEntry(src, out *os.Root, h aisecCrypto.Hasher, e integrity.Entry) error {
	info, err := src.Lstat(e.Path)
	if err != nil {
		return fmt.Errorf("%s: файл отсутствует или недоступен", e.Path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: не обычный файл (ссылка или каталог)", e.Path)
	}
	if info.Size() != e.Size {
		return fmt.Errorf("%s: размер не совпадает с манифестом", e.Path)
	}
	f, err := src.Open(e.Path)
	if err != nil {
		return fmt.Errorf("%s: %w", e.Path, err)
	}
	defer f.Close() //nolint:errcheck // файл только читается
	hs := h.New()
	r := io.TeeReader(io.LimitReader(f, e.Size+1), hs)
	if out == nil {
		n, err := io.Copy(io.Discard, r)
		if err != nil {
			return fmt.Errorf("%s: %w", e.Path, err)
		}
		return compareEntry(e, n, hs.Sum(nil))
	}
	if err := mkdirAllIn(out, path.Dir(e.Path)); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if e.Kind == integrity.KindBinary || e.Kind == integrity.KindLibrary {
		mode = 0o755
	}
	cw := &countWriter{}
	if err := writeNew(out, e.Path, io.TeeReader(r, cw), mode); err != nil {
		return err
	}
	return compareEntry(e, cw.n, hs.Sum(nil))
}

func compareEntry(e integrity.Entry, n int64, sum []byte) error {
	if n != e.Size {
		return fmt.Errorf("%s: размер изменился при чтении", e.Path)
	}
	if hex.EncodeToString(sum) != e.Hash {
		return fmt.Errorf("%s: содержимое не совпадает с подписанным манифестом", e.Path)
	}
	return nil
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(b []byte) (int, error) { c.n += int64(len(b)); return len(b), nil }

// writeNew создаёт файл с O_EXCL, пишет, fsync и выставляет права.
func writeNew(root *os.Root, name string, r io.Reader, mode os.FileMode) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close() //nolint:gosec // G104: исходная ошибка важнее
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close() //nolint:gosec // G104: исходная ошибка важнее
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close() //nolint:gosec // G104: исходная ошибка важнее
		return err
	}
	return f.Close()
}

// mkdirAllIn создаёт каталоги пути внутри root с правами 0755.
func mkdirAllIn(root *os.Root, dir string) error {
	if dir == "." || dir == "" {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(dir, "/") {
		cur = path.Join(cur, part)
		if err := root.Mkdir(cur, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err := root.Lstat(cur)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s — не каталог", cur)
		}
		if err := root.Chmod(cur, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// layout — раскладка компонента: <корень>/opt/aisec — ссылка на
// aisec-releases/<ID> (ADR-0036, раздел 3).
type layout struct {
	Root     string // корень компонента: «/», /opt/aisec-ml, /opt/aisec-media
	OwnerUID int
}

func (l layout) optDir() string   { return filepath.Join(l.Root, "opt") }
func (l layout) link() string     { return filepath.Join(l.optDir(), installLink) }
func (l layout) releases() string { return filepath.Join(l.optDir(), releasesDir) }
func (l layout) release(id string) string {
	return filepath.Join(l.releases(), id)
}

// installed — что сейчас по пути установки: ссылка на каталог версии (id)
// или каталог (раскладка без версий, adopt).
func (l layout) installed() (id string, isDir bool, err error) {
	info, err := os.Lstat(l.link())
	if err != nil {
		return "", false, fmt.Errorf("установка %s: %w", l.link(), err)
	}
	if info.IsDir() {
		return "", true, nil
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		return "", false, fmt.Errorf("%s — не каталог и не ссылка", l.link())
	}
	target, err := os.Readlink(l.link())
	if err != nil {
		return "", false, err
	}
	dir, id, ok := strings.Cut(target, "/")
	if !ok || dir != releasesDir || !releaseIDRe.MatchString(id) {
		return "", false, fmt.Errorf("%s указывает не на каталог версии (%s)", l.link(), target)
	}
	return id, false, nil
}

// checkDirs — каталоги раскладки принадлежат root и не доступны на запись
// группе и остальным: иначе пользователь службы мог бы подложить выпуск.
func (l layout) checkDirs() error {
	if err := checkOwnedDir(l.optDir(), 0o755, l.OwnerUID); err != nil {
		return err
	}
	if _, err := os.Lstat(l.releases()); err == nil {
		return checkOwnedDir(l.releases(), 0o755, l.OwnerUID)
	}
	return nil
}

// stage копирует выпуск в .staging-<ID> и переименовывает в <ID>; прежний
// незавершённый каталог удаляется — ему не доверяют.
func (l layout) stage(ctx context.Context, p aisecCrypto.Provider, rel *releaseInfo) error {
	if err := ensureOwnedDir(l.releases(), 0o755, l.OwnerUID); err != nil {
		return err
	}
	if err := os.Chmod(l.releases(), 0o755); err != nil { //nolint:gosec // G302: каталог выпусков root 0755 — службы читают свои программы (ADR-0036, раздел 3)
		return err
	}
	tmp := filepath.Join(l.releases(), stagingPref+rel.ID)
	final := l.release(rel.ID)
	for _, d := range []string{tmp, final} {
		if err := os.RemoveAll(d); err != nil { //nolint:gosec // G703: ID выпуска проверен releaseIDRe, каталог — свой
			return err
		}
	}
	if err := os.Mkdir(tmp, 0o755); err != nil { //nolint:gosec // G301: каталог версии root 0755 — службы читают свои программы (ADR-0036, раздел 3)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil { //nolint:gosec // G302: каталог версии root 0755 — права не зависят от umask
		return err
	}
	if err := copyRelease(ctx, p, rel, tmp); err != nil {
		return err
	}
	if err := updSyncDir(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil { //nolint:gosec // G703: ID выпуска проверен releaseIDRe, каталог — свой
		return err
	}
	if err := updSyncDir(l.releases()); err != nil {
		return err
	}
	// Повторная проверка уже в установке — тем же кодом, что verify -release.
	checker, err := integrity.NewChecker(integrity.Config{
		Component: "cli", Provider: p, ManifestPath: filepath.Join(final, integrity.ManifestFile), AllFiles: true,
	})
	if err != nil {
		return err
	}
	res, err := checker.Check(ctx, integrity.TriggerManual)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("копия выпуска не прошла проверку: %s", reasonText(res.Reason))
	}
	return nil
}

// adopt — переход на раскладку версий: каталог установки становится
// каталогом версии id, на его место — ссылка. Повторный вызов после
// прерывания доводит переход.
func (l layout) adopt(id string) error {
	if err := ensureOwnedDir(l.releases(), 0o755, l.OwnerUID); err != nil {
		return err
	}
	info, err := os.Lstat(l.link())
	switch {
	case err == nil && info.IsDir():
		if _, err := os.Lstat(l.release(id)); err == nil {
			return fmt.Errorf("%s уже существует: переход на раскладку версий не выполнен", l.release(id))
		}
		if err := os.Rename(l.link(), l.release(id)); err != nil {
			return err
		}
		if err := updSyncDir(l.optDir()); err != nil {
			return err
		}
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	return l.switchTo(id)
}

// switchTo атомарно направляет ссылку установки на каталог версии id:
// новая ссылка создаётся рядом и переименовывается поверх прежней.
func (l layout) switchTo(id string) error {
	if !releaseIDRe.MatchString(id) {
		return errors.New("неверный каталог версии")
	}
	info, err := os.Lstat(l.release(id))
	if err != nil || !info.IsDir() {
		return fmt.Errorf("каталога версии %s нет", id)
	}
	if cur, err := os.Lstat(l.link()); err == nil && cur.IsDir() {
		return fmt.Errorf("%s — каталог, а не ссылка: переключение невозможно", l.link())
	}
	tmp := filepath.Join(l.optDir(), ".aisec-link-"+id)
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Symlink(releasesDir+"/"+id, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, l.link()); err != nil {
		return err
	}
	return updSyncDir(l.optDir())
}

// prune удаляет каталоги версий, кроме keep, и незавершённые копии.
// drop удаляет каталог выпуска id и его недописанную копию (после отката).
func (l layout) drop(id string) error {
	if !releaseIDRe.MatchString(id) {
		return errors.New("неверный ID выпуска")
	}
	for _, name := range []string{id, stagingPref + id} {
		if err := os.RemoveAll(filepath.Join(l.releases(), name)); err != nil { //nolint:gosec // G703: ID выпуска проверен releaseIDRe, каталог — свой
			return err
		}
	}
	if _, err := os.Lstat(l.releases()); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return updSyncDir(l.releases())
}

func (l layout) prune(keep ...string) error {
	entries, err := os.ReadDir(l.releases())
	if err != nil {
		return err
	}
	kept := map[string]bool{}
	for _, k := range keep {
		kept[k] = true
	}
	for _, e := range entries {
		if kept[e.Name()] {
			continue
		}
		if !releaseIDRe.MatchString(e.Name()) && !strings.HasPrefix(e.Name(), stagingPref) {
			continue // чужое имя не трогаем
		}
		if err := os.RemoveAll(filepath.Join(l.releases(), e.Name())); err != nil {
			return err
		}
	}
	return updSyncDir(l.releases())
}

// installedRelease — подписанный манифест текущей установки компонента.
func (l layout) installedRelease(p aisecCrypto.Provider) (*releaseInfo, error) {
	return readManifestPair(p, l.link())
}

// migrationEntries — миграции из манифеста по порядку пути.
func migrationEntries(m *integrity.Manifest) ([]store.Applied, error) {
	var out []store.Applied
	for _, e := range m.Files {
		if e.Kind != integrity.KindMigration {
			continue
		}
		v, name, err := store.ParseMigrationName(path.Base(e.Path))
		if err != nil {
			return nil, fmt.Errorf("миграция %s: %w", e.Path, err)
		}
		out = append(out, store.Applied{Version: v, Name: name, Checksum: e.Hash})
	}
	for i, a := range out {
		if a.Version != i+1 {
			return nil, errors.New("миграции в манифесте идут не подряд с 0001")
		}
	}
	return out, nil
}

// checkSchema — применённые миграции — начало миграций выпуска: те же
// номера, имена и хеши (ADR-0036, раздел 2). Возвращает число новых.
func checkSchema(applied []store.Applied, m *integrity.Manifest) (pending int, err error) {
	want, err := migrationEntries(m)
	if err != nil {
		return 0, err
	}
	if len(applied) > len(want) {
		return 0, fmt.Errorf("в БД %d миграций, в выпуске %d: база новее выпуска, откат без восстановления копии невозможен", len(applied), len(want))
	}
	for i, a := range applied {
		w := want[i]
		if a.Version != w.Version || a.Name != w.Name {
			return 0, fmt.Errorf("миграция %04d_%s в БД не совпадает с %04d_%s выпуска", a.Version, a.Name, w.Version, w.Name)
		}
		if a.Checksum != w.Checksum {
			return 0, fmt.Errorf("миграция %04d_%s в выпуске изменена после применения", a.Version, a.Name)
		}
	}
	return len(want) - len(applied), nil
}

// newUpdateID — ID обновления по времени начала.
func newUpdateID(now time.Time) string { return now.UTC().Format("20060102T150405Z") }
