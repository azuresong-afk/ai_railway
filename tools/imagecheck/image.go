package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Проверка образа поставки (ЗИ.5, ADR-0019) по архиву docker save — без
// запуска контейнера: настройки образа (пользователь, порты, точка входа) и
// полный список файлов всех слоёв. В образе разрешены только каталоги
// установки, манифест целостности с подписью и бинарники этого образа;
// оболочка, пакетный менеджер и любой другой файл — нарушение.

// imageRule — что должно быть в образе.
type imageRule struct {
	Bins  []string // бинарники в /opt/aisec/bin
	Ports []string // EXPOSE, «порт/tcp»
}

// productCmds — бинарники поставки (PRODUCT_CMDS в Makefile).
var productCmds = []string{"aisec-cli", "aisec-gateway", "aisec-media", "aisec-server"}

var imageRules = map[string]imageRule{
	"aisec-server":  {Bins: []string{"aisec-server"}, Ports: []string{"8444/tcp", "8445/tcp"}},
	"aisec-gateway": {Bins: []string{"aisec-gateway"}, Ports: []string{"8443/tcp"}},
	// aisec-cli — полный выпуск: aisec-cli verify сверяет все файлы манифеста.
	"aisec-cli": {Bins: productCmds},
}

const (
	installDir    = "opt/aisec"
	binDir        = installDir + "/bin"
	manifestFile  = installDir + "/aisec-manifest.json"
	signatureFile = manifestFile + ".sig"
	runUser       = "65534:65534"
	labelKind     = "ru.aisec.build-kind"
	labelVersion  = "org.opencontainers.image.version"

	maxJSON    = 1 << 20   // manifest.json, index.json, настройки образа
	maxFile    = 256 << 20 // бинарник или файл манифеста внутри слоя
	maxEntries = 10000     // записей в архиве и в каждом слое
	maxArchive = 2 << 30   // весь архив
	maxLayers  = 64
	maxSmall   = 16 << 20  // все небольшие blob первого прохода вместе
	maxLayer   = 1 << 30   // распакованный слой: защита от gzip-бомбы
	maxData    = 512 << 20 // содержимое бинарников и манифеста во всех слоях
	gzipMagic0 = 0x1f
	gzipMagic1 = 0x8b
)

// forbiddenNames — оболочки и пакетные менеджеры: для них отдельное
// сообщение, хотя любой лишний файл — уже нарушение.
var forbiddenNames = map[string]bool{
	"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true, "ksh": true,
	"busybox": true, "toybox": true, "su": true, "sudo": true,
	"apk": true, "apt": true, "apt-get": true, "dpkg": true, "rpm": true,
	"yum": true, "dnf": true, "microdnf": true, "pip": true, "pip3": true,
}

// dockerManifest — запись manifest.json архива docker save.
type dockerManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// imageConfig — нужные поля настроек образа (OCI image config).
type imageConfig struct {
	OS     string `json:"os"`
	Config struct {
		User         string              `json:"User"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Env          []string            `json:"Env"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		Volumes      map[string]struct{} `json:"Volumes"`
		Labels       map[string]string   `json:"Labels"`
	} `json:"config"`
	RootFS struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// fileEntry — файл слоя.
type fileEntry struct {
	Type     byte
	Mode     int64
	UID, GID int
	Xattrs   []string // имена расширенных атрибутов (security.capability и т. п.)
	Data     []byte   // только для бинарников и манифеста
}

// image — разобранный архив.
type image struct {
	Tag    string
	Name   string // последний элемент репозитория: aisec-server
	Config imageConfig
	Files  map[string]fileEntry
}

// parseDockerManifest разбирает manifest.json: ровно один образ с одним тегом.
func parseDockerManifest(data []byte) (dockerManifest, error) {
	var ms []dockerManifest
	if err := json.Unmarshal(data, &ms); err != nil {
		return dockerManifest{}, fmt.Errorf("manifest.json: %w", err)
	}
	if len(ms) != 1 {
		return dockerManifest{}, fmt.Errorf("manifest.json: ожидается один образ, найдено %d", len(ms))
	}
	m := ms[0]
	if len(m.RepoTags) != 1 {
		return dockerManifest{}, fmt.Errorf("manifest.json: ожидается один тег образа, найдено %d", len(m.RepoTags))
	}
	if len(m.Layers) == 0 || len(m.Layers) > maxLayers {
		return dockerManifest{}, fmt.Errorf("manifest.json: слоёв %d, ожидается от 1 до %d", len(m.Layers), maxLayers)
	}
	for _, p := range append([]string{m.Config}, m.Layers...) {
		if !blobPath(p) {
			return dockerManifest{}, fmt.Errorf("manifest.json: путь %q — не blobs/sha256/<hex>", p)
		}
	}
	return m, nil
}

// blobPath — путь вида blobs/sha256/<64 hex>.
func blobPath(p string) bool {
	h, ok := strings.CutPrefix(p, "blobs/sha256/")
	if !ok || len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil && strings.ToLower(h) == h
}

// parseConfig разбирает настройки образа.
func parseConfig(data []byte) (imageConfig, error) {
	var c imageConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return imageConfig{}, fmt.Errorf("настройки образа: %w", err)
	}
	return c, nil
}

// imageName — имя образа из тега: «реестр/репозиторий/aisec-server:тег» → aisec-server.
func imageName(tag string) string {
	repo := tag
	if i := strings.LastIndexByte(tag, ':'); i > strings.LastIndexByte(tag, '/') {
		repo = tag[:i]
	}
	return path.Base(repo)
}

// loadImage читает архив docker save в два прохода: сначала manifest.json и
// настройки, затем слои по порядку. Хеш каждого blob сверяется с его именем,
// хеш распакованного слоя — с diff_ids настроек.
func loadImage(archivePath string, hasher aisecCrypto.Hasher) (*image, error) {
	small := map[string][]byte{}
	smallTotal := 0
	if err := walkArchive(archivePath, func(name string, r io.Reader) error {
		if name != "manifest.json" && !blobPath(name) {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(r, maxJSON+1))
		if err != nil {
			return err
		}
		if len(data) <= maxJSON {
			if smallTotal += len(data); smallTotal > maxSmall {
				return fmt.Errorf("небольших blob больше %d байт", maxSmall)
			}
			small[name] = data
		}
		return nil
	}); err != nil {
		return nil, err
	}
	mdata, ok := small["manifest.json"]
	if !ok {
		return nil, errors.New("в архиве нет manifest.json (ожидается архив docker save)")
	}
	m, err := parseDockerManifest(mdata)
	if err != nil {
		return nil, err
	}
	cdata, ok := small[m.Config]
	if !ok {
		return nil, fmt.Errorf("в архиве нет настроек образа %s", m.Config)
	}
	if err := checkDigest(m.Config, cdata, hasher); err != nil {
		return nil, err
	}
	cfg, err := parseConfig(cdata)
	if err != nil {
		return nil, err
	}
	if len(cfg.RootFS.DiffIDs) != len(m.Layers) {
		return nil, fmt.Errorf("слоёв в manifest.json %d, в настройках %d", len(m.Layers), len(cfg.RootFS.DiffIDs))
	}
	img := &image{Tag: m.RepoTags[0], Name: imageName(m.RepoTags[0]), Config: cfg, Files: map[string]fileEntry{}}

	layers := map[string][]int{}
	for i, l := range m.Layers {
		layers[l] = append(layers[l], i)
	}
	perLayer := make([]map[string]fileEntry, len(m.Layers))
	budget := int64(maxData)
	err = walkArchive(archivePath, func(name string, r io.Reader) error {
		idx, ok := layers[name]
		if !ok || perLayer[idx[0]] != nil {
			return nil
		}
		files, err := readLayer(name, r, hasher, cfg.RootFS.DiffIDs[idx[0]], &budget)
		if err != nil {
			return err
		}
		for _, i := range idx {
			perLayer[i] = files
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i, files := range perLayer {
		if files == nil {
			return nil, fmt.Errorf("в архиве нет слоя %s", m.Layers[i])
		}
		for p, f := range files {
			img.Files[p] = f
		}
	}
	return img, nil
}

// walkArchive обходит записи архива и передаёт обычные файлы fn.
func walkArchive(archivePath string, fn func(name string, r io.Reader) error) error {
	f, err := os.Open(archivePath) //nolint:gosec // G304: путь к архиву образа задаёт Makefile
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	tr := tar.NewReader(io.LimitReader(f, maxArchive))
	for n := 0; ; n++ {
		if n > maxEntries {
			return fmt.Errorf("%s: больше %d записей", archivePath, maxEntries)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", archivePath, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := fn(path.Clean(hdr.Name), tr); err != nil {
			return fmt.Errorf("%s: %s: %w", archivePath, hdr.Name, err)
		}
	}
}

func checkDigest(blob string, data []byte, hasher aisecCrypto.Hasher) error {
	want := strings.TrimPrefix(blob, "blobs/sha256/")
	if got := hex.EncodeToString(hasher.Sum(data)); got != want {
		return fmt.Errorf("%s: хеш содержимого %s не совпадает с именем", blob, got)
	}
	return nil
}

// layerLimit — предел распакованного слоя (maxLayer; тесты уменьшают).
var layerLimit int64 = maxLayer

// errLayerTooBig — распакованный слой больше layerLimit.
var errLayerTooBig = errors.New("распакованный слой больше предела")

// capReader — чтение не больше n байт; дальше — ошибка, а не тихий обрыв,
// иначе хеш обрезанного слоя сверялся бы как полного.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, errLayerTooBig
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	k, err := c.r.Read(p)
	c.n -= int64(k)
	return k, err
}

// readLayer читает слой (tar или tar+gzip): хеш blob сверяется с именем,
// хеш распакованного tar — с diffID. Бинарники и манифест сохраняются целиком
// в пределах общего бюджета budget (maxData на образ).
func readLayer(blob string, r io.Reader, hasher aisecCrypto.Hasher, diffID string, budget *int64) (map[string]fileEntry, error) {
	blobHash := hasher.New()
	br := bufio.NewReader(io.TeeReader(r, blobHash))
	var layer io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == gzipMagic0 && magic[1] == gzipMagic1 {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		gz.Multistream(false)
		layer = gz
	}
	diffHash := hasher.New()
	unpacked := io.TeeReader(&capReader{r: layer, n: layerLimit}, diffHash)
	tr := tar.NewReader(unpacked)
	files := map[string]fileEntry{}
	for n := 0; ; n++ {
		if n > maxEntries {
			return nil, fmt.Errorf("больше %d записей в слое", maxEntries)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if name == "" {
			continue
		}
		e := fileEntry{Type: hdr.Typeflag, Mode: hdr.Mode, UID: hdr.Uid, GID: hdr.Gid}
		for k := range hdr.PAXRecords {
			if x, ok := strings.CutPrefix(k, "SCHILY.xattr."); ok {
				e.Xattrs = append(e.Xattrs, x)
			}
		}
		sort.Strings(e.Xattrs)
		if hdr.Typeflag == tar.TypeReg && (path.Dir(name) == binDir || name == manifestFile || name == signatureFile) {
			if hdr.Size > maxFile {
				return nil, fmt.Errorf("%s больше %d байт", name, maxFile)
			}
			if *budget -= hdr.Size; *budget < 0 {
				return nil, fmt.Errorf("%s: бинарников и манифеста в образе больше %d байт", name, maxData)
			}
			if e.Data, err = io.ReadAll(io.LimitReader(tr, maxFile)); err != nil {
				return nil, err
			}
		}
		files[name] = e
	}
	// Остаток слоя (выравнивание tar) — в хеши.
	if _, err := io.Copy(io.Discard, unpacked); err != nil {
		return nil, err
	}
	if _, err := io.Copy(io.Discard, br); err != nil {
		return nil, err
	}
	if got := "sha256:" + hex.EncodeToString(diffHash.Sum(nil)); got != diffID {
		return nil, fmt.Errorf("хеш распакованного слоя %s не совпадает с diff_id %s", got, diffID)
	}
	if got := hex.EncodeToString(blobHash.Sum(nil)); got != strings.TrimPrefix(blob, "blobs/sha256/") {
		return nil, fmt.Errorf("хеш слоя %s не совпадает с именем", got)
	}
	return files, nil
}

// checkImage проверяет образ по правилу его имени. kind — release или test
// (метка ru.aisec.build-kind); release — каталог выпуска, с которым
// побайтно сравниваются бинарники, манифест и подпись (пусто — без сверки).
func checkImage(img *image, kind, release string) []string {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	rule, ok := imageRules[img.Name]
	if !ok {
		add("неизвестный образ %q: ожидается один из aisec-server, aisec-gateway, aisec-cli", img.Name)
		return problems
	}
	c := img.Config.Config
	if img.Config.OS != "linux" {
		add("ОС образа %q, ожидается linux", img.Config.OS)
	}
	if c.User != runUser {
		add("пользователь %q, ожидается %s (не root)", c.User, runUser)
	}
	ports := make([]string, 0, len(c.ExposedPorts))
	for p := range c.ExposedPorts {
		ports = append(ports, p)
	}
	sort.Strings(ports)
	want := slices.Clone(rule.Ports)
	sort.Strings(want)
	if !slices.Equal(ports, want) {
		add("порты %v, ожидаются %v", ports, want)
	}
	if entry := []string{"/" + binDir + "/" + img.Name}; !slices.Equal(c.Entrypoint, entry) || len(c.Cmd) > 0 {
		add("точка входа %v %v, ожидается %v без Cmd", c.Entrypoint, c.Cmd, entry)
	}
	for _, e := range c.Env {
		if !strings.HasPrefix(e, "PATH=") {
			add("переменная окружения в образе: %s", strings.SplitN(e, "=", 2)[0])
		}
	}
	if len(c.Volumes) > 0 {
		add("в образе объявлены тома: %d", len(c.Volumes))
	}
	if c.Labels[labelKind] != kind {
		add("метка %s=%q, ожидается %q", labelKind, c.Labels[labelKind], kind)
	}
	if c.Labels[labelVersion] == "" {
		add("нет метки %s", labelVersion)
	}
	problems = append(problems, checkFiles(img, rule)...)
	if release != "" {
		problems = append(problems, checkRelease(img, rule, release)...)
	}
	return problems
}

// checkFiles сверяет файлы образа с разрешённым списком.
func checkFiles(img *image, rule imageRule) []string {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	dirs := map[string]bool{"opt": true, installDir: true, binDir: true}
	files := map[string]bool{manifestFile: true, signatureFile: true}
	for _, b := range rule.Bins {
		files[binDir+"/"+b] = true
	}
	names := make([]string, 0, len(img.Files))
	for n := range img.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := img.Files[n]
		base := path.Base(n)
		switch {
		case strings.HasPrefix(base, ".wh."):
			add("/%s: удаление файла слоем (whiteout) — образ собирается одним проходом", n)
			continue
		case forbiddenNames[base]:
			add("/%s: оболочка или пакетный менеджер", n)
			continue
		case dirs[n]:
			if f.Type != tar.TypeDir {
				add("/%s: ожидается каталог", n)
			}
		case files[n]:
			if f.Type != tar.TypeReg {
				add("/%s: ожидается обычный файл", n)
			}
		default:
			add("/%s: лишний файл в образе", n)
			continue
		}
		if f.UID != 0 || f.GID != 0 {
			add("/%s: владелец %d:%d, ожидается 0:0", n, f.UID, f.GID)
		}
		if f.Mode&0o7000 != 0 {
			add("/%s: биты setuid, setgid или sticky (%04o)", n, f.Mode&0o7777)
		}
		if f.Mode&0o022 != 0 {
			add("/%s: запись доступна группе или остальным (%04o)", n, f.Mode&0o7777)
		}
		if len(f.Xattrs) > 0 {
			add("/%s: расширенные атрибуты %s (в том числе возможны capabilities)", n, strings.Join(f.Xattrs, ", "))
		}
	}
	for n := range files {
		if _, ok := img.Files[n]; !ok {
			add("/%s: нет в образе", n)
		}
	}
	for _, b := range rule.Bins {
		f, ok := img.Files[binDir+"/"+b]
		if !ok || f.Type != tar.TypeReg {
			continue
		}
		if f.Mode&0o111 == 0 {
			add("/%s/%s: не исполняемый", binDir, b)
		}
		if err := checkStatic(f.Data); err != nil {
			add("/%s/%s: %v", binDir, b, err)
		}
	}
	sort.Strings(problems)
	return problems
}

// checkStatic: ELF без интерпретатора и разделяемых библиотек.
func checkStatic(data []byte) error {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("не ELF: %w", err)
	}
	defer f.Close() //nolint:errcheck // файл в памяти
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("собран динамически (есть PT_INTERP) — нужен CGO_ENABLED=0")
		}
	}
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		return fmt.Errorf("зависит от разделяемых библиотек %v", libs)
	}
	return nil
}

// checkRelease побайтно сравнивает бинарники, манифест и подпись образа с
// каталогом выпуска (ОБН.1: образ — ровно те файлы, что подписаны).
func checkRelease(img *image, rule imageRule, release string) []string {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	pairs := map[string]string{
		manifestFile:  filepath.Join(release, "aisec-manifest.json"),
		signatureFile: filepath.Join(release, "aisec-manifest.json.sig"),
	}
	for _, b := range rule.Bins {
		pairs[binDir+"/"+b] = filepath.Join(release, "bin", b)
	}
	for in, out := range pairs {
		f, ok := img.Files[in]
		if !ok {
			continue // уже в checkFiles
		}
		want, err := readLimited(out)
		if err != nil {
			add("выпуск: %v", err)
			continue
		}
		if !bytes.Equal(f.Data, want) {
			add("/%s отличается от %s", in, out)
		}
	}
	sort.Strings(problems)
	return problems
}

func readLimited(p string) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // G304: путь к каталогу выпуска задаёт Makefile
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFile {
		return nil, fmt.Errorf("%s больше %d байт", p, maxFile)
	}
	return data, nil
}
