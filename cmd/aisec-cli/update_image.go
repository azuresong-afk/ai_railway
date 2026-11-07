package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// Проверка образа из архива docker save до его загрузки (ADR-0036, раздел
// 7; ОБН.1 для compose). Архив — недоверенный ввод с носителя, поэтому
// разбирается без Docker: имена и хеши всех blob, настройки образа и
// содержимое слоёв сверяются с подписанным манифестом выпуска. Сверка той
// же копии, которую затем читает docker load, закрывает подмену файла на
// носителе между проверкой и загрузкой (3Н6 ревью 3.r1). Разбор покрыт
// fuzz-тестом FuzzVerifyImageArchive.

const (
	// imgMaxJSON — предел manifest.json, index.json, настроек образа и
	// манифеста OCI.
	imgMaxJSON = 1 << 20
	// imgMaxSmall — все небольшие blob первого прохода вместе.
	imgMaxSmall = 16 << 20
	// imgMaxEntries — записей в архиве и в каждом слое.
	imgMaxEntries = 10000
	imgMaxLayers  = 64
	// imgMaxBytes — предел архива и распакованного слоя.
	imgMaxBytes = maxReleaseBytes
	// imgInstall — каталог установки внутри образа.
	imgInstall = "opt/aisec"
	// imgPath — PATH образа: единственная переменная окружения.
	imgPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	// imgUser — пользователь процесса в образе.
	imgUser = "65534:65534"
)

// imageSpec — что обязано быть в образе.
type imageSpec struct {
	Ref   string       // aisec/aisec-server:1.2.3
	Name  string       // aisec-server
	Rel   *releaseInfo // подписанный манифест, которому принадлежит образ
	Ports []string     // открытые порты образа: «8444/tcp»
	// Bins — исполняемые файлы образа; пусто и All — все невстроенные
	// файлы манифеста (образ aisec-media: бинарник, библиотеки и модели).
	Bins []string
	All  bool
}

// expected — файлы образа: путь внутри образа → хеш содержимого. Манифест
// и подпись лежат в каждом образе, как их кладёт Dockerfile.release.
func (s imageSpec) expected(p aisecCrypto.Provider) (map[string]string, error) {
	want := map[string]string{
		imgInstall + "/" + integrity.ManifestFile:  hex.EncodeToString(sha256Of(p, s.Rel.Data)),
		imgInstall + "/" + integrity.SignatureFile: hex.EncodeToString(sha256Of(p, s.Rel.Sig)),
	}
	found := map[string]bool{}
	for _, e := range s.Rel.Manifest.Files {
		if e.Kind.Embedded() {
			continue
		}
		name := path.Base(e.Path)
		take := s.All
		if e.Kind == integrity.KindBinary && slices.Contains(s.Bins, name) {
			take = true
			found[name] = true
		}
		if take {
			want[imgInstall+"/"+e.Path] = e.Hash
		}
	}
	for _, b := range s.Bins {
		if !found[b] {
			return nil, fmt.Errorf("в манифесте нет bin/%s для образа %s", b, s.Ref)
		}
	}
	return want, nil
}

// verifiedImage — итог проверки: что обязан показать Docker после загрузки.
type verifiedImage struct {
	// DiffIDs — хеши распакованных слоёв из настроек образа.
	DiffIDs []string
	// Size — размер архива.
	Size int64
}

type dockerManifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Annotations map[string]string `json:"annotations"`
}

type ociIndex struct {
	Manifests []ociDescriptor `json:"manifests"`
}

type ociManifest struct {
	Config ociDescriptor   `json:"config"`
	Layers []ociDescriptor `json:"layers"`
}

type imageConfigJSON struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Config       struct {
		User         string              `json:"User"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Env          []string            `json:"Env"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		Volumes      map[string]struct{} `json:"Volumes"`
		Healthcheck  json.RawMessage     `json:"Healthcheck"`
		OnBuild      []string            `json:"OnBuild"`
		Shell        []string            `json:"Shell"`
	} `json:"config"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// blobName — имя blob вида blobs/sha256/<64 hex> и его хеш.
func blobName(p string) (string, bool) {
	h, ok := strings.CutPrefix(p, "blobs/sha256/")
	if !ok || len(h) != 64 {
		return "", false
	}
	if raw, err := hex.DecodeString(h); err != nil || len(raw) != 32 || strings.ToLower(h) != h {
		return "", false
	}
	return h, true
}

// archiveEntryOK — запись архива docker save, допустимая в раскладке OCI.
// Любое другое имя — отказ (старый формат с layer.tar, лишние образы).
func archiveEntryOK(name string) bool {
	switch name {
	case ".", "blobs", "blobs/sha256", "index.json", "manifest.json", "oci-layout":
		return true
	}
	_, ok := blobName(name)
	return ok
}

// walkImageArchive обходит записи архива: каталоги пропускает, всё кроме
// обычных файлов — отказ.
func walkImageArchive(open func() (*os.File, error), fn func(name string, size int64, r io.Reader) error) (int64, error) {
	f, err := open()
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("архив образа — не обычный файл")
	}
	if info.Size() > imgMaxBytes {
		return 0, fmt.Errorf("архив образа больше %d ГиБ", imgMaxBytes>>30)
	}
	tr := tar.NewReader(io.LimitReader(f, imgMaxBytes))
	seen := map[string]bool{}
	for n := 0; ; n++ {
		if n > imgMaxEntries {
			return 0, fmt.Errorf("в архиве больше %d записей", imgMaxEntries)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return info.Size(), nil
		}
		if err != nil {
			return 0, fmt.Errorf("архив образа: %w", err)
		}
		name := path.Clean(hdr.Name)
		if !archiveEntryOK(name) {
			return 0, fmt.Errorf("лишняя запись в архиве: %q", shortName(hdr.Name))
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return 0, fmt.Errorf("запись архива %q — не обычный файл", shortName(name))
		}
		// Повтор имени: разные проходы по архиву увидели бы разные записи.
		if seen[name] {
			return 0, fmt.Errorf("запись архива %q повторяется", shortName(name))
		}
		seen[name] = true
		if err := fn(name, hdr.Size, tr); err != nil {
			return 0, fmt.Errorf("%s: %w", shortName(name), err)
		}
	}
}

func shortName(s string) string {
	if len(s) > 80 {
		s = s[:80]
	}
	return strings.ToValidUTF8(s, "?")
}

// verifyImageArchive — раздел 7 ADR-0036: архив содержит ровно один образ с
// тегом spec.Ref, настройки образа — как у образов поставки, а файлы слоёв —
// ровно те, что перечисляет spec, с хешами подписанного манифеста.
func verifyImageArchive(p aisecCrypto.Provider, open func() (*os.File, error), spec imageSpec) (*verifiedImage, error) {
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	want, err := spec.expected(p)
	if err != nil {
		return nil, err
	}
	small := map[string][]byte{}
	smallTotal := 0
	size, err := walkImageArchive(open, func(name string, sz int64, r io.Reader) error {
		if name != "manifest.json" && name != "index.json" && name != "oci-layout" {
			if _, ok := blobName(name); !ok || sz > imgMaxJSON {
				return nil
			}
		}
		if sz > imgMaxJSON {
			return errors.New("служебный файл больше предела")
		}
		data, err := io.ReadAll(io.LimitReader(r, imgMaxJSON+1))
		if err != nil {
			return err
		}
		if smallTotal += len(data); smallTotal > imgMaxSmall {
			return errors.New("небольших файлов в архиве больше предела")
		}
		small[name] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, need := range []string{"manifest.json", "index.json", "oci-layout"} {
		if _, ok := small[need]; !ok {
			return nil, fmt.Errorf("в архиве нет %s (ожидается архив docker save)", need)
		}
	}
	// manifest.json: один образ с одним тегом.
	var ms []dockerManifestEntry
	if err := lenientJSON(small["manifest.json"], &ms); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	if len(ms) != 1 {
		return nil, fmt.Errorf("в архиве не ровно один образ (manifest.json: %d)", len(ms))
	}
	m := ms[0]
	if len(m.RepoTags) != 1 || m.RepoTags[0] != spec.Ref {
		return nil, fmt.Errorf("в архиве не ровно один образ %s", spec.Ref)
	}
	if len(m.Layers) == 0 || len(m.Layers) > imgMaxLayers {
		return nil, fmt.Errorf("слоёв %d, ожидается от 1 до %d", len(m.Layers), imgMaxLayers)
	}
	cfgHash, ok := blobName(m.Config)
	if !ok {
		return nil, errors.New("manifest.json: неверный путь настроек образа")
	}
	layerHash := make([]string, len(m.Layers))
	for i, l := range m.Layers {
		if layerHash[i], ok = blobName(l); !ok {
			return nil, errors.New("manifest.json: неверный путь слоя")
		}
	}
	// index.json и манифест OCI: Docker с хранилищем containerd загружает
	// образ по ним, а не по manifest.json, поэтому они обязаны называть те
	// же настройки и слои и то же имя.
	if err := checkOCI(h, small, spec.Ref, cfgHash, layerHash); err != nil {
		return nil, err
	}
	// Настройки образа.
	cdata, ok := small[m.Config]
	if !ok {
		return nil, errors.New("в архиве нет настроек образа")
	}
	if err := checkBlobDigest(h, cdata, cfgHash); err != nil {
		return nil, fmt.Errorf("настройки образа: %w", err)
	}
	var cfg imageConfigJSON
	if err := json.Unmarshal(cdata, &cfg); err != nil {
		return nil, fmt.Errorf("настройки образа: %w", err)
	}
	if err := checkImageConfig(cfg, spec); err != nil {
		return nil, err
	}
	if len(cfg.RootFS.DiffIDs) != len(m.Layers) {
		return nil, fmt.Errorf("слоёв в manifest.json %d, в настройках %d", len(m.Layers), len(cfg.RootFS.DiffIDs))
	}
	// Слои.
	index := map[string][]int{}
	for i, name := range m.Layers {
		index[name] = append(index[name], i)
	}
	for name, idx := range index {
		for _, i := range idx[1:] {
			if cfg.RootFS.DiffIDs[i] != cfg.RootFS.DiffIDs[idx[0]] {
				return nil, fmt.Errorf("слой %s повторён с разными diff_id", shortName(name))
			}
		}
	}
	perLayer := make([]map[string]imgFile, len(m.Layers))
	if _, err := walkImageArchive(open, func(name string, _ int64, r io.Reader) error {
		idx, ok := index[name]
		if !ok || perLayer[idx[0]] != nil {
			return nil
		}
		files, err := readImageLayer(h, r, layerHash[idx[0]], cfg.RootFS.DiffIDs[idx[0]])
		if err != nil {
			return err
		}
		for _, i := range idx {
			perLayer[i] = files
		}
		return nil
	}); err != nil {
		return nil, err
	}
	final := map[string]imgFile{}
	for i, files := range perLayer {
		if files == nil {
			return nil, fmt.Errorf("в архиве нет слоя %d", i+1)
		}
		for name, f := range files {
			if prev, ok := final[name]; ok && prev.Dir != f.Dir {
				return nil, fmt.Errorf("%s: слои меняют тип записи", shortName(name))
			}
			final[name] = f
		}
	}
	if err := checkImageFiles(final, want); err != nil {
		return nil, err
	}
	return &verifiedImage{DiffIDs: cfg.RootFS.DiffIDs, Size: size}, nil
}

// lenientJSON — разбор JSON образа: поля, которых мы не читаем (Docker
// добавляет свои, например LayerSources), допустимы; данные после значения — нет.
func lenientJSON(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("данные после JSON")
	}
	return nil
}

func checkBlobDigest(h aisecCrypto.Hasher, data []byte, want string) error {
	if hex.EncodeToString(h.Sum(data)) != want {
		return errors.New("хеш содержимого не совпадает с именем")
	}
	return nil
}

// checkOCI сверяет index.json и манифест OCI с manifest.json.
func checkOCI(h aisecCrypto.Hasher, small map[string][]byte, ref, cfgHash string, layers []string) error {
	var idx ociIndex
	if err := lenientJSON(small["index.json"], &idx); err != nil {
		return fmt.Errorf("index.json: %w", err)
	}
	if len(idx.Manifests) != 1 {
		return fmt.Errorf("index.json: ожидается один манифест, найдено %d", len(idx.Manifests))
	}
	d := idx.Manifests[0]
	switch d.MediaType {
	case "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
	default:
		return fmt.Errorf("index.json: неожиданный вид манифеста %q", shortName(d.MediaType))
	}
	_, tag, _ := strings.Cut(ref, ":")
	if name := d.Annotations["io.containerd.image.name"]; name != "" && name != "docker.io/"+ref {
		return errors.New("index.json: другое имя образа")
	}
	if rn := d.Annotations["org.opencontainers.image.ref.name"]; rn != "" && rn != tag && rn != "docker.io/"+ref {
		return errors.New("index.json: другой тег образа")
	}
	mh, ok := strings.CutPrefix(d.Digest, "sha256:")
	if !ok {
		return errors.New("index.json: неверный хеш манифеста")
	}
	mdata, ok := small["blobs/sha256/"+mh]
	if !ok {
		return errors.New("в архиве нет манифеста образа из index.json")
	}
	if err := checkBlobDigest(h, mdata, mh); err != nil {
		return fmt.Errorf("манифест образа: %w", err)
	}
	var om ociManifest
	if err := lenientJSON(mdata, &om); err != nil {
		return fmt.Errorf("манифест образа: %w", err)
	}
	if om.Config.Digest != "sha256:"+cfgHash {
		return errors.New("манифест образа и manifest.json называют разные настройки образа")
	}
	if len(om.Layers) != len(layers) {
		return errors.New("манифест образа и manifest.json называют разное число слоёв")
	}
	for i, l := range om.Layers {
		if l.Digest != "sha256:"+layers[i] {
			return errors.New("манифест образа и manifest.json называют разные слои")
		}
	}
	return nil
}

// checkImageConfig — настройки образа как у образов поставки
// (Dockerfile.release): не root, свой вход, один PATH, свои порты.
func checkImageConfig(cfg imageConfigJSON, spec imageSpec) error {
	c := cfg.Config
	switch {
	case cfg.OS != "linux" || cfg.Architecture != "amd64":
		return fmt.Errorf("образ для %s/%s, ожидается linux/amd64", shortName(cfg.OS), shortName(cfg.Architecture))
	case c.User != imgUser:
		return fmt.Errorf("пользователь образа %q, ожидается %s", shortName(c.User), imgUser)
	case len(c.Entrypoint) != 1 || c.Entrypoint[0] != "/"+imgInstall+"/bin/"+spec.Name:
		return errors.New("точка входа образа отличается от ожидаемой")
	case len(c.Cmd) != 0 || len(c.OnBuild) != 0 || len(c.Shell) != 0 || len(c.Volumes) != 0:
		return errors.New("образ задаёт команду, тома, оболочку или инструкции сборки")
	case len(c.Healthcheck) != 0 && string(c.Healthcheck) != "null":
		return errors.New("образ задаёт проверку работоспособности")
	case len(c.Env) != 1 || c.Env[0] != imgPath:
		return errors.New("окружение образа отличается от ожидаемого")
	case cfg.RootFS.Type != "layers":
		return errors.New("настройки образа: rootfs не слои")
	}
	var ports []string
	for port := range c.ExposedPorts {
		ports = append(ports, port)
	}
	sort.Strings(ports)
	wantPorts := slices.Clone(spec.Ports)
	sort.Strings(wantPorts)
	if !slices.Equal(ports, wantPorts) {
		return errors.New("порты образа отличаются от ожидаемых")
	}
	return nil
}

// imgFile — запись слоя.
type imgFile struct {
	Dir  bool
	Hash string // хеш содержимого обычного файла
}

// readImageLayer читает слой (tar или tar+gzip): хеш blob сверяется с
// именем, хеш распакованного tar — с diff_id; возвращает обычные файлы и
// каталоги слоя. Ссылки, устройства, переименования (whiteout), записи не
// от root и права шире 0755 — отказ.
func readImageLayer(h aisecCrypto.Hasher, r io.Reader, blobHex, diffID string) (map[string]imgFile, error) {
	blobSum := h.New()
	br := bufio.NewReader(io.TeeReader(r, blobSum))
	var layer io.Reader = br
	magic, _ := br.Peek(4) //nolint:gosec // G104: короткий поток даёт меньше байт, тип определяется по ним
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		gz.Multistream(false)
		layer = gz
	case len(magic) == 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd:
		return nil, errors.New("слой сжат zstd: не поддерживается")
	}
	diffSum := h.New()
	unpacked := io.TeeReader(&capReader{r: layer, n: imgMaxBytes}, diffSum)
	tr := tar.NewReader(unpacked)
	files := map[string]imgFile{}
	for n := 0; ; n++ {
		if n > imgMaxEntries {
			return nil, fmt.Errorf("в слое больше %d записей", imgMaxEntries)
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
		if err := checkLayerEntry(hdr, name); err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeDir {
			files[name] = imgFile{Dir: true}
			continue
		}
		fh := h.New()
		if _, err := io.Copy(fh, io.LimitReader(tr, hdr.Size+1)); err != nil {
			return nil, err
		}
		files[name] = imgFile{Hash: hex.EncodeToString(fh.Sum(nil))}
	}
	// Остаток слоя (выравнивание tar) идёт в оба хеша.
	if _, err := io.Copy(io.Discard, unpacked); err != nil {
		return nil, err
	}
	if _, err := io.Copy(io.Discard, br); err != nil {
		return nil, err
	}
	if got := "sha256:" + hex.EncodeToString(diffSum.Sum(nil)); got != diffID {
		return nil, errors.New("хеш распакованного слоя не совпадает с diff_id настроек")
	}
	if hex.EncodeToString(blobSum.Sum(nil)) != blobHex {
		return nil, errors.New("хеш слоя не совпадает с его именем")
	}
	return files, nil
}

func checkLayerEntry(hdr *tar.Header, name string) error {
	if hdr.Typeflag != tar.TypeDir && hdr.Typeflag != tar.TypeReg {
		return fmt.Errorf("%s: в слое не обычный файл и не каталог", shortName(name))
	}
	if slices.Contains(strings.Split(name, "/"), "..") || strings.HasPrefix(path.Base(name), ".wh.") {
		return fmt.Errorf("%s: недопустимое имя в слое", shortName(name))
	}
	if hdr.Uid != 0 || hdr.Gid != 0 {
		return fmt.Errorf("%s: владелец в слое — не root", shortName(name))
	}
	if hdr.Mode&^0o755 != 0 {
		return fmt.Errorf("%s: права %#o шире допустимых", shortName(name), hdr.Mode)
	}
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, "SCHILY.xattr.") {
			return fmt.Errorf("%s: расширенные атрибуты в слое", shortName(name))
		}
	}
	return nil
}

// checkImageFiles: обычные файлы образа — ровно ожидаемые и с их хешами;
// каталоги — только родители ожидаемых файлов.
func checkImageFiles(final map[string]imgFile, want map[string]string) error {
	parents := map[string]bool{}
	for name := range want {
		for d := path.Dir(name); d != "." && d != "/"; d = path.Dir(d) {
			parents[d] = true
		}
	}
	var extra []string
	for name, f := range final {
		switch {
		case f.Dir:
			if !parents[name] {
				extra = append(extra, name+"/")
			}
		case want[name] == "":
			extra = append(extra, name)
		case want[name] != f.Hash:
			return fmt.Errorf("%s: содержимое не совпадает с подписанным манифестом", shortName(name))
		}
	}
	for name := range want {
		if f, ok := final[name]; !ok || f.Dir {
			return fmt.Errorf("в образе нет %s", shortName(name))
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		if len(extra) > 3 {
			extra = extra[:3]
		}
		return fmt.Errorf("в образе лишние файлы: %s", shortName(strings.Join(extra, ", ")))
	}
	return nil
}

// capReader читает не больше n байт; дальше — ошибка, а не тихий обрыв:
// иначе хеш обрезанного слоя сверялся бы как полного.
type capReader struct {
	r io.Reader
	n int64
}

var errLayerTooBig = errors.New("распакованный слой больше предела")

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
