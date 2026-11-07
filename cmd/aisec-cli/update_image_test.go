package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Проверка образа до docker load (задача 6.21, ADR-0036, раздел 7): архивы
// собираются по раскладке docker save (OCI) без Docker; каждый случай
// подмены меняет ровно одно свойство.

// imgBuild — описание тестового образа; пустые поля — как у образа поставки.
type imgBuild struct {
	ref    string
	name   string
	ports  []string
	files  map[string][]byte // путь внутри образа (opt/aisec/…) → содержимое
	mode   map[string]int64
	gzip   bool
	mutate func(c *imageConfigJSON)
	// ociLayers — подмена слоёв в манифесте OCI (index.json): расхождение с manifest.json.
	ociLayers []string
	extra     map[string][]byte // лишние записи верхнего уровня архива
	tagInIdx  string
	// extraLayer — второй слой с лишним файлом.
	extraLayer map[string][]byte
}

func sum(p aisecCrypto.Provider, data []byte) string {
	return hex.EncodeToString(sha256Of(p, data))
}

// layerTar — tar слоя: каталоги-родители и файлы.
func layerTar(t testing.TB, files map[string][]byte, mode map[string]int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	dirs := map[string]bool{}
	var order []string
	for name := range files {
		for d := filepath.Dir(name); d != "." && d != "/"; d = filepath.Dir(d) {
			if !dirs[d] {
				dirs[d] = true
				order = append(order, d)
			}
		}
	}
	sortStrings(order)
	for _, d := range order {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d + "/", Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		m := int64(0o644)
		if strings.Contains(n, "/bin/") {
			m = 0o755
		}
		if v, ok := mode[n]; ok {
			m = v
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: m, Size: int64(len(files[n]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func gz(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildImage собирает архив образа в раскладке docker save (OCI).
func buildImage(t testing.TB, p aisecCrypto.Provider, b imgBuild) []byte {
	t.Helper()
	layerRaw := layerTar(t, b.files, b.mode)
	layers := [][]byte{layerRaw}
	if b.extraLayer != nil {
		layers = append(layers, layerTar(t, b.extraLayer, nil))
	}
	var diffIDs, layerNames []string
	blobs := map[string][]byte{}
	for _, raw := range layers {
		diffIDs = append(diffIDs, "sha256:"+sum(p, raw))
		blob := raw
		if b.gzip {
			blob = gz(t, raw)
		}
		h := sum(p, blob)
		blobs["blobs/sha256/"+h] = blob
		layerNames = append(layerNames, h)
	}
	var cfg imageConfigJSON
	cfg.OS, cfg.Architecture = "linux", "amd64"
	cfg.Config.User = imgUser
	cfg.Config.Env = []string{imgPath}
	cfg.Config.Entrypoint = []string{"/" + imgInstall + "/bin/" + b.name}
	if len(b.ports) > 0 {
		cfg.Config.ExposedPorts = map[string]struct{}{}
		for _, port := range b.ports {
			cfg.Config.ExposedPorts[port] = struct{}{}
		}
	}
	cfg.RootFS.Type = "layers"
	cfg.RootFS.DiffIDs = diffIDs
	if b.mutate != nil {
		b.mutate(&cfg)
	}
	cdata, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgHash := sum(p, cdata)
	blobs["blobs/sha256/"+cfgHash] = cdata

	ociL := layerNames
	if b.ociLayers != nil {
		ociL = b.ociLayers
	}
	om := ociManifest{Config: ociDescriptor{Digest: "sha256:" + cfgHash}}
	for _, l := range ociL {
		om.Layers = append(om.Layers, ociDescriptor{Digest: "sha256:" + l})
	}
	odata, err := json.Marshal(om)
	if err != nil {
		t.Fatal(err)
	}
	ohash := sum(p, odata)
	blobs["blobs/sha256/"+ohash] = odata

	manifest := []dockerManifestEntry{{Config: "blobs/sha256/" + cfgHash, RepoTags: []string{b.ref}}}
	for _, l := range layerNames {
		manifest[0].Layers = append(manifest[0].Layers, "blobs/sha256/"+l)
	}
	mdata, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, tag, _ := strings.Cut(b.ref, ":")
	if b.tagInIdx != "" {
		tag = b.tagInIdx
	}
	idx := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":%d,"annotations":{"io.containerd.image.name":"docker.io/%s","org.opencontainers.image.ref.name":"%s"}}]}`,
		ohash, len(odata), b.ref, tag)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	put("index.json", []byte(idx))
	put("manifest.json", mdata)
	for n, d := range blobs {
		put(n, d)
	}
	for n, d := range b.extra {
		put(n, d)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// specFiles — файлы образа по спецификации: то, что перечисляет expected.
func specFiles(t testing.TB, p aisecCrypto.Provider, spec imageSpec, dir string) map[string][]byte {
	t.Helper()
	want, err := spec.expected(p)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		imgInstall + "/aisec-manifest.json":     spec.Rel.Data,
		imgInstall + "/aisec-manifest.json.sig": spec.Rel.Sig,
	}
	for name := range want {
		if _, ok := files[name]; ok {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(name, imgInstall+"/"))) //nolint:gosec // G304: каталог выпуска теста
		if err != nil {
			t.Fatal(err)
		}
		files[name] = data
	}
	return files
}

// testSpec: выпуск 2.0 во временном каталоге и спецификация образа
// aisec-server.
func testSpec(t testing.TB) (imageSpec, string, aisecCrypto.Provider) {
	t.Helper()
	dir := t.TempDir()
	writeRelease(t, dir, mainSpec("2.0", updNew, ""))
	p := standardProvider(t)
	rel, err := readManifestPair(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	return imageSpec{Ref: "aisec-test/aisec-server:2.0-test", Name: "aisec-server", Rel: rel, Bins: []string{"aisec-server"}, Ports: []string{"8444/tcp", "8445/tcp"}}, dir, p
}

func writeImage(t testing.TB, data []byte) func() (*os.File, error) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return func() (*os.File, error) { return os.Open(f) } //nolint:gosec // G304: файл теста
}

func goodBuild(t testing.TB, p aisecCrypto.Provider, spec imageSpec, dir string) imgBuild {
	t.Helper()
	return imgBuild{ref: spec.Ref, name: spec.Name, ports: spec.Ports, files: specFiles(t, p, spec, dir)}
}

func TestVerifyImageArchiveOK(t *testing.T) {
	spec, dir, p := testSpec(t)
	for _, gzipped := range []bool{false, true} {
		b := goodBuild(t, p, spec, dir)
		b.gzip = gzipped
		v, err := verifyImageArchive(p, writeImage(t, buildImage(t, p, b)), spec)
		if err != nil {
			t.Fatalf("gzip=%v: %v", gzipped, err)
		}
		if len(v.DiffIDs) != 1 || !strings.HasPrefix(v.DiffIDs[0], "sha256:") {
			t.Fatalf("diff_ids: %v", v.DiffIDs)
		}
	}
}

// Каждая подмена образа отвергается до загрузки.
func TestVerifyImageArchiveRejects(t *testing.T) {
	spec, dir, p := testSpec(t)
	cases := []struct {
		name  string
		build func(b *imgBuild)
		want  string
	}{
		{"подменённый бинарник", func(b *imgBuild) { b.files[imgInstall+"/bin/aisec-server"] = []byte("чужой бинарник") }, "не совпадает с подписанным манифестом"},
		{"подменённый манифест", func(b *imgBuild) { b.files[imgInstall+"/aisec-manifest.json"] = []byte("{}") }, "не совпадает с подписанным манифестом"},
		{"нет бинарника", func(b *imgBuild) { delete(b.files, imgInstall+"/bin/aisec-server") }, "нет opt/aisec/bin/aisec-server"},
		{"лишний файл", func(b *imgBuild) { b.files["bin/sh"] = []byte("#!") }, "лишние файлы"},
		{"лишний бинарник выпуска", func(b *imgBuild) { b.files[imgInstall+"/bin/aisec-cli"] = []byte("x") }, "лишние файлы"},
		{"тег в архиве другой", func(b *imgBuild) { b.ref = "aisec-test/aisec-server:3.0-test" }, "не ровно один образ"},
		{"пользователь root", func(b *imgBuild) { b.mutate = func(c *imageConfigJSON) { c.Config.User = "0:0" } }, "пользователь образа"},
		{"другая точка входа", func(b *imgBuild) {
			b.mutate = func(c *imageConfigJSON) { c.Config.Entrypoint = []string{"/bin/sh"} }
		}, "точка входа"},
		{"лишняя переменная окружения", func(b *imgBuild) {
			b.mutate = func(c *imageConfigJSON) { c.Config.Env = append(c.Config.Env, "LD_PRELOAD=/x") }
		}, "окружение"},
		{"лишний порт", func(b *imgBuild) { b.ports = []string{"8444/tcp", "8445/tcp", "22/tcp"} }, "порты"},
		{"команда в образе", func(b *imgBuild) { b.mutate = func(c *imageConfigJSON) { c.Config.Cmd = []string{"-x"} } }, "команду"},
		{"другая архитектура", func(b *imgBuild) { b.mutate = func(c *imageConfigJSON) { c.Architecture = "arm64" } }, "linux/amd64"},
		{"слои в OCI-манифесте другие", func(b *imgBuild) { b.ociLayers = []string{strings.Repeat("a", 64)} }, "разные слои"},
		{"тег в index.json другой", func(b *imgBuild) { b.tagInIdx = "9.9" }, "другой тег"},
		{"лишняя запись архива", func(b *imgBuild) { b.extra = map[string][]byte{"repositories": []byte("{}")} }, "лишняя запись"},
		{"расхождение diff_id", func(b *imgBuild) {
			b.mutate = func(c *imageConfigJSON) { c.RootFS.DiffIDs = []string{"sha256:" + strings.Repeat("0", 64)} }
		}, "diff_id"},
		{"лишний слой с файлом", func(b *imgBuild) { b.extraLayer = map[string][]byte{"etc/passwd": []byte("x")} }, "лишние файлы"},
		{"права setuid", func(b *imgBuild) { b.mode = map[string]int64{imgInstall + "/bin/aisec-server": 0o4755} }, "права"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := goodBuild(t, p, spec, dir)
			c.build(&b)
			_, err := verifyImageArchive(p, writeImage(t, buildImage(t, p, b)), spec)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ожидалась ошибка с %q: %v", c.want, err)
			}
		})
	}
}

// Повреждённые и подменённые архивы: обрезка, чужие байты, символьная
// ссылка вместо обычного файла, имя blob не по хешу.
func TestVerifyImageArchiveBroken(t *testing.T) {
	spec, dir, p := testSpec(t)
	good := buildImage(t, p, goodBuild(t, p, spec, dir))
	t.Run("обрезан", func(t *testing.T) {
		if _, err := verifyImageArchive(p, writeImage(t, good[:len(good)/2]), spec); err == nil {
			t.Fatal("обрезанный архив принят")
		}
	})
	t.Run("мусор", func(t *testing.T) {
		if _, err := verifyImageArchive(p, writeImage(t, []byte("не tar")), spec); err == nil {
			t.Fatal("мусор принят")
		}
	})
	t.Run("blob переименован без пересчёта хеша", func(t *testing.T) {
		// Меняем один байт внутри слоя: имя blob перестаёт быть его хешем.
		bad := append([]byte(nil), good...)
		i := bytes.Index(bad, []byte("синтетический бинарник"))
		if i < 0 {
			t.Fatal("нет содержимого бинарника в архиве")
		}
		bad[i+2] ^= 0xff
		if _, err := verifyImageArchive(p, writeImage(t, bad), spec); err == nil {
			t.Fatal("подмена байта принята")
		}
	})
	t.Run("архив — ссылка", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "real.tar")
		if err := os.WriteFile(dst, good, 0o600); err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		root1, err := os.OpenRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		defer root1.Close() //nolint:errcheck // тест
		if err := os.Symlink(dst, filepath.Join(root, "link.tar")); err != nil {
			t.Fatal(err)
		}
		// Через os.Root ссылка за пределы каталога не открывается.
		if _, err := verifyImageArchive(p, func() (*os.File, error) { return root1.Open("link.tar") }, spec); err == nil {
			t.Fatal("ссылка за пределы каталога принята")
		}
	})
	t.Run("символьная ссылка в слое", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "opt/aisec/bin/aisec-server", Linkname: "/bin/sh"}) //nolint:gosec // G104: тест
		_ = tw.Close()                                                                                                      //nolint:gosec // G104: тест
		if err := os.WriteFile(filepath.Join(t.TempDir(), "x"), buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readImageLayer(mustHasher(t, p), bytes.NewReader(buf.Bytes()), "", "")
		if err == nil || !strings.Contains(err.Error(), "не обычный файл") {
			t.Fatalf("ссылка в слое: %v", err)
		}
	})
	t.Run("повтор имени записи", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for i := 0; i < 2; i++ {
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "oci-layout", Mode: 0o644, Size: 2}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte("{}")); err != nil {
				t.Fatal(err)
			}
		}
		_ = tw.Close() //nolint:gosec // G104: тест
		if _, err := verifyImageArchive(p, writeImage(t, buf.Bytes()), spec); err == nil || !strings.Contains(err.Error(), "повторяется") {
			t.Fatalf("повтор имени: %v", err)
		}
	})
	t.Run("пределы записей", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for i := 0; i <= imgMaxEntries+1; i++ {
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: fmt.Sprintf("blobs/sha256/%064x/", i)}); err != nil {
				t.Fatal(err)
			}
		}
		_ = tw.Close() //nolint:gosec // G104: тест
		if _, err := verifyImageArchive(p, writeImage(t, buf.Bytes()), spec); err == nil || !strings.Contains(err.Error(), "записей") {
			t.Fatalf("записей больше предела: %v", err)
		}
	})
}

func mustHasher(t testing.TB, p aisecCrypto.Provider) aisecCrypto.Hasher {
	t.Helper()
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Разбор архива образа — недоверенный ввод с носителя (fuzz-тест, ЗИ.4).
func FuzzVerifyImageArchive(f *testing.F) {
	spec, dir, p := testSpec(f)
	for _, gzipped := range []bool{false, true} {
		b := goodBuild(f, p, spec, dir)
		b.gzip = gzipped
		f.Add(buildImage(f, p, b))
	}
	f.Add([]byte{})
	f.Add([]byte("ustar"))
	tmp := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		name := filepath.Join(tmp, "f.tar")
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = verifyImageArchive(p, func() (*os.File, error) { return os.Open(name) }, spec) //nolint:gosec // G304: файл теста
	})
}
