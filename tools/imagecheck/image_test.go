package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func hasher(t testing.TB) aisecCrypto.Hasher {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fakeELF — минимальный ELF64; interp добавляет PT_INTERP (динамическая сборка).
func fakeELF(t testing.TB, interp bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	hdr := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: 1, Ehsize: 64, Phentsize: 56, Shentsize: 64}
	copy(hdr.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	if interp {
		hdr.Phoff, hdr.Phnum = 64, 1
	}
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		t.Fatal(err)
	}
	if interp {
		if err := binary.Write(&buf, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 120, Filesz: 1, Memsz: 1}); err != nil {
			t.Fatal(err)
		}
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

// layerFile — файл слоя тестового образа.
type layerFile struct {
	Name     string
	Type     byte
	Mode     int64
	UID      int
	Data     []byte
	Linkname string
	PAX      map[string]string
}

// fixture — тестовый образ: настройки и слои.
type fixture struct {
	Tag    string
	Config map[string]any
	Layers [][]layerFile
	Gzip   bool
	// Порча архива после сборки.
	BadDiffID, BadBlob, NoManifest bool
}

func goodFiles(t testing.TB, bins ...string) []layerFile {
	files := []layerFile{
		{Name: "opt/", Type: tar.TypeDir, Mode: 0o755},
		{Name: "opt/aisec/", Type: tar.TypeDir, Mode: 0o755},
		{Name: "opt/aisec/aisec-manifest.json", Type: tar.TypeReg, Mode: 0o644, Data: []byte(`{"m":1}`)},
		{Name: "opt/aisec/aisec-manifest.json.sig", Type: tar.TypeReg, Mode: 0o644, Data: []byte("sig")},
		{Name: "opt/aisec/bin/", Type: tar.TypeDir, Mode: 0o755},
	}
	for _, b := range bins {
		files = append(files, layerFile{Name: "opt/aisec/bin/" + b, Type: tar.TypeReg, Mode: 0o755, Data: fakeELF(t, false)})
	}
	return files
}

func goodConfig(name string, ports ...string) map[string]any {
	exposed := map[string]any{}
	for _, p := range ports {
		exposed[p] = map[string]any{}
	}
	return map[string]any{
		"os": "linux",
		"config": map[string]any{
			"User":         runUser,
			"ExposedPorts": exposed,
			"Env":          []string{"PATH=/usr/bin"},
			"Entrypoint":   []string{"/opt/aisec/bin/" + name},
			"Labels":       map[string]string{labelKind: "test", labelVersion: "1.0.0"},
		},
	}
}

func gatewayFixture(t testing.TB) *fixture {
	return &fixture{
		Tag:    "aisec-test/aisec-gateway:1.0.0-test",
		Config: goodConfig("aisec-gateway", "8443/tcp"),
		Layers: [][]layerFile{goodFiles(t, "aisec-gateway")},
	}
}

func tarOf(t testing.TB, files []layerFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		hdr := &tar.Header{Name: f.Name, Typeflag: f.Type, Mode: f.Mode, Uid: f.UID, Gid: f.UID, Size: int64(len(f.Data)), Linkname: f.Linkname, PAXRecords: f.PAX}
		if f.PAX != nil {
			hdr.Format = tar.FormatPAX
		}
		if f.Type != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if f.Type == tar.TypeReg {
			if _, err := tw.Write(f.Data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// write собирает архив в формате docker save и возвращает путь.
func (fx *fixture) write(t testing.TB) string {
	t.Helper()
	h := hasher(t)
	digest := func(b []byte) string { return hex.EncodeToString(h.Sum(b)) }
	blobs := map[string][]byte{}
	var layerPaths, diffIDs []string
	for _, files := range fx.Layers {
		raw := tarOf(t, files)
		diffIDs = append(diffIDs, "sha256:"+digest(raw))
		blob := raw
		if fx.Gzip {
			var gz bytes.Buffer
			zw := gzip.NewWriter(&gz)
			if _, err := zw.Write(raw); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			blob = gz.Bytes()
		}
		p := "blobs/sha256/" + digest(blob)
		blobs[p] = blob
		layerPaths = append(layerPaths, p)
	}
	if fx.BadDiffID {
		diffIDs[0] = "sha256:" + strings.Repeat("0", 64)
	}
	cfg := map[string]any{}
	for k, v := range fx.Config {
		cfg[k] = v
	}
	cfg["rootfs"] = map[string]any{"type": "layers", "diff_ids": diffIDs}
	cdata, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cpath := "blobs/sha256/" + digest(cdata)
	blobs[cpath] = cdata
	if fx.BadBlob {
		blobs[layerPaths[0]] = append(append([]byte{}, blobs[layerPaths[0]]...), 0)
	}
	mdata, err := json.Marshal([]dockerManifest{{Config: cpath, RepoTags: []string{fx.Tag}, Layers: layerPaths}})
	if err != nil {
		t.Fatal(err)
	}
	var files []layerFile
	if !fx.NoManifest {
		files = append(files, layerFile{Name: "manifest.json", Type: tar.TypeReg, Mode: 0o644, Data: mdata})
	}
	for p, b := range blobs {
		files = append(files, layerFile{Name: p, Type: tar.TypeReg, Mode: 0o444, Data: b})
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(path, tarOf(t, files), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func load(t *testing.T, fx *fixture) *image {
	t.Helper()
	img, err := loadImage(fx.write(t), hasher(t))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestImageOK(t *testing.T) {
	for _, gz := range []bool{false, true} {
		fx := gatewayFixture(t)
		fx.Gzip = gz
		img := load(t, fx)
		if img.Name != "aisec-gateway" || img.Tag != fx.Tag {
			t.Fatalf("образ: %s %s", img.Name, img.Tag)
		}
		if p := checkImage(img, "test", ""); len(p) > 0 {
			t.Fatalf("gzip=%v: %v", gz, p)
		}
	}
}

func TestImageLaterLayerWins(t *testing.T) {
	fx := gatewayFixture(t)
	fx.Layers = [][]layerFile{
		{{Name: "opt/aisec/bin/aisec-gateway", Type: tar.TypeReg, Mode: 0o755, Data: []byte("old")}},
		goodFiles(t, "aisec-gateway"),
	}
	if p := checkImage(load(t, fx), "test", ""); len(p) > 0 {
		t.Fatal(p)
	}
}

func TestImageRejects(t *testing.T) {
	cfg := func(edit func(c map[string]any)) func(*fixture) {
		return func(fx *fixture) { edit(fx.Config["config"].(map[string]any)) }
	}
	addFile := func(f layerFile) func(*fixture) {
		return func(fx *fixture) { fx.Layers[0] = append(fx.Layers[0], f) }
	}
	editBin := func(edit func(f *layerFile)) func(*fixture) {
		return func(fx *fixture) {
			for i := range fx.Layers[0] {
				if fx.Layers[0][i].Name == "opt/aisec/bin/aisec-gateway" {
					edit(&fx.Layers[0][i])
				}
			}
		}
	}
	for name, tc := range map[string]struct {
		edit func(*fixture)
		want string
	}{
		"root":              {cfg(func(c map[string]any) { c["User"] = "" }), "не root"},
		"root явно":         {cfg(func(c map[string]any) { c["User"] = "0:0" }), "не root"},
		"лишний порт":       {cfg(func(c map[string]any) { c["ExposedPorts"] = map[string]any{"8443/tcp": nil, "22/tcp": nil} }), "порты"},
		"точка входа":       {cfg(func(c map[string]any) { c["Entrypoint"] = []string{"/bin/sh", "-c"} }), "точка входа"},
		"Cmd":               {cfg(func(c map[string]any) { c["Cmd"] = []string{"-x"} }), "точка входа"},
		"переменная":        {cfg(func(c map[string]any) { c["Env"] = []string{"API_TOKEN=x"} }), "API_TOKEN"},
		"том":               {cfg(func(c map[string]any) { c["Volumes"] = map[string]any{"/data": map[string]any{}} }), "тома"},
		"метка вида":        {cfg(func(c map[string]any) { c["Labels"] = map[string]string{labelKind: "release", labelVersion: "1"} }), labelKind},
		"нет версии":        {cfg(func(c map[string]any) { c["Labels"] = map[string]string{labelKind: "test"} }), labelVersion},
		"не linux":          {func(fx *fixture) { fx.Config["os"] = "windows" }, "linux"},
		"оболочка":          {addFile(layerFile{Name: "bin/sh", Type: tar.TypeReg, Mode: 0o755, Data: []byte("x")}), "оболочка"},
		"busybox":           {addFile(layerFile{Name: "bin/busybox", Type: tar.TypeReg, Mode: 0o755, Data: []byte("x")}), "оболочка"},
		"пакетный менеджер": {addFile(layerFile{Name: "sbin/apk", Type: tar.TypeReg, Mode: 0o755, Data: []byte("x")}), "пакетный"},
		"лишний файл":       {addFile(layerFile{Name: "etc/passwd", Type: tar.TypeReg, Mode: 0o644, Data: []byte("x")}), "лишний"},
		"whiteout":          {addFile(layerFile{Name: "opt/aisec/.wh.old", Type: tar.TypeReg, Mode: 0o644}), "whiteout"},
		"setuid":            {editBin(func(f *layerFile) { f.Mode = 0o4755 }), "setuid"},
		"запись для всех":   {editBin(func(f *layerFile) { f.Mode = 0o777 }), "запись"},
		"не root владелец":  {editBin(func(f *layerFile) { f.UID = 65534 }), "владелец"},
		"не исполняемый":    {editBin(func(f *layerFile) { f.Mode = 0o644 }), "не исполняемый"},
		"capabilities":      {editBin(func(f *layerFile) { f.PAX = map[string]string{"SCHILY.xattr.security.capability": "x"} }), "security.capability"},
		"динамический":      {editBin(func(f *layerFile) { f.Data = fakeELF(t, true) }), "динамически"},
		"не ELF":            {editBin(func(f *layerFile) { f.Data = []byte("#!/bin/sh") }), "не ELF"},
		"ссылка":            {editBin(func(f *layerFile) { f.Type, f.Linkname, f.Data = tar.TypeSymlink, "/bin/sh", nil }), "обычный файл"},
		"нет манифеста":     {func(fx *fixture) { fx.Layers[0] = append(fx.Layers[0][:2], fx.Layers[0][3:]...) }, "aisec-manifest.json: нет в образе"},
		"чужой бинарник":    {addFile(layerFile{Name: "opt/aisec/bin/aisec-server", Type: tar.TypeReg, Mode: 0o755, Data: fakeELF(t, false)}), "лишний"},
		"неизвестный образ": {func(fx *fixture) { fx.Tag = "aisec-test/mock-llm:1" }, "неизвестный образ"},
	} {
		t.Run(name, func(t *testing.T) {
			fx := gatewayFixture(t)
			tc.edit(fx)
			problems := checkImage(load(t, fx), "test", "")
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Fatalf("ожидалось нарушение %q, получено %v", tc.want, problems)
			}
		})
	}
}

func TestImageRelease(t *testing.T) {
	fx := gatewayFixture(t)
	img := load(t, fx)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0o755); err != nil { //nolint:gosec // тест: каталог выпуска во временном каталоге, права как у поставки
		t.Fatal(err)
	}
	for in, out := range map[string]string{manifestFile: "aisec-manifest.json", signatureFile: "aisec-manifest.json.sig", binDir + "/aisec-gateway": "bin/aisec-gateway"} {
		if err := os.WriteFile(filepath.Join(dir, out), img.Files[in].Data, 0o644); err != nil { //nolint:gosec // тест: файлы выпуска во временном каталоге, права как у поставки
			t.Fatal(err)
		}
	}
	if p := checkImage(img, "test", dir); len(p) > 0 {
		t.Fatal(p)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin/aisec-gateway"), []byte("другой"), 0o644); err != nil { //nolint:gosec // тест: подмена бинарника во временном каталоге
		t.Fatal(err)
	}
	if p := checkImage(img, "test", dir); len(p) != 1 || !strings.Contains(p[0], "отличается") {
		t.Fatalf("подмена бинарника в выпуске: %v", p)
	}
	if err := os.Remove(filepath.Join(dir, "aisec-manifest.json.sig")); err != nil {
		t.Fatal(err)
	}
	if p := checkImage(img, "test", dir); len(p) != 2 {
		t.Fatalf("нет подписи в выпуске: %v", p)
	}
}

func TestLoadImageRejects(t *testing.T) {
	for name, edit := range map[string]func(*fixture){
		"подменён слой":      func(fx *fixture) { fx.BadBlob = true },
		"неверный diff_id":   func(fx *fixture) { fx.BadDiffID = true },
		"нет manifest.json":  func(fx *fixture) { fx.NoManifest = true },
		"подменён gzip-слой": func(fx *fixture) { fx.Gzip, fx.BadBlob = true, true },
	} {
		t.Run(name, func(t *testing.T) {
			fx := gatewayFixture(t)
			edit(fx)
			if _, err := loadImage(fx.write(t), hasher(t)); err == nil {
				t.Fatal("архив принят")
			}
		})
	}
	if _, err := loadImage(filepath.Join(t.TempDir(), "нет.tar"), hasher(t)); err == nil {
		t.Fatal("нет файла — нет ошибки")
	}
}

// TestReadLayerLimits — распакованный слой и содержимое бинарников
// ограничены: gzip-бомба и множество крупных файлов отвергаются до исчерпания
// памяти.
func TestReadLayerLimits(t *testing.T) {
	h := hasher(t)
	layerLimit = 1 << 20
	t.Cleanup(func() { layerLimit = maxLayer })
	zeros := func(n int64) io.Reader { return io.LimitReader(zeroReader{}, n) }
	var bomb bytes.Buffer
	zw := gzip.NewWriter(&bomb)
	if _, err := io.Copy(zw, zeros(layerLimit+1)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	budget := int64(maxData)
	if _, err := readLayer("blobs/sha256/x", &bomb, h, "", &budget); !errors.Is(err, errLayerTooBig) {
		t.Fatalf("gzip-бомба: %v", err)
	}

	raw := tarOf(t, []layerFile{{Name: "opt/aisec/bin/a", Type: tar.TypeReg, Mode: 0o755, Data: make([]byte, 1024)}})
	budget = 1023
	if _, err := readLayer("blobs/sha256/x", bytes.NewReader(raw), h, "", &budget); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Fatalf("бюджет содержимого не соблюдён: %v", err)
	}
	budget = 1024
	if _, err := readLayer("blobs/sha256/x", bytes.NewReader(raw), h, "", &budget); err == nil || !strings.Contains(err.Error(), "diff_id") {
		t.Fatalf("на границе бюджета ожидалась только ошибка diff_id: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// FuzzReadLayer — разбор недоверенного слоя (tar и tar+gzip) не паникует и
// принимает слой только с верными хешами.
func FuzzReadLayer(f *testing.F) {
	raw := tarOf(f, goodFiles(f, "aisec-gateway"))
	f.Add(raw)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw) //nolint:gosec // тест: запись в bytes.Buffer не ошибается
	_ = zw.Close()       //nolint:gosec // тест: запись в bytes.Buffer не ошибается
	f.Add(gz.Bytes())
	f.Add([]byte{gzipMagic0, gzipMagic1})
	h := hasher(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		budget := int64(maxData)
		if _, err := readLayer("blobs/sha256/"+strings.Repeat("0", 64), bytes.NewReader(data), h, "sha256:"+strings.Repeat("0", 64), &budget); err == nil {
			t.Fatal("принят слой с неверными хешами")
		}
	})
}

// FuzzLoadImage — разбор недоверенного архива docker save целиком.
func FuzzLoadImage(f *testing.F) {
	fx := gatewayFixture(f)
	seed, err := os.ReadFile(fx.write(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add(tarOf(f, []layerFile{{Name: "manifest.json", Type: tar.TypeReg, Mode: 0o644, Data: []byte("[]")}}))
	h := hasher(f)
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(dir, "image.tar")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		img, err := loadImage(p, h)
		if err == nil && (img.Name == "" || len(img.Config.RootFS.DiffIDs) == 0) {
			t.Fatalf("принят неполный образ: %+v", img.Config)
		}
	})
}

func TestParseDockerManifest(t *testing.T) {
	blob := "blobs/sha256/" + strings.Repeat("a", 64)
	ok := `[{"Config":"` + blob + `","RepoTags":["a/aisec-cli:1"],"Layers":["` + blob + `"]}]`
	if _, err := parseDockerManifest([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"два образа": `[{"Config":"` + blob + `","RepoTags":["a:1"],"Layers":["` + blob + `"]},{"Config":"` + blob + `","RepoTags":["b:1"],"Layers":["` + blob + `"]}]`,
		"без тега":   `[{"Config":"` + blob + `","RepoTags":[],"Layers":["` + blob + `"]}]`,
		"без слоёв":  `[{"Config":"` + blob + `","RepoTags":["a:1"],"Layers":[]}]`,
		"путь вне":   `[{"Config":"../etc/passwd","RepoTags":["a:1"],"Layers":["` + blob + `"]}]`,
		"заглавные":  `[{"Config":"blobs/sha256/` + strings.Repeat("A", 64) + `","RepoTags":["a:1"],"Layers":["` + blob + `"]}]`,
		"не JSON":    `{`,
	} {
		if _, err := parseDockerManifest([]byte(doc)); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
}

func TestImageName(t *testing.T) {
	for tag, want := range map[string]string{
		"aisec/aisec-server:1.0":                     "aisec-server",
		"registry.example.ru:5000/aisec/aisec-cli:1": "aisec-cli",
		"aisec-gateway":                              "aisec-gateway",
	} {
		if got := imageName(tag); got != want {
			t.Errorf("%s: %s, ожидалось %s", tag, got, want)
		}
	}
}

func FuzzParseDockerManifest(f *testing.F) {
	blob := "blobs/sha256/" + strings.Repeat("a", 64)
	f.Add([]byte(`[{"Config":"` + blob + `","RepoTags":["a/aisec-cli:1"],"Layers":["` + blob + `"]}]`))
	f.Add([]byte(`{"os":"linux","config":{"User":"65534:65534"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if m, err := parseDockerManifest(data); err == nil {
			if len(m.RepoTags) != 1 || len(m.Layers) == 0 || !blobPath(m.Config) {
				t.Fatalf("принят неверный manifest.json: %+v", m)
			}
		}
		if c, err := parseConfig(data); err == nil {
			img := &image{Name: "aisec-cli", Config: c, Files: map[string]fileEntry{}}
			if len(checkImage(img, "test", "")) == 0 {
				t.Fatal("образ без файлов прошёл проверку")
			}
		}
	})
}
