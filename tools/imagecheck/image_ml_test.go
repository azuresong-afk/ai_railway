package main

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDynELF — ELF64 с загрузчиком interp (PT_INTERP), без разделяемых библиотек.
func fakeDynELF(t testing.TB, interp string) []byte {
	t.Helper()
	var buf bytes.Buffer
	hdr := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: 1, Ehsize: 64, Phentsize: 56, Shentsize: 64, Phoff: 64, Phnum: 1}
	copy(hdr.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		t.Fatal(err)
	}
	n := uint64(len(interp) + 1)
	if err := binary.Write(&buf, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 120, Filesz: n, Memsz: n}); err != nil {
		t.Fatal(err)
	}
	buf.WriteString(interp)
	buf.WriteByte(0)
	return buf.Bytes()
}

const mlLoader = "/opt/aisec/lib/ld-linux-x86-64.so.2"

// mlFixture — образ aisec-ml (ADR-0024): бинарник с загрузчиком из
// /opt/aisec/lib, библиотеки и пакет моделей.
func mlFixture(t testing.TB) *fixture {
	files := goodFiles(t)
	files = append(files,
		layerFile{Name: "opt/aisec/bin/aisec-ml", Type: tar.TypeReg, Mode: 0o755, Data: fakeDynELF(t, mlLoader)},
		layerFile{Name: "opt/aisec/lib/", Type: tar.TypeDir, Mode: 0o755},
		layerFile{Name: "opt/aisec/lib/ld-linux-x86-64.so.2", Type: tar.TypeReg, Mode: 0o755, Data: []byte("loader")},
		layerFile{Name: "opt/aisec/lib/libonnxruntime.so.1.31.0", Type: tar.TypeReg, Mode: 0o644, Data: []byte("ort")},
		layerFile{Name: "opt/aisec/models/", Type: tar.TypeDir, Mode: 0o755},
		layerFile{Name: "opt/aisec/models/toxicity-ru/", Type: tar.TypeDir, Mode: 0o755},
		layerFile{Name: "opt/aisec/models/toxicity-ru/model.onnx", Type: tar.TypeReg, Mode: 0o644, Data: []byte("onnx")},
	)
	return &fixture{Tag: "aisec-test/aisec-ml:1.0.0-test", Config: goodConfig("aisec-ml"), Layers: [][]layerFile{files}}
}

// mlRelease — каталог выпуска aisec-ml с теми же файлами, что в образе.
func mlRelease(t *testing.T, img *image) string {
	t.Helper()
	dir := t.TempDir()
	for n, f := range img.Files {
		if f.Type != tar.TypeReg {
			continue
		}
		p := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(n, installDir+"/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestImageMLOK(t *testing.T) {
	img := load(t, mlFixture(t))
	if p := checkImage(img, "test", mlRelease(t, img)); len(p) > 0 {
		t.Fatal(p)
	}
	// Пакета моделей в выпуске ещё нет (часть 2 задачи 4.19) — нет и в образе.
	fx := mlFixture(t)
	var files []layerFile
	for _, f := range fx.Layers[0] {
		if !strings.HasPrefix(f.Name, "opt/aisec/models") {
			files = append(files, f)
		}
	}
	fx.Layers[0] = files
	img = load(t, fx)
	if p := checkImage(img, "test", mlRelease(t, img)); len(p) > 0 {
		t.Fatal(p)
	}
}

func TestImageMLRejects(t *testing.T) {
	editFile := func(name string, edit func(f *layerFile)) func(*fixture) {
		return func(fx *fixture) {
			for i := range fx.Layers[0] {
				if fx.Layers[0][i].Name == name {
					edit(&fx.Layers[0][i])
				}
			}
		}
	}
	bin := "opt/aisec/bin/aisec-ml"
	for name, tc := range map[string]struct {
		edit func(*fixture)
		want string
	}{
		"системный загрузчик": {editFile(bin, func(f *layerFile) { f.Data = fakeDynELF(t, "/lib64/ld-linux-x86-64.so.2") }), "загрузчик /lib64"},
		"нет загрузчика":      {editFile(bin, func(f *layerFile) { f.Data = fakeELF(t, false) }), "нет загрузчика"},
		"загрузчик не файл": {editFile("opt/aisec/lib/ld-linux-x86-64.so.2", func(f *layerFile) {
			f.Type, f.Linkname, f.Data = tar.TypeSymlink, "/lib64/ld-linux-x86-64.so.2", nil
		}), "только каталоги и обычные файлы"},
		"оболочка в lib": {func(fx *fixture) {
			fx.Layers[0] = append(fx.Layers[0], layerFile{Name: "opt/aisec/lib/sh", Type: tar.TypeReg, Mode: 0o755, Data: []byte("x")})
		}, "оболочка"},
		"библиотека с записью": {editFile("opt/aisec/lib/libonnxruntime.so.1.31.0", func(f *layerFile) { f.Mode = 0o666 }), "запись"},
	} {
		t.Run(name, func(t *testing.T) {
			fx := mlFixture(t)
			tc.edit(fx)
			problems := checkImage(load(t, fx), "test", "")
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Fatalf("ожидалось нарушение %q, получено %v", tc.want, problems)
			}
		})
	}
}

// Файлы lib/ и models/ образа — ровно файлы выпуска aisec-ml (ОБН.1).
func TestImageMLRelease(t *testing.T) {
	img := load(t, mlFixture(t))
	for name, tc := range map[string]struct {
		edit func(dir string) error
		want string
	}{
		"подменена библиотека": {func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "lib/libonnxruntime.so.1.31.0"), []byte("evil"), 0o600)
		}, "отличается"},
		"лишняя модель в образе": {func(dir string) error {
			return os.Remove(filepath.Join(dir, "models/toxicity-ru/model.onnx"))
		}, "нет в выпуске"},
		"нет библиотеки в образе": {func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "lib/libextra.so"), []byte("x"), 0o600)
		}, "нет в образе"},
		"ссылка в выпуске": {func(dir string) error {
			return os.Symlink("/etc/passwd", filepath.Join(dir, "lib/libx.so"))
		}, "не обычный файл"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := mlRelease(t, img)
			if err := tc.edit(dir); err != nil {
				t.Fatal(err)
			}
			problems := checkImage(img, "test", dir)
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Fatalf("ожидалось нарушение %q, получено %v", tc.want, problems)
			}
		})
	}
}
