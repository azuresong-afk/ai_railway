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

// fakeSharedLib — разделяемая библиотека ELF64 с одной строкой tag (DT_RPATH
// или DT_RUNPATH) в динамической секции и без зависимостей.
func fakeSharedLib(t testing.TB, tag elf.DynTag, val string) []byte {
	t.Helper()
	dynstr := append(append([]byte{0}, val...), 0)
	shstr := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")
	var dyn bytes.Buffer
	for _, d := range []elf.Dyn64{{Tag: int64(tag), Val: 1}, {Tag: int64(elf.DT_NULL)}} {
		if err := binary.Write(&dyn, binary.LittleEndian, d); err != nil {
			t.Fatal(err)
		}
	}
	dynb := dyn.Bytes()
	offStr := uint64(64)
	offDyn := (offStr + uint64(len(dynstr)) + 7) &^ 7
	offShstr := offDyn + uint64(len(dynb))
	offSh := (offShstr + uint64(len(shstr)) + 7) &^ 7
	hdr := elf.Header64{Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_X86_64), Version: 1, Ehsize: 64, Phentsize: 56, Shentsize: 64,
		Shoff: offSh, Shnum: 4, Shstrndx: 3}
	copy(hdr.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	out := make([]byte, offSh)
	var head bytes.Buffer
	if err := binary.Write(&head, binary.LittleEndian, hdr); err != nil {
		t.Fatal(err)
	}
	copy(out, head.Bytes())
	copy(out[offStr:], dynstr)
	copy(out[offDyn:], dynb)
	copy(out[offShstr:], shstr)
	buf := bytes.NewBuffer(out)
	for _, sh := range []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: offStr, Size: uint64(len(dynstr)), Addralign: 1},
		{Name: 9, Type: uint32(elf.SHT_DYNAMIC), Off: offDyn, Size: uint64(len(dynb)), Link: 1, Entsize: 16, Addralign: 8},
		{Name: 18, Type: uint32(elf.SHT_STRTAB), Off: offShstr, Size: uint64(len(shstr)), Addralign: 1},
	} {
		if err := binary.Write(buf, binary.LittleEndian, sh); err != nil {
			t.Fatal(err)
		}
	}
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
		layerFile{Name: "opt/aisec/lib/libonnxruntime.so.1.31.0", Type: tar.TypeReg, Mode: 0o644, Data: fakeSharedLib(t, elf.DT_RPATH, "/opt/aisec/lib")},
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
	ortLib := "opt/aisec/lib/libonnxruntime.so.1.31.0"
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
		// 4В24: RUNPATH $ORIGIN у ORT, загруженной через /proc/self/fd/N.
		"RUNPATH $ORIGIN у библиотеки": {editFile(ortLib, func(f *layerFile) { f.Data = fakeSharedLib(t, elf.DT_RUNPATH, "$ORIGIN") }), "RUNPATH $ORIGIN"},
		"RUNPATH lib у библиотеки":     {editFile(ortLib, func(f *layerFile) { f.Data = fakeSharedLib(t, elf.DT_RUNPATH, "/opt/aisec/lib") }), "RUNPATH /opt/aisec/lib"},
		"RPATH $ORIGIN у библиотеки":   {editFile(ortLib, func(f *layerFile) { f.Data = fakeSharedLib(t, elf.DT_RPATH, "/opt/aisec/lib:$ORIGIN") }), "$ORIGIN вне"},
		"RPATH системы у библиотеки":   {editFile(ortLib, func(f *layerFile) { f.Data = fakeSharedLib(t, elf.DT_RPATH, "/usr/lib") }), "/usr/lib вне"},
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
