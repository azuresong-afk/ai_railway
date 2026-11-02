package modelscan

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Образцы — синтетические байты опкодов и заголовков, без настоящих весов.
// Потоки pickle только просматриваются сканером и нигде не исполняются.

// pickleProto2 — «os.system('id')» в протоколе 2 (GLOBAL, кортеж, REDUCE).
var pickleProto2 = []byte("\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.")

// pickleProto4 — протокол 4 с FRAME и STACK_GLOBAL, как у torch.save.
var pickleProto4 = func() []byte {
	body := []byte("\x8c\x0ctorch._utils\x94\x8c\x12_rebuild_tensor_v2\x94\x93\x94)R\x94.")
	out := []byte{0x80, 0x04, 0x95}
	out = binary.LittleEndian.AppendUint64(out, uint64(len(body)))
	return append(out, body...)
}()

// pickleProto0 — тот же вызов в текстовом протоколе 0 (без сигнатуры).
var pickleProto0 = []byte("cos\nsystem\n(S'id'\ntR.")

func zipBytes(t testing.TB, entries map[string][]byte, order ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range order {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func npyBytes(descr string, data []byte) []byte {
	header := fmt.Sprintf("{'descr': %s, 'fortran_order': False, 'shape': (2,), }", descr)
	for (10+len(header)+1)%64 != 0 {
		header += " "
	}
	header += "\n"
	out := []byte("\x93NUMPY\x01\x00")
	out = binary.LittleEndian.AppendUint16(out, uint16(len(header))) //nolint:gosec // G115: заголовок образца короче 64 КиБ
	out = append(out, header...)
	return append(out, data...)
}

func gzipBytes(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// safetensorsBytes собирает файл из заголовка JSON и данных.
func safetensorsBytes(header string, data []byte) []byte {
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(header)))
	out = append(out, header...)
	return append(out, data...)
}

func scanBytes(t testing.TB, name string, data []byte, l Limits) FileReport {
	t.Helper()
	return New(l).ScanReader(bytes.NewReader(data), int64(len(data)), name)
}

// Покрывает: DM-27
// pickle и форматы на его основе запрещены по содержимому при любом имени
// файла, переопределить запрет нечем.
func TestDM27_PickleRejected(t *testing.T) {
	torch := zipBytes(t, map[string][]byte{
		"archive/data.pkl": pickleProto2,
		"archive/version":  []byte("3\n"),
		"archive/data/0":   make([]byte, 16),
	}, "archive/data.pkl", "archive/version", "archive/data/0")
	cases := []struct {
		name, file string
		data       []byte
		format     Format
		detail     string
	}{
		{"протокол 2", "model.pkl", pickleProto2, FormatPickle, "os.system"},
		{"протокол 4, PyTorch старого формата", "pytorch_model.bin", pickleProto4, FormatPickle, "torch._utils._rebuild_tensor_v2"},
		{"протокол 0 без сигнатуры", "weights.ckpt", pickleProto0, FormatPickle, "os.system"},
		{"архив PyTorch", "model.pt", torch, FormatPyTorch, "archive/data.pkl"},
		{"архив PyTorch под чужим расширением", "model.safetensors", torch, FormatPyTorch, "data.pkl"},
		{"joblib со сжатием gzip", "model.joblib", gzipBytes(t, pickleProto2), FormatCompressed, "gzip"},
		{"npy с типом object", "arr.npy", npyBytes("'|O'", pickleProto2), FormatNumpy, "object"},
		{"npy со структурным полем object", "arr.npy", npyBytes("[('a', '<f4'), ('b', '|O')]", nil), FormatNumpy, "object"},
		{"npz с типом object", "arr.npz", zipBytes(t, map[string][]byte{
			"x.npy": npyBytes("'<f4'", make([]byte, 8)),
			"y.npy": npyBytes("'O'", pickleProto2),
		}, "x.npy", "y.npy"), FormatNumpyZip, "y.npy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := scanBytes(t, tc.file, tc.data, Limits{})
			if fr.Format != tc.format {
				t.Errorf("формат %q, ожидался %q", fr.Format, tc.format)
			}
			if !fr.HasFinding(CodePickle) || !fr.Blocked() {
				t.Fatalf("нет запрета pickle: %+v", fr.Findings)
			}
			for _, f := range fr.Findings {
				if f.Code == CodePickle && !strings.Contains(f.Detail, tc.detail) {
					t.Errorf("в пояснении нет %q: %s", tc.detail, f.Detail)
				}
			}
		})
	}
}

// Покрывает: DM-27
// Правильный safetensors принимается без находок.
func TestDM27_SafetensorsAccepted(t *testing.T) {
	header := `{"__metadata__":{"format":"pt"},"w":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]},` +
		`"b":{"dtype":"BF16","shape":[2],"data_offsets":[16,20]},"e":{"dtype":"F16","shape":[0],"data_offsets":[20,20]}}    `
	fr := scanBytes(t, "model.bin", safetensorsBytes(header, make([]byte, 20)), Limits{})
	if fr.Format != FormatSafetensors {
		t.Fatalf("формат %q", fr.Format)
	}
	if len(fr.Findings) != 0 || fr.Blocked() {
		t.Fatalf("лишние находки: %+v", fr.Findings)
	}
	if fr.Tensors != 3 {
		t.Errorf("тензоров %d, ожидалось 3", fr.Tensors)
	}
}

func TestSafetensorsBoundaries(t *testing.T) {
	ok := `{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}`
	cases := []struct {
		name string
		data []byte
		lim  Limits
		code string
	}{
		{"обрезанный заголовок", safetensorsBytes(ok, nil)[:20], Limits{}, CodeMalformed},
		{"заголовок длиннее файла", append(binary.LittleEndian.AppendUint64(nil, 1000), "{}"...), Limits{}, CodeMalformed},
		{"смещение за концом", safetensorsBytes(`{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}`, make([]byte, 4)), Limits{}, CodeMalformed},
		{"перекрытие", safetensorsBytes(`{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"b":{"dtype":"F32","shape":[2],"data_offsets":[4,12]}}`, make([]byte, 12)), Limits{}, CodeMalformed},
		{"размер не по типу", safetensorsBytes(`{"w":{"dtype":"F32","shape":[3],"data_offsets":[0,8]}}`, make([]byte, 8)), Limits{}, CodeMalformed},
		{"начало после конца", safetensorsBytes(`{"w":{"dtype":"U8","shape":[0],"data_offsets":[8,0]}}`, make([]byte, 8)), Limits{}, CodeMalformed},
		{"повтор имени", safetensorsBytes(`{"w":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"w":{"dtype":"U8","shape":[1],"data_offsets":[1,2]}}`, make([]byte, 2)), Limits{}, CodeMalformed},
		{"мусор после JSON", safetensorsBytes(ok+"x", make([]byte, 8)), Limits{}, CodeMalformed},
		{"метаданные не строки", safetensorsBytes(`{"__metadata__":{"a":1}}`, nil), Limits{}, CodeMalformed},
		{"отрицательная размерность", safetensorsBytes(`{"w":{"dtype":"U8","shape":[-1],"data_offsets":[0,0]}}`, nil), Limits{}, CodeMalformed},
		{"переполнение формы", safetensorsBytes(`{"w":{"dtype":"U8","shape":[4294967296,4294967296],"data_offsets":[0,0]}}`, nil), Limits{}, CodeMalformed},
		{"заголовок больше предела", safetensorsBytes(ok, make([]byte, 8)), Limits{MaxSafetensorsHeader: 16}, CodeLimitExceeded},
		{"тензоров больше предела", safetensorsBytes(`{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"b":{"dtype":"U8","shape":[1],"data_offsets":[1,2]}}`, make([]byte, 2)), Limits{MaxTensors: 1}, CodeLimitExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := scanBytes(t, "model.safetensors", tc.data, tc.lim)
			if fr.Format != FormatSafetensors {
				t.Fatalf("формат %q", fr.Format)
			}
			if !fr.HasFinding(tc.code) || !fr.Blocked() {
				t.Fatalf("ожидалась находка %s с запретом: %+v", tc.code, fr.Findings)
			}
		})
	}
}

func TestEmptyAndUnknown(t *testing.T) {
	if fr := scanBytes(t, "model.safetensors", nil, Limits{}); fr.Format != FormatEmpty || len(fr.Findings) != 0 {
		t.Errorf("пустой файл: %+v", fr)
	}
	fr := scanBytes(t, "model.bin", []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x10}, Limits{})
	if fr.Format != FormatUnknown || !fr.HasFinding(CodeUnknownFormat) || fr.Blocked() {
		t.Errorf("неизвестный формат — оповещение без запрета: %+v", fr)
	}
	fr = scanBytes(t, "README.md", []byte("# Модель\n\nОписание (c) 2026.\n"), Limits{})
	if fr.Format != FormatText || len(fr.Findings) != 0 {
		t.Errorf("текст: %+v", fr)
	}
	fr = scanBytes(t, "model.h5", []byte("\x89HDF\r\n\x1a\n\x00\x00"), Limits{})
	if !fr.HasFinding(CodeUnknownFormat) || !strings.Contains(fr.Findings[0].Detail, "HDF5") {
		t.Errorf("HDF5: %+v", fr)
	}
	fr = scanBytes(t, "model.joblib", []byte("\xfd7zXZ\x00\x00\x04"), Limits{})
	if fr.Format != FormatCompressed || !fr.HasFinding(CodeUnknownFormat) {
		t.Errorf("xz: %+v", fr)
	}
}

func TestZipBoundaries(t *testing.T) {
	entries := map[string][]byte{"a": []byte("1"), "b": []byte("2"), "c": []byte("3"), "d": []byte("4"), "e": []byte("5")}
	z := zipBytes(t, entries, "a", "b", "c", "d", "e")
	fr := scanBytes(t, "big.zip", z, Limits{MaxZipEntries: 3})
	if !fr.HasFinding(CodeLimitExceeded) || !fr.Blocked() {
		t.Errorf("записей сверх предела: %+v", fr.Findings)
	}
	if fr := scanBytes(t, "ok.zip", z, Limits{}); fr.Format != FormatZip || len(fr.Findings) != 0 {
		t.Errorf("обычный ZIP: %+v", fr)
	}
	if fr := scanBytes(t, "cut.zip", z[:len(z)-10], Limits{}); !fr.HasFinding(CodeMalformed) {
		t.Errorf("обрезанный ZIP: %+v", fr.Findings)
	}
	if fr := scanBytes(t, "dir.zip", z, Limits{MaxZipDirectory: 10}); !fr.HasFinding(CodeLimitExceeded) {
		t.Errorf("каталог больше предела: %+v", fr.Findings)
	}
	// pickle в записи с невинным именем находится по сигнатуре.
	hidden := zipBytes(t, map[string][]byte{"weights/blob": pickleProto4}, "weights/blob")
	if fr := scanBytes(t, "x.zip", hidden, Limits{}); !fr.HasFinding(CodePickle) {
		t.Errorf("pickle в записи: %+v", fr.Findings)
	}
}

func TestNumpyAccepted(t *testing.T) {
	fr := scanBytes(t, "arr.npy", npyBytes("'<f4'", make([]byte, 8)), Limits{})
	if fr.Format != FormatNumpy || len(fr.Findings) != 0 {
		t.Fatalf("npy с float32: %+v", fr)
	}
	z := zipBytes(t, map[string][]byte{"x.npy": npyBytes("'<i8'", make([]byte, 16))}, "x.npy")
	if fr := scanBytes(t, "arr.npz", z, Limits{}); fr.Format != FormatNumpyZip || len(fr.Findings) != 0 {
		t.Fatalf("npz: %+v", fr)
	}
	bad := npyBytes("'<f4'", nil)
	if fr := scanBytes(t, "arr.npy", bad[:20], Limits{}); !fr.HasFinding(CodeMalformed) {
		t.Errorf("обрезанный заголовок npy: %+v", fr.Findings)
	}
	if fr := scanBytes(t, "arr.npy", npyBytes("'<f4'", nil), Limits{MaxNumpyHeader: 8}); !fr.HasFinding(CodeLimitExceeded) {
		t.Errorf("заголовок больше предела: %+v", fr.Findings)
	}
}

func TestScanPathDirectory(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("model.safetensors", safetensorsBytes(`{"w":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}`, []byte{1}))
	write("sub/extra.bin", pickleProto2)
	write("README.md", []byte("модель\n"))
	if err := os.Symlink(filepath.Join(dir, "sub", "extra.bin"), filepath.Join(dir, "link.bin")); err != nil {
		t.Fatal(err)
	}
	rep, err := New(Limits{}).ScanPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Files) != 4 || !rep.Blocked() {
		t.Fatalf("отчёт: %+v", rep)
	}
	byPath := map[string]FileReport{}
	for _, f := range rep.Files {
		byPath[f.Path] = f
	}
	if f := byPath["link.bin"]; !f.Symlink || !f.HasFinding(CodePickle) {
		t.Errorf("ссылка проверяется по цели: %+v", f)
	}
	if f := byPath["sub/extra.bin"]; !f.HasFinding(CodePickle) {
		t.Errorf("вложенный каталог: %+v", f)
	}
	rep, err = New(Limits{MaxFiles: 2}).ScanPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Truncated || len(rep.Files) != 2 || !rep.Blocked() {
		t.Errorf("предел файлов: %+v", rep)
	}
	one, err := New(Limits{}).ScanPath(filepath.Join(dir, "model.safetensors"))
	if err != nil || len(one.Files) != 1 || one.Blocked() {
		t.Errorf("один файл: %+v, %v", one, err)
	}
}

func TestCleanDetail(t *testing.T) {
	if got := clean("a\x1b[31m\u202eb"); got != "a?[31m?b" {
		t.Errorf("clean = %q", got)
	}
	if got := clean(strings.Repeat("я", 200)); len([]rune(got)) != maxNameInDetail+1 {
		t.Errorf("длина %d", len([]rune(got)))
	}
}

func FuzzWalkPickle(f *testing.F) {
	for _, s := range [][]byte{pickleProto0, pickleProto2, pickleProto4, []byte("(."), []byte("# text")} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		w, err := walkPickle(data)
		if err == nil && w.ops == 0 && len(data) > 0 && !w.short {
			t.Fatal("ни одного опкода без ошибки")
		}
		_ = looksLikePickle(data)
	})
}

func FuzzNumpyHeader(f *testing.F) {
	f.Add(npyBytes("'<f4'", nil))
	f.Add(npyBytes("[('a', '<f4'), ('b', [('c', '|O')])]", nil))
	f.Add([]byte("\x93NUMPY\x02\x00\x10\x00\x00\x00{'descr': 'O'}  "))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = numpyHasObject(bytes.NewReader(data), int64(len(data)), 1<<12) //nolint:gosec // G104: в fuzz важна только паника
	})
}

func FuzzZipDirectory(f *testing.F) {
	f.Add(zipBytes(f, map[string][]byte{"archive/data.pkl": pickleProto2}, "archive/data.pkl"))
	f.Add(zipBytes(f, map[string][]byte{"x.npy": npyBytes("'O'", nil)}, "x.npy"))
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))
	s := New(Limits{MaxZipEntries: 64, MaxZipDirectory: 1 << 16})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readZipDirectory(bytes.NewReader(data), int64(len(data))) //nolint:gosec // G104: в fuzz важна только паника
		fr := FileReport{}
		s.scanZip(bytes.NewReader(data), int64(len(data)), &fr)
	})
}

func FuzzSafetensorsHeader(f *testing.F) {
	f.Add([]byte(`{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}`), uint64(8))
	f.Add([]byte(`{"__metadata__":{"a":"b"},"a":{"dtype":"F4","shape":[3],"data_offsets":[0,2]}}`), uint64(2))
	f.Fuzz(func(t *testing.T, header []byte, dataLen uint64) {
		spans, err := parseSafetensorsHeader(header, dataLen, 1<<10)
		if err != nil {
			return
		}
		for _, sp := range spans {
			if sp.begin > sp.end || sp.end > dataLen {
				t.Fatalf("принят тензор вне данных: %+v", sp)
			}
		}
	})
}

func FuzzScanReader(f *testing.F) {
	f.Add(pickleProto0)
	f.Add(safetensorsBytes(`{"w":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}`, []byte{1}))
	f.Add([]byte("\x1f\x8b\x08\x00"))
	f.Add([]byte("\x93NUMPY\x01\x00\x04\x00{} "))
	s := New(Limits{MaxZipEntries: 64, MaxSafetensorsHeader: 1 << 16})
	f.Fuzz(func(t *testing.T, data []byte) {
		fr := s.ScanReader(bytes.NewReader(data), int64(len(data)), "f")
		if len(fr.Findings) > maxFindingsPerFile {
			t.Fatalf("находок %d", len(fr.Findings))
		}
	})
}
