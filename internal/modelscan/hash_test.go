package modelscan

import (
	"os"
	"path/filepath"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Хеши файлов модели (задача 5.22 этапа 5): SHA-256 каждого файла в
// отчёте scan (WithHash) и в отчёте verify без разбора форматов (HashPath).

// shaABC — SHA-256 строки «abc» (FIPS 180-2, пример B.1).
const shaABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func sha256Scanner(t *testing.T) *Scanner {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return New(Limits{}).WithHash(h.New)
}

func TestScanPathWithHash(t *testing.T) {
	dir := writeFiles(t, map[string][]byte{"weights/a.bin": []byte("abc"),
		"model.safetensors": safetensorsBytes(`{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}`, make([]byte, 4))})
	plain, err := New(Limits{}).ScanPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range plain.Files {
		if f.SHA256 != "" {
			t.Fatalf("хеш без WithHash: %+v", f)
		}
	}
	s := sha256Scanner(t)
	rep, err := s.ScanPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]FileReport{}
	for _, f := range rep.Files {
		got[f.Path] = f
	}
	if got["weights/a.bin"].SHA256 != shaABC || got["model.safetensors"].Format != FormatSafetensors || len(got["model.safetensors"].SHA256) != 64 {
		t.Fatalf("scan с хешами: %+v", rep.Files)
	}
	// verify: только пути, размеры и хеши, форматы не разбираются.
	rep, err = s.HashPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Files {
		if f.Format != "" || len(f.Findings) != 0 || len(f.SHA256) != 64 {
			t.Fatalf("HashPath: %+v", f)
		}
		if f.Path == "weights/a.bin" && (f.SHA256 != shaABC || f.Size != 3) {
			t.Fatalf("HashPath: %+v", f)
		}
	}
	// Один файл, а не каталог.
	rep, err = s.HashPath(filepath.Join(dir, "weights", "a.bin"))
	if err != nil || len(rep.Files) != 1 || rep.Files[0].Path != "a.bin" || rep.Files[0].SHA256 != shaABC {
		t.Fatalf("файл: %+v %v", rep, err)
	}
	if _, err := New(Limits{}).HashPath(dir); err == nil {
		t.Fatal("HashPath без WithHash")
	}
	if _, err := s.HashPath(filepath.Join(dir, "нет")); err == nil {
		t.Fatal("нет пути")
	}
	// Символьная ссылка на файл — хеш содержимого цели, пометка ссылки.
	if err := os.Symlink(filepath.Join(dir, "weights", "a.bin"), filepath.Join(dir, "link.bin")); err != nil {
		t.Skip(err)
	}
	rep, _ = s.HashPath(dir) //nolint:gosec // G104: ошибку покажет проверка файлов ниже
	for _, f := range rep.Files {
		if f.Path == "link.bin" && (!f.Symlink || f.SHA256 != shaABC) {
			t.Fatalf("ссылка: %+v", f)
		}
	}
}
