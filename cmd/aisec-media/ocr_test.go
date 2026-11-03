package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/media"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// TestOCRModelHashesMatchLock — хеши моделей, встроенные в aisec-media,
// совпадают с источниками make media-models (deploy/build/ocr/models.json),
// списком сверки без сети (models.sha256) и ML-BOM (mlbom.cdx.json): одна
// модель — один хеш во всех четырёх местах (задача 5.41).
func TestOCRModelHashesMatchLock(t *testing.T) {
	want := map[string]string{ocrDetModel.File: ocrDetModel.SHA256, ocrRecModel.File: ocrRecModel.SHA256}
	var lock struct {
		Files []struct{ Name, SHA256, License string } `json:"files"`
	}
	readJSON(t, "../../deploy/build/ocr/models.json", &lock)
	got := map[string]string{}
	for _, f := range lock.Files {
		if f.License != "Apache-2.0" {
			t.Errorf("%s: лицензия %q", f.Name, f.License)
		}
		got[f.Name] = f.SHA256
	}
	if !mapsEqual(got, want) {
		t.Errorf("models.json: %v, встроено %v", got, want)
	}
	sums, err := os.ReadFile("../../deploy/build/ocr/models.sha256")
	if err != nil {
		t.Fatal(err)
	}
	got = map[string]string{}
	for l := range strings.Lines(string(sums)) {
		if f := strings.Fields(l); len(f) == 2 {
			got[f[1]] = f[0]
		}
	}
	if !mapsEqual(got, want) {
		t.Errorf("models.sha256: %v, встроено %v", got, want)
	}
	var bom struct {
		Components []struct {
			Type, Name string
			Hashes     []struct{ Alg, Content string }
		}
	}
	readJSON(t, "../../deploy/build/ocr/mlbom.cdx.json", &bom)
	got = map[string]string{}
	for _, c := range bom.Components {
		if c.Type == "machine-learning-model" && len(c.Hashes) == 1 && c.Hashes[0].Alg == "SHA-256" {
			got[c.Name+".onnx"] = c.Hashes[0].Content
		}
	}
	if !mapsEqual(got, want) {
		t.Errorf("mlbom.cdx.json: %v, встроено %v", got, want)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: файл репозитория
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestLoadOCRModelChecksHash — модель с другим хешем, каталог вместо файла
// и отсутствующий файл не загружаются; верная — загружается.
func TestLoadOCRModelChecksHash(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	data := []byte("не модель, но байты с известным хешем")
	if err := os.WriteFile(filepath.Join(dir, "m.onnx"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	good := ocrModel{File: "m.onnx", SHA256: hex.EncodeToString(h.Sum(data))}
	if got, err := loadOCRModel(dir, good, p); err != nil || string(got) != string(data) {
		t.Fatalf("верная модель: %v", err)
	}
	bad := good
	bad.SHA256 = strings.Repeat("00", 32)
	if _, err := loadOCRModel(dir, bad, p); err == nil || !strings.Contains(err.Error(), "хеш не совпадает") {
		t.Fatalf("чужой хеш: %v", err)
	}
	if _, err := loadOCRModel(dir, ocrModel{File: "нет.onnx", SHA256: good.SHA256}, p); err == nil {
		t.Fatal("нет файла")
	}
	if err := os.Mkdir(filepath.Join(dir, "d.onnx"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOCRModel(dir, ocrModel{File: "d.onnx", SHA256: good.SHA256}, p); err == nil {
		t.Fatal("каталог вместо файла")
	}
}

func TestParseCharset(t *testing.T) {
	if cs, err := parseCharset("а\nб\nв\n", 5); err != nil || !slices.Equal(cs, []string{"а", "б", "в", " "}) {
		t.Fatalf("с пробелом: %q %v", cs, err)
	}
	if cs, err := parseCharset("а\nб", 3); err != nil || len(cs) != 2 {
		t.Fatalf("без пробела: %q %v", cs, err)
	}
	if _, err := parseCharset("а\nб", 7); err == nil {
		t.Fatal("число классов не совпало — принято")
	}
}

// selftestEngine — исполнитель-заглушка: одна строка на всё изображение,
// распознаётся как text.
type selftestEngine struct{ text string }

func (e selftestEngine) Charset() []string {
	var cs []string
	for _, r := range "Инструкцияпонастрйкеё XYZ" {
		if !slices.Contains(cs, string(r)) {
			cs = append(cs, string(r))
		}
	}
	return cs
}

func (e selftestEngine) Detect(_ context.Context, _ []float32, h, w int) ([]float32, error) {
	out := make([]float32, h*w)
	for y := h / 4; y < 3*h/4; y++ {
		for x := w / 10; x < 9*w/10; x++ {
			out[y*w+x] = 0.9
		}
	}
	return out, nil
}

func (e selftestEngine) Recognize(context.Context, []float32, int) ([]float32, int, error) {
	cs := e.Charset()
	c := len(cs) + 1
	var out []float32
	for _, r := range e.text {
		p := make([]float32, c)
		p[slices.Index(cs, string(r))+1] = 1
		out = append(out, p...)
		out = append(out, append([]float32{1}, make([]float32, c-1)...)...)
	}
	return out, c, nil
}

// TestStartOCRSelftest — запуск с OCR проходит, только если эталонное
// изображение распознано как ожидается; иначе aisec-media не запускается.
// Без исполнителя (сборка без тега aisec_onnx) OCR нет, и это не ошибка.
func TestStartOCRSelftest(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config{Limits: media.Limits{MaxBytes: media.DefaultMaxBytes, MaxPixels: media.DefaultMaxPixels}, Workers: 1}
	d := deps{provider: p, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), ocrEngine: selftestEngine{text: ocrSelftestText}}
	o, err := startOCR(context.Background(), cfg, d)
	if err != nil || o == nil {
		t.Fatalf("самопроверка с верным текстом: %v", err)
	}
	d.ocrEngine = selftestEngine{text: "XYZ"}
	if _, err := startOCR(context.Background(), cfg, d); err == nil || !strings.Contains(err.Error(), "самопроверка OCR") {
		t.Fatalf("неверный текст: %v", err)
	}
	if !ocrBuilt {
		d.ocrEngine = nil
		if o, err := startOCR(context.Background(), cfg, d); err != nil || o != nil {
			t.Fatalf("сборка без OCR: %v %v", o, err)
		}
	}
	// Итог с OCR проходит проверку протокола и содержит ocr в checks.
	res, err := media.Analyzer{Limits: cfg.Limits, OCR: o}.Analyze(context.Background(), ocrSelftestPNG)
	if err != nil || res.Validate() != nil || !slices.Contains(res.Checks, wire.CheckOCR) {
		t.Fatalf("%+v %v", res, err)
	}
}
