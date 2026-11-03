package media

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// corpusDir — корпус изображений (задача 5.36, testdata/corpus/media).
const corpusDir = "../../testdata/corpus/media"

// corpusSample — описание образца корпуса (<id>.json).
type corpusSample struct {
	ID       string   `json:"id"`
	File     string   `json:"file"`
	Kind     string   `json:"kind"`
	DM       []string `json:"dm"`
	Metadata []struct {
		Container string `json:"container"`
		Field     string `json:"field"`
		Text      string `json:"text"`
	} `json:"metadata"`
	QR     []string `json:"qr"`
	Expect []struct {
		Type   string `json:"type"`
		Source string `json:"source"`
		Text   string `json:"text"`
	} `json:"expect"`
}

func corpusSamples(t *testing.T) []corpusSample {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(corpusDir, "*.json"))
	if err != nil || len(files) < 28 {
		t.Fatalf("корпус: %d файлов, %v", len(files), err)
	}
	var out []corpusSample
	for _, f := range files {
		if filepath.Base(f) == "manifest.json" {
			continue
		}
		var s corpusSample
		if err := json.Unmarshal(readTestFile(t, f), &s); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, s)
	}
	return out
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: файл корпуса в репозитории
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// imageFindings — находки текстовых детекторов на тексте изображения, как
// их ищет шлюз: вход, источник image, язык неизвестен.
func imageFindings(t *testing.T, text string) []detect.Finding {
	t.Helper()
	var out []detect.Finding
	for _, d := range builtin.All() {
		if !slices.Contains(d.Directions(), detect.Input) {
			continue
		}
		fs, err := d.Detect(context.Background(), detect.Text{Text: text, Direction: detect.Input, Source: detect.Source("image")})
		if err != nil {
			t.Fatalf("%s: %v", d.ID(), err)
		}
		out = append(out, fs...)
	}
	return out
}

// TestDM47_EXIFAndQRText — текст метаданных (EXIF, XMP, текстовые чанки
// PNG, комментарий JPEG) и QR-кодов корпуса извлекается анализатором с
// источником metadata или qr, а текстовые детекторы находят на нём то, что
// размечено в корпусе; на чистых образцах (clean-04, qr-03) находок нет.
// Покрывает: DM-47
func TestDM47_EXIFAndQRText(t *testing.T) {
	checked := 0
	for _, s := range corpusSamples(t) {
		t.Run(s.ID, func(t *testing.T) {
			res, err := Analyze(readTestFile(t, filepath.Join(corpusDir, s.File)), testLimits)
			if err != nil || res.Status != wire.StatusOK || res.Validate() != nil {
				t.Fatalf("итог %+v, %v", res, err)
			}
			if !slices.Contains(res.Checks, wire.CheckMetadata) || !slices.Contains(res.Checks, wire.CheckQR) {
				t.Fatalf("проверки %v", res.Checks)
			}
			got := map[wire.Source][]wire.Text{}
			for _, x := range res.Texts {
				got[x.Source] = append(got[x.Source], x)
			}
			// Всё записанное в метаданные и QR извлечено.
			for _, m := range s.Metadata {
				if !slices.ContainsFunc(got[wire.SourceMetadata], func(x wire.Text) bool { return x.Text == m.Text && x.Box == nil }) {
					t.Errorf("нет текста %s %s: %q", m.Container, m.Field, m.Text)
				}
			}
			for _, q := range s.QR {
				if !slices.ContainsFunc(got[wire.SourceQR], func(x wire.Text) bool { return x.Text == q && x.Box != nil }) {
					t.Errorf("нет текста QR %q (с рамкой): %+v", q, got[wire.SourceQR])
				}
			}
			if len(got[wire.SourceQR]) != len(s.QR) {
				t.Errorf("лишние QR: %+v", got[wire.SourceQR])
			}
			if len(s.Metadata) == 0 && len(got[wire.SourceMetadata]) != 0 {
				t.Errorf("лишний текст метаданных: %+v", got[wire.SourceMetadata])
			}
			// Находки детекторов на тексте metadata и qr.
			if slices.Contains(s.DM, "DM-47") && len(s.Expect) == 0 {
				for _, x := range res.Texts {
					for _, f := range imageFindings(t, x.Text) {
						t.Errorf("чистый образец: %s дал %s на %q (%s)", f.Detector, f.Category, x.Text[f.Start:f.End], x.Source)
					}
				}
			}
			for _, want := range s.Expect {
				if want.Source != string(wire.SourceMetadata) && want.Source != string(wire.SourceQR) {
					continue
				}
				checked++
				found := false
				for _, x := range got[wire.Source(want.Source)] {
					at := strings.Index(x.Text, want.Text)
					if at < 0 {
						continue
					}
					for _, f := range imageFindings(t, x.Text) {
						if f.Category == want.Type && f.Start < at+len(want.Text) && f.End > at {
							found = true
						}
					}
				}
				if !found {
					t.Errorf("нет находки %s на %q (%s)", want.Type, want.Text, want.Source)
				}
			}
		})
	}
	if checked < 10 {
		t.Fatalf("проверено ожиданий DM-47: %d", checked)
	}
}
