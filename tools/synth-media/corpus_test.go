package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
)

const corpusDir = "../../testdata/corpus/media"

// Корпус в репозитории сходится с манифестом и генератором: файлы и SHA-256,
// размеры по заголовку в пределах ADR-0032, эталон и ожидания у каждого
// изображения, метаданные записаны в сами файлы.
func TestCorpusMatchesManifest(t *testing.T) {
	problems, err := verify(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// Состав корпуса покрывает то, что требует задача 5.36.
func TestCorpusComposition(t *testing.T) {
	kinds := map[string]int{}
	formats := map[string]int{}
	sources := map[string]int{}
	containers := map[string]bool{}
	ids := map[string]bool{}
	for _, s := range samples() {
		if ids[s.ID] {
			t.Errorf("%s: ID повторяется", s.ID)
		}
		ids[s.ID] = true
		kinds[s.Kind]++
		formats[s.Format]++
		for _, f := range s.Expect {
			sources[f.Source]++
		}
		for _, m := range s.Meta {
			containers[m.Container] = true
		}
		if s.Width*s.Height > limitPixels {
			t.Errorf("%s: больше предела пикселей ADR-0032", s.ID)
		}
		if (s.Kind == "clean") != (len(s.Expect) == 0) {
			t.Errorf("%s: находки ожидаются только у образцов, кроме clean", s.ID)
		}
	}
	for _, k := range []string{"card", "scan", "screenshot", "faint", "small", "injection", "qr", "metadata", "clean"} {
		if kinds[k] == 0 {
			t.Errorf("нет образцов вида %s", k)
		}
	}
	for _, src := range []string{"ocr", "ocr_contrast", "metadata", "qr"} {
		if sources[src] == 0 {
			t.Errorf("нет находок с источником %s", src)
		}
	}
	for _, c := range []string{"png-text", "png-ztxt", "png-itxt", "exif", "xmp", "jpeg-com"} {
		if !containers[c] {
			t.Errorf("нет метаданных в контейнере %s", c)
		}
	}
	if formats["png"] == 0 || formats["jpeg"] == 0 {
		t.Errorf("нужны и PNG, и JPEG: %v", formats)
	}
}

// Ожидаемые находки согласованы с текстовыми детекторами: текст, который
// aisec-media извлечёт из источника (OCR, метаданные, QR), даёт находку
// указанной категории на указанном фрагменте, а чистые образцы не дают
// находок вовсе. Это проверка разметки корпуса, а не aisec-media: OCR и
// разбор метаданных проверяются на корпусе в задачах 5.40–5.43.
func TestCorpusFindingsMatchTextDetectors(t *testing.T) {
	dets := builtin.All()
	run := func(t *testing.T, s *sample, text string) []detect.Finding {
		t.Helper()
		var out []detect.Finding
		for _, d := range dets {
			if !slices.Contains(d.Directions(), detect.Input) {
				continue
			}
			fs, err := d.Detect(context.Background(), detect.Text{Text: text, Direction: detect.Input, Source: detect.SourceUser, Lang: s.Lang})
			if err != nil {
				t.Fatalf("%s: %s: %v", s.ID, d.ID(), err)
			}
			out = append(out, fs...)
		}
		return out
	}
	for _, s := range samples() {
		t.Run(s.ID, func(t *testing.T) {
			texts := map[string][]string{"ocr": {s.refText()}, "qr": s.qrTexts()}
			texts["ocr_contrast"] = texts["ocr"]
			for _, m := range s.Meta {
				texts["metadata"] = append(texts["metadata"], m.Text)
			}
			if len(s.Expect) == 0 {
				for src, list := range texts {
					for _, txt := range list {
						for _, f := range run(t, &s, txt) {
							t.Errorf("чистый образец: %s дал %s на %q (%s)", f.Detector, f.Category, txt[f.Start:f.End], src)
						}
					}
				}
				return
			}
			for _, want := range s.Expect {
				found := false
				for _, txt := range texts[want.Source] {
					at := strings.Index(txt, want.Text)
					if at < 0 {
						continue
					}
					for _, f := range run(t, &s, txt) {
						if f.Category == want.Type && f.Start < at+len(want.Text) && f.End > at {
							found = true
						}
					}
				}
				if !found {
					t.Errorf("нет находки %s на %q в источнике %s", want.Type, want.Text, want.Source)
				}
				// Бледный текст — только у проходов с повышенной контрастностью, и наоборот.
				faint := false
				for _, l := range s.Lines {
					if strings.Contains(l.Class, "faint") && strings.Contains(l.Text, want.Text) {
						faint = true
					}
				}
				if (want.Source == "ocr_contrast") != faint {
					t.Errorf("%q: источник %s не соответствует оформлению строки", want.Text, want.Source)
				}
			}
		})
	}
}

// readFile и writeFile — файлы корпуса и временного каталога теста.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: файл корпуса или временного каталога теста
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil { //nolint:gosec // G703: путь во временном каталоге теста
		t.Fatal(err)
	}
}

// copyCorpus — копия корпуса во временный каталог для отрицательных проверок.
func copyCorpus(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		writeFile(t, filepath.Join(dst, e.Name()), readFile(t, filepath.Join(corpusDir, e.Name())))
	}
	return dst
}

func wantProblem(t *testing.T, dir, substr string) {
	t.Helper()
	problems, err := verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		if strings.Contains(p, substr) {
			return
		}
	}
	t.Fatalf("нет расхождения с %q, есть: %v", substr, problems)
}

func TestVerifyDetectsTampering(t *testing.T) {
	t.Run("изменён байт изображения", func(t *testing.T) {
		dir := copyCorpus(t)
		path := filepath.Join(dir, "card-01.png")
		b := readFile(t, path)
		b[len(b)/2] ^= 0xff
		writeFile(t, path, b)
		wantProblem(t, dir, "card-01.png: SHA-256")
	})
	t.Run("нет эталона", func(t *testing.T) {
		dir := copyCorpus(t)
		if err := os.Remove(filepath.Join(dir, "scan-02.txt")); err != nil {
			t.Fatal(err)
		}
		wantProblem(t, dir, "scan-02.txt: в манифесте, но нет в каталоге")
		wantProblem(t, dir, "scan-02.txt: эталон устарел или отсутствует")
	})
	t.Run("лишний файл", func(t *testing.T) {
		dir := copyCorpus(t)
		writeFile(t, filepath.Join(dir, "extra.png"), []byte("x"))
		wantProblem(t, dir, "extra.png: файла нет в манифесте")
	})
	t.Run("изменены ожидания", func(t *testing.T) {
		dir := copyCorpus(t)
		path := filepath.Join(dir, "meta-01.json")
		b := readFile(t, path)
		b = []byte(strings.Replace(string(b), "injection.override", "injection.role", 1))
		writeFile(t, path, b)
		wantProblem(t, dir, "meta-01.json: ожидания устарели")
	})
	t.Run("размеры в манифесте не те", func(t *testing.T) {
		dir := copyCorpus(t)
		path := filepath.Join(dir, manifestName)
		b := readFile(t, path)
		b = []byte(strings.Replace(string(b), `"width": 1000`, `"width": 1001`, 1))
		writeFile(t, path, b)
		wantProblem(t, dir, "размеры по заголовку")
	})
	t.Run("неизвестное поле манифеста", func(t *testing.T) {
		dir := copyCorpus(t)
		writeFile(t, filepath.Join(dir, manifestName), []byte(`{"version":1,"extra":1}`))
		if _, err := verify(dir); err == nil {
			t.Fatal("манифест с неизвестным полем принят")
		}
	})
}
