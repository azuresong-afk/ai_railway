//go:build aisec_onnx && cgo

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/media"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// OCR на настоящих моделях и ONNX Runtime (ADR-0033, задачи 5.41 и 5.42).
// Нужны библиотека ORT 1.31.0 (AISEC_ORT_LIB=…/libonnxruntime.so.1.31.0,
// make ort-build) и модели (AISEC_MEDIA_MODELS_DIR, make media-models); без
// них тесты пропускаются — так в make check и CI, где библиотеки нет
// (docs/cert/build-env.md). Запуск: make media-ocr-test AISEC_ORT_LIB=…

const corpusDir = "../../testdata/corpus/media"

var (
	ocrTestOnce sync.Once
	ocrTest     *media.OCR
	ocrTestErr  error
)

// testOCR — исполнитель на настоящей библиотеке и моделях (один на процесс:
// среда ORT поднимается один раз).
func testOCR(t *testing.T) *media.OCR {
	t.Helper()
	lib := os.Getenv("AISEC_ORT_LIB")
	if lib == "" {
		t.Skip("AISEC_ORT_LIB не задан")
	}
	ocrTestOnce.Do(func() {
		p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
		if err != nil {
			ocrTestErr = err
			return
		}
		data, err := os.ReadFile(lib) //nolint:gosec // G304: путь к библиотеке задаёт тот, кто запускает тест
		if err != nil {
			ocrTestErr = err
			return
		}
		h, err := p.Hasher()
		if err != nil {
			ocrTestErr = err
			return
		}
		ortLibHash = hex.EncodeToString(h.Sum(data))
		models := testModelsDir()
		os.Setenv("ORT_DISABLE_TELEMETRY", "1") //nolint:errcheck,gosec,usetesting // среда ORT общая для процесса
		e, err := newOCREngine(&config{ORTLib: lib, Models: models, Workers: 1}, p)
		if err != nil {
			ocrTestErr = err
			return
		}
		ocrTest, ocrTestErr = media.NewOCR(e)
	})
	if ocrTestErr != nil {
		t.Fatal(ocrTestErr)
	}
	return ocrTest
}

// testModelsDir — каталог моделей: AISEC_MEDIA_MODELS_DIR или
// build/media-models (make media-models). Абсолютный путь — требование
// newOCREngine; относительный из Abs не выходит только при сбое Getwd, и
// тогда загрузка откажет с понятной ошибкой.
func testModelsDir() string {
	if d := os.Getenv("AISEC_MEDIA_MODELS_DIR"); d != "" {
		return d
	}
	if d, err := filepath.Abs("../../build/media-models"); err == nil {
		return d
	}
	return "../../build/media-models"
}

var testLimits = media.Limits{MaxBytes: media.DefaultMaxBytes, MaxPixels: media.DefaultMaxPixels}

// sample — образец корпуса (<id>.json).
type sample struct {
	ID, File, Lang string
	Kind           string
	DM             []string
	Expect         []struct{ Type, Source, Text string }
	TextFileName   string `json:"text_file"`
}

func corpus(t *testing.T) []sample {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(corpusDir, "*.json"))
	if err != nil || len(files) < 28 {
		t.Fatalf("корпус: %d, %v", len(files), err)
	}
	var out []sample
	for _, f := range files {
		if filepath.Base(f) == "manifest.json" {
			continue
		}
		var s sample
		b, err := os.ReadFile(f) //nolint:gosec // G304: корпус репозитория
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, s)
	}
	return out
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpusDir, name)) //nolint:gosec // G304: корпус репозитория
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// findings — находки текстовых детекторов входа на тексте изображения, как
// их ищет шлюз: источник image, язык неизвестен.
func findings(t *testing.T, text string) []detect.Finding {
	t.Helper()
	var out []detect.Finding
	for _, d := range builtin.All() {
		if !slices.Contains(d.Directions(), detect.Input) {
			continue
		}
		fs, err := d.Detect(context.Background(), detect.Text{Text: text, Direction: detect.Input, Source: detect.SourceImage})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, fs...)
	}
	return out
}

// ocrRun — итог анализа образца: тексты OCR (все проходы) и их находки.
type ocrRun struct {
	res  wire.Result
	took time.Duration
	hits []policy.Hit
}

var (
	runsOnce sync.Once
	runs     map[string]ocrRun
)

// analyzeCorpus анализирует весь корпус один раз (как aisec-media: срок —
// умолчание -run-timeout для sync, 2 с; без кэша).
func analyzeCorpus(t *testing.T) map[string]ocrRun {
	t.Helper()
	o := testOCR(t)
	runsOnce.Do(func() {
		runs = map[string]ocrRun{}
		an := media.Analyzer{Limits: testLimits, OCR: o}
		for _, s := range corpus(t) {
			ctx, cancel := context.WithTimeout(context.Background(), media.DefaultRunTimeout)
			start := time.Now()
			res, err := an.Analyze(ctx, read(t, s.File))
			took := time.Since(start)
			cancel()
			if err != nil || res.Validate() != nil {
				t.Fatalf("%s: %v %v", s.ID, err, res.Validate())
			}
			r := ocrRun{res: res, took: took}
			for _, x := range res.Texts {
				if x.Source != wire.SourceOCR && x.Source != wire.SourceOCRContrast {
					continue
				}
				for _, f := range findings(t, x.Text) {
					r.hits = append(r.hits, policy.Hit{Finding: f, Source: detect.SourceImage})
				}
			}
			runs[s.ID] = r
		}
	})
	return runs
}

// checkExpected — у образцов строки dm все ожидаемые находки OCR найдены
// (по тексту любого прохода, как в шлюзе); итог — найдено и ожидалось.
func checkExpected(t *testing.T, dm string) (found, want int) {
	t.Helper()
	all := analyzeCorpus(t)
	for _, s := range corpus(t) {
		if !slices.Contains(s.DM, dm) {
			continue
		}
		r := all[s.ID]
		if !slices.Contains(r.res.Checks, wire.CheckOCR) {
			t.Fatalf("%s: нет ocr в checks: %v", s.ID, r.res.Checks)
		}
		for _, e := range s.Expect {
			if e.Source != string(wire.SourceOCR) && e.Source != string(wire.SourceOCRContrast) {
				continue
			}
			want++
			if slices.ContainsFunc(r.hits, func(h policy.Hit) bool { return h.Finding.Category == e.Type }) {
				found++
			} else {
				var texts []string
				for _, x := range r.res.Texts {
					texts = append(texts, fmt.Sprintf("%s: %q", x.Source, x.Text))
				}
				t.Errorf("%s: нет находки %s; тексты: %s", s.ID, e.Type, strings.Join(texts, "; "))
			}
		}
	}
	return found, want
}

// TestDM45_FaintTextInstruction — инструкции-инъекции на изображениях
// корпуса (бледный текст — проходом «контраст», мелкий 7 px — проходом ×2,
// слайд, скан, «системное сообщение») находятся текстовыми детекторами по
// тексту OCR.
// Покрывает: DM-45
func TestDM45_FaintTextInstruction(t *testing.T) {
	found, want := checkExpected(t, "DM-45")
	if want < 8 || found != want {
		t.Fatalf("DM-45: найдено %d из %d", found, want)
	}
}

// TestDM46_PIIOnScreenshotBlocked — ПДн и секреты на скриншотах и сканах
// корпуса находятся по тексту OCR, а политика по умолчанию в режиме
// enforce блокирует запрос с таким изображением (замаскировать текст на
// изображении нельзя, Р9).
// Покрывает: DM-46
func TestDM46_PIIOnScreenshotBlocked(t *testing.T) {
	found, want := checkExpected(t, "DM-46")
	if want < 22 || found != want {
		t.Fatalf("DM-46: найдено %d из %d", found, want)
	}
	reg, err := detect.NewRegistry(builtin.Catalog()...)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve("", nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	all := analyzeCorpus(t)
	for _, s := range corpus(t) {
		if !slices.Contains(s.DM, "DM-46") || len(s.Expect) == 0 || slices.ContainsFunc(s.Expect, func(e struct{ Type, Source, Text string }) bool {
			return e.Source != string(wire.SourceOCR) && e.Source != string(wire.SourceOCRContrast)
		}) {
			continue
		}
		d := p.Evaluate(policy.Request{Endpoint: policy.EndpointChat, Direction: detect.Input, Mode: policy.Enforce, Hits: all[s.ID].hits})
		if !d.Block {
			t.Errorf("%s: изображение с ПДн не заблокировано: %+v", s.ID, d)
		}
	}
}

// TestOCRCorpusNoFalsePositives — на образцах без ожидаемых находок OCR
// (чистые, метаданные, QR) текст OCR не даёт находок, а у остальных — только
// ожидаемые категории.
func TestOCRCorpusNoFalsePositives(t *testing.T) {
	all := analyzeCorpus(t)
	for _, s := range corpus(t) {
		var allowed []string
		for _, e := range s.Expect {
			allowed = append(allowed, e.Type)
		}
		for _, h := range all[s.ID].hits {
			if !slices.Contains(allowed, h.Finding.Category) {
				t.Errorf("%s: ложная находка %s (%s)", s.ID, h.Finding.Category, h.Finding.Detector)
			}
		}
	}
}

// TestOCRCorpusCER — критерий ADR-0033, п. 1 на выходе самого aisec-media:
// CER обычного прохода по корпусу — не больше 5 % по русскому и 2 % по
// английскому. Время — на изображение, оба прохода и ×2 вместе (для
// docs/detectors.md; на 4 vCPU — make media-ocr-test под taskset).
func TestOCRCorpusCER(t *testing.T) {
	o := testOCR(t)
	an := media.Analyzer{Limits: testLimits, OCR: o}
	errs, refs := map[string]int{}, map[string]int{}
	for _, s := range corpus(t) {
		if s.TextFileName == "" {
			continue
		}
		ref := normalize(string(read(t, s.TextFileName)))
		if ref == "" {
			continue
		}
		normal, _, err := an.PassTexts(context.Background(), read(t, s.File))
		if err != nil {
			t.Fatal(err)
		}
		d := distance(normalize(normal), ref)
		errs[s.Lang] += d
		refs[s.Lang] += len([]rune(ref))
		t.Logf("%s: CER %.1f %%", s.ID, 100*float64(d)/float64(len([]rune(ref))))
	}
	ru, en := float64(errs["ru"])/float64(refs["ru"]), float64(errs["en"])/float64(refs["en"])
	t.Logf("CER RU %.2f %%, EN %.2f %%", 100*ru, 100*en)
	if ru > 0.05 || en > 0.02 {
		t.Fatalf("CER RU %.2f %% (предел 5 %%), EN %.2f %% (предел 2 %%)", 100*ru, 100*en)
	}
	var times []time.Duration
	for id, r := range analyzeCorpus(t) {
		times = append(times, r.took)
		t.Logf("%s: %v", id, r.took.Round(time.Millisecond))
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	t.Logf("время на изображение (GOMAXPROCS и потоки ORT — по процессу): медиана %v, p95 %v, наибольшее %v",
		times[len(times)/2].Round(time.Millisecond), times[len(times)*95/100].Round(time.Millisecond), times[len(times)-1].Round(time.Millisecond))
}

// TestOCRCorpusTwoWorkers — нагрузка как у aisec-media по умолчанию:
// -workers=2 (потоки ORT делятся между исполнителями), два изображения
// одновременно, корпус дважды, срок 2 с. Время пишется в журнал теста для
// docs/detectors.md; ошибка, кроме срока, — провал. Сроки зависят от
// процессоров машины и считаются в журнале, а не проваливают тест.
func TestOCRCorpusTwoWorkers(t *testing.T) {
	testOCR(t)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	models := testModelsDir()
	e, err := newOCREngine(&config{ORTLib: os.Getenv("AISEC_ORT_LIB"), Models: models, Workers: 2}, p)
	if err != nil {
		t.Fatal(err)
	}
	o, err := media.NewOCR(e)
	if err != nil {
		t.Fatal(err)
	}
	an := media.Analyzer{Limits: testLimits, OCR: o}
	ss := corpus(t)
	var (
		mu       sync.Mutex
		times    []time.Duration
		timeouts int
		wg       sync.WaitGroup
	)
	jobs := make(chan sample)
	for range 2 {
		wg.Go(func() {
			for s := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), media.DefaultRunTimeout)
				start := time.Now()
				_, err := an.Analyze(ctx, read(t, s.File))
				d := time.Since(start)
				cancel()
				mu.Lock()
				times = append(times, d)
				switch {
				case errors.Is(err, context.DeadlineExceeded):
					timeouts++
				case err != nil:
					t.Errorf("%s: %v", s.ID, err)
				}
				mu.Unlock()
			}
		})
	}
	for range 2 {
		for _, s := range ss {
			jobs <- s
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	t.Logf("-workers=2, два изображения одновременно, GOMAXPROCS %d: %d анализов, медиана %v, p95 %v, наибольшее %v, по сроку %d",
		runtime.GOMAXPROCS(0), len(times), times[len(times)/2].Round(time.Millisecond), times[len(times)*95/100].Round(time.Millisecond),
		times[len(times)-1].Round(time.Millisecond), timeouts)
}

// normalize — строки без пустых, пробелы внутри строки схлопнуты (как
// tools/ocr-eval).
func normalize(s string) string {
	var lines []string
	for l := range strings.SplitSeq(s, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			lines = append(lines, strings.Join(f, " "))
		}
	}
	return strings.Join(lines, "\n")
}

// distance — расстояние Левенштейна по символам Unicode.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev, cur := make([]int, len(rb)+1), make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			c := prev[j-1]
			if ra[i-1] != rb[j-1] {
				c++
			}
			cur[j] = min(c, prev[j]+1, cur[j-1]+1)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

// TestOCRSelftestRealModels — самопроверка при запуске на настоящих моделях.
func TestOCRSelftestRealModels(t *testing.T) {
	o := testOCR(t)
	if err := ocrSelftest(context.Background(), media.Analyzer{Limits: testLimits, OCR: o}); err != nil {
		t.Fatal(err)
	}
}

// TestInitORTRefusesForeignLibraryMedia — библиотека с другим хешем или
// сборка без встроенного хеша не загружаются (как у aisec-ml).
func TestInitORTRefusesForeignLibraryMedia(t *testing.T) {
	lib := os.Getenv("AISEC_ORT_LIB")
	if lib == "" {
		t.Skip("AISEC_ORT_LIB не задан")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if err := initORT(lib, p, strings.Repeat("00", 32)); err == nil || !strings.Contains(err.Error(), "хеш не совпадает") {
		t.Fatalf("чужой хеш: %v", err)
	}
	if err := initORT(lib, p, ""); err == nil {
		t.Fatal("сборка без хеша загрузила библиотеку")
	}
}
