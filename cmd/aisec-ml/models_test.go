//go:build aisec_onnx && cgo && aisec_models

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/injection"
	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/ml"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/tools/detector-quality/p4"
)

// Проверка настоящих моделей на машине владельца (задача 4.19): make
// ml-verify и make ml-p4. Нужны библиотека ONNX Runtime 1.31.0
// (AISEC_ORT_LIB) и каталог build/ml после make ml-export (AISEC_ML_DIR):
// models/<id>/model.onnx и tokenizer.json, models.spec.json и эталоны
// ref/<id>.tokref.jsonl, ref/<id>.logits.jsonl. Подпись пакета здесь не
// нужна: её проверяет aisec-ml при запуске (make ml-package).

const repoRoot = "../.."

func mlDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("AISEC_ML_DIR"); d != "" {
		return d
	}
	return filepath.Join(repoRoot, "build", "ml")
}

// loadModels — модели из build/ml/models на исполнителе ONNX Runtime.
func loadModels(t *testing.T) map[string]*onnxModel {
	t.Helper()
	lib := os.Getenv("AISEC_ORT_LIB")
	if lib == "" {
		t.Fatal("AISEC_ORT_LIB не задан: путь к libonnxruntime.so.1.31.0 (make ort-build)")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(lib) //nolint:gosec // G304: путь задаёт тот, кто запускает проверку
	if err != nil {
		t.Fatal(err)
	}
	ortLibHash = hex.EncodeToString(h.Sum(data))
	exec, err := newExecutor(&config{ORTLib: lib}, p)
	if err != nil {
		t.Fatal(err)
	}
	dir := mlDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "models.spec.json")) //nolint:gosec // G304: каталог сборки
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Models []ml.ModelSpec `json:"models"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	out := map[string]*onnxModel{}
	for _, s := range spec.Models {
		model, err := os.ReadFile(filepath.Join(dir, "models", s.ID, ml.ModelFileName)) //nolint:gosec // G304: каталог сборки
		if err != nil {
			t.Fatal(err)
		}
		tok, err := os.ReadFile(filepath.Join(dir, "models", s.ID, ml.TokenizerFileName)) //nolint:gosec // G304: каталог сборки
		if err != nil {
			t.Fatal(err)
		}
		m, err := exec.Load(ml.LoadedModel{Spec: s, Model: model, Tokenizer: tok})
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		t.Cleanup(func() { _ = m.Close() })
		out[s.ID] = m.(*onnxModel)
	}
	if len(out) == 0 {
		t.Fatal("в models.spec.json нет моделей")
	}
	return out
}

func readJSONL(t *testing.T, path string, each func(line []byte)) {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: каталог сборки
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // только чтение
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		each(sc.Bytes())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}

// Токенизатор на Go совпадает с эталоном tokenizers на текстах корпуса, а
// выход модели в aisec-ml (ONNX Runtime) — с выходом исходной модели torch:
// экспорт, токенизатор и исполнитель вместе дают те же числа.
func TestModelsMatchReference(t *testing.T) {
	dir := mlDir(t)
	for id, m := range loadModels(t) {
		t.Run(id, func(t *testing.T) {
			n, bad := 0, 0
			readJSONL(t, filepath.Join(dir, "ref", id+".tokref.jsonl"), func(line []byte) {
				var r struct {
					Text    string   `json:"text"`
					IDs     []int64  `json:"ids"`
					Offsets [][2]int `json:"offsets"`
				}
				if err := json.Unmarshal(line, &r); err != nil {
					t.Fatal(err)
				}
				n++
				ids, offs, _, err := m.tok.Encode(context.Background(), r.Text, ml.MaxText)
				if err != nil {
					t.Fatal(err)
				}
				if len(r.IDs) == 0 {
					r.IDs, r.Offsets = nil, nil
				}
				if !slices.Equal(ids, r.IDs) || !slices.Equal(offs, r.Offsets) {
					if bad++; bad <= 5 {
						t.Errorf("токены %.80q:\n  go  %v\n  ref %v", r.Text, ids, r.IDs)
					}
				}
			})
			if n == 0 || bad > 0 {
				t.Fatalf("токенизатор: текстов %d, расхождений %d", n, bad)
			}
			cls, sep := m.tok.Special()
			n, worst := 0, 0.0
			readJSONL(t, filepath.Join(dir, "ref", id+".logits.jsonl"), func(line []byte) {
				var r struct {
					Text   string    `json:"text"`
					Logits []float64 `json:"logits"`
				}
				if err := json.Unmarshal(line, &r); err != nil {
					t.Fatal(err)
				}
				ids, _, trunc, err := m.tok.Encode(context.Background(), r.Text, m.spec.MaxTokens-2)
				if err != nil || trunc {
					t.Fatalf("%.60q: %v %v", r.Text, trunc, err)
				}
				got, err := m.infer(context.Background(), append(append([]int64{cls}, ids...), sep))
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != len(r.Logits) {
					t.Fatalf("%.60q: выходов %d, в эталоне %d", r.Text, len(got), len(r.Logits))
				}
				for i := range got {
					worst = max(worst, math.Abs(float64(got[i])-r.Logits[i]))
				}
				n++
			})
			// float32 против float32 torch: расхождение порядка 1e-5.
			if n == 0 || worst > 2e-3 {
				t.Fatalf("logits: текстов %d, наибольшее расхождение %g", n, worst)
			}
			t.Logf("%s: токены и logits совпадают (текстов %d, расхождение logits до %.2g)", id, n, worst)
		})
	}
}

// Замер Р4 (ADR-0024, раздел 7): ML-детекторы через сервер протокола
// aisec-ml и клиент шлюза против эвристик на проверочных корпусах, задержка
// p50 и p95 на тексте около 2 000 токенов. Итог — build/ml/p4.md, таблица
// для docs/detectors.md. Запускать на машине с 4 vCPU (make ml-p4).
func TestP4Measure(t *testing.T) {
	models := loadModels(t)
	var list []ml.Model
	for _, m := range models {
		list = append(list, m)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Срок вывода — с запасом (по умолчанию он короче): задержку меряет замер, а не срок.
	srv, err := ml.NewServer(ml.ServerConfig{Models: list, Logger: quiet, RunTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("", "aisec-ml-p4")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })  //nolint:gosec // G104: ошибка в тесте не важна
	if err := os.Chmod(sockDir, 0o750); err != nil { //nolint:gosec // G302: тест задаёт права сокета и каталога намеренно
		t.Fatal(err)
	}
	sock := filepath.Join(sockDir, "ml.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, 0o660); err != nil { //nolint:gosec // G302: тест задаёт права сокета и каталога намеренно
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, l); close(done) }() //nolint:gosec // G104: ошибка в тесте не важна
	t.Cleanup(func() { cancel(); <-done })
	// Срок вызова — с запасом: здесь меряется задержка, а не отсрочка.
	client, err := gateway.NewMLClient(gateway.MLClientConfig{Socket: sock, Timeout: 5 * time.Second, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	base, err := p4.ListsBaseline(filepath.Join(repoRoot, "testdata/ml/toxicity-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	nerBase, err := p4.ListsBaseline(filepath.Join(repoRoot, "testdata/ml/ner-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	heur := map[string]detect.Detector{builtin.InjectionMLID: injection.New(), builtin.ToxicityMLID: base, builtin.PIINERID: nerBase}
	var cases []p4.Case
	for _, s := range builtin.MLSpecs() {
		m, ok := models[s.Model]
		if !ok {
			t.Logf("модели %s нет в пакете: %s не замеряется", s.Model, s.ID)
			continue
		}
		d, err := gateway.NewMLDetector(s, client)
		if err != nil {
			t.Fatal(err)
		}
		th, _ := policy.TemplateMLThreshold(s.ID)
		dir := filepath.Join(repoRoot, "testdata/corpus", s.ID)
		text, n, err := p4.LatencyText(dir, func(x string) (int, error) {
			ids, _, _, err := m.tok.Encode(context.Background(), x, ml.MaxText)
			return len(ids), err
		}, p4.LatencyTokens)
		if err != nil {
			t.Fatal(err)
		}
		model := s.Model
		c := p4.Case{ML: d, Heuristic: heur[s.ID], Corpus: dir, Threshold: th, LatencyText: text, LatencyTokens: n,
			LatencyRuns: 200, Latency: func(ctx context.Context, x string) error { _, err := client.Detect(ctx, model, x); return err },
			// pii.ner — правило «при той же доле ложных» (решение владельца
			// 30.10.2026, ADR-0024, дополнение 4.20).
			EqualFPR: s.ID == builtin.PIINERID}
		cases = append(cases, c)
		// pii.ner — ещё и против pii.ru: он имён не ищет, строка для
		// сравнения показывает, что добавляет NER к детектору этапа 1.
		if s.ID == builtin.PIINERID {
			c.Heuristic, c.Reference, c.Latency = pii.New(), true, nil
			cases = append(cases, c)
		}
	}
	rs, err := p4.Run(context.Background(), cases)
	if err != nil {
		t.Fatal(err)
	}
	env := fmt.Sprintf("%s, %s, процессоров %d (GOMAXPROCS %d), %s, %s", cpuModel(), runtime.GOARCH, runtime.NumCPU(),
		runtime.GOMAXPROCS(0), runtime.Version(), time.Now().Format("02.01.2006"))
	md := p4.Markdown(rs, env)
	// 4В30 (г): все модели одновременно на тексте в 16 окон — как их
	// вызывают детекторы одного фрагмента — против срока вызова шлюза.
	calls := map[string]func(context.Context, string) error{}
	var counter *onnxModel
	for id, m := range models {
		calls[id] = func(ctx context.Context, x string) error { _, err := client.Detect(ctx, id, x); return err }
		if counter == nil || m.spec.MaxTokens < counter.spec.MaxTokens {
			counter = m
		}
	}
	if counter != nil {
		const windows = 16
		text, n, err := p4.LatencyText(filepath.Join(repoRoot, "testdata/corpus", builtin.InjectionMLID), func(x string) (int, error) {
			ids, _, _, err := counter.tok.Encode(context.Background(), x, ml.MaxText)
			return len(ids), err
		}, windows*(counter.spec.MaxTokens-2-windowOverlap))
		if err != nil {
			t.Fatal(err)
		}
		limit := gateway.DefaultMLTimeout + (windows-1)*gateway.DefaultMLTimePerWindow
		cr, err := p4.Concurrent(context.Background(), calls, text, n, 100, limit)
		if err != nil {
			t.Fatal(err)
		}
		md += cr.Markdown()
	}
	md += factRuLine(t)
	out := filepath.Join(mlDir(t), "p4.md")
	if err := os.WriteFile(out, []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("замер Р4 -> %s\n%s", out, md)
}

// factRuLine — полнота pii.ner по фрагментам на testset factRuEval-2016 из
// отчёта дообучки (tools/ml/train_ner.py): вторая часть правила Р4 для
// pii.ner (решение владельца 30.10.2026) — проверка на живом тексте, а не
// только на синтетике. Нет отчёта или проверки — так и пишется.
func factRuLine(t *testing.T) string {
	t.Helper()
	path := filepath.Join(mlDir(t), "train", "pii-ner-ru", "train_report.json")
	data, err := os.ReadFile(path) //nolint:gosec // G304: путь собирает тест из каталога сборки
	if err != nil {
		return "\n`pii.ner` на testset factRuEval-2016: отчёта дообучки нет (" + path + ").\n"
	}
	var rep struct {
		CheckFactru *struct {
			PII struct{ Precision, Recall, F1 float64 } `json:"pii"`
		} `json:"check_factru"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if rep.CheckFactru == nil {
		return "\n`pii.ner` на testset factRuEval-2016: проверки не было (набор не скачан).\n"
	}
	m := rep.CheckFactru.PII
	dec := func(v float64) string { return strings.Replace(strconv.FormatFloat(v, 'f', 3, 64), ".", ",", 1) }
	return fmt.Sprintf("\n`pii.ner` на testset factRuEval-2016 (живые новости, фрагменты имён и организаций; из отчёта дообучки): точность %s, полнота %s, F1 %s.\n",
		dec(m.Precision), dec(m.Recall), dec(m.F1))
}

func cpuModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "процессор неизвестен"
	}
	for _, l := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
			return strings.TrimSpace(v)
		}
	}
	return "процессор неизвестен"
}
