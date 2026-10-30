package selftest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/corpus"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }

func standard(t *testing.T) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestVectorsMatchCorpus — каждый эталон дословно совпадает с примером
// корпуса того же детектора и с тем же ID (текст, направление, источник,
// язык, ожидание): эталоны синтетические и размечены вместе с корпусом.
func TestVectorsMatchCorpus(t *testing.T) {
	byDetector := map[string][]corpus.Sample{}
	for _, v := range vectors {
		samples, ok := byDetector[v.Detector]
		if !ok {
			var err error
			if samples, err = corpus.Load(filepath.Join("..", "..", "..", "testdata", "corpus", v.Detector)); err != nil {
				t.Fatal(err)
			}
			byDetector[v.Detector] = samples
		}
		i := slices.IndexFunc(samples, func(s corpus.Sample) bool { return s.ID == v.ID })
		if i < 0 {
			t.Errorf("%s/%s: нет в корпусе", v.Detector, v.ID)
			continue
		}
		s := samples[i]
		if s.Text != v.Text || s.Direction != v.Direction || s.Source != v.Source || s.Lang != v.Lang {
			t.Errorf("%s/%s: эталон расходится с корпусом", v.Detector, v.ID)
		}
		if !slices.Equal(slices.Sorted(slices.Values(s.Expect)), slices.Sorted(slices.Values(v.Expect))) {
			t.Errorf("%s/%s: ожидание %v, в корпусе %v", v.Detector, v.ID, v.Expect, s.Expect)
		}
	}
}

// TestVectorsCoverBuiltin — у каждого встроенного детектора, в том числе
// ML-детектора, есть оба вида эталонов, и нет эталонов для неизвестных
// детекторов.
func TestVectorsCoverBuiltin(t *testing.T) {
	ids := map[string]bool{}
	for _, d := range append(builtin.All(), builtin.ML()...) {
		ids[d.ID()] = true
		if !hasBoth(vectorsFor(d.ID())) {
			t.Errorf("%s: нужны положительный и отрицательный эталоны", d.ID())
		}
	}
	seen := map[string]bool{}
	for _, v := range vectors {
		if !ids[v.Detector] {
			t.Errorf("эталон %s для неизвестного детектора %s", v.ID, v.Detector)
		}
		if seen[v.Detector+"/"+v.ID] {
			t.Errorf("эталон %s/%s повторяется", v.Detector, v.ID)
		}
		seen[v.Detector+"/"+v.ID] = true
	}
}

func TestMinScoreMatchesCorpus(t *testing.T) {
	if minScore != corpus.MinScore {
		t.Fatalf("порог %v, у корпусного стенда %v", minScore, corpus.MinScore)
	}
}

func TestRunBuiltinOK(t *testing.T) {
	res, err := Run(context.Background(), Config{Component: "gateway", Provider: standard(t), Detectors: builtin.All(), Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Detectors != len(builtin.All()) || res.Vectors != len(vectors)-mlVectors() ||
		res.Tools != len(toolVectors)+1+len(descriptorVectors) || res.Hashes != len(promptVectors)+len(historyVectors) || res.MLUnavailable != 0 {
		t.Fatalf("итог %+v", res)
	}
	if !res.At.Equal(fixedNow()) || res.Profile != aisecCrypto.ProfileStandard {
		t.Fatalf("время или профиль: %+v", res)
	}
}

// TestDM20_ToolVectorsCoverThreats — эталоны политики вызовов покрывают
// неодобренный инструмент и инструмент вне разрешённых (DM-20), аргументы
// вне ограничений (DM-21), подтверждение (DM-22), изменённое описание
// (DM-25), зацикливание (DM-23) и разрешённый вызов; расхождение решения
// с эталоном — провал. Покрывает: DM-20, DM-21, DM-22, DM-23, DM-25.
func TestDM20_ToolVectorsCoverThreats(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range toolVectors {
		seen[strings.SplitN(v.ID, "-", 2)[0]] = true
	}
	for _, k := range []string{"dm20", "dm21", "dm22", "dm25", "allow"} {
		if !seen[k] {
			t.Errorf("нет эталона %s", k)
		}
	}
	saved := toolVectors
	t.Cleanup(func() { toolVectors = saved })
	toolVectors = slices.Clone(saved)
	toolVectors[0].Expect = policy.Allow
	res, err := Run(context.Background(), Config{Component: "gateway", Provider: standard(t), Detectors: builtin.All()})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || len(res.Failures) != 1 || res.Failures[0] != (Failure{Detector: ToolsCheck, Vector: toolVectors[0].ID,
		Problem: ProblemDecision, Category: string(policy.Block)}) {
		t.Fatalf("провал решения не найден: %+v", res.Failures)
	}
}

// TestDM25_DescriptorVectors — эталоны хеша описания: равенство при
// эквивалентной записи, различие при подмене описания, отказ при повторе
// ключа; неверный эталон — провал hash. Покрывает: DM-25.
func TestDM25_DescriptorVectors(t *testing.T) {
	var same, diff, invalid bool
	for _, v := range descriptorVectors {
		same = same || v.Same
		diff = diff || !v.Same && !v.Invalid
		invalid = invalid || v.Invalid
	}
	if !same || !diff || !invalid {
		t.Fatal("эталоны хеша описания неполны")
	}
	var n int
	if f := runDescriptors(standard(t), &n); len(f) != 0 || n != len(descriptorVectors) {
		t.Fatalf("эталоны: %+v", f)
	}
	// Профиль без хеш-функции (заглушка ГОСТ) — провал, а не пропуск.
	gost, err := aisecCrypto.New(aisecCrypto.ProfileGOST)
	if err != nil {
		t.Fatal(err)
	}
	if f := runDescriptors(gost, &n); len(f) != 1 || f[0].Problem != ProblemError {
		t.Fatalf("профиль без хеша: %+v", f)
	}
	saved := descriptorVectors
	t.Cleanup(func() { descriptorVectors = saved })
	descriptorVectors = slices.Clone(saved)
	descriptorVectors[1].Same = true
	descriptorVectors[0].SHA256 = strings.Repeat("0", 64)
	if f := runDescriptors(standard(t), &n); len(f) != 2 || f[0] != (Failure{Detector: DescriptorCheck,
		Vector: descriptorVectors[0].ID, Problem: ProblemHash}) || f[1] != (Failure{Detector: DescriptorCheck,
		Vector: descriptorVectors[1].ID, Problem: ProblemHash}) {
		t.Fatalf("провал хеша не найден: %+v", f)
	}
}

// mlVectors — число эталонов ML-детекторов.
func mlVectors() int {
	n := 0
	for _, d := range builtin.ML() {
		n += len(vectorsFor(d.ID()))
	}
	return n
}

// TestDM26_PromptHashVectors — эталоны хеша системного промпта: пробельные
// символы хеш не меняют, невидимый символ и дописанная инструкция меняют,
// известный хеш в профиле standard совпадает; неверный эталон — провал
// hash, профиль без хеш-функции — провал error по обеим проверкам.
func TestDM26_PromptHashVectors(t *testing.T) {
	var same, diff bool
	for _, v := range promptVectors {
		same = same || v.Same && v.SHA256 != ""
		diff = diff || !v.Same
	}
	if !same || !diff {
		t.Fatal("эталоны хеша промпта неполны")
	}
	var n int
	if f := runHashes(standard(t), &n); len(f) != 0 || n != len(promptVectors)+len(historyVectors) {
		t.Fatalf("эталоны: %+v", f)
	}
	gost, err := aisecCrypto.New(aisecCrypto.ProfileGOST)
	if err != nil {
		t.Fatal(err)
	}
	if f := runHashes(gost, &n); len(f) != 2 || f[0] != (Failure{Detector: PromptCheck, Problem: ProblemError}) ||
		f[1] != (Failure{Detector: HistoryCheck, Problem: ProblemError}) {
		t.Fatalf("профиль без хеша: %+v", f)
	}
	saved := promptVectors
	t.Cleanup(func() { promptVectors = saved })
	promptVectors = slices.Clone(saved)
	promptVectors[0].SHA256 = strings.Repeat("0", 64)
	promptVectors[1].Same = true
	if f := runHashes(standard(t), &n); len(f) != 2 || f[0] != (Failure{Detector: PromptCheck, Vector: promptVectors[0].ID,
		Problem: ProblemHash}) || f[1] != (Failure{Detector: PromptCheck, Vector: promptVectors[1].ID, Problem: ProblemHash}) {
		t.Fatalf("провал хеша не найден: %+v", f)
	}
}

// TestDM03_HistoryHashVectors — эталоны хеша реплик: ответ модели,
// разрезанный посреди символа UTF-8, совпадает с той же репликой в истории,
// изменённая реплика — нет; неверный эталон — провал hash.
func TestDM03_HistoryHashVectors(t *testing.T) {
	var split, diff bool
	for _, v := range historyVectors {
		for _, p := range v.Stream {
			split = split || v.Same && !utf8.ValidString(p)
		}
		diff = diff || !v.Same
	}
	if !split || !diff {
		t.Fatal("эталоны хеша реплик неполны")
	}
	saved := historyVectors
	t.Cleanup(func() { historyVectors = saved })
	historyVectors = slices.Clone(saved)
	historyVectors[0].Stream = []string{"Да, конечно."}
	historyVectors[1].Same = true
	var n int
	if f := runHashes(standard(t), &n); len(f) != 2 || f[0] != (Failure{Detector: HistoryCheck, Vector: historyVectors[0].ID,
		Problem: ProblemHash}) || f[1] != (Failure{Detector: HistoryCheck, Vector: historyVectors[1].ID, Problem: ProblemHash}) {
		t.Fatalf("провал хеша не найден: %+v", f)
	}
}

// mlFake — ML-детектор с описанием заглушки и своим поведением: имитирует
// детектор шлюза с клиентом aisec-ml.
type mlFake struct {
	detect.Detector
	fn func(t detect.Text) ([]detect.Finding, error)
}

func (f mlFake) Detect(_ context.Context, t detect.Text) ([]detect.Finding, error) { return f.fn(t) }
func (mlFake) MLBacked() bool                                                      { return true }

// mlDetectors — встроенные детекторы и ML-детекторы с поведением fn; nil —
// заглушки без aisec-ml.
func mlDetectors(fn func(d detect.Detector, t detect.Text) ([]detect.Finding, error)) []detect.Detector {
	ds := builtin.All()
	for _, stub := range builtin.ML() {
		if fn == nil {
			ds = append(ds, stub)
			continue
		}
		ds = append(ds, mlFake{Detector: stub, fn: func(t detect.Text) ([]detect.Finding, error) { return fn(stub, t) }})
	}
	return ds
}

// TestMLVectors — ML-детекторы (ADR-0024): без aisec-ml эталоны дают
// ml_unavailable и самотест проходит; с доступным aisec-ml модель, которая
// находит положительные эталоны и молчит на отрицательных, проходит, а
// молчащая или шумная — нет.
func TestMLVectors(t *testing.T) {
	run := func(ds []detect.Detector) Result {
		t.Helper()
		res, err := Run(context.Background(), Config{Component: "gateway", Provider: standard(t), Detectors: ds, Now: fixedNow})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := run(mlDetectors(nil)); !res.OK() || res.MLUnavailable != mlVectors() || res.Vectors != len(vectors) {
		t.Fatalf("без aisec-ml: %+v", res)
	}
	if res := run(mlDetectors(func(detect.Detector, detect.Text) ([]detect.Finding, error) {
		return nil, errors.New("aisec-ml недоступен: отсрочка после сбоя")
	})); !res.OK() || res.MLUnavailable != mlVectors() {
		t.Fatalf("сбой связи: %+v", res)
	}
	// Модель «знает» эталоны: находка — на положительных, по ожиданию.
	model := func(d detect.Detector, tx detect.Text) ([]detect.Finding, error) {
		for _, v := range vectorsFor(d.ID()) {
			if v.Text == tx.Text && len(v.Expect) > 0 {
				return []detect.Finding{{Detector: d.ID(), Version: d.Version(), Category: v.Expect[0], Threat: "DM-01",
					Score: 0.9, End: len(tx.Text)}}, nil
			}
		}
		return nil, nil
	}
	if res := run(mlDetectors(model)); !res.OK() || res.MLUnavailable != 0 || res.Vectors != len(vectors) {
		t.Fatalf("aisec-ml доступен: %+v", res)
	}
	res := run(mlDetectors(func(detect.Detector, detect.Text) ([]detect.Finding, error) { return nil, nil }))
	if res.OK() || !slices.Contains(res.Failures, Failure{Detector: builtin.InjectionMLID, Vector: "inj-ru-p005",
		Problem: ProblemMissed, Category: "injection.ml"}) || !slices.Contains(res.Failures, Failure{Detector: builtin.ToxicityMLID,
		Vector: "tox-insult-001", Problem: ProblemMissed, Category: "toxicity.insult"}) {
		t.Fatalf("молчащая модель: %+v", res.Failures)
	}
	res = run(mlDetectors(func(d detect.Detector, tx detect.Text) ([]detect.Finding, error) {
		return []detect.Finding{{Detector: d.ID(), Version: d.Version(), Category: d.(detect.Categorizer).Categories()[0],
			Threat: "DM-18", Score: 0.9, End: len(tx.Text)}}, nil
	}))
	if res.OK() || !slices.ContainsFunc(res.Failures, func(f Failure) bool {
		return f.Vector == "tox-clean-002" && f.Problem == ProblemUnexpected
	}) {
		t.Fatalf("шумная модель: %+v", res.Failures)
	}
}

// fake — детектор с ID и версией настоящего, но со своим поведением.
type fake struct {
	detect.Detector
	fn func(ctx context.Context, d detect.Detector, t detect.Text) ([]detect.Finding, error)
}

func (f fake) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	return f.fn(ctx, f.Detector, t)
}

func replace(id string, fn func(ctx context.Context, d detect.Detector, t detect.Text) ([]detect.Finding, error)) []detect.Detector {
	ds := builtin.All()
	for i, d := range ds {
		if d.ID() == id {
			ds[i] = fake{Detector: d, fn: fn}
		}
	}
	return ds
}

func finding(d detect.Detector, cat string, end int) detect.Finding {
	return detect.Finding{Detector: d.ID(), Version: d.Version(), Category: cat, Threat: "DM-01", Score: 0.9, End: end}
}

// TestRunDetectsBrokenDetector — неисправный детектор не проходит самотест
// (ОЦЛ.4): молчит, находит лишнее, выдаёт находку вне текста, зависает,
// падает; детектор без эталонов — no_vectors.
func TestRunDetectsBrokenDetector(t *testing.T) {
	cases := []struct {
		name    string
		ds      []detect.Detector
		problem Problem
		vector  string
	}{
		{"молчит", replace("pii.ru", func(context.Context, detect.Detector, detect.Text) ([]detect.Finding, error) {
			return nil, nil
		}), ProblemMissed, "snils-01"},
		{"лишняя находка", replace("secrets", func(_ context.Context, d detect.Detector, t detect.Text) ([]detect.Finding, error) {
			return []detect.Finding{finding(d, "secret.token", len(t.Text))}, nil
		}), ProblemUnexpected, "neg-04"},
		{"находка вне текста", replace("lists", func(_ context.Context, d detect.Detector, t detect.Text) ([]detect.Finding, error) {
			return []detect.Finding{finding(d, "lists.marker", len(t.Text)+1)}, nil
		}), ProblemError, "mark-p05"},
		{"зависает", replace("canary", func(ctx context.Context, _ detect.Detector, _ detect.Text) ([]detect.Finding, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}), ProblemError, "leak-29"},
		{"падает", replace("output.exfil", func(context.Context, detect.Detector, detect.Text) ([]detect.Finding, error) {
			panic("сбой")
		}), ProblemError, "img-06"},
		{"ошибка", replace("injection.heuristic", func(context.Context, detect.Detector, detect.Text) ([]detect.Finding, error) {
			return nil, errors.New("сбой")
		}), ProblemError, "ov-ru-01"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Run(context.Background(), Config{Component: "gateway", Provider: standard(t), Detectors: c.ds, Timeout: 50 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if res.OK() || !res.CryptoOK {
				t.Fatalf("итог %+v", res)
			}
			if !slices.ContainsFunc(res.Failures, func(f Failure) bool { return f.Problem == c.problem && f.Vector == c.vector }) {
				t.Fatalf("нет провала %s на %s: %+v", c.problem, c.vector, res.Failures)
			}
		})
	}

	t.Run("нет эталонов", func(t *testing.T) {
		d := fake{Detector: builtin.All()[0], fn: func(context.Context, detect.Detector, detect.Text) ([]detect.Finding, error) { return nil, nil }}
		res, err := Run(context.Background(), Config{Component: "gateway", Provider: standard(t), Detectors: []detect.Detector{renamed{d}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Failures) != 1 || res.Failures[0].Problem != ProblemNoVectors || res.Failures[0].Detector != "custom.words" {
			t.Fatalf("провалы %+v", res.Failures)
		}
	})
}

type renamed struct{ fake }

func (renamed) ID() string { return "custom.words" }

func TestRunErrors(t *testing.T) {
	if _, err := Run(context.Background(), Config{}); err == nil {
		t.Fatal("без криптопрофиля — принято")
	}
	ds := builtin.All()
	if _, err := Run(context.Background(), Config{Provider: standard(t), Detectors: append(ds, ds[0])}); err == nil {
		t.Fatal("повтор детектора — принято")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Config{Provider: standard(t), Detectors: ds}); !errors.Is(err, context.Canceled) {
		t.Fatalf("отменённый контекст: %v", err)
	}
}

// TestStartupReactions — реакции ОЦЛ.5: alert — запуск продолжается, stop —
// ErrFailed; провал криптопрофиля — ErrFailed при любой реакции.
func TestStartupReactions(t *testing.T) {
	silent := replace("pii.ru", func(context.Context, detect.Detector, detect.Text) ([]detect.Finding, error) { return nil, nil })
	run := func(p aisecCrypto.Provider, ds []detect.Detector, a integrity.Action) (Result, error) {
		return Startup(context.Background(), StartupConfig{
			Config: Config{Component: "gateway", Provider: p, Detectors: ds}, Action: a, Logger: discard(),
		})
	}
	if res, err := run(standard(t), builtin.All(), integrity.ActionStop); err != nil || !res.OK() {
		t.Fatalf("исправные детекторы: %v %+v", err, res)
	}
	if res, err := run(standard(t), silent, integrity.ActionAlert); err != nil || res.OK() {
		t.Fatalf("alert: %v %+v", err, res)
	}
	if _, err := run(standard(t), silent, integrity.ActionStop); !errors.Is(err, ErrFailed) {
		t.Fatalf("stop: %v", err)
	}
	gost, err := aisecCrypto.New(aisecCrypto.ProfileGOST)
	if err != nil {
		t.Fatal(err)
	}
	res, err := run(gost, nil, integrity.ActionAlert)
	if !errors.Is(err, ErrFailed) || res.CryptoOK {
		t.Fatalf("криптопрофиль: %v %+v", err, res)
	}
	if _, err := run(standard(t), nil, "ignore"); err == nil {
		t.Fatal("неизвестная реакция принята")
	}
}

type fakeRecorder struct {
	entries []audit.Entry
	techs   []audit.TechEntry
}

func (r *fakeRecorder) Record(_ context.Context, e audit.Entry) error {
	r.entries = append(r.entries, e)
	return nil
}

func (r *fakeRecorder) Tech(_ context.Context, e audit.TechEntry) error {
	r.techs = append(r.techs, e)
	return nil
}

func TestRecordAudit(t *testing.T) {
	ok, err := Run(context.Background(), Config{Component: "server", Provider: standard(t)})
	if err != nil {
		t.Fatal(err)
	}
	var rec fakeRecorder
	if err := RecordAudit(context.Background(), &rec, ok); err != nil {
		t.Fatal(err)
	}
	if len(rec.entries) != 1 || len(rec.techs) != 0 {
		t.Fatalf("успех: %+v %+v", rec.entries, rec.techs)
	}
	e := rec.entries[0]
	if e.Action != "selftest.result" || e.Result != audit.ResultSuccess || e.Actor.Type != audit.ActorSystem || e.Object.ID != "server" {
		t.Fatalf("запись %+v", e)
	}

	noisy := replace("secrets", func(_ context.Context, d detect.Detector, t detect.Text) ([]detect.Finding, error) {
		return []detect.Finding{finding(d, "secret.token", len(t.Text))}, nil
	})
	bad, err := Run(context.Background(), Config{Component: "gateway", Provider: standard(t), Detectors: noisy})
	if err != nil {
		t.Fatal(err)
	}
	rec = fakeRecorder{}
	if err := RecordAudit(context.Background(), &rec, bad); err != nil {
		t.Fatal(err)
	}
	if len(rec.entries) != 1 || rec.entries[0].Result != audit.ResultFailure || len(rec.techs) != 1 || rec.techs[0].Level != audit.LevelCritical {
		t.Fatalf("провал: %+v %+v", rec.entries, rec.techs)
	}
	// В подробностях — только ID эталонов и категории, без текста.
	js, err := json.Marshal(rec.entries[0].Details)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		if strings.Contains(string(js), v.Text) {
			t.Fatalf("текст эталона %s в записи аудита", v.ID)
		}
	}
	if !strings.Contains(string(js), `"vector":"pass-02"`) {
		t.Fatalf("подробности %s", js)
	}
}

func TestDetailsLimited(t *testing.T) {
	res := Result{Component: "gateway", CryptoOK: true}
	for range maxAuditFailures + 5 {
		res.Failures = append(res.Failures, Failure{Detector: "pii.ru", Vector: "x", Problem: ProblemMissed})
	}
	d := res.Details()
	if len(d["failures"].([]any)) != maxAuditFailures || d["omitted"] != 5 {
		t.Fatalf("подробности %+v", d)
	}
}
