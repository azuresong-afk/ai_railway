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

// TestVectorsCoverBuiltin — у каждого встроенного детектора есть оба вида
// эталонов, и нет эталонов для неизвестных детекторов.
func TestVectorsCoverBuiltin(t *testing.T) {
	ids := map[string]bool{}
	for _, d := range builtin.All() {
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
	if !res.OK() || res.Detectors != len(builtin.All()) || res.Vectors != len(vectors) || res.Tools != len(toolVectors)+1 {
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
