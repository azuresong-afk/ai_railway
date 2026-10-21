// Пакет selftest — самотестирование компонента при запуске (ТЗ, ОЦЛ.4–5):
// криптопрофиль на эталонных значениях (internal/crypto.SelfTest) и каждый
// детектор шлюза на эталонных входах — положительном (детектор обязан дать
// находку ожидаемой категории) и отрицательном (без находок). Эталоны —
// синтетические примеры корпуса testdata/corpus (vectors.go).
//
// Провал криптопрофиля всегда останавливает запуск: без исправной
// криптографии компонент не работает. Провал детекторов — по реакции
// -selftest-action: alert (журнал) или stop (отказ запуска).
package selftest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// Problem — вид провала.
type Problem string

// Виды провала.
const (
	ProblemCrypto     Problem = "crypto"     // криптопрофиль не совпал с эталоном
	ProblemNoVectors  Problem = "no_vectors" // у детектора нет положительного или отрицательного эталона
	ProblemError      Problem = "error"      // сбой, превышение срока, паника или некорректная находка
	ProblemMissed     Problem = "missed"     // ожидаемая категория не найдена
	ProblemUnexpected Problem = "unexpected" // находка, которой не должно быть
)

// Failure — провал одного эталона. Текста эталона и находок не содержит.
type Failure struct {
	Detector string // пусто — криптопрофиль
	Vector   string // ID эталона (ID примера корпуса)
	Problem  Problem
	Category string // для missed и unexpected
}

// Result — итог самотестирования.
type Result struct {
	Component string
	At        time.Time
	Profile   string
	CryptoOK  bool
	Detectors int // проверено детекторов
	Vectors   int // прогнано эталонов
	Failures  []Failure
	// cryptoErr — причина провала криптопрофиля для журнала.
	cryptoErr error
}

// OK — самотест пройден полностью.
func (r Result) OK() bool { return r.CryptoOK && len(r.Failures) == 0 }

// ErrFailed — запуск остановлен по итогам самотестирования.
var ErrFailed = errors.New("самотестирование не пройдено")

// minScore — порог уверенности находки, как у корпусного стенда
// (corpus.MinScore; сверка — в тесте).
const minScore = 0.5

// DefaultTimeout — срок одного детектора на эталоне.
const DefaultTimeout = time.Second

// Config — параметры самотеста.
type Config struct {
	Component string
	Provider  aisecCrypto.Provider
	// Detectors — детекторы компонента; у сервера их нет.
	Detectors []detect.Detector
	Timeout   time.Duration // 0 — DefaultTimeout
	Now       func() time.Time
}

// Run выполняет самотест. Ошибка — только неверные параметры или отмена ctx;
// провалы — в Result.
func Run(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Provider == nil {
		return Result{}, errors.New("самотест: нет криптопрофиля")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	res := Result{Component: cfg.Component, At: cfg.Now().UTC(), Profile: cfg.Provider.Name(), CryptoOK: true}
	if err := aisecCrypto.SelfTest(cfg.Provider); err != nil {
		res.CryptoOK = false
		res.cryptoErr = err
		res.Failures = append(res.Failures, Failure{Problem: ProblemCrypto})
	}
	if len(cfg.Detectors) == 0 {
		return res, nil
	}
	reg, err := detect.NewRegistry(cfg.Detectors...)
	if err != nil {
		return res, fmt.Errorf("самотест: %w", err)
	}
	for _, d := range cfg.Detectors {
		res.Detectors++
		vs := vectorsFor(d.ID())
		if !hasBoth(vs) {
			res.Failures = append(res.Failures, Failure{Detector: d.ID(), Problem: ProblemNoVectors})
		}
		for _, v := range vs {
			fs, runErrs, err := reg.Run(ctx, []string{d.ID()}, v.text(), cfg.Timeout)
			if err != nil {
				return res, fmt.Errorf("самотест: %w", err)
			}
			if err := ctx.Err(); err != nil {
				return res, fmt.Errorf("самотест прерван: %w", err)
			}
			res.Vectors++
			res.Failures = append(res.Failures, compare(d.ID(), v, fs, runErrs)...)
		}
	}
	return res, nil
}

func hasBoth(vs []Vector) bool {
	pos, neg := false, false
	for _, v := range vs {
		if len(v.Expect) == 0 {
			neg = true
		} else {
			pos = true
		}
	}
	return pos && neg
}

// compare сверяет находки с ожиданием эталона по категориям, как корпусный
// стенд: найденная и ожидаемая категория — совпадение, ожидаемая без
// находки — missed, найденная без ожидания — unexpected.
func compare(id string, v Vector, fs []detect.Finding, runErrs []detect.RunError) []Failure {
	if len(runErrs) > 0 {
		return []Failure{{Detector: id, Vector: v.ID, Problem: ProblemError}}
	}
	var got []string
	for _, f := range fs {
		if f.Score >= minScore && !slices.Contains(got, f.Category) {
			got = append(got, f.Category)
		}
	}
	sort.Strings(got)
	var out []Failure
	for _, c := range v.Expect {
		if !slices.Contains(got, c) {
			out = append(out, Failure{Detector: id, Vector: v.ID, Problem: ProblemMissed, Category: c})
		}
	}
	for _, c := range got {
		if !slices.Contains(v.Expect, c) {
			out = append(out, Failure{Detector: id, Vector: v.ID, Problem: ProblemUnexpected, Category: c})
		}
	}
	return out
}

// StartupConfig — самотест при запуске с реакцией.
type StartupConfig struct {
	Config
	Action integrity.Action
	Logger *slog.Logger
}

// Startup выполняет самотест, пишет итог в технический журнал и применяет
// реакцию: провал криптопрофиля — всегда ErrFailed; провал детекторов —
// ErrFailed при реакции stop, иначе только журнал.
func Startup(ctx context.Context, cfg StartupConfig) (Result, error) {
	if _, err := integrity.ParseAction(string(cfg.Action)); err != nil {
		return Result{}, fmt.Errorf("самотест: реакция: %w", err)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	res, err := Run(ctx, cfg.Config)
	if err != nil {
		return res, err
	}
	attrs := []any{"class", "selftest", "profile", res.Profile, "crypto_ok", res.CryptoOK,
		"detectors", res.Detectors, "vectors", res.Vectors}
	if res.OK() {
		cfg.Logger.Info("самотестирование пройдено", attrs...)
		return res, nil
	}
	attrs = append(attrs, "failures", res.Failures, "action", string(cfg.Action))
	if res.cryptoErr != nil {
		attrs = append(attrs, "error", res.cryptoErr)
	}
	cfg.Logger.Error("самотестирование не пройдено", attrs...)
	if !res.CryptoOK {
		return res, fmt.Errorf("%w: криптопрофиль: %w", ErrFailed, res.cryptoErr)
	}
	if cfg.Action == integrity.ActionStop {
		return res, fmt.Errorf("%w: детекторы", ErrFailed)
	}
	return res, nil
}

// maxAuditFailures — сколько провалов попадает в запись аудита.
const maxAuditFailures = 20

// Details — подробности для журнала аудита и технического журнала: итоги
// и виды провалов, без текста эталонов и находок.
func (r Result) Details() map[string]any {
	failures := r.Failures
	omitted := 0
	if len(failures) > maxAuditFailures {
		omitted = len(failures) - maxAuditFailures
		failures = failures[:maxAuditFailures]
	}
	list := make([]any, 0, len(failures))
	for _, f := range failures {
		item := map[string]any{"problem": string(f.Problem)}
		if f.Detector != "" {
			item["detector"] = f.Detector
		}
		if f.Vector != "" {
			item["vector"] = f.Vector
		}
		if f.Category != "" {
			item["category"] = f.Category
		}
		list = append(list, item)
	}
	return map[string]any{
		"profile": r.Profile, "crypto_ok": r.CryptoOK, "detectors": r.Detectors, "vectors": r.Vectors,
		"failures": list, "omitted": omitted,
	}
}

// Recorder — журнал аудита и технического состояния (audit.Log).
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) error
	Tech(ctx context.Context, e audit.TechEntry) error
}

// RecordAudit пишет итог в журнал аудита (selftest.result) и, при провале,
// в журнал технического состояния.
func RecordAudit(ctx context.Context, log Recorder, res Result) error {
	result := audit.ResultSuccess
	if !res.OK() {
		result = audit.ResultFailure
	}
	if err := log.Record(ctx, audit.Entry{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "selftest-" + res.Component, Name: "Самотестирование"},
		Action: "selftest.result", Object: audit.Object{Type: "component", ID: res.Component},
		Result: result, Details: res.Details(),
	}); err != nil {
		return err
	}
	if res.OK() {
		return nil
	}
	return log.Tech(ctx, audit.TechEntry{
		Component: res.Component, Kind: audit.TechError, Level: audit.LevelCritical, Class: audit.ClassIntegrity,
		Message: "самотестирование не пройдено", Details: res.Details(),
	})
}
