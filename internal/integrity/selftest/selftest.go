// Пакет selftest — самотестирование компонента при запуске (ТЗ, ОЦЛ.4–5):
// криптопрофиль на эталонных значениях (internal/crypto.SelfTest) и каждый
// детектор шлюза на эталонных входах — положительном (детектор обязан дать
// находку ожидаемой категории) и отрицательном (без находок). Эталоны —
// синтетические примеры корпуса testdata/corpus (vectors.go). Вместе с
// детекторами проверяется политика вызовов инструментов агентами
// (ADR-0023): эталонные вызовы обязаны получить ожидаемое решение; хеш
// описаний инструментов (DM-25), эталона системного промпта (DM-26) и
// реплик ассистента (DM-03) — совпасть с эталонами.
//
// ML-детекторы (ADR-0024) проверяются, если компонент их передал: без
// aisec-ml (detect.ErrMLUnavailable) эталон даёт ml_unavailable
// (Result.MLUnavailable) и самотест не валит — как конвейер шлюза, где
// недоступность ML не включает fail_closed. Паника, другая ошибка или
// неверная находка ML-детектора — провал, как у остальных детекторов.
//
// Провал криптопрофиля всегда останавливает запуск: без исправной
// криптографии компонент не работает. Провал детекторов и политики
// вызовов — по реакции -selftest-action: alert (журнал) или stop (отказ
// запуска).
package selftest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/tooldesc"
	"github.com/azuresong-afk/ai_railway/internal/policy/toolrate"
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
	ProblemDecision   Problem = "decision"   // решение политики вызовов не совпало с эталоном
	ProblemHash       Problem = "hash"       // хеш описания инструмента, эталона промпта или реплики не совпал с эталоном
)

// Failure — провал одного эталона. Текста эталона и находок не содержит.
type Failure struct {
	// Detector: пусто — криптопрофиль; ToolsCheck — политика вызовов;
	// DescriptorCheck — хеш описаний; PromptCheck, HistoryCheck — хеш
	// эталона промпта и реплик.
	Detector string
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
	Vectors   int // прогнано эталонов детекторов
	Tools     int // прогнано эталонов политики вызовов и хеша описаний
	Hashes    int // прогнано эталонов хеша промпта и реплик (DM-26, DM-03)
	// MLUnavailable — эталоны ML-детекторов без ответа aisec-ml
	// (ml_unavailable): не провал, но в журнале и аудите.
	MLUnavailable int
	Failures      []Failure
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
	// Detectors — детекторы компонента (у сервера — для песочницы политик).
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
	res.Failures = append(res.Failures, runTools(cfg.Now(), &res.Tools)...)
	res.Failures = append(res.Failures, runDescriptors(cfg.Provider, &res.Tools)...)
	res.Failures = append(res.Failures, runHashes(cfg.Provider, &res.Hashes)...)
	reg, err := detect.NewRegistry(cfg.Detectors...)
	if err != nil {
		return res, fmt.Errorf("самотест: %w", err)
	}
	for _, d := range cfg.Detectors {
		res.Detectors++
		ml := mlBacked(d)
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
			if ml && mlUnavailable(runErrs) {
				res.MLUnavailable++
				continue
			}
			res.Failures = append(res.Failures, compare(d.ID(), v, fs, runErrs)...)
		}
	}
	return res, nil
}

// runTools прогоняет эталоны политики вызовов (toolVectors); n — счётчик
// прогнанных. Проверка идёт вместе с детекторами: у компонента без
// детекторов нет и решений по вызовам.
func runTools(now time.Time, n *int) []Failure {
	spec, err := policy.Parse(strings.NewReader(toolVectorPolicy))
	var p *policy.Policy
	if err == nil {
		p, err = policy.Compile(spec, nil)
	}
	if err != nil {
		return []Failure{{Detector: ToolsCheck, Problem: ProblemError}}
	}
	var out []Failure
	for _, v := range toolVectors {
		*n++
		d := p.DecideTool(policy.ToolCall{App: "selftest", Agent: "selftest", Server: v.Server, Name: v.Name,
			Status: v.Status, HashMatch: v.HashMatch, Risk: v.Risk, Args: []byte(v.Args), Now: now}, nil)
		if d.Action != v.Expect {
			out = append(out, Failure{Detector: ToolsCheck, Vector: v.ID, Problem: ProblemDecision, Category: string(d.Action)})
		}
	}
	// Лимиты (DM-23): счётчики в памяти, повтор одного вызова в сессии.
	*n++
	rc := toolrate.New(16)
	var d policy.ToolDecision
	for range 3 {
		d = p.DecideTool(policy.ToolCall{App: "selftest", Agent: "selftest", Session: "selftest", Server: "files", Name: "read_text",
			Status: policy.ToolApproved, HashMatch: true, Risk: policy.RiskLow, Args: []byte(`{"path":"/data/a.txt"}`),
			ArgsHash: "selftest", Now: now}, rc)
	}
	if d.Action != policy.Block {
		out = append(out, Failure{Detector: ToolsCheck, Vector: toolRepeatVector, Problem: ProblemDecision, Category: string(d.Action)})
	}
	return out
}

// runDescriptors прогоняет эталоны хеша описаний инструментов
// (descriptorVectors) на криптопрофиле компонента: шлюз и сервер обязаны
// считать хеш одинаково, иначе одобренный инструмент выглядит изменённым
// или изменённый — одобренным (DM-25).
func runDescriptors(p aisecCrypto.Provider, n *int) []Failure {
	h, err := p.Hasher()
	if err != nil {
		return []Failure{{Detector: DescriptorCheck, Problem: ProblemError}}
	}
	var out []Failure
	for _, v := range descriptorVectors {
		*n++
		a, err := tooldesc.Parse([]byte(v.A))
		if v.Invalid {
			if err == nil {
				out = append(out, Failure{Detector: DescriptorCheck, Vector: v.ID, Problem: ProblemHash})
			}
			continue
		}
		b, errB := tooldesc.Parse([]byte(v.B))
		if err != nil || errB != nil {
			out = append(out, Failure{Detector: DescriptorCheck, Vector: v.ID, Problem: ProblemError})
			continue
		}
		ha := tooldesc.Hash(h, a)
		if bytes.Equal(ha, tooldesc.Hash(h, b)) != v.Same ||
			v.SHA256 != "" && h.Name() == "SHA-256" && hex.EncodeToString(ha) != v.SHA256 {
			out = append(out, Failure{Detector: DescriptorCheck, Vector: v.ID, Problem: ProblemHash})
		}
	}
	return out
}

// runHashes прогоняет эталоны хеша системного промпта (promptVectors) и
// реплик ассистента (historyVectors) на криптопрофиле компонента: хеш
// эталона промпта считает сервер, а сравнивает шлюз; хеши реплик шлюз
// считает потоком и целиком. Расхождение дало бы ложные находки
// prompt.integrity и history.integrity или пропуск подмены.
func runHashes(p aisecCrypto.Provider, n *int) []Failure {
	h, err := p.Hasher()
	if err != nil {
		return []Failure{{Detector: PromptCheck, Problem: ProblemError}, {Detector: HistoryCheck, Problem: ProblemError}}
	}
	sha := h.Name() == "SHA-256"
	var out []Failure
	for _, v := range promptVectors {
		*n++
		a := session.PromptHash(h, v.A)
		if (a == session.PromptHash(h, v.B)) != v.Same || sha && v.SHA256 != "" && a != v.SHA256 {
			out = append(out, Failure{Detector: PromptCheck, Vector: v.ID, Problem: ProblemHash})
		}
	}
	for _, v := range historyVectors {
		*n++
		s := replyHash(h, v.Stream...)
		if bytes.Equal(s, replyHash(h, v.History)) != v.Same || sha && v.SHA256 != "" && hex.EncodeToString(s) != v.SHA256 {
			out = append(out, Failure{Detector: HistoryCheck, Vector: v.ID, Problem: ProblemHash})
		}
	}
	return out
}

// replyHash — хеш реплики, как его считает шлюз до имитовставки на ключе
// сессий: та же функция session.ReplyHasher, по частям.
func replyHash(h aisecCrypto.Hasher, parts ...string) []byte {
	r := session.NewReplyHasher(h)
	for _, p := range parts {
		r.WriteString(p)
	}
	return r.Sum()
}

// mlBacked — детектор работает через aisec-ml (ADR-0024): заглушка
// internal/detect/builtin или детектор шлюза с клиентом aisec-ml.
func mlBacked(d detect.Detector) bool {
	m, ok := d.(interface{ MLBacked() bool })
	return ok && m.MLBacked()
}

// mlUnavailable — ML-эталон не проверен из-за недоступности aisec-ml
// (detect.ErrMLUnavailable). Паника, срок детектора и другие ошибки — провал
// самотеста, как у остальных детекторов (4.28 (б)).
func mlUnavailable(runErrs []detect.RunError) bool {
	if len(runErrs) == 0 {
		return false
	}
	for _, e := range runErrs {
		if !errors.Is(e.Err, detect.ErrMLUnavailable) {
			return false
		}
	}
	return true
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
		"detectors", res.Detectors, "vectors", res.Vectors, "tool_vectors", res.Tools, "hash_vectors", res.Hashes,
		"ml_unavailable", res.MLUnavailable}
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
		"tool_vectors": r.Tools, "hash_vectors": r.Hashes, "ml_unavailable": r.MLUnavailable, "failures": list, "omitted": omitted,
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
