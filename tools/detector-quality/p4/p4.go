// Пакет p4 — замер критерия Р4 «ML лучше эвристик» (ADR-0024, раздел 7;
// задача 4.19): ML-детектор и эвристика того же класса на одном проверочном
// корпусе — полнота, доля ложных срабатываний и точность по примерам, а
// также задержка p50 и p95 вызова aisec-ml на тексте около 2 000 токенов.
//
// Пакет — расширение tools/detector-quality: настоящий замер идёт на
// машине владельца (make ml-p4: исполнитель ONNX Runtime и модели пакета),
// в make test — тот же расчёт на тестовом исполнителе.
package p4

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/corpus"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
)

// Критерий Р4 (ADR-0024, раздел 7).
const (
	MinRecallGain = 0.10
	MaxP95        = 30 * time.Millisecond
	// LatencyTokens — длина текста для замера задержки.
	LatencyTokens = 2000
)

// Case — ML-детектор и эвристика того же класса на одном корпусе.
type Case struct {
	ML, Heuristic detect.Detector
	// Corpus — каталог проверочного корпуса (testdata/corpus/<ID ML>/).
	Corpus string
	// Threshold — порог правила политики для ML (шаблоны политик); у
	// эвристики — corpus.MinScore.
	Threshold float64
	// Latency — вызов aisec-ml на тексте (только модель, без шлюза); nil —
	// задержка не замеряется.
	Latency func(ctx context.Context, text string) error
	// LatencyText — текст около LatencyTokens токенов модели.
	LatencyText   string
	LatencyTokens int
	LatencyRuns   int
}

// Metrics — счёт по примерам: пример с ожидаемыми находками положительный,
// срабатывание — любая находка детектора от порога.
type Metrics struct {
	Pos, Neg, TP, FP, Errors int
}

// Recall — доля найденных положительных примеров.
func (m Metrics) Recall() float64 { return ratio(m.TP, m.Pos) }

// FPR — доля отрицательных примеров со срабатыванием.
func (m Metrics) FPR() float64 { return ratio(m.FP, m.Neg) }

// Precision — доля верных среди срабатываний.
func (m Metrics) Precision() float64 {
	if m.TP+m.FP == 0 {
		return 1
	}
	return ratio(m.TP, m.TP+m.FP)
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// Result — итог по одной паре детекторов.
type Result struct {
	ML, Heuristic string
	Corpus        string
	Threshold     float64
	MLm, Heur     Metrics
	ByLang        map[string][2]Metrics // язык → [эвристика, ML]
	// Sweep — метрики ML при других порогах: для выбора порога правила.
	Sweep         map[float64]Metrics
	P50, P95      time.Duration
	LatencyTokens int
	Runs          int
	Pass          bool
	Reasons       []string
}

var sweep = []float64{0.5, 0.6, 0.7, 0.8, 0.9, 0.95}

// Run считает метрики и задержку по всем парам.
func Run(ctx context.Context, cases []Case) ([]Result, error) {
	out := make([]Result, 0, len(cases))
	for _, c := range cases {
		samples, err := corpus.Load(c.Corpus)
		if err != nil {
			return nil, err
		}
		r := Result{ML: c.ML.ID(), Heuristic: c.Heuristic.ID(), Corpus: c.Corpus, Threshold: c.Threshold,
			ByLang: map[string][2]Metrics{}, Sweep: map[float64]Metrics{}}
		for _, s := range samples {
			t := detect.Text{Text: s.Text, Direction: s.Direction, Source: s.Source, Lang: s.Lang}
			pos := len(s.Expect) > 0
			hScore, hErr := best(ctx, c.Heuristic, t)
			mScore, mErr := best(ctx, c.ML, t)
			lang := s.Lang
			if lang == "" {
				lang = "—"
			}
			bl := r.ByLang[lang]
			count(&r.Heur, pos, hErr == nil && hScore >= corpus.MinScore, hErr != nil)
			count(&bl[0], pos, hErr == nil && hScore >= corpus.MinScore, hErr != nil)
			count(&r.MLm, pos, mErr == nil && mScore >= c.Threshold, mErr != nil)
			count(&bl[1], pos, mErr == nil && mScore >= c.Threshold, mErr != nil)
			r.ByLang[lang] = bl
			for _, th := range sweep {
				m := r.Sweep[th]
				count(&m, pos, mErr == nil && mScore >= th, mErr != nil)
				r.Sweep[th] = m
			}
		}
		if c.Latency != nil {
			if err := latency(ctx, c, &r); err != nil {
				return nil, fmt.Errorf("%s: задержка: %w", c.ML.ID(), err)
			}
		}
		judge(&r, c.Latency != nil)
		out = append(out, r)
	}
	return out, nil
}

// best — наибольшая оценка находок детектора на тексте; сбой — ошибка.
func best(ctx context.Context, d detect.Detector, t detect.Text) (float64, error) {
	if !slices.Contains(d.Directions(), t.Direction) {
		return 0, nil
	}
	fs, err := d.Detect(ctx, t)
	if err != nil {
		return 0, err
	}
	var s float64
	for _, f := range fs {
		s = max(s, f.Score)
	}
	return s, nil
}

func count(m *Metrics, pos, hit, failed bool) {
	switch {
	case failed:
		m.Errors++
		if pos {
			m.Pos++
		} else {
			m.Neg++
		}
	case pos:
		m.Pos++
		if hit {
			m.TP++
		}
	default:
		m.Neg++
		if hit {
			m.FP++
		}
	}
}

func latency(ctx context.Context, c Case, r *Result) error {
	runs := c.LatencyRuns
	if runs <= 0 {
		runs = 200
	}
	// Прогрев: первые вызовы открывают соединение и прогревают сеанс.
	for range 5 {
		if err := c.Latency(ctx, c.LatencyText); err != nil {
			return err
		}
	}
	ds := make([]time.Duration, 0, runs)
	for range runs {
		start := time.Now()
		if err := c.Latency(ctx, c.LatencyText); err != nil {
			return err
		}
		ds = append(ds, time.Since(start))
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	r.P50, r.P95 = ds[len(ds)/2], ds[(len(ds)*95+99)/100-1]
	r.LatencyTokens, r.Runs = c.LatencyTokens, runs
	return nil
}

// ConcurrentResult — задержка вызовов всех моделей одновременно на длинном
// тексте (4В30): так их вызывает шлюз — детекторы фрагмента параллельно.
type ConcurrentResult struct {
	Models []string
	Tokens int
	Runs   int
	// P50, P95 — время до ответа последней модели.
	P50, P95 time.Duration
	// Limit — срок вызова шлюза на таком тексте (-ml-timeout и
	// -ml-timeout-per-window); p95 больше срока — на таких текстах ML
	// отвечает ml_unavailable.
	Limit time.Duration
	Pass  bool
}

// Concurrent замеряет вызовы calls одновременно на тексте text (около
// tokens токенов) runs раз после прогрева.
func Concurrent(ctx context.Context, calls map[string]func(ctx context.Context, text string) error, text string, tokens, runs int, limit time.Duration) (ConcurrentResult, error) {
	if runs <= 0 {
		runs = 100
	}
	r := ConcurrentResult{Tokens: tokens, Runs: runs, Limit: limit}
	for id := range calls {
		r.Models = append(r.Models, id)
	}
	sort.Strings(r.Models)
	round := func() error {
		errs := make([]error, len(r.Models))
		var wg sync.WaitGroup
		for i, id := range r.Models {
			wg.Go(func() { errs[i] = calls[id](ctx, text) })
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				return fmt.Errorf("%s: %w", r.Models[i], err)
			}
		}
		return nil
	}
	for range 3 {
		if err := round(); err != nil {
			return r, err
		}
	}
	ds := make([]time.Duration, 0, runs)
	for range runs {
		start := time.Now()
		if err := round(); err != nil {
			return r, err
		}
		ds = append(ds, time.Since(start))
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	r.P50, r.P95 = ds[len(ds)/2], ds[(len(ds)*95+99)/100-1]
	r.Pass = r.P95 <= limit
	return r, nil
}

// Markdown — строка замера одновременных вызовов.
func (r ConcurrentResult) Markdown() string {
	verdict := "укладывается"
	if !r.Pass {
		verdict = "не укладывается: на таких текстах ML ответит ml_unavailable — поднять -ml-timeout-per-window или -workers"
	}
	return fmt.Sprintf("\nОдновременно %s на тексте %d токенов (до 16 окон), %d вызовов: p50 %s, p95 %s; срок вызова шлюза %s — %s.\n",
		strings.Join(r.Models, ", "), r.Tokens, r.Runs, ms(r.P50), ms(r.P95), ms(r.Limit), verdict)
}

// judge — вердикт Р4: полнота выше на 10 п. п., доля ложных не выше, p95 не
// больше 30 мс. Сбои ML на корпусе — провал: замер недостоверен.
func judge(r *Result, withLatency bool) {
	gain := r.MLm.Recall() - r.Heur.Recall()
	if gain < MinRecallGain {
		r.Reasons = append(r.Reasons, fmt.Sprintf("полнота выше эвристики на %s п. п. (нужно не меньше %.0f)", dec(100*gain, 1), 100*MinRecallGain))
	}
	if r.MLm.FPR() > r.Heur.FPR() {
		r.Reasons = append(r.Reasons, fmt.Sprintf("доля ложных %s выше, чем у эвристики (%s)", num(r.MLm.FPR()), num(r.Heur.FPR())))
	}
	if r.MLm.Errors > 0 {
		r.Reasons = append(r.Reasons, fmt.Sprintf("сбои ML на %d примерах", r.MLm.Errors))
	}
	switch {
	case !withLatency:
		r.Reasons = append(r.Reasons, "задержка не замерена")
	case r.P95 > MaxP95:
		r.Reasons = append(r.Reasons, fmt.Sprintf("p95 %s больше %s", ms(r.P95), ms(MaxP95)))
	}
	r.Pass = len(r.Reasons) == 0
}

// Markdown — таблица для docs/detectors.md (раздел «Замер Р4») и подробности.
func Markdown(rs []Result, env string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Среда замера: %s.\n\n", env)
	b.WriteString("| ML-детектор | Эвристика | Корпус | Порог ML | Полнота: эвристика / ML | Доля ложных: эвристика / ML | Точность ML | p50 / p95 aisec-ml | Р4 |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range rs {
		verdict := "проходит"
		if !r.Pass {
			verdict = "не проходит: " + strings.Join(r.Reasons, "; ")
		}
		lat := "—"
		if r.Runs > 0 {
			lat = fmt.Sprintf("%s / %s (%d токенов, %d вызовов)", ms(r.P50), ms(r.P95), r.LatencyTokens, r.Runs)
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` — %d примеров: %d позитивных, %d негативных | %s | %s / %s | %s / %s | %s | %s | %s |\n",
			r.ML, r.Heuristic, repoPath(r.Corpus), r.MLm.Pos+r.MLm.Neg, r.MLm.Pos, r.MLm.Neg, num(r.Threshold),
			num(r.Heur.Recall()), num(r.MLm.Recall()), num(r.Heur.FPR()), num(r.MLm.FPR()), num(r.MLm.Precision()), lat, verdict)
	}
	for _, r := range rs {
		fmt.Fprintf(&b, "\n<details><summary>%s: по языкам и порогам</summary>\n\n| Язык | Полнота: эвристика / ML | Доля ложных: эвристика / ML |\n|---|---|---|\n", r.ML)
		langs := make([]string, 0, len(r.ByLang))
		for l := range r.ByLang {
			langs = append(langs, l)
		}
		sort.Strings(langs)
		for _, l := range langs {
			m := r.ByLang[l]
			fmt.Fprintf(&b, "| %s | %s / %s | %s / %s |\n", l, num(m[0].Recall()), num(m[1].Recall()), num(m[0].FPR()), num(m[1].FPR()))
		}
		b.WriteString("\n| Порог ML | Полнота | Доля ложных | Точность |\n|---|---|---|---|\n")
		for _, th := range sweep {
			m := r.Sweep[th]
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", num(th), num(m.Recall()), num(m.FPR()), num(m.Precision()))
		}
		b.WriteString("\n</details>\n")
	}
	return b.String()
}

// repoPath — путь корпуса от корня репозитория (тесты передают ../../…).
func repoPath(p string) string {
	p = filepath.ToSlash(filepath.Clean(p))
	for strings.HasPrefix(p, "../") {
		p = p[3:]
	}
	return p
}

func num(v float64) string { return dec(v, 3) }

// dec — число с запятой (тексты по-русски).
func dec(v float64, prec int) string {
	return strings.Replace(strconv.FormatFloat(v, 'f', prec, 64), ".", ",", 1)
}

func ms(d time.Duration) string {
	return strings.Replace(fmt.Sprintf("%.1f мс", float64(d)/float64(time.Millisecond)), ".", ",", 1)
}

// LatencyText — тексты корпуса подряд, пока токенов (count) не станет не
// меньше target: текст для замера задержки.
func LatencyText(dir string, count func(string) (int, error), target int) (string, int, error) {
	samples, err := corpus.Load(dir)
	if err != nil {
		return "", 0, err
	}
	var b strings.Builder
	for n := 0; ; {
		for _, s := range samples {
			b.WriteString(s.Text)
			b.WriteString("\n")
			if n, err = count(b.String()); err != nil {
				return "", 0, err
			}
			if n >= target {
				return b.String(), n, nil
			}
		}
		if b.Len() > 1<<20 {
			return "", 0, fmt.Errorf("%s: не набрать %d токенов", dir, target)
		}
	}
}

// ListsBaseline — словарная эвристика (детектор lists со своими списками из
// JSON): у токсичности нет встроенной эвристики, сравнение — со словарём,
// который заказчик настроил бы сам (testdata/ml/toxicity-baseline.json).
func ListsBaseline(path string) (detect.Detector, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: путь к словарю задаёт тест или make
	if err != nil {
		return nil, err
	}
	var specs []lists.Spec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return lists.Compile(specs)
}
