package judgeq

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
)

// Ориентир для сравнения — как у замера Р4 (ADR-0024, раздел 7): полнота
// выше эвристики не меньше чем на 10 п. п. при доле ложных не выше. Для
// judge.llm критерий приёмки в ADR-0030 не задан: вердикт «ориентир
// выдержан» — подсказка владельцу, решение о включении правил за ним.
const MinRecallGain = 0.10

// DefaultThreshold — уверенность оценщика, с которой вердикт считается
// нарушением (порог правила политики по умолчанию — 0,5).
const DefaultThreshold = 0.5

// Counts — счёт по парам «пример — правило»: пара положительная, если пример
// нарушает правило. Unchecked — оценка не получена («не проверено»): пара
// считается без срабатывания и отдельно показывается в отчёте.
type Counts struct {
	TP, FP, FN, TN, Unchecked int
}

// Recall — доля найденных нарушений.
func (c Counts) Recall() float64 { return ratio(c.TP, c.TP+c.FN) }

// FPR — доля ложных срабатываний среди пар без нарушения.
func (c Counts) FPR() float64 { return ratio(c.FP, c.FP+c.TN) }

// Precision — доля верных среди срабатываний; без срабатываний — 1.
func (c Counts) Precision() float64 {
	if c.TP+c.FP == 0 {
		return 1
	}
	return ratio(c.TP, c.TP+c.FP)
}

// Pairs — число пар.
func (c Counts) Pairs() int { return c.TP + c.FP + c.FN + c.TN }

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func (c *Counts) add(positive, hit, unchecked bool) {
	switch {
	case positive && hit:
		c.TP++
	case positive:
		c.FN++
	case hit:
		c.FP++
	default:
		c.TN++
	}
	if unchecked {
		c.Unchecked++
	}
}

// Side — счёт оценщика и словаря на одних и тех же парах.
type Side struct {
	Judge, Lists Counts
}

// Config — что и чем мерить.
type Config struct {
	Corpus *Corpus
	// Engine — оценщик (judge.Engine с настоящим провайдером или стендом).
	Engine *judge.Engine
	// Baseline — словарная эвристика (Baseline).
	Baseline detect.Detector
	// Threshold — уверенность, с которой вердикт оценщика считается
	// нарушением; 0 — DefaultThreshold.
	Threshold float64
	// Timeout — срок одного вызова оценщика; 0 — judge.AsyncTimeout.
	Timeout time.Duration
	// Mode — подпись среды замера для отчёта.
	Mode string
}

// Result — итог замера.
type Result struct {
	Mode      string
	Threshold float64
	Samples   int
	Rules     int
	Total     Side
	ByRule    map[string]Side
	ByClass   map[string]Side
	ByLang    map[string]Side
	ByKind    map[string]Side
	// Calls — вызовов оценщика; Cached — ответов из кэша; Unchecked — вызовов
	// без вердиктов, по причинам (Reasons).
	Calls, Cached, Unchecked int
	Reasons                  map[judge.Reason]int
	Prompt, Completion       int
	// P50, P95 — время вызовов оценщика (без кэша).
	P50, P95 time.Duration
	// Meets — ориентир выдержан; NotMeets — почему нет.
	Meets    bool
	NotMeets []string
}

// Run мерит оценщика и словарь на корпусе. Пример оценивается так, как это
// делает шлюз: один вызов на пример со всеми правилами его направления.
// Ошибок оценщика не возвращает: неудача — «не проверено» с причиной.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Corpus == nil || cfg.Engine == nil || cfg.Baseline == nil {
		return nil, fmt.Errorf("замер judge.llm: нужны корпус, оценщик и словарь")
	}
	th := cfg.Threshold
	if th <= 0 || th > 1 {
		th = DefaultThreshold
	}
	r := &Result{Mode: cfg.Mode, Threshold: th, Samples: len(cfg.Corpus.Samples), Rules: len(cfg.Corpus.Rules),
		ByRule: map[string]Side{}, ByClass: map[string]Side{}, ByLang: map[string]Side{}, ByKind: map[string]Side{},
		Reasons: map[judge.Reason]int{}}
	var lat []time.Duration
	for _, s := range cfg.Corpus.Samples {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var crit []judge.Criterion
		var applied []Rule
		for _, rule := range cfg.Corpus.Rules {
			if rule.Applies(s.Direction) {
				crit = append(crit, judge.Criterion{Rule: rule.ID, Kind: rule.Kind, Text: rule.Criterion})
				applied = append(applied, rule)
			}
		}
		if len(crit) == 0 {
			continue
		}
		out := cfg.Engine.Evaluate(ctx, judge.Request{Direction: s.Direction, Text: s.Text, Criteria: crit, Timeout: cfg.Timeout})
		r.Calls++
		r.Prompt += out.Prompt
		r.Completion += out.Completion
		switch {
		case out.Cached:
			r.Cached++
		case out.Checked:
			lat = append(lat, out.Latency)
		}
		if !out.Checked {
			r.Unchecked++
			r.Reasons[out.Reason]++
		}
		judged := map[string]bool{}
		for _, v := range out.Verdicts {
			judged[v.Rule] = v.Violated && v.Confidence >= th
		}
		fs, err := cfg.Baseline.Detect(ctx, detect.Text{Text: s.Text, Direction: s.Direction, Source: detect.SourceUser, Lang: s.Lang})
		if err != nil {
			return nil, fmt.Errorf("пример %s: словарь: %w", s.ID, err)
		}
		for _, rule := range applied {
			positive := slices.Contains(s.Violates, rule.ID)
			j := judged[rule.ID]
			l := listsHit(fs, rule.ID)
			un := !out.Checked
			r.Total = addPair(r.Total, positive, j, l, un)
			r.ByRule[rule.ID] = addPair(r.ByRule[rule.ID], positive, j, l, un)
			r.ByClass[s.Class] = addPair(r.ByClass[s.Class], positive, j, l, un)
			r.ByLang[s.Lang] = addPair(r.ByLang[s.Lang], positive, j, l, un)
			r.ByKind[rule.Kind] = addPair(r.ByKind[rule.Kind], positive, j, l, un)
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	if n := len(lat); n > 0 {
		r.P50, r.P95 = lat[n/2], lat[(n*95+99)/100-1]
	}
	verdict(r)
	return r, nil
}

func addPair(s Side, positive, judgeHit, listsHit, unchecked bool) Side {
	s.Judge.add(positive, judgeHit, unchecked)
	s.Lists.add(positive, listsHit, false)
	return s
}

// listsHit — словарь нашёл нарушение правила: находка списка с ID правила
// (Rule находки — «list.<id>.word» или «list.<id>.regex»).
func listsHit(fs []detect.Finding, rule string) bool {
	want := "list." + rule
	return slices.ContainsFunc(fs, func(f detect.Finding) bool {
		return f.Rule == want || strings.HasPrefix(f.Rule, want+".")
	})
}

// verdict — ориентир Р4-образца: полнота выше словаря не меньше чем на
// 10 п. п., доля ложных не выше, оценка получена на всех примерах.
func verdict(r *Result) {
	gain := r.Total.Judge.Recall() - r.Total.Lists.Recall()
	if gain < MinRecallGain {
		r.NotMeets = append(r.NotMeets, fmt.Sprintf("полнота выше словаря на %s п. п. (нужно не меньше %.0f)", dec(100*gain, 1), 100*MinRecallGain))
	}
	if r.Total.Judge.FPR() > r.Total.Lists.FPR() {
		r.NotMeets = append(r.NotMeets, fmt.Sprintf("доля ложных %s выше, чем у словаря (%s)", num(r.Total.Judge.FPR()), num(r.Total.Lists.FPR())))
	}
	if r.Unchecked > 0 {
		r.NotMeets = append(r.NotMeets, fmt.Sprintf("оценка не получена на %d примерах из %d", r.Unchecked, r.Calls))
	}
	r.Meets = len(r.NotMeets) == 0
}

// Markdown — отчёт: итоговая таблица, разрезы и вердикт-ориентир.
func (r *Result) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Замер judge.llm против lists\n\nСреда замера: %s. Порог уверенности оценщика %s. Корпус `testdata/corpus/judge`: %d примеров, %d правил, %d пар «пример — правило».\n\n",
		r.Mode, num(r.Threshold), r.Samples, r.Rules, r.Total.Judge.Pairs())
	b.WriteString("| Проверка | Полнота | Доля ложных | Точность |\n|---|---|---|---|\n")
	fmt.Fprintf(&b, "| `lists` (словарь заказчика) | %s | %s | %s |\n", num(r.Total.Lists.Recall()), num(r.Total.Lists.FPR()), num(r.Total.Lists.Precision()))
	fmt.Fprintf(&b, "| `judge.llm` | %s | %s | %s |\n\n", num(r.Total.Judge.Recall()), num(r.Total.Judge.FPR()), num(r.Total.Judge.Precision()))
	verdictText := "выдержан"
	if !r.Meets {
		verdictText = "не выдержан: " + strings.Join(r.NotMeets, "; ")
	}
	fmt.Fprintf(&b, "Ориентир (по образцу Р4: полнота выше не меньше чем на 10 п. п. при доле ложных не выше) — %s. Это подсказка: решение о включении правил `judge.llm` принимает владелец.\n\n", verdictText)
	fmt.Fprintf(&b, "Вызовов оценщика %d, из кэша %d, без вердиктов — %s; расход %d + %d токенов; время вызова p50 %s, p95 %s.\n",
		r.Calls, r.Cached, reasonsText(r.Reasons), r.Prompt, r.Completion, ms(r.P50), ms(r.P95))
	section(&b, "По правилам", "Правило", r.ByRule, nil)
	section(&b, "По видам правил (DM-18 — content, DM-19 — business)", "Вид", r.ByKind, nil)
	section(&b, "По классам примеров", "Класс", r.ByClass, Classes)
	section(&b, "По языкам", "Язык", r.ByLang, langs)
	return b.String()
}

func section(b *strings.Builder, title, head string, m map[string]Side, order []string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if order != nil {
		var ks []string
		for _, k := range order {
			if _, ok := m[k]; ok {
				ks = append(ks, k)
			}
		}
		keys = ks
	}
	fmt.Fprintf(b, "\n<details><summary>%s</summary>\n\n| %s | Пар | Полнота: lists / judge | Доля ложных: lists / judge | Не проверено |\n|---|---|---|---|---|\n", title, head)
	for _, k := range keys {
		s := m[k]
		fmt.Fprintf(b, "| %s | %d | %s / %s | %s / %s | %d |\n", k, s.Judge.Pairs(),
			num(s.Lists.Recall()), num(s.Judge.Recall()), num(s.Lists.FPR()), num(s.Judge.FPR()), s.Judge.Unchecked)
	}
	b.WriteString("\n</details>\n")
}

func reasonsText(m map[judge.Reason]int) string {
	if len(m) == 0 {
		return "нет"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s — %d", k, m[judge.Reason(k)]))
	}
	return strings.Join(parts, ", ")
}

func num(v float64) string { return dec(v, 3) }

// dec — число с запятой (тексты по-русски).
func dec(v float64, prec int) string {
	return strings.Replace(strconv.FormatFloat(v, 'f', prec, 64), ".", ",", 1)
}

func ms(d time.Duration) string {
	return strings.Replace(fmt.Sprintf("%.1f мс", float64(d)/float64(time.Millisecond)), ".", ",", 1)
}
