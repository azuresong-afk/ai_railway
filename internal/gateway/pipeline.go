package gateway

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
	"github.com/azuresong-afk/ai_railway/internal/detect/secretscan"
	"github.com/azuresong-afk/ai_railway/internal/detect/unihidden"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Конвейер проверки входа (ТЗ, 4.3, шаги 4–5): детекторы политики по
// каждому текстовому фрагменту — параллельно, каждый со своим сроком;
// решение политики; режим приложения при сбое (ТЗ, 4.4); маскирование
// фрагментов. Проверка ответа — задача 1.23, Check API — 1.24: оба
// используют inspect.

// Срок детектора. Он растёт с длиной текста: при постоянном сроке длинный
// текст не успевал бы проверяться, и при fail_open запрос прошёл бы без
// проверки (обход через срок, docs/cert/threat-model.md). Запас взят от
// наихудшей измеренной скорости детекторов (injection.heuristic,
// 2,4 МБ/с) с коэффициентом около 5 на конкуренцию за процессор.
const (
	// DefaultDetectorTimeout — срок детектора на короткий текст.
	DefaultDetectorTimeout = 100 * time.Millisecond
	// detectorTimePerKB — добавка к сроку на каждый килобайт текста
	// (расчётная скорость 0,5 МБ/с).
	detectorTimePerKB = 2 * time.Millisecond
	// MaxDetectorTimeout — предел срока на один фрагмент: тело запроса не
	// больше 32 МБ (config.MaxBodyBytesLimit), так что предел достигается
	// только на крайних настройках.
	MaxDetectorTimeout = time.Minute
)

// detectorTimeout — срок детектора для текста длиной n байт.
func detectorTimeout(base time.Duration, n int) time.Duration {
	return min(base+time.Duration(n)*detectorTimePerKB/1024, MaxDetectorTimeout)
}

// RedactMark заменяет фрагмент при redact. Псевдонимы (1.20) — в двойных
// скобках, поэтому маска в одинарных: обратная подстановка её не тронет.
const RedactMark = "[REDACTED]"

// Пределы события: решение принимается по всем находкам, но в событие
// попадают первые maxEventFindings, а содержимое — не длиннее
// maxEventContent байт.
const (
	maxEventFindings = 1024
	maxEventContent  = 64 << 10
)

// Служебные имена правил в решении (events.Decision.Rule).
const (
	ruleFailClosed  = "fail_closed"
	ruleModel       = "model_not_allowed"
	ruleQuotaPrefix = "quota."
)

// maskDetectors — детекторы, по находкам которых маскируется содержимое
// события в режиме хранения masked (ТЗ, 5.5), даже если политика их не
// использует.
var maskDetectors = []string{pii.ID, secretscan.ID}

// inspectText — проверяемый фрагмент.
type inspectText struct {
	Text   string
	Source detect.Source
	// Location — место фрагмента для события (messages[0].content).
	Location string
	// Parts — фрагмент склеен из текстовых частей одного сообщения (номера
	// фрагментов по порядку): провайдер склеит их так же, и разрезанная на
	// части инъекция видна только в склейке. Склейку проверяют только
	// детекторы injection.*, а маскирование находки в склейке переносится
	// на сами части.
	Parts []int
}

// joinedDetector — детектор проверяет и склейку частей сообщения.
func joinedDetector(id string) bool { return strings.HasPrefix(id, "injection.") }

// inspectRequest — что проверяется.
type inspectRequest struct {
	Endpoint policy.Endpoint
	External bool
	Texts    []inspectText
	Media    []policy.MediaPart
	// Mask — нужны находки детекторов маскирования (хранение masked).
	Mask bool
	// Timeout — базовый срок детектора (DefaultDetectorTimeout).
	Timeout time.Duration
}

// locatedFinding — находка и номер фрагмента, в котором она найдена.
type locatedFinding struct {
	detect.Finding
	Text int
}

// inspection — результат проверки.
type inspection struct {
	Decision policy.Decision
	// Findings — все находки; Decision.Matches[].Hit — индексы сюда.
	Findings []locatedFinding
	// Failures — сбои детекторов политики.
	Failures []events.DetectorFailure
	// FailBlock — сбой при fail_closed: запрос блокируется.
	FailBlock bool
	// MaskFailed — сбой детектора маскирования: содержимое в событие не
	// пишется, раз его нельзя замаскировать.
	MaskFailed bool
	// Texts — фрагменты после маскирования; Changed[i] — фрагмент изменён.
	Texts   []string
	Changed []bool
}

// Blocked — запрос не пропускается: решение политики или fail_closed.
func (in *inspection) Blocked() bool { return in.Decision.Block || in.FailBlock }

// inspect проверяет фрагменты по политике приложения. Ошибка — клиент ушёл
// (контекст отменён) или конвейер собран неверно (детектор политики не
// зарегистрирован); решения тогда нет. Общий срок проверки запроса —
// MaxDetectorTimeout: фрагменты, до которых очередь не дошла, — сбой по
// сроку у всех детекторов политики.
func (a *App) inspect(ctx context.Context, req inspectRequest) (*inspection, error) {
	if req.Timeout <= 0 {
		req.Timeout = DefaultDetectorTimeout
	}
	policyIDs := a.Policy.Detectors(detect.Input)
	runIDs := slices.Clone(policyIDs)
	if req.Mask {
		for _, id := range maskDetectors {
			if _, ok := a.Detectors.Get(id); ok && !slices.Contains(runIDs, id) {
				runIDs = append(runIDs, id)
			}
		}
	}
	in := &inspection{}
	total, cancel := context.WithTimeout(ctx, MaxDetectorTimeout)
	defer cancel()
	joinedIDs := slices.DeleteFunc(slices.Clone(runIDs), func(id string) bool { return !joinedDetector(id) })
	for i, t := range req.Texts {
		ids := runIDs
		if t.Parts != nil {
			ids = joinedIDs
		}
		if t.Text == "" || len(ids) == 0 {
			continue
		}
		if total.Err() != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			in.overall(policyIDs, t.Location)
			break
		}
		fs, rerrs, err := a.Detectors.Run(total, ids, detect.Text{Text: t.Text, Direction: detect.Input, Source: t.Source},
			detectorTimeout(req.Timeout, len(t.Text)))
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, f := range fs {
			in.Findings = append(in.Findings, locatedFinding{Finding: f, Text: i})
		}
		for _, re := range rerrs {
			reason := events.FailureError
			if errors.Is(re.Err, detect.ErrDetectorTimeout) || errors.Is(re.Err, context.DeadlineExceeded) {
				reason = events.FailureTimeout
			}
			if slices.Contains(policyIDs, re.Detector) {
				in.Failures = append(in.Failures, events.DetectorFailure{Detector: re.Detector, Location: t.Location, Reason: reason})
			}
			if slices.Contains(maskDetectors, re.Detector) {
				in.MaskFailed = true
			}
		}
	}
	hits := make([]policy.Hit, len(in.Findings))
	for i, f := range in.Findings {
		hits[i] = policy.Hit{Finding: f.Finding, Source: req.Texts[f.Text].Source}
	}
	in.Decision = a.Policy.Evaluate(policy.Request{
		Endpoint: req.Endpoint, Direction: detect.Input, Mode: a.Mode, External: req.External, Hits: hits, Media: req.Media,
	})
	// Режим при сбое (ТЗ, 4.4) действует и в monitor: проверка, которая не
	// состоялась, не может подтвердить, что защита данных не нужна.
	in.FailBlock = len(in.Failures) > 0 && !a.FailOpen
	// Псевдонимизация подключается к конвейеру в задаче 1.23; до неё
	// pseudonymize выполняется как redact: ПДн маскируются необратимо, но
	// провайдеру не уходят.
	for k := range in.Decision.Matches {
		if m := &in.Decision.Matches[k]; m.Apply == policy.Pseudonymize {
			m.Apply = policy.Redact
		}
	}
	if !in.Blocked() {
		in.redact(req.Texts)
	}
	return in, nil
}

// located — участок фрагмента.
type located struct {
	text       int
	start, end int
}

// partSpans — участки, которые занимает находка: в самом фрагменте или,
// для склейки, в каждой из частей, которые она задевает. Части склеены без
// разделителя, границы частей — границы символов UTF-8.
func partSpans(texts []inspectText, f locatedFinding) []located {
	t := texts[f.Text]
	if t.Parts == nil {
		return []located{{f.Text, f.Start, f.End}}
	}
	var out []located
	off := 0
	for _, p := range t.Parts {
		n := len(texts[p].Text)
		if s, e := max(f.Start, off), min(f.End, off+n); s < e {
			out = append(out, located{p, s - off, e - off})
		}
		off += n
	}
	return out
}

// overall — общий срок проверки истёк: оставшиеся фрагменты (начиная с
// location) не проверены ни одним детектором политики, детекторы
// маскирования — тоже.
func (in *inspection) overall(policyIDs []string, location string) {
	for _, id := range policyIDs {
		in.Failures = append(in.Failures, events.DetectorFailure{Detector: id, Location: location, Reason: events.FailureTimeout})
	}
	in.MaskFailed = true
}

// span — заменяемый участок фрагмента [start, end).
type span struct {
	start, end int
	repl       string
}

// redact выполняет защиту данных из решения: маскирует фрагменты, а
// символы unicode.hidden вырезает (DM-05).
func (in *inspection) redact(texts []inspectText) {
	byText := map[int][]span{}
	for _, m := range in.Decision.Matches {
		if m.Apply != policy.Redact {
			continue
		}
		f := in.Findings[m.Hit]
		repl := RedactMark
		if cutOut(f.Finding) {
			repl = ""
		}
		for _, l := range partSpans(texts, f) {
			byText[l.text] = append(byText[l.text], span{l.start, l.end, repl})
		}
	}
	if len(byText) == 0 {
		return
	}
	in.Texts = make([]string, len(texts))
	in.Changed = make([]bool, len(texts))
	for i, t := range texts {
		in.Texts[i] = t.Text
		if spans, ok := byText[i]; ok {
			in.Texts[i] = rewrite(t.Text, spans)
			in.Changed[i] = in.Texts[i] != t.Text
		}
	}
}

// cutOut — находка, которую redact вырезает, а не заменяет маской:
// невидимые символы, теги Unicode и управление направлением текста (DM-05).
// Гомоглифы — видимые буквы, их слово маскируется.
func cutOut(f detect.Finding) bool {
	return f.Detector == unihidden.ID && f.Category != unihidden.CatHomoglyph
}

// rewrite заменяет участки текста. Пересекающиеся участки сливаются в один;
// у слитого участка — маска первого непустого.
func rewrite(text string, spans []span) string {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for i := 0; i < len(spans); {
		cur := spans[i]
		for i++; i < len(spans) && spans[i].start < cur.end; i++ {
			cur.end = max(cur.end, spans[i].end)
			if cur.repl == "" {
				cur.repl = spans[i].repl
			}
		}
		if cur.start < pos || cur.end > len(text) {
			continue // позиции проверены ValidateFinding; защита от ошибки кода
		}
		b.WriteString(text[pos:cur.start])
		b.WriteString(cur.repl)
		pos = cur.end
	}
	b.WriteString(text[pos:])
	return b.String()
}

// maskedContent — содержимое запроса для события в режиме masked: ПДн,
// секреты и всё, что замаскировала политика, заменены категорией находки,
// скрытые символы вырезаны. Пусто и false — замаскировать нельзя (сбой
// детектора маскирования).
func (in *inspection) maskedContent(texts []inspectText) (string, bool) {
	if in.MaskFailed {
		return "", false
	}
	applied := map[int]bool{}
	for _, m := range in.Decision.Matches {
		if m.Apply != "" || m.Protect != "" {
			applied[m.Hit] = true
		}
	}
	byText := map[int][]span{}
	for i, f := range in.Findings {
		cut := cutOut(f.Finding)
		if !applied[i] && !cut && !slices.Contains(maskDetectors, f.Detector) {
			continue
		}
		repl := "[" + f.Category + "]"
		if cut {
			repl = ""
		}
		for _, l := range partSpans(texts, f) {
			byText[l.text] = append(byText[l.text], span{l.start, l.end, repl})
		}
	}
	var b strings.Builder
	for i, t := range texts {
		if t.Parts != nil {
			continue // склейка повторяет части
		}
		if b.Len() >= maxEventContent {
			break
		}
		b.WriteString(t.Location)
		b.WriteString(": ")
		b.WriteString(rewrite(t.Text, byText[i]))
		b.WriteByte('\n')
	}
	return truncateUTF8(b.String(), maxEventContent), true
}

// truncateUTF8 обрезает строку до n байт, не разрезая символ.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
