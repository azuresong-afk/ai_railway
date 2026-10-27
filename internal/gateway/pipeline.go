package gateway

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
	"github.com/azuresong-afk/ai_railway/internal/detect/secretscan"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
	"github.com/azuresong-afk/ai_railway/internal/detect/unihidden"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/pseudonym"
)

// Конвейер проверки (ТЗ, 4.3, шаги 4–5 и 7): детекторы политики по
// каждому текстовому фрагменту — параллельно, каждый со своим сроком;
// решение политики; режим приложения при сбое (ТЗ, 4.4); защита данных во
// фрагментах — псевдонимизация и маскирование (internal/pseudonym). Вход
// чата, ответ модели (response.go), Check API и эмбеддинги используют
// inspect.

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
	// фрагментов по порядку) через Sep: разрезанная на части инъекция видна
	// только в склейке. Провайдеры склеивают по-разному (без разделителя,
	// через перевод строки — адаптеры GigaChat и YandexGPT), поэтому
	// проверяются обе склейки. Склейку проверяют только детекторы
	// injection.*, а маскирование находки в склейке переносится на сами части.
	Parts []int
	Sep   string
	// NoCode — окно потока без учёта разметки кода (detect.Text.NoCode).
	NoCode bool
	// Threat — строка матрицы для всех находок фрагмента вместо строки
	// детектора: аргументы tool_calls в ответе — DM-13 (ТЗ, 5.16).
	Threat string
	// Message — номер сообщения запроса чата, к которому относится
	// фрагмент; -1 — не сообщение (описание инструмента, ответ модели,
	// Check API). По нему session.risk отбирает находки нового хода.
	Message int
}

// joinedDetector — детектор проверяет и склейку частей сообщения.
func joinedDetector(id string) bool { return strings.HasPrefix(id, "injection.") }

// inspectRequest — что проверяется.
type inspectRequest struct {
	Endpoint policy.Endpoint
	// Direction — направление проверки; пусто — вход (detect.Input). Выход
	// проверяют Check API (1.24) и проверка ответа (1.23).
	Direction detect.Direction
	// Mode — режим политики для решения; пусто — режим приложения. Ответ
	// при потоковой передаче в режиме monitor проверяется с Mode = monitor:
	// он уже передан, применять нечего (ТЗ, 5.1).
	Mode     policy.Mode
	External bool
	Texts    []inspectText
	Media    []policy.MediaPart
	// Mask — нужны находки детекторов маскирования (хранение masked).
	Mask bool
	// Timeout — базовый срок детектора (DefaultDetectorTimeout).
	Timeout time.Duration
	// Vault — словарь псевдонимов запроса; nil — только маскирование
	// (Check API, эмбеддинги, ответ модели: там pseudonymize не выполняется).
	Vault *pseudonym.Vault
	// DetectOnly — только находки и решение, фрагменты не меняются
	// (окна потока, проверка после передачи).
	DetectOnly bool
	// User — псевдоним пользователя запроса (условие исключений).
	User string
	// Extra — находки детекторов уровня запроса, найденные до проверки
	// (prompt.integrity): они участвуют в решении наравне с остальными.
	Extra []locatedFinding
	// Session — сессия запроса чата для session.risk; nil — без сессии.
	Session *reqSession
}

// locatedFinding — находка и номер фрагмента, в котором она найдена.
// Находка детектора уровня запроса или сессии (prompt.integrity,
// session.risk) к фрагменту не относится: Text = -1, место и источник —
// в Location и Src, позиций в тексте нет.
type locatedFinding struct {
	detect.Finding
	Text     int
	Location string
	Src      detect.Source
}

// place — место и источник находки для события и решения.
func (f locatedFinding) place(texts []inspectText) (string, detect.Source) {
	if f.Text < 0 || f.Text >= len(texts) {
		return f.Location, f.Src
	}
	return texts[f.Text].Location, texts[f.Text].Source
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
	// Fragments — хеши текста находок (fragmentHash) по номерам Findings;
	// nil — ключа нет.
	Fragments []string
}

// excepted — номер находки → ID исключения, по которому она пропущена.
func (in *inspection) excepted() map[int]string {
	if len(in.Decision.Excepted) == 0 {
		return nil
	}
	out := make(map[int]string, len(in.Decision.Excepted))
	for _, x := range in.Decision.Excepted {
		out[x.Hit] = x.Exception
	}
	return out
}

// fragmentDomain — разделитель назначения имитовставки: псевдоним
// пользователя — HMAC идентификатора без управляющих символов, поэтому
// хеш фрагмента с префиксом из U+0000 с ним не совпадает. Версия 2 —
// с ID приложения (3Н41 ревью 3.r3).
const fragmentDomain = "\x00aisec-fragment/2\x00"

// fragmentHash — хеш текста находки для исключений по фрагменту (ТЗ 5.3,
// решение Р8 этапа 3): HMAC на ключе псевдонимов шлюза, 16 байт в hex, как
// псевдоним пользователя. Простой хеш не годится: ПДн из находки (номер
// карты, телефон) перебираются по словарю. ID приложения входит в домен
// (3Н41 ревью 3.r3): у одного текста в разных приложениях разные хеши, и
// держатель ключа одного приложения через /v1/check не узнает, встречалось
// ли значение в запросах другого. ID приложения — без U+0000 (формат ID),
// поэтому граница между ним и текстом однозначна.
func fragmentHash(mac aisecCrypto.MAC, app, text string) string {
	return hex.EncodeToString(mac.Sum([]byte(fragmentDomain + app + "\x00" + text))[:16])
}

// fragments — хеши текста находок; nil без ключа.
func (a *App) fragments(texts []inspectText, fs []locatedFinding) []string {
	if a.fragmentMAC == nil || len(fs) == 0 {
		return nil
	}
	out := make([]string, len(fs))
	for i, f := range fs {
		if f.Text < 0 || f.Text >= len(texts) {
			continue // находка уровня запроса: текста нет
		}
		t := texts[f.Text].Text
		if f.Start < 0 || f.End > len(t) || f.Start >= f.End {
			continue // позиции проверены ValidateFinding; защита от ошибки кода
		}
		out[i] = fragmentHash(a.fragmentMAC, a.ID, t[f.Start:f.End])
	}
	return out
}

// Blocked — запрос не пропускается: решение политики или fail_closed.
func (in *inspection) Blocked() bool { return in.Decision.Block || in.FailBlock }

// inspect проверяет фрагменты по политике приложения. Ошибка — клиент ушёл
// (контекст отменён), конвейер собран неверно (детектор политики не
// зарегистрирован) или защита данных не применена (неверные позиции
// находки); решения тогда нет. Общий срок проверки запроса —
// MaxDetectorTimeout: фрагменты, до которых очередь не дошла, — сбой по
// сроку у всех детекторов политики.
func (a *App) inspect(ctx context.Context, req inspectRequest) (*inspection, error) {
	if req.Timeout <= 0 {
		req.Timeout = DefaultDetectorTimeout
	}
	if req.Direction == "" {
		req.Direction = detect.Input
	}
	policyIDs := a.Policy.Detectors(req.Direction)
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
	// seen — находки по участкам частей: склейка повторяет находку внутри
	// одной части, а две склейки (без разделителя и через перевод строки) —
	// друг друга; в событие и решение каждая идёт один раз.
	seen := map[string]bool{}
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
		fs, rerrs, err := a.Detectors.Run(total, ids, detect.Text{Text: t.Text, Direction: req.Direction, Source: t.Source, NoCode: t.NoCode},
			detectorTimeout(req.Timeout, len(t.Text)))
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, f := range fs {
			if t.Threat != "" {
				f.Threat = t.Threat
			}
			lf := locatedFinding{Finding: f, Text: i}
			key := fmt.Sprint(f.Detector, "\x00", f.Category, "\x00", partSpans(req.Texts, lf))
			if seen[key] {
				continue
			}
			seen[key] = true
			in.Findings = append(in.Findings, lf)
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
	in.Findings = append(in.Findings, req.Extra...)
	a.evaluate(in, req)
	// session.risk — после решения по остальным находкам: находки под
	// исключением (ложные срабатывания) в оценку сессии не входят.
	if req.Session != nil && slices.Contains(policyIDs, session.RiskID) {
		if f, ok := in.sessionRisk(req); ok {
			in.Findings = append(in.Findings, f)
			a.evaluate(in, req)
		}
	}
	// Режим при сбое (ТЗ, 4.4) действует и в monitor: проверка, которая не
	// состоялась, не может подтвердить, что защита данных не нужна. Ответу
	// модели в monitor не применяется ничего (ТЗ, 5.3), поэтому сбой его
	// проверки там только журналируется: блокировать ответ строже, чем при
	// успешной проверке, незачем.
	in.FailBlock = len(in.Failures) > 0 && !a.FailOpen &&
		(req.Direction == detect.Input || req.Endpoint != policy.EndpointChat || in.Decision.Mode == policy.Enforce)
	if !in.Blocked() && !req.DetectOnly {
		v := req.Vault
		if v == nil {
			v = pseudonym.NewVault(pseudonym.Limits{})
		}
		if err := in.protect(req.Texts, v); err != nil {
			return nil, err
		}
	}
	return in, nil
}

// evaluate — хеши фрагментов находок и решение политики по ним.
func (a *App) evaluate(in *inspection, req inspectRequest) {
	in.Fragments = a.fragments(req.Texts, in.Findings)
	hits := make([]policy.Hit, len(in.Findings))
	for i, f := range in.Findings {
		_, src := f.place(req.Texts)
		hits[i] = policy.Hit{Finding: f.Finding, Source: src}
		if in.Fragments != nil {
			hits[i].Fragment = in.Fragments[i]
		}
	}
	mode := req.Mode
	if mode == "" {
		mode = a.Mode
	}
	// Исключения применяются после детекторов и до решения политики; срок —
	// по a.now (не раньше времени сервера, 3Н40): истёкшее исключение не
	// действует без нового пакета.
	in.Decision = a.Policy.Evaluate(policy.Request{
		Endpoint: req.Endpoint, Direction: req.Direction, Mode: mode, External: req.External, Hits: hits, Media: req.Media,
		App: a.ID, User: req.User, Now: a.now(),
	})
}

// sessionRisk обновляет session.risk сессии вкладом этого хода —
// наибольшей оценкой находок детекторов атак в новых сообщениях, кроме
// пропущенных по исключению, — и возвращает находку session.risk, если
// оценка сессии не ниже minRiskFinding. Ход учитывается один раз: проверка
// входа чата — одна на запрос. Общий отпечаток без пользователя (shared)
// оценку не копит.
func (in *inspection) sessionRisk(req inspectRequest) (locatedFinding, bool) {
	s := req.Session
	excepted := in.excepted()
	turn := 0.0
	for i, f := range in.Findings {
		if _, skip := excepted[i]; skip || f.Text < 0 || f.Text >= len(req.Texts) || !riskDetector(f.Detector) {
			continue
		}
		if req.Texts[f.Text].Message >= s.newFrom {
			turn = max(turn, f.Score)
		}
	}
	if s.shared {
		return locatedFinding{}, false
	}
	risk, turns := s.tracker.observe(s.key, turn)
	s.ev.Risk, s.ev.Turns = risk, turns
	if risk < minRiskFinding {
		return locatedFinding{}, false
	}
	return locatedFinding{Finding: detect.Finding{Detector: session.RiskID, Version: session.RiskVersion,
		Category: session.CatEscalation, Threat: session.ThreatRisk, Score: risk},
		Text: -1, Location: riskLocation, Src: detect.SourceUser}, true
}

// located — участок фрагмента.
type located struct {
	text       int
	start, end int
}

// partSpans — участки, которые занимает находка: в самом фрагменте или,
// для склейки, в каждой из частей, которые она задевает. Части склеены через
// Sep, границы частей — границы символов UTF-8; разделитель не маскируется.
func partSpans(texts []inspectText, f locatedFinding) []located {
	if f.Text < 0 || f.Text >= len(texts) {
		return nil // находка уровня запроса: позиций в тексте нет
	}
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
		off += n + len(t.Sep)
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

// protectSpan — участок фрагмента под защитой данных.
type protectSpan struct {
	start, end int
	category   string
	action     policy.Action // redact или pseudonymize
	// cut — вырезать символы (unicode.hidden), а не заменять маской.
	cut bool
}

// protectSpans — участки защиты данных из решения по фрагментам.
func (in *inspection) protectSpans(texts []inspectText) map[int][]protectSpan {
	byText := map[int][]protectSpan{}
	for _, m := range in.Decision.Matches {
		if m.Apply != policy.Redact && m.Apply != policy.Pseudonymize {
			continue
		}
		f := in.Findings[m.Hit]
		for _, l := range partSpans(texts, f) {
			byText[l.text] = append(byText[l.text], protectSpan{l.start, l.end, f.Category, m.Apply, m.Apply == policy.Redact && cutOut(f.Finding)})
		}
	}
	return byText
}

// protect выполняет защиту данных из решения: pseudonymize — псевдоним
// [[ТИП_N]] из словаря v, redact — маска [[ТИП]] (ADR-0005), символы
// unicode.hidden вырезаются (DM-05).
func (in *inspection) protect(texts []inspectText, v *pseudonym.Vault) error {
	byText := in.protectSpans(texts)
	if len(byText) == 0 {
		return nil
	}
	in.Texts = make([]string, len(texts))
	in.Changed = make([]bool, len(texts))
	for i, t := range texts {
		in.Texts[i] = t.Text
		if spans, ok := byText[i]; ok {
			s, err := applySpans(t.Text, spans, v)
			if err != nil {
				return fmt.Errorf("%s: %w", t.Location, err)
			}
			in.Texts[i], in.Changed[i] = s, s != t.Text
		}
	}
	return nil
}

// applySpans заменяет участки текста. Пересекающиеся участки сливаются в
// один (как в Vault.Protect): если среди них есть redact или вырезание,
// слитый участок маскируется необратимо, тип — по первому участку с маской;
// участок только из вырезаний удаляется.
func applySpans(text string, spans []protectSpan, v *pseudonym.Vault) (string, error) {
	spans = slices.Clone(spans)
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
		masked := !cur.cut
		for i++; i < len(spans) && spans[i].start < cur.end; i++ {
			s := spans[i]
			cur.end = max(cur.end, s.end)
			if s.action == policy.Redact {
				cur.action = policy.Redact
			}
			if !s.cut && !masked {
				cur.category, masked = s.category, true
			}
		}
		if cur.start < pos || cur.end > len(text) {
			return "", errors.New("участок защиты данных вне текста")
		}
		b.WriteString(text[pos:cur.start])
		pos = cur.end
		if !masked {
			continue
		}
		repl, err := v.Protect(text[cur.start:cur.end], []pseudonym.Span{{Start: 0, End: cur.end - cur.start, Category: cur.category, Action: cur.action}})
		if err != nil {
			return "", err
		}
		b.WriteString(repl)
	}
	b.WriteString(text[pos:])
	return b.String(), nil
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
	return eventText(b.String()), true
}

// fullContent — содержимое для события в режиме full: тексты как есть.
// Хранится только на сервере, зашифрованным (ЗИ.1, задача 2.15).
func fullContent(texts []inspectText) string {
	var b strings.Builder
	for _, t := range texts {
		if t.Parts != nil {
			continue // склейка повторяет части
		}
		if b.Len() >= maxEventContent {
			break
		}
		b.WriteString(t.Location)
		b.WriteString(": ")
		b.WriteString(t.Text)
		b.WriteByte('\n')
	}
	return eventText(b.String())
}

// eventText обрезает содержимое события до maxEventContent и заменяет U+0000
// (его не хранит PostgreSQL, и сервер отверг бы событие).
func eventText(s string) string {
	return strings.ReplaceAll(truncateUTF8(s, maxEventContent), "\x00", "\uFFFD")
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
