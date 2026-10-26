package gateway

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/pseudonym"
)

// record — событие gateway_request, которое собирается по ходу запроса и
// отправляется в конце (ТЗ, 4.3, шаг 8; 5.5).
type record struct {
	ev    events.Event
	start time.Time
	app   *App
	// in и texts — результат проверки входа; nil — до проверки не дошло.
	in    *inspection
	texts []inspectText
	// res — резерв квоты; sent — запрос ушёл провайдеру; tokens — расход
	// по usage провайдера, -1 — неизвестен. Без usage (или с нулевым) расход
	// оценивается по размеру: inTokens — оценка входа, outBytes — размер
	// ответа провайдера до действий политики (nil — ответа нет).
	res      *Reservation
	sent     bool
	tokens   int
	inTokens int
	outBytes func() int
	// maxOut — предел ответа запроса (max_tokens или подставленный квотой),
	// 0 — не задан. unknown — исход запроса, ушедшего провайдеру,
	// неизвестен (клиент прервал запрос, таймаут, обрыв связи до ответа):
	// провайдер вход, как правило, уже обработал (3В22 ревью 3.r3).
	maxOut  int
	unknown bool
	// skip — событие не отправляется: клиент ушёл до решения.
	skip bool
	// output — проверялся текст ответа: содержимое в событии пишется в
	// content.response, а не в content.request (Check API).
	output bool
	// vault — словарь псевдонимов запроса чата; jsonMode — ответ в формате
	// JSON (response_format).
	vault    *pseudonym.Vault
	jsonMode bool
	// resp и respTexts — проверка ответа модели (задача 1.23); respMode —
	// режим проверки; respCut — поток оборван (respCutRule — правило),
	// respMasked — в потоке что-то замаскировано; respFailures — сбои
	// детекторов на окнах потока; withheld — тексты, где подстановка
	// отменена проверкой output.exfil.
	resp        *inspection
	respTexts   []inspectText
	respMode    string
	respCut     bool
	respCutRule string
	// respCutFinding — находка, из-за которой поток оборван правилом
	// stream_late (детектор и категория — в трассировку).
	respCutFinding *detect.Finding
	respMasked     bool
	// respCheckFailed — поток оборван, потому что проверка не состоялась.
	respCheckFailed bool
	respFailures    []events.DetectorFailure
	withheld        int
}

// newRecord заводит событие и сообщает его ID приложению заголовком
// X-AISec-Event-Id. Без ID события запрос не обрабатывается.
func (h *ChatHandler) newRecord(w http.ResponseWriter, app *App, req *chat.Request, user string, start time.Time) (*record, bool) {
	return h.newEventRecord(w, app, events.TypeGatewayRequest, req.Model, req.Stream, user, start)
}

// newEventRecord заводит событие заданного типа: gateway_request, check.
func (h *ChatHandler) newEventRecord(w http.ResponseWriter, app *App, typ, model string, stream bool, user string, start time.Time) (*record, bool) {
	u, err := h.cfg.IDs.New()
	if err != nil {
		h.logger.Error("идентификатор события", "error", err)
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
		return nil, false
	}
	rec := &record{start: start, app: app, tokens: -1, ev: events.Event{
		ID: u.String(), Time: start.UTC(), Type: typ, App: app.ID, Env: app.Env, User: user,
		Provider: app.Provider.ID(), Model: model, PolicyMode: string(effectiveMode(app)), Stream: stream,
		Storage: app.Storage, LatencyMS: map[string]int64{},
	}}
	w.Header().Set(HeaderEventID, rec.ev.ID)
	return rec, true
}

// effectiveMode — режим политики приложения, как его применит Evaluate.
func effectiveMode(app *App) policy.Mode {
	switch app.Mode {
	case "":
		return app.Policy.Mode
	case policy.Monitor, policy.Enforce:
		return app.Mode
	}
	return policy.Enforce
}

// reject — отказ до проверки детекторами: неразрешённая модель или квота.
// Такой отказ действует и в monitor: это ограничения приложения, а не
// правила политики.
func (rec *record) reject(rule, threat string) {
	rec.ev.Decision = &events.Decision{
		Action: string(policy.Block), Applied: []string{string(policy.Block)}, Rule: rule,
		Policy: rec.app.Policy.ID, PolicyVersion: rec.app.Policy.Version,
	}
	rec.ev.Threats = []string{threat}
}

// failClosed — запрос не пропущен из-за внутренней ошибки шлюза.
func (rec *record) failClosed() {
	if rec.in != nil {
		rec.in.FailBlock = true
		return
	}
	rec.ev.Decision = &events.Decision{
		Action: string(policy.Block), Applied: []string{string(policy.Block)}, Rule: ruleFailClosed,
		Policy: rec.app.Policy.ID, PolicyVersion: rec.app.Policy.Version,
	}
}

// respFailClosed — ответ не отдан из-за внутренней ошибки шлюза.
func (rec *record) respFailClosed() {
	if rec.resp == nil {
		rec.resp = &inspection{Decision: policy.Decision{
			PolicyID: rec.app.Policy.ID, Version: rec.app.Policy.Version, Mode: effectiveMode(rec.app), Action: policy.Allow,
		}}
	}
	rec.resp.FailBlock = true
}

// usage запоминает расход токенов из ответа или последней части потока.
func (rec *record) usage(u *chat.Usage) {
	if u == nil {
		return
	}
	// Часть OpenAI-совместимых серверов не заполняет total_tokens.
	rec.tokens = max(u.TotalTokens, u.PromptTokens+u.CompletionTokens)
	rec.ev.Tokens = &events.Tokens{Prompt: u.PromptTokens, Completion: u.CompletionTokens}
}

// emit уточняет квоту и ставит событие в очередь.
func (h *ChatHandler) emit(rec *record) {
	switch {
	case !rec.sent:
		rec.res.Settle(0) // до модели не дошло — резерв возвращается
	case rec.tokens > 0:
		rec.res.Settle(rec.tokens)
	case rec.outBytes != nil:
		// Провайдер не прислал usage (поток без stream_options.include_usage)
		// или прислал нули: иначе резерв без max_tokens покрывал бы только
		// вход (или возвращался бы целиком), и ответ любой длины не
		// учитывался бы в tokens_per_minute и tokens_per_day (DM-36).
		rec.res.SettleAtLeast(rec.inTokens + estimateTokens(rec.outBytes()))
	case rec.unknown:
		// Исход неизвестен — оценка сверху: вход и предел ответа. Иначе
		// разрыв соединения после отправки обходил бы квоту токенов (DM-36).
		rec.res.SettleAtLeast(rec.inTokens + rec.maxOut)
	default:
		// Явный отказ провайдера (статус, учётные данные) или usage с нулями
		// без ответа — расхода нет.
		rec.res.Settle(0)
	}
	h.spend(rec)
	if rec.skip {
		return
	}
	rec.ev.LatencyMS["total"] = h.cfg.Now().Sub(rec.start).Milliseconds()
	if rec.in != nil {
		rec.fill()
	}
	rec.fillResponse()
	if err := h.cfg.Events.Enqueue(rec.ev); err != nil {
		h.logger.Error("событие не принято", "type", rec.ev.Type, "event_id", rec.ev.ID, "error", err)
	}
}

// spend учитывает расход запроса, ушедшего провайдеру (задача 3.18): по
// usage провайдера, без него — по оценке размера входа и ответа (оценка
// сверху: бюджет не занижается). Исход неизвестен (разрыв клиента,
// таймаут, обрыв до ответа) — вход и предел ответа запроса (3В22 ревью
// 3.r3). Явный отказ провайдера — расхода нет и запрос не считается.
func (h *ChatHandler) spend(rec *record) {
	if h.cfg.Budget == nil || !rec.sent || rec.ev.Type != events.TypeGatewayRequest {
		return
	}
	var in, out int64
	switch t := rec.ev.Tokens; {
	case t != nil && t.Prompt+t.Completion > 0:
		in, out = int64(t.Prompt), int64(t.Completion)
	case rec.outBytes != nil:
		in, out = int64(rec.inTokens), int64(estimateTokens(rec.outBytes()))
	case rec.unknown:
		in, out = int64(rec.inTokens), int64(rec.maxOut)
	default:
		return
	}
	h.cfg.Budget.Record(rec.app.ID, rec.ev.Provider, rec.ev.Model, in, out)
}

// fill переносит в событие решение, находки, трассировку и содержимое.
func (rec *record) fill() {
	in := rec.in
	d := in.Decision
	ed := rec.decision(in)
	threats := rec.findings(in, rec.texts)
	if d.NonTextUnchecked || d.Rule == policy.NonTextRule {
		threats["DM-14"] = true
	}
	rec.addThreats(threats)
	rec.ev.Decision = ed
	rec.ev.PolicyMode = string(d.Mode)
	rec.ev.NonTextUnchecked = d.NonTextUnchecked && !in.FailBlock
	c, ok := "", false
	switch rec.app.Storage {
	case events.StorageMasked:
		c, ok = in.maskedContent(rec.texts)
	case events.StorageFull:
		c, ok = fullContent(rec.texts), true
	}
	if ok && c != "" {
		rec.ev.Content = &events.Content{Request: c}
		if rec.output {
			rec.ev.Content = &events.Content{Response: c}
		}
	}
}

// fillResponse переносит в событие проверку ответа модели и счётчики
// псевдонимизации.
func (rec *record) fillResponse() {
	if v := rec.vault; v != nil {
		st := v.Stats()
		if st != (pseudonym.Stats{}) || rec.withheld > 0 {
			rec.ev.Pseudonyms = &events.Pseudonyms{
				Issued: st.Issued, Pseudonymized: st.Pseudonymized, Redacted: st.Redacted, Fallback: st.Fallback,
				Restored: st.Restored, Failed: st.Failed(), Unknown: st.Unknown, Mangled: st.Mangled, Unsafe: st.Unsafe,
				Limited: st.Limited, Withheld: rec.withheld,
			}
		}
	}
	if rec.respMode == "" {
		return
	}
	r := &events.Response{Mode: rec.respMode, Cut: rec.respCut}
	rec.ev.Response = r
	in := rec.resp
	if in == nil {
		return
	}
	for _, f := range rec.respFailures {
		if !slices.Contains(in.Failures, f) {
			in.Failures = append(in.Failures, f)
		}
	}
	if rec.respCheckFailed {
		in.FailBlock = true
	}
	ed := rec.decision(in)
	if rec.respMode == events.ResponseIncremental {
		// В incremental применено то, что сделано с потоком, а не итог
		// проверки всего ответа.
		ed.Applied = []string{}
		if rec.respCut {
			ed.Applied = append(ed.Applied, string(policy.Block))
		}
		if rec.respMasked {
			ed.Applied = append(ed.Applied, string(policy.Redact))
		}
		switch rec.respCutRule {
		case ruleStreamCut:
			ed.Trace = append(ed.Trace, events.TraceStep{Rule: ruleStreamCut, Matched: true, Action: string(policy.Block),
				Note: "фрагмент для маскирования начался в уже переданном тексте: поток оборван"})
		case ruleStreamHold:
			ed.Trace = append(ed.Trace, events.TraceStep{Rule: ruleStreamHold, Matched: true, Action: string(policy.Block),
				Note: "непереданного текста больше предела проверки: поток оборван"})
		case ruleStreamLate:
			st := events.TraceStep{Rule: ruleStreamLate, Matched: true, Action: string(policy.Block),
				Note: "находка целиком в уже переданном тексте, применить её поздно: поток оборван"}
			if f := rec.respCutFinding; f != nil {
				st.Detector, st.Note = f.Detector, st.Note+" ("+f.Category+", "+f.Threat+")"
			}
			ed.Trace = append(ed.Trace, st)
		}
	}
	if d := in.Decision; d.Rule == ruleToolArgsJSON {
		ed.Trace = append(ed.Trace, events.TraceStep{Rule: ruleToolArgsJSON, Matched: true, Action: string(policy.Block),
			Note: "маска сломала JSON аргументов вызова: ответ заблокирован"})
	}
	r.Decision = ed
	rec.addThreats(rec.findings(in, rec.respTexts))
	c, ok := "", false
	switch rec.app.Storage {
	case events.StorageMasked:
		c, ok = in.maskedContent(rec.respTexts)
	case events.StorageFull:
		c, ok = fullContent(rec.respTexts), true
	}
	if ok && c != "" {
		if rec.ev.Content == nil {
			rec.ev.Content = &events.Content{}
		}
		rec.ev.Content.Response = c
	}
}

// decision — решение для события: итог, применённое, трассировка, сбои.
func (rec *record) decision(in *inspection) *events.Decision {
	d := in.Decision
	ed := &events.Decision{
		Action: string(d.Action), Applied: []string{}, Rule: d.Rule, Severity: string(d.Severity),
		Policy: d.PolicyID, PolicyVersion: d.Version, Failures: in.Failures,
	}
	for _, a := range d.Applied() {
		ed.Applied = append(ed.Applied, string(a))
	}
	if len(in.Failures) > 0 {
		ed.FailMode = "fail_closed"
		if rec.app.FailOpen {
			ed.FailMode = failOpen
		}
	}
	if in.FailBlock {
		ed.Action, ed.Rule = string(policy.Block), ruleFailClosed
		if !slices.Contains(ed.Applied, string(policy.Block)) {
			ed.Applied = append([]string{string(policy.Block)}, ed.Applied...)
		}
	}
	for _, m := range d.Matches {
		if len(ed.Trace) >= maxEventFindings {
			break
		}
		f := in.Findings[m.Hit]
		ed.Trace = append(ed.Trace, events.TraceStep{Rule: m.Rule, Detector: f.Detector, Matched: true, Action: string(m.Action), Note: traceNote(m)})
	}
	if d.Rule == policy.NonTextRule {
		ed.Trace = append(ed.Trace, events.TraceStep{Rule: policy.NonTextRule, Matched: true, Action: string(policy.Block)})
	}
	for _, x := range d.Excepted {
		if len(ed.Trace) >= maxEventFindings {
			break
		}
		f := in.Findings[x.Hit]
		ed.Trace = append(ed.Trace, events.TraceStep{Rule: ruleException, Detector: f.Detector, Matched: true,
			Action: string(policy.Allow), Note: "находка пропущена по исключению " + x.Exception})
	}
	return ed
}

// ruleException — шаг трассировки находки, пропущенной по исключению.
const ruleException = "exception"

// findings добавляет находки в событие (всего не больше maxEventFindings)
// и возвращает категории угроз решения.
func (rec *record) findings(in *inspection, texts []inspectText) map[string]bool {
	threats := map[string]bool{}
	for _, m := range in.Decision.Matches {
		threats[in.Findings[m.Hit].Threat] = true
	}
	excepted := in.excepted()
	for i, f := range in.Findings {
		if len(rec.ev.Findings) >= maxEventFindings {
			break
		}
		if f.Text >= len(texts) {
			continue
		}
		ef := events.Finding{
			Detector: f.Detector, Version: f.Version, Category: f.Category, Score: f.Score, Start: f.Start, End: f.End,
			Location: texts[f.Text].Location, Threat: f.Threat, Rule: f.Rule, Exception: excepted[i], Source: string(texts[f.Text].Source),
		}
		if i < len(in.Fragments) {
			ef.Fragment = in.Fragments[i]
		}
		rec.ev.Findings = append(rec.ev.Findings, ef)
	}
	return threats
}

// addThreats добавляет категории угроз в событие без повторов.
func (rec *record) addThreats(threats map[string]bool) {
	for t := range threats {
		if t != "" && !slices.Contains(rec.ev.Threats, t) {
			rec.ev.Threats = append(rec.ev.Threats, t)
		}
	}
	slices.Sort(rec.ev.Threats)
}

// traceNote — пояснение к шагу трассировки: что сделано с фрагментом,
// если это не итог правила.
func traceNote(m policy.Match) string {
	var notes []string
	switch {
	case m.Apply != "" && m.Apply != m.Action:
		notes = append(notes, "применено "+string(m.Apply)+" по правилу "+m.ProtectRule)
	case m.Apply == "" && m.Protect != "":
		notes = append(notes, "не применено "+string(m.Protect)+" по правилу "+m.ProtectRule+" (monitor)")
	}
	if m.AsRedact {
		notes = append(notes, "pseudonymize выполнено как redact: обратной подстановки нет")
	}
	return strings.Join(notes, "; ")
}

// headerDecision — X-AISec-Decision ответа без потока и buffered: самое
// сильное из того, что шлюз сделал с запросом и с ответом.
func (rec *record) headerDecision() string {
	h := rec.in.headerDecision()
	if rec.resp == nil {
		return h
	}
	if r := rec.resp.headerDecision(); policy.Stronger(policy.Action(r), policy.Action(h)) {
		return r
	}
	return h
}

// headerDecision — значение X-AISec-Decision: что шлюз сделал с запросом
// (block, redact, pseudonymize или allow). Что было бы в enforce, видно
// только в событии.
func (in *inspection) headerDecision() string {
	if in.Blocked() {
		return string(policy.Block)
	}
	if a := in.Decision.Applied(); len(a) > 0 {
		return string(a[0])
	}
	return string(policy.Allow)
}

// responseBytes — размер текста ответа для оценки токенов: содержимое,
// отказ, имена и аргументы вызовов инструментов всех вариантов.
func responseBytes(resp *chat.Response) int {
	n := 0
	for _, c := range resp.Choices {
		if c.Message.Content != nil {
			n += len(*c.Message.Content)
		}
		if c.Message.Refusal != nil {
			n += len(*c.Message.Refusal)
		}
		for _, tc := range c.Message.ToolCalls {
			n += len(tc.Function.Name) + len(tc.Function.Arguments)
		}
	}
	return n
}
