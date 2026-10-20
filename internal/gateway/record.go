package gateway

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
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
	// по usage провайдера, -1 — неизвестен.
	res    *Reservation
	sent   bool
	tokens int
	// skip — событие не отправляется: клиент ушёл до решения.
	skip bool
}

// newRecord заводит событие и сообщает его ID приложению заголовком
// X-AISec-Event-Id. Без ID события запрос не обрабатывается.
func (h *ChatHandler) newRecord(w http.ResponseWriter, app *App, req *chat.Request, user string, start time.Time) (*record, bool) {
	u, err := h.cfg.IDs.New()
	if err != nil {
		h.logger.Error("идентификатор события", "error", err)
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
		return nil, false
	}
	rec := &record{start: start, app: app, tokens: -1, ev: events.Event{
		ID: u.String(), Time: start.UTC(), Type: events.TypeGatewayRequest, App: app.ID, Env: app.Env, User: user,
		Provider: app.Provider.ID(), Model: req.Model, PolicyMode: string(effectiveMode(app)), Stream: req.Stream,
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

// usage запоминает расход токенов из ответа или последней части потока.
func (rec *record) usage(u *chat.Usage) {
	if u == nil {
		return
	}
	rec.tokens = u.TotalTokens
	rec.ev.Tokens = &events.Tokens{Prompt: u.PromptTokens, Completion: u.CompletionTokens}
}

// emit уточняет квоту и ставит событие в очередь.
func (h *ChatHandler) emit(rec *record) {
	switch {
	case !rec.sent:
		rec.res.Settle(0) // до модели не дошло — резерв возвращается
	case rec.tokens >= 0:
		rec.res.Settle(rec.tokens)
	}
	if rec.skip {
		return
	}
	rec.ev.LatencyMS["total"] = h.cfg.Now().Sub(rec.start).Milliseconds()
	if rec.in != nil {
		rec.fill()
	}
	if err := h.cfg.Events.Enqueue(rec.ev); err != nil {
		h.logger.Error("событие gateway_request не принято", "event_id", rec.ev.ID, "error", err)
	}
}

// fill переносит в событие решение, находки, трассировку и содержимое.
func (rec *record) fill() {
	in := rec.in
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
	threats := map[string]bool{}
	for _, m := range d.Matches {
		f := in.Findings[m.Hit]
		threats[f.Threat] = true
		if len(ed.Trace) >= maxEventFindings {
			continue
		}
		ed.Trace = append(ed.Trace, events.TraceStep{Rule: m.Rule, Detector: f.Detector, Matched: true, Action: string(m.Action), Note: traceNote(m)})
	}
	if d.Rule == policy.NonTextRule {
		ed.Trace = append(ed.Trace, events.TraceStep{Rule: policy.NonTextRule, Matched: true, Action: string(policy.Block)})
	}
	if len(rec.texts) > 0 && len(in.Findings) > 0 {
		for i, f := range in.Findings {
			if i >= maxEventFindings {
				break
			}
			rec.ev.Findings = append(rec.ev.Findings, events.Finding{
				Detector: f.Detector, Version: f.Version, Category: f.Category, Score: f.Score, Start: f.Start, End: f.End,
				Location: rec.texts[f.Text].Location, Threat: f.Threat, Rule: f.Rule,
			})
		}
	}
	if d.NonTextUnchecked || d.Rule == policy.NonTextRule {
		threats["DM-14"] = true
	}
	for t := range threats {
		rec.ev.Threats = append(rec.ev.Threats, t)
	}
	slices.Sort(rec.ev.Threats)
	rec.ev.Decision = ed
	rec.ev.PolicyMode = string(d.Mode)
	rec.ev.NonTextUnchecked = d.NonTextUnchecked && !in.FailBlock
	if rec.app.Storage == events.StorageMasked {
		if c, ok := in.maskedContent(rec.texts); ok {
			rec.ev.Content = &events.Content{Request: c}
		}
	}
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
	switch {
	case m.AsRedact:
		notes = append(notes, "pseudonymize для эмбеддингов выполнено как redact")
	case m.Protect == policy.Pseudonymize && m.Apply == policy.Redact:
		notes = append(notes, "псевдонимизация в конвейере не подключена, выполнено redact")
	}
	return strings.Join(notes, "; ")
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
