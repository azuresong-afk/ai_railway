package gateway

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/injection"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Оценщик judge.llm в шлюзе (ТЗ 5.2, DM-18 и DM-19 «LLM — 5»; задача 5.28
// этапа 5, ADR-0030, разделы 3–7). Правила judge.llm одного направления и
// режима оцениваются одним вызовом: sync — до решения (находки участвуют в
// нём наравне с остальными), async — после ответа приложению (находки
// попадают в событие, решение не меняется). Текст запроса, критерии и ответ
// оценщика в технические журналы не пишутся.

// Места находок оценщика в событии: у находки нет позиций в тексте.
const (
	judgeInputLocation  = "messages"
	judgeOutputLocation = locContent
)

// Judges — оценщики шлюза: общее состояние (кэш, бюджеты, очереди) и
// адаптеры провайдеров с признаком «у заказчика» по slug.
type Judges struct {
	Shared *judge.Shared
	// Clients — адаптеры провайдеров пакета с on_premise (транспорт только
	// к частной сети, providers.NewPrivateTransport). Провайдера политики
	// здесь нет — её правила дают «не проверено» (unavailable).
	Clients map[string]judge.Client
	Hasher  aisecCrypto.Hasher
	Random  aisecCrypto.Random
}

// SetJudges строит оценщиков политик приложений с разделом judge.
// Вызывается до начала обслуживания запросов. Без вызова правила judge.llm
// дают «не проверено» (unavailable).
func (rt *Router) SetJudges(j Judges) error {
	for _, a := range rt.apps {
		cfg := a.Policy.Judge()
		if cfg == nil {
			continue
		}
		e, err := judge.NewEngine(judge.Config{Provider: cfg.Provider, Model: cfg.Model, Client: j.Clients[cfg.Provider],
			Hasher: j.Hasher, Random: j.Random, Shared: j.Shared, BudgetKey: a.Policy.ID,
			Limits: judge.Limits{CallsPerMinute: cfg.CallsPerMinute, TokensPerHour: cfg.TokensPerHour}})
		if err != nil {
			return fmt.Errorf("приложение %s: %w", a.ID, err)
		}
		a.judge, a.judgeShared = e, j.Shared
		a.judgeProvider, a.judgeModel = cfg.Provider, cfg.Model
	}
	return nil
}

// judgeTask — асинхронная оценка: текст и правила направления.
type judgeTask struct {
	dir   detect.Direction
	text  string
	rules []policy.JudgeRule
}

// judgeRules — правила judge.llm направления: sync или async.
func (a *App) judgeRules(dir detect.Direction, sync bool) []policy.JudgeRule {
	return slices.DeleteFunc(a.Policy.JudgeRules(dir), func(r policy.JudgeRule) bool { return r.Sync != sync })
}

// judgeCriteria — критерии оценщика по правилам.
func judgeCriteria(rules []policy.JudgeRule) []judge.Criterion {
	out := make([]judge.Criterion, len(rules))
	for i, r := range rules {
		out[i] = judge.Criterion{Rule: r.ID, Kind: r.Kind, Text: r.Criterion}
	}
	return out
}

// judgeInputText — текст входа для оценщика: текстовые части последнего
// сообщения user (новый ход диалога; история уже оценивалась), через
// перевод строки.
func judgeInputText(req *chat.Request) string {
	last := -1
	for i, m := range req.Messages {
		if m.Role == "user" {
			last = i
		}
	}
	if last < 0 {
		return ""
	}
	var parts []string
	for _, s := range req.Segments() {
		if s.Message == last && s.Kind == chat.SegContent {
			parts = append(parts, s.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// judgeOutputText — текст ответа для оценщика: content вариантов ответа.
func judgeOutputText(texts []inspectText) string {
	var parts []string
	for _, t := range texts {
		if t.Location == locContent {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// injectionGuard — проверка текста детекторами инъекций приложения до
// отправки оценщику (ADR-0030, раздел 4): injection.heuristic и, если
// подключён aisec-ml, injection.ml. Для оценщика любой текст — вход,
// поэтому и ответ модели проверяется как вход. Сбой ML-детектора не мешает
// (эвристика проверила текст), сбой эвристики — «не проверено» (error).
func (a *App) injectionGuard(timeout time.Duration) judge.Guard {
	if timeout <= 0 {
		timeout = DefaultDetectorTimeout
	}
	return func(ctx context.Context, text string, _ detect.Direction) (bool, error) {
		var ids []string
		if _, ok := a.Detectors.Get(injection.ID); ok {
			ids = append(ids, injection.ID)
		}
		if mlBacked(a.Detectors, builtin.InjectionMLID) {
			ids = append(ids, builtin.InjectionMLID)
		}
		if len(ids) == 0 {
			return false, nil
		}
		fs, rerrs, err := a.Detectors.Run(ctx, ids, detect.Text{Text: text, Direction: detect.Input, Source: detect.SourceUser},
			detectorTimeout(timeout, len(text)))
		if err != nil {
			return false, err
		}
		for _, re := range rerrs {
			if !mlBacked(a.Detectors, re.Detector) {
				return false, re.Err
			}
		}
		return slices.ContainsFunc(fs, func(f detect.Finding) bool { return f.Score >= judge.InjectionThreshold }), nil
	}
}

// evaluateJudge — одна оценка правил rules; без оценщика — «не проверено»
// (unavailable).
func (h *ChatHandler) evaluateJudge(ctx context.Context, a *App, t judgeTask, sync bool, timeout time.Duration) judge.Outcome {
	if a.judge == nil {
		return judge.Outcome{Reason: judge.ReasonUnavailable}
	}
	return a.judge.Evaluate(ctx, judge.Request{Direction: t.dir, Text: t.text, Criteria: judgeCriteria(t.rules), Sync: sync,
		Timeout: timeout, Guard: a.injectionGuard(h.cfg.DetectorTimeout)})
}

// judgeSync — синхронная оценка направления до решения. Находки — для
// Extra проверки; failed — оценка не получена; block — среди правил есть
// on_failure: block.
func (h *ChatHandler) judgeSync(ctx context.Context, rec *record, dir detect.Direction, text string) (extra []locatedFinding, failed, block bool) {
	a := rec.app
	rules := a.judgeRules(dir, true)
	if len(rules) == 0 {
		return nil, false, false
	}
	timeout := time.Duration(0)
	for _, r := range rules {
		timeout = max(timeout, r.Timeout)
		block = block || r.BlockOnFailure
	}
	start := h.cfg.Now()
	o := h.evaluateJudge(ctx, a, judgeTask{dir: dir, text: text, rules: rules}, true, timeout)
	rec.ev.LatencyMS["judge_"+string(dir)] = h.cfg.Now().Sub(start).Milliseconds()
	h.judgeDone(rec, dir, events.JudgeModeSync, len(rules), o)
	if !o.Checked {
		return nil, true, block
	}
	loc, src := judgePlace(dir)
	fs := o.Findings(judgeCriteria(rules))
	keep, _ := a.judgeKept(dir, rec.ev.User, fs)
	for i, f := range fs {
		if _, ok := keep[i]; ok {
			extra = append(extra, locatedFinding{Finding: f, Text: -1, Location: loc, Src: src})
		}
	}
	return extra, false, false
}

// judgePlace — место и источник находок оценщика.
func judgePlace(dir detect.Direction) (string, detect.Source) {
	if dir == detect.Output {
		return judgeOutputLocation, detect.SourceOutput
	}
	return judgeInputLocation, detect.SourceUser
}

// judgeFailBlock — отказ синхронной оценки с on_failure: block: в enforce
// запрос или ответ блокируется как при fail_closed (сбой judge.llm в
// failures); в monitor только журналируется. fail_mode приложения на
// judge.llm не действует (ADR-0030, раздел 3).
func judgeFailBlock(in *inspection, dir detect.Direction, failed, block bool) {
	if !failed || !block || in.Decision.Mode != policy.Enforce {
		return
	}
	loc, _ := judgePlace(dir)
	in.Failures = append(in.Failures, events.DetectorFailure{Detector: judge.ID, Location: loc, Reason: events.FailureError})
	in.FailBlock = true
}

// judgeDone — запись об оценке в событие и расход оценщика в учёт
// расхода приложения (по ценам модели оценщика, задача 3.18).
func (h *ChatHandler) judgeDone(rec *record, dir detect.Direction, mode string, rules int, o judge.Outcome) {
	if len(rec.judge) < events.MaxJudge {
		jc := events.JudgeCheck{Direction: string(dir), Mode: mode, Checked: o.Checked, Cached: o.Cached, Rules: rules,
			LatencyMS: o.Latency.Milliseconds(), Tokens: o.Prompt + o.Completion}
		if !o.Checked {
			jc.Reason = string(o.Reason)
		}
		rec.judge = append(rec.judge, jc)
	}
	if !o.Checked {
		h.logger.Warn("оценка judge.llm не получена", "app", rec.app.ID, "event_id", rec.ev.ID,
			"policy", rec.app.Policy.ID, "direction", string(dir), "mode", mode, "reason", string(o.Reason),
			"latency_ms", o.Latency.Milliseconds())
	}
	if h.cfg.Budget != nil && o.Prompt+o.Completion > 0 {
		h.cfg.Budget.Record(rec.app.ID, rec.app.judgeProvider, rec.app.judgeModel, int64(o.Prompt), int64(o.Completion))
	}
}

// judgeAsyncTasks — асинхронные оценки запроса: вход (задан при проверке
// входа) и ответ. Правила ответа sync для потокового ответа incremental и
// monitor оцениваются асинхронно: ответ уже передаётся частями. Ответ,
// который приложение не получило (заблокирован целиком), не оценивается.
func (rec *record) judgeAsyncTasks() []judgeTask {
	tasks := slices.Clone(rec.judgeAsync)
	if rec.resp == nil || rec.respTexts == nil {
		return tasks
	}
	streamed := rec.respMode == events.ResponseIncremental || rec.respMode == events.ResponseMonitor
	if !streamed && rec.resp.Blocked() {
		return tasks
	}
	rules := rec.app.judgeRules(detect.Output, false)
	if streamed {
		rules = rec.app.Policy.JudgeRules(detect.Output)
	}
	if len(rules) > 0 {
		tasks = append(tasks, judgeTask{dir: detect.Output, text: judgeOutputText(rec.respTexts), rules: rules})
	}
	return tasks
}

// finishJudge выполняет асинхронные оценки после ответа приложению:
// находки и категории угроз попадают в событие, решение по запросу уже
// принято и не меняется. Место в очереди оценщика — не дольше срока
// оценки; очередь заполнена — «не проверено» (overloaded).
func (h *ChatHandler) finishJudge(rec *record, tasks []judgeTask) {
	a := rec.app
	for _, t := range tasks {
		o := judge.Outcome{Reason: judge.ReasonUnavailable}
		if a.judge != nil {
			o = h.evaluateAsync(a, t)
		}
		h.judgeDone(rec, t.dir, events.JudgeModeAsync, len(t.rules), o)
		if o.Checked {
			rec.addJudgeFindings(t.dir, o.Findings(judgeCriteria(t.rules)))
		}
	}
	rec.judgeFinish()
}

func (h *ChatHandler) evaluateAsync(a *App, t judgeTask) judge.Outcome {
	ctx, cancel := context.WithTimeout(context.Background(), judge.AsyncTimeout)
	defer cancel()
	release, ok := a.judgeShared.AcquireAsync(ctx)
	if !ok {
		return judge.Outcome{Reason: judge.ReasonOverloaded}
	}
	defer release()
	return h.evaluateJudge(context.Background(), a, t, false, 0)
}

// addJudgeFindings — находки асинхронной оценки в событие. Порог правила
// и исключения применяет политика (в monitor: решение уже принято):
// находка ниже порога в событие не попадает, под исключением — с его ID.
func (rec *record) addJudgeFindings(dir detect.Direction, fs []detect.Finding) {
	if len(fs) == 0 {
		return
	}
	loc, src := judgePlace(dir)
	keep, threats := rec.app.judgeKept(dir, rec.ev.User, fs)
	for i, f := range fs {
		exc, ok := keep[i]
		if !ok || len(rec.ev.Findings) >= maxEventFindings {
			continue
		}
		rec.ev.Findings = append(rec.ev.Findings, events.Finding{Detector: f.Detector, Version: f.Version, Category: f.Category,
			Score: f.Score, Location: loc, Threat: f.Threat, Rule: f.Rule, Exception: exc, Source: string(src)})
	}
	rec.addThreats(threats)
}

// judgeKept — находки оценщика, которые совпали с правилом политики (порог
// правила) или пропущены по исключению (номер → ID исключения, пусто —
// совпала), и категории угроз совпавших. Решение — в monitor: оно нужно
// только для отбора, применяет решение проверка запроса или ответа.
func (a *App) judgeKept(dir detect.Direction, user string, fs []detect.Finding) (map[int]string, map[string]bool) {
	_, src := judgePlace(dir)
	hits := make([]policy.Hit, len(fs))
	for i, f := range fs {
		hits[i] = policy.Hit{Finding: f, Source: src}
	}
	d := a.Policy.Evaluate(policy.Request{Endpoint: policy.EndpointChat, Direction: dir, Mode: policy.Monitor,
		External: a.Provider.External(), Hits: hits, App: a.ID, User: user, Now: a.now()})
	keep := map[int]string{}
	threats := map[string]bool{}
	for _, m := range d.Matches {
		keep[m.Hit] = ""
		threats[fs[m.Hit].Threat] = true
	}
	for _, x := range d.Excepted {
		keep[x.Hit] = x.Exception
	}
	return keep, threats
}

// judgeFinish переносит записи об оценках в событие и ставит признак
// judge_unchecked.
func (rec *record) judgeFinish() {
	if len(rec.judge) == 0 {
		return
	}
	rec.ev.Judge = rec.judge
	if d := rec.ev.Decision; d != nil {
		d.JudgeUnchecked = slices.ContainsFunc(rec.judge, func(j events.JudgeCheck) bool { return !j.Checked })
	}
}
