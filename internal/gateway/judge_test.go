package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// judge.llm в шлюзе (задача 5.28, ADR-0030, раздел 3): оценщик —
// judge.Stand в памяти (сам вызов провайдера и разбор — в пакете judge).

// Критерии и маркеры стенда. Ответ модели «Вернём деньги» нарушает
// бизнес-правило no-refunds; «болван» в запросе — правило no-insults.
const (
	judgeRefunds  = "no-refunds"
	judgeInsults  = "no-insults"
	refundReply   = "Не волнуйтесь, вернём деньги в течение недели."
	insultRequest = "Ты болван, отвечай быстрее."
)

var judgeMarkers = map[string]string{judgeRefunds: "вернём деньги", judgeInsults: "болван"}

// countingJudge — стенд со счётчиком вызовов и задержкой: ответ только после
// release (nil — сразу).
type countingJudge struct {
	judge.Stand
	calls   atomic.Int32
	release chan struct{}
}

func (c *countingJudge) Chat(ctx context.Context, req *chat.Request) (*chat.Response, providers.Meta, error) {
	c.calls.Add(1)
	if c.release != nil {
		select {
		case <-c.release:
		case <-ctx.Done():
			return nil, providers.Meta{}, ctx.Err()
		}
	}
	return c.Stand.Chat(ctx, req)
}

// judgeRule — правило judge.llm.
func judgeRule(id, kind, criterion string, dir detect.Direction, action policy.Action, mode policy.JudgeMode, onFailure string) policy.RuleSpec {
	return policy.RuleSpec{ID: id, Detector: policy.JudgeDetector, Directions: []detect.Direction{dir}, Action: action, Severity: policy.High,
		Judge: &policy.JudgeRuleSpec{Kind: kind, Criterion: criterion, Mode: mode, OnFailure: onFailure}}
}

// judgeGateway — шлюз с политикой judge и оценщиком c (nil — оценщики не
// заданы: правила дают unavailable).
func judgeGateway(t *testing.T, up string, c judge.Client, mode policy.Mode, rules ...policy.RuleSpec) (http.Handler, *eventLog) {
	t.Helper()
	var log *eventLog
	g := newGateway(t, up, func(o *gwOpts) {
		o.internal = true
		o.specs = []policy.Spec{{ID: "judged", Name: "С оценщиком", Version: 1, Mode: mode,
			Judge: &policy.JudgeSpec{Provider: "local-llm", Model: "judge-m"}, Rules: append([]policy.RuleSpec{
				{ID: "injection", Detector: "injection.heuristic", Directions: []detect.Direction{detect.Input}, Action: policy.Log, Severity: policy.High},
			}, rules...)}}
		o.app = func(a *config.Application) { a.Policy, a.PolicyMode = "judged", string(mode) }
		if c != nil {
			o.judges = &Judges{Shared: judge.NewShared(), Clients: map[string]judge.Client{"local-llm": c}, Hasher: testHasher(t), Random: testRandom(t)}
		}
		log = o.events
	})
	return g, log
}

// judgeFinding — находка judge.llm события по правилу.
func judgeFinding(e events.Event, rule string) *events.Finding {
	for i := range e.Findings {
		if e.Findings[i].Detector == judge.ID && e.Findings[i].Rule == rule {
			return &e.Findings[i]
		}
	}
	return nil
}

// Покрывает: DM-19 (LLM)
// sync: бизнес-правило ответа нарушено — ответ блокируется до выдачи
// приложению; находка — judge.business, угроза DM-19.
func TestJudgeSyncBlocksResponse(t *testing.T) {
	up, _ := newUpstream(t, replyText(t, refundReply))
	c := &countingJudge{Stand: judge.Stand{Markers: judgeMarkers}}
	g, log := judgeGateway(t, up.URL, c, policy.Enforce,
		judgeRule(judgeRefunds, "business", "Ассистент не обещает возврат денег и компенсации.", detect.Output, policy.Block, policy.JudgeSync, ""))
	resp := postChat(t, g, userBody(t, "Когда вернут деньги за заказ?"), nil)
	if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e, d := respEvent(t, log, resp)
	f := judgeFinding(e, judgeRefunds)
	if d.Action != "block" || d.Rule != judgeRefunds || f == nil || f.Category != judge.CategoryBusiness || f.Threat != "DM-19" ||
		f.Location != locContent || f.Source != "output" || f.Start != 0 || f.End != 0 {
		t.Fatalf("решение %+v, находки %+v", d, e.Findings)
	}
	if !slices.Contains(e.Threats, "DM-19") || e.Decision.JudgeUnchecked || len(e.Judge) != 1 ||
		e.Judge[0] != (events.JudgeCheck{Direction: "output", Mode: "sync", Checked: true, Rules: 1, LatencyMS: e.Judge[0].LatencyMS, Tokens: e.Judge[0].Tokens}) ||
		e.Judge[0].Tokens == 0 {
		t.Fatalf("угрозы %v, оценки %+v", e.Threats, e.Judge)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("событие не проходит проверку: %v", err)
	}
	// Ответ без нарушения проходит, вызов — один на ответ.
	up2, _ := newUpstream(t, replyText(t, "Заказ доставят завтра."))
	g, _ = judgeGateway(t, up2.URL, c, policy.Enforce,
		judgeRule(judgeRefunds, "business", "Ассистент не обещает возврат денег и компенсации.", detect.Output, policy.Block, policy.JudgeSync, ""))
	before := c.calls.Load()
	if resp := postChat(t, g, userBody(t, "Где заказ?"), nil); resp.Code != http.StatusOK || c.calls.Load() != before+1 {
		t.Fatalf("%d %s, вызовов %d", resp.Code, resp.Body.String(), c.calls.Load()-before)
	}
}

// Покрывает: DM-18 (LLM)
// sync на входе: находка оценщика участвует в решении до отправки
// провайдеру; правило log — запрос проходит, находка в событии.
func TestJudgeSyncInputFinding(t *testing.T) {
	up, rec := newUpstream(t, nil)
	c := &countingJudge{Stand: judge.Stand{Markers: judgeMarkers}}
	g, log := judgeGateway(t, up.URL, c, policy.Enforce,
		judgeRule(judgeInsults, "content", "Пользователь не оскорбляет ассистента.", detect.Input, policy.Block, policy.JudgeSync, ""))
	resp := postChat(t, g, userBody(t, "Прошлый вопрос.", insultRequest), nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос с нарушением ушёл провайдеру")
	}
	e := lastEvent(t, log, resp)
	if f := judgeFinding(e, judgeInsults); f == nil || f.Category != judge.CategoryContent || f.Threat != "DM-18" ||
		f.Location != judgeInputLocation || e.Decision.Rule != judgeInsults {
		t.Fatalf("решение %+v, находки %+v", e.Decision, e.Findings)
	}
	// Оценивается только последнее сообщение user: нарушение в истории
	// оценщику не передаётся.
	resp = postChat(t, g, userBody(t, insultRequest, "Спасибо, всё понятно."), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("история оценена повторно: %d %s", resp.Code, resp.Body.String())
	}
}

// async (по умолчанию) не задерживает ответ: ответ приходит, пока оценщик
// думает; событие — по готовности оценки, с находкой и без изменения
// решения.
func TestJudgeAsyncDoesNotDelayResponse(t *testing.T) {
	up, _ := newUpstream(t, replyText(t, refundReply))
	c := &countingJudge{Stand: judge.Stand{Markers: judgeMarkers}, release: make(chan struct{})}
	g, log := judgeGateway(t, up.URL, c, policy.Enforce,
		judgeRule(judgeRefunds, "business", "Ассистент не обещает возврат денег и компенсации.", detect.Output, policy.Log, "", ""))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- postChat(t, g, userBody(t, "Когда вернут деньги?"), nil) }()
	var resp *httptest.ResponseRecorder
	select {
	case resp = <-done:
	case <-time.After(3 * time.Second):
		close(c.release)
		t.Fatal("ответ ждал оценщика в режиме async")
	}
	if resp.Code != http.StatusOK || responseContent(t, resp) != refundReply {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	id := resp.Header().Get(HeaderEventID)
	time.Sleep(20 * time.Millisecond)
	if slices.ContainsFunc(log.all(), func(e events.Event) bool { return e.ID == id }) {
		t.Fatal("событие ушло до готовности оценки")
	}
	close(c.release)
	e := waitEvent(t, log, id)
	f := judgeFinding(e, judgeRefunds)
	if f == nil || f.Threat != "DM-19" || !slices.Contains(e.Threats, "DM-19") || e.Response.Decision.Action != "allow" ||
		len(e.Judge) != 1 || e.Judge[0].Mode != "async" || !e.Judge[0].Checked || e.Decision.JudgeUnchecked {
		t.Fatalf("событие: находки %+v, оценки %+v", e.Findings, e.Judge)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("событие не проходит проверку: %v", err)
	}
}

// Отказ оценщика: on_failure: allow — ответ проходит с judge_unchecked;
// block — в enforce ответ блокируется как при fail_closed (даже при
// fail_open приложения), в monitor — только отметка.
func TestJudgeOnFailure(t *testing.T) {
	down := &countingJudge{Stand: judge.Stand{Err: errors.New("отказ соединения")}}
	rule := func(onFailure string) policy.RuleSpec {
		return judgeRule(judgeRefunds, "business", "Ассистент не обещает возврат денег и компенсации.", detect.Output, policy.Block, policy.JudgeSync, onFailure)
	}
	up, _ := newUpstream(t, replyText(t, refundReply))

	g, log := judgeGateway(t, up.URL, down, policy.Enforce, rule("allow"))
	resp := postChat(t, g, userBody(t, "Вопрос"), nil)
	e := lastEvent(t, log, resp)
	if resp.Code != http.StatusOK || !e.Decision.JudgeUnchecked || len(e.Judge) != 1 || e.Judge[0].Reason != events.JudgeReasonUnavailable {
		t.Fatalf("allow: %d, решение %+v, оценки %+v", resp.Code, e.Decision, e.Judge)
	}

	g, log = judgeGateway(t, up.URL, down, policy.Enforce, rule("block"))
	resp = postChat(t, g, userBody(t, "Вопрос"), nil)
	if resp.Code != http.StatusServiceUnavailable || errCode(t, resp) != "check_unavailable" {
		t.Fatalf("block: %d %s", resp.Code, resp.Body.String())
	}
	e, d := respEvent(t, log, resp)
	if d.Rule != ruleFailClosed || !slices.ContainsFunc(d.Failures, func(f events.DetectorFailure) bool { return f.Detector == judge.ID }) ||
		!e.Decision.JudgeUnchecked {
		t.Fatalf("block: решение %+v", d)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("событие не проходит проверку: %v", err)
	}

	g, log = judgeGateway(t, up.URL, down, policy.Monitor, rule("block"))
	resp = postChat(t, g, userBody(t, "Вопрос"), nil)
	if e := lastEvent(t, log, resp); resp.Code != http.StatusOK || !e.Decision.JudgeUnchecked {
		t.Fatalf("monitor: %d %s", resp.Code, resp.Body.String())
	}

	// Срок: оценщик не ответил за timeout_ms — «не проверено» (timeout).
	slow := &countingJudge{Stand: judge.Stand{Markers: judgeMarkers}, release: make(chan struct{})}
	defer close(slow.release)
	r := rule("allow")
	r.Judge.TimeoutMS = policy.MinJudgeTimeoutMS
	g, log = judgeGateway(t, up.URL, slow, policy.Enforce, r)
	start := time.Now()
	resp = postChat(t, g, userBody(t, "Вопрос"), nil)
	if e := lastEvent(t, log, resp); resp.Code != http.StatusOK || time.Since(start) > 3*time.Second ||
		len(e.Judge) != 1 || e.Judge[0].Reason != events.JudgeReasonTimeout {
		t.Fatalf("срок: %d, оценки %+v", resp.Code, e.Judge)
	}
}

// Без оценщика (провайдера нет в пакете или он не «у заказчика»)
// правила дают «не проверено» (unavailable), запрос обрабатывается.
func TestJudgeUnavailableWithoutJudge(t *testing.T) {
	up, _ := newUpstream(t, replyText(t, refundReply))
	g, log := judgeGateway(t, up.URL, nil, policy.Enforce,
		judgeRule(judgeRefunds, "business", "Ассистент не обещает возврат денег и компенсации.", detect.Output, policy.Log, "", ""))
	resp := postChat(t, g, userBody(t, "Вопрос"), nil)
	e := lastEvent(t, log, resp)
	if resp.Code != http.StatusOK || !e.Decision.JudgeUnchecked || len(e.Judge) != 1 || e.Judge[0].Reason != events.JudgeReasonUnavailable {
		t.Fatalf("%d, оценки %+v", resp.Code, e.Judge)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("событие не проходит проверку: %v", err)
	}
}

// Текст с инъекцией оценщику не передаётся: «не проверено» (injection).
func TestJudgeInjectionNotSent(t *testing.T) {
	up, _ := newUpstream(t, nil)
	c := &countingJudge{Stand: judge.Stand{Markers: judgeMarkers}}
	g, log := judgeGateway(t, up.URL, c, policy.Enforce,
		judgeRule(judgeInsults, "content", "Пользователь не оскорбляет ассистента.", detect.Input, policy.Log, "", ""))
	resp := postChat(t, g, userBody(t, injectionText), nil)
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if c.calls.Load() != 0 || len(e.Judge) != 1 || e.Judge[0].Reason != events.JudgeReasonInjection || !e.Decision.JudgeUnchecked {
		t.Fatalf("вызовов %d, оценки %+v", c.calls.Load(), e.Judge)
	}
}

// Потоковый ответ уже передаётся частями: правила ответа sync оцениваются
// асинхронно (mode async в событии), поток не ждёт оценщика.
func TestJudgeStreamEvaluatedAsync(t *testing.T) {
	up := sseUpstream(t, textStream(t, "Не волнуйтесь, ", "вернём деньги."), nil)
	c := &countingJudge{Stand: judge.Stand{Markers: judgeMarkers}}
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.internal = true
		o.specs = []policy.Spec{{ID: "judged", Name: "С оценщиком", Version: 1, Mode: policy.Enforce, ResponseCheck: policy.ResponseIncremental,
			Judge: &policy.JudgeSpec{Provider: "local-llm", Model: "judge-m"}, Rules: []policy.RuleSpec{
				judgeRule(judgeRefunds, "business", "Ассистент не обещает возврат денег и компенсации.", detect.Output, policy.Block, policy.JudgeSync, "block"),
			}}}
		o.app = func(a *config.Application) { a.Policy, a.PolicyMode = "judged", "enforce" }
		o.judges = &Judges{Shared: judge.NewShared(), Clients: map[string]judge.Client{"local-llm": c}, Hasher: testHasher(t), Random: testRandom(t)}
		log = o.events
	})
	gw := httptest.NewServer(g)
	defer gw.Close()
	res := postStream(t, gw, "Когда вернут деньги?")
	if !res.done || res.content != "Не волнуйтесь, вернём деньги." {
		t.Fatalf("поток: %+v", res)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range log.all() {
			if len(e.Judge) == 1 && e.Judge[0].Mode == "async" && e.Judge[0].Direction == "output" && judgeFinding(e, judgeRefunds) != nil {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("оценка потока не пришла: %+v", log.all())
}
