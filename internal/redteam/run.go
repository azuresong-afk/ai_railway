package redteam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// Заголовки ответа шлюза (internal/gateway, chat.go).
const (
	headerEventID  = "X-AISec-Event-Id"
	headerDecision = "X-AISec-Decision"
	decisionBlock  = "block"
	userAgent      = "aisec-redteam"
)

// message — реплика диалога в формате OpenAI.
type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// execution — идущий запуск.
type execution struct {
	s         *Service
	run       Run
	target    Target
	scenarios []Scenario
	key       string
	authValue string
	cancel    context.CancelFunc

	client *http.Client
	ev     *evaluator
	limit  *limiter

	mu          sync.Mutex
	cancelledBy *By
}

func (x *execution) cancelBy(by By) {
	x.mu.Lock()
	if x.cancelledBy == nil {
		x.cancelledBy = &by
	}
	x.mu.Unlock()
	x.cancel()
}

func (x *execution) canceller() *By {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.cancelledBy
}

// limiter — не чаще одного запроса за interval (частота цели).
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	at := l.next
	if at.Before(now) {
		at = now
	}
	l.next = at.Add(l.interval)
	l.mu.Unlock()
	d := time.Until(at)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (x *execution) logger() *slog.Logger {
	return x.s.o.Logger.With("component", "redteam", "run", x.run.ID, "target", x.target.ID)
}

// execute выполняет запуск и записывает итог. Технический журнал — только
// ID, число сценариев, итоги и коды ошибок.
func (x *execution) execute(ctx context.Context) {
	defer x.s.release(x)
	status, reason := RunDone, ""
	counts := Counts{}
	results, err := x.prepare(ctx)
	if err == nil {
		results, err = x.runAll(ctx)
	}
	switch {
	case x.canceller() != nil:
		status = RunCancelled
	case errors.Is(err, errKeyNotDelivered):
		status, reason = RunFailed, ReasonKeyNotDelivered
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		status, reason = RunFailed, ReasonDeadline
	case ctx.Err() != nil:
		status, reason = RunFailed, ReasonInterrupted
	case err != nil:
		status, reason = RunFailed, ReasonInternal
		x.logger().Error("тестирование устойчивости: запуск не выполнен", "error", err)
	}
	// Сценарии без итога — skipped.
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	for _, sc := range x.scenarios {
		if _, done := results[sc.ID]; done {
			continue
		}
		res := Result{RunID: x.run.ID, ScenarioID: sc.ID, Lang: sc.Lang, Threat: sc.Threat, Category: sc.Category, Verdict: VerdictSkipped}
		if err := x.s.o.Store.SaveResult(dbCtx, x.run.OrgID, res); err != nil {
			x.logger().Error("тестирование устойчивости: итог сценария не записан", "scenario", sc.ID, "error", err)
		}
		results[sc.ID] = VerdictSkipped
	}
	for _, v := range results {
		counts[v]++
	}
	now := x.s.o.Clock().UTC()
	r := x.run
	r.Status, r.Reason, r.Counts, r.FinishedAt = status, reason, counts, &now
	details := map[string]any{"status": status, "counts": counts, "scenarios": len(x.scenarios)}
	if reason != "" {
		details["reason"] = reason
	}
	rec := systemEntry(ActionRunFinished, r, details)
	if by := x.canceller(); by != nil {
		rec = by.entry(ActionRunCancelled, objectRun, r.ID, details)
	}
	if err := x.s.o.Store.FinishRun(dbCtx, r, rec); err != nil {
		x.logger().Error("тестирование устойчивости: итог запуска не записан", "error", err)
		return
	}
	x.logger().Info("тестирование устойчивости: запуск завершён", "status", status, "reason", reason,
		"succeeded", counts[VerdictSucceeded], "scenarios", len(x.scenarios))
}

var errKeyNotDelivered = errors.New("ключ запуска не дошёл до шлюза")

// prepare — клиент, оценщик, частота; у цели gateway — ожидание ключа на
// шлюзе.
func (x *execution) prepare(ctx context.Context) (map[string]string, error) {
	t := x.target
	timeout := time.Duration(t.Limits.RequestTimeoutSec) * time.Second
	var err error
	switch t.Kind {
	case KindGateway:
		x.client, err = newClient(x.s.tp, x.s.o.GatewayCA, timeout, false, nil, nil)
	default:
		x.client, err = newClient(x.s.tp, []byte(t.CAPEM), timeout, true, x.s.o.Lookup, x.s.connect)
	}
	if err != nil {
		return map[string]string{}, err
	}
	var jc judge.Client
	if t.JudgeProvider != "" && x.s.o.Judges != nil {
		if jc, err = x.s.o.Judges(ctx, t.JudgeProvider); err != nil {
			x.logger().Warn("тестирование устойчивости: оценщик judge.llm недоступен", "provider", t.JudgeProvider, "error", err)
			jc = nil
		}
	}
	if x.ev, err = newEvaluator(jc, t.JudgeProvider, t.JudgeModel, x.s.o.Provider); err != nil {
		return map[string]string{}, err
	}
	x.limit = &limiter{interval: time.Minute / time.Duration(t.Limits.RatePerMinute)}
	if t.Kind == KindGateway {
		if err := x.waitKey(ctx); err != nil {
			return map[string]string{}, err
		}
	}
	return map[string]string{}, nil
}

// waitKey ждёт, пока шлюз примет ключ запуска: GET /v1/models до 200, не
// дольше KeyWait.
func (x *execution) waitKey(runCtx context.Context) error {
	ctx, cancel := context.WithTimeout(runCtx, x.s.o.KeyWait)
	defer cancel()
	u := x.s.gateway.JoinPath("v1", "models").String()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+x.key)
		req.Header.Set("User-Agent", userAgent)
		if resp, err := x.client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponse)) //nolint:gosec // G104: тело не нужно
			_ = resp.Body.Close()                                              //nolint:gosec // G104: тело прочитано
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		t := time.NewTimer(x.s.o.KeyPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			if runCtx.Err() != nil {
				return runCtx.Err()
			}
			return errKeyNotDelivered
		case <-t.C:
		}
	}
}

// runAll выполняет сценарии в Concurrency горутинах.
func (x *execution) runAll(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	var mu sync.Mutex
	work := make(chan Scenario)
	var wg sync.WaitGroup
	var saveErr error
	for range x.target.Limits.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sc := range work {
				res, ok := x.scenario(ctx, sc)
				if !ok {
					continue
				}
				if err := x.s.o.Store.SaveResult(context.WithoutCancel(ctx), x.run.OrgID, res); err != nil {
					mu.Lock()
					saveErr = err
					mu.Unlock()
					continue
				}
				mu.Lock()
				out[sc.ID] = res.Verdict
				mu.Unlock()
			}
		}()
	}
	for _, sc := range x.scenarios {
		if ctx.Err() != nil {
			break
		}
		select {
		case work <- sc:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()
	return out, saveErr
}

// stepReply — ответ цели на шаг.
type stepReply struct {
	text    string
	status  int
	eventID string
	blocked bool
	errCode string
}

// scenario выполняет шаги сценария. ok=false — запуск прерван до итога
// (сценарий станет skipped).
func (x *execution) scenario(ctx context.Context, sc Scenario) (Result, bool) {
	res := Result{RunID: x.run.ID, ScenarioID: sc.ID, Lang: sc.Lang, Threat: sc.Threat, Category: sc.Category}
	start := time.Now()
	var history []message
	var findings []detect.Finding
	judgeOnly := !sc.Success.Canary && len(sc.Success.Contains) == 0 && len(sc.Success.Findings) == 0
	unchecked := false
	for i, st := range sc.Steps {
		if err := x.limit.wait(ctx); err != nil {
			return Result{}, false
		}
		history = append(history, message{Role: "user", Content: st.Prompt})
		rep := x.send(ctx, history)
		if ctx.Err() != nil && rep.errCode != "" {
			return Result{}, false
		}
		res.Step, res.HTTPStatus = i+1, rep.status
		if rep.eventID != "" {
			res.EventIDs = append(res.EventIDs, rep.eventID)
		}
		if rep.blocked {
			res.Verdict = VerdictBlocked
			break
		}
		if rep.errCode != "" {
			res.Verdict, res.ErrorCode = VerdictError, rep.errCode
			break
		}
		e := x.ev.evaluate(ctx, rep.text, sc.Success)
		findings = append(findings, e.findings...)
		if e.judge != "" {
			res.Judge = e.judge
			if e.judge != JudgeOK && e.judge != JudgeViolated {
				unchecked = true
			}
		}
		if e.succeeded() {
			res.Verdict, res.Matched = VerdictSucceeded, e.matched
			if x.target.Kind == KindEndpoint && x.target.Storage == StorageMasked {
				res.Example = x.sealExample(ctx, sc.ID, maskedExample(rep.text, e.findings))
			}
			break
		}
		history = append(history, message{Role: "assistant", Content: rep.text})
	}
	if res.Verdict == "" {
		res.Verdict = VerdictDefended
		if judgeOnly && unchecked {
			res.Verdict = VerdictUnchecked
		}
	}
	res.Findings = findingsOf(findings)
	res.LatencyMS = time.Since(start).Milliseconds()
	return res, true
}

// send отправляет шаг цели и читает ответ с пределом.
func (x *execution) send(ctx context.Context, history []message) stepReply {
	var (
		u    string
		body []byte
		err  error
	)
	t := x.target
	if t.Kind == KindGateway {
		u = x.s.gateway.JoinPath("v1", "chat", "completions").String()
		body, err = json.Marshal(map[string]any{"model": t.Model, "messages": history, "stream": false})
	} else {
		u = t.URL
		body, err = renderTemplate(t.RequestTemplate, history[len(history)-1].Content, history)
	}
	if err != nil || len(body) > MaxRequestBody {
		return stepReply{errCode: ErrCodeRequest}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return stepReply{errCode: ErrCodeRequest}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if t.Kind == KindGateway {
		req.Header.Set("Authorization", "Bearer "+x.key)
	} else {
		for _, h := range t.Headers {
			req.Header.Set(h.Name, h.Value)
		}
		if t.AuthHeader != "" {
			req.Header.Set(t.AuthHeader, x.authValue)
		}
	}
	resp, err := x.client.Do(req)
	if err != nil {
		return stepReply{errCode: netErrCode(ctx, err)}
	}
	defer func() { _ = resp.Body.Close() }() //nolint:gosec // G104: тело прочитано
	rep := stepReply{status: resp.StatusCode}
	if t.Kind == KindGateway {
		if id := resp.Header.Get(headerEventID); uuidRe.MatchString(id) {
			rep.eventID = id
		}
		if resp.Header.Get(headerDecision) == decisionBlock {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponse)) //nolint:gosec // G104: тело не нужно
			rep.blocked = true
			return rep
		}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	switch {
	case err != nil:
		rep.errCode = netErrCode(ctx, err)
		return rep
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		rep.errCode = ErrCodeRedirect
		return rep
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		rep.errCode = ErrCodeHTTP
		return rep
	case len(data) > MaxResponse:
		rep.errCode = ErrCodeTooLarge
		return rep
	}
	path := t.ResponsePath
	if t.Kind == KindGateway {
		path = "choices.0.message.content"
	}
	text, ok := extractPath(data, path)
	if !ok {
		rep.errCode = ErrCodeBadResponse
		return rep
	}
	rep.text = text
	return rep
}

// netErrCode — код ошибки соединения без текста ошибки (в нём может быть
// адрес).
func netErrCode(ctx context.Context, err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, errBlockedAddr):
		return ErrCodeBlockedAddr
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || errors.As(err, &ne) && ne.Timeout():
		return ErrCodeTimeout
	default:
		return ErrCodeDial
	}
}

// newJudgeClient — адаптер провайдера-оценщика: OpenAI-совместимый, внутри
// контура, транспорт только к частной сети (providers.NewPrivateTransport).
func newJudgeClient(p apps.Provider, key string, tp aisecCrypto.TLSProvider, logger *slog.Logger) (judge.Client, error) {
	if p.Type != config.ProviderOpenAI || p.External || !p.OnPremise {
		return nil, nil
	}
	if tp == nil {
		return nil, errors.New("TLS недоступен в криптопрофиле")
	}
	connect, header := time.Duration(p.ConnectTimeout)*time.Second, time.Duration(p.HeaderTimeout)*time.Second
	if connect == 0 {
		connect = config.DefaultConnectTimeout
	}
	if header == 0 {
		header = config.DefaultHeaderTimeout
	}
	var roots []byte
	if strings.TrimSpace(p.CAPEM) != "" {
		roots = []byte(p.CAPEM)
	}
	transport, err := providers.NewPrivateTransport(tp, roots, connect, header)
	if err != nil {
		return nil, err
	}
	u, err := config.ParseUpstreamURL(p.BaseURL)
	if err != nil {
		return nil, err
	}
	return providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: providers.BaseConfig{ID: p.Slug, Transport: transport, Logger: logger,
		ResponseTimeout: time.Duration(p.ResponseTimeout) * time.Second}, BaseURL: u, Key: key})
}
