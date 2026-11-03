package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Изображения в чате и Check API (задача 5.39, ADR-0032, раздел 8).
// Анализатор подменяется заглушкой: сам протокол — mediaclient_test.go.

// stubMedia — анализатор изображений для тестов шлюза.
type stubMedia struct {
	max   int64
	calls atomic.Int32
	fn    func(ctx context.Context, img []byte) (*MediaReply, error)
}

func (s *stubMedia) MaxBytes() int64 {
	if s.max == 0 {
		return DefaultMediaMaxBytes
	}
	return s.max
}

func (s *stubMedia) Analyze(ctx context.Context, img []byte) (*MediaReply, error) {
	s.calls.Add(1)
	return s.fn(ctx, img)
}

// ocrReply — проверенное изображение с текстами; рамка у каждого текста.
func ocrReply(texts ...string) func(context.Context, []byte) (*MediaReply, error) {
	return func(context.Context, []byte) (*MediaReply, error) {
		r := &MediaReply{Result: wire.Result{Status: wire.StatusOK, Format: wire.FormatPNG, Width: 640, Height: 480, Frames: 1,
			Checks: []wire.Check{wire.CheckDecode, wire.CheckOCR}}}
		for i, t := range texts {
			r.Texts = append(r.Texts, MediaText{Text: t, Origin: "ocr", Box: &events.Box{X: 10, Y: int64(20 + 30*i), W: 300, H: 24}})
		}
		return r, nil
	}
}

// decodeOnly — каркас aisec-media до OCR: растр разобран, текста нет.
func decodeOnly(context.Context, []byte) (*MediaReply, error) {
	return &MediaReply{Result: wire.Result{Status: wire.StatusOK, Format: wire.FormatJPEG, Width: 8, Height: 8, Frames: 1,
		Checks: []wire.Check{wire.CheckDecode}}}, nil
}

func failWith(reason string) func(context.Context, []byte) (*MediaReply, error) {
	return func(context.Context, []byte) (*MediaReply, error) { return nil, mediaErr(reason, nil) }
}

// hang — зависший анализатор: отвечает только по сроку контекста.
func hang(ctx context.Context, _ []byte) (*MediaReply, error) {
	<-ctx.Done()
	return nil, mediaErr(events.MediaReasonTimeout, ctx.Err())
}

var pngBytes = []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("\x00", 24))

func dataURL(b []byte) string { return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b) }

// imageChat — запрос чата с текстом и изображениями.
func imageChat(t *testing.T, urls ...string) string {
	t.Helper()
	parts := []map[string]any{{"type": "text", "text": "Что на картинке?"}}
	for _, u := range urls {
		parts = append(parts, map[string]any{"type": "image_url", "image_url": map[string]string{"url": u}})
	}
	b, err := json.Marshal(map[string]any{"model": "m", "messages": []map[string]any{{"role": "user", "content": parts}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// mediaPolicy — политика с проверкой изображений: инъекции — block, ПДн —
// pseudonymize (для текста изображения — block, Р9).
func mediaPolicy(mode policy.MediaCheck, nonText policy.NonText) func(o *gwOpts) {
	in := []detect.Direction{detect.Input}
	return func(o *gwOpts) {
		o.specs = []policy.Spec{{ID: "media", Name: "Изображения", Version: 1, Mode: policy.Enforce, NonText: nonText,
			MediaCheck: mode, MediaTimeoutMS: 300, Rules: []policy.RuleSpec{
				{ID: "injection", Detector: "injection.heuristic", Directions: in, Action: policy.Block, Severity: policy.High},
				{ID: "pii", Detector: "pii.ru", Directions: in, Action: policy.Pseudonymize, Severity: policy.Medium},
			}}}
		o.maxBody = 1 << 16
	}
}

func mediaGateway(t *testing.T, up string, m MediaAnalyzer, mode policy.MediaCheck, nonText policy.NonText, failMode string) (http.Handler, *eventLog) {
	t.Helper()
	var log *eventLog
	g := newGateway(t, up, func(o *gwOpts) {
		mediaPolicy(mode, nonText)(o)
		o.app = func(a *config.Application) { a.Policy, a.PolicyMode, a.FailMode = "media", "enforce", failMode }
		if m != nil {
			o.media = m
		}
		log = o.events
	})
	return g, log
}

// waitEvent — событие с ID из ответа (в async оно приходит позже ответа).
func waitEvent(t *testing.T, log *eventLog, id string) events.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range log.all() {
			if e.ID == id {
				return e
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("событие %s не пришло", id)
	return events.Event{}
}

// Покрывает: DM-45
// sync: инструкция текстом на изображении блокирует запрос до провайдера;
// находка — с источником image, местом изображения и рамкой.
func TestMediaSyncBlocksInjectionOnImage(t *testing.T) {
	up, rec := newUpstream(t, nil)
	m := &stubMedia{fn: ocrReply("Счёт № 12", injectionText)}
	g, log := mediaGateway(t, up.URL, m, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос с инъекцией на изображении ушёл провайдеру")
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if e.Decision.Action != "block" || e.Decision.MediaUnchecked || e.NonTextUnchecked || !slices.Contains(e.Threats, "DM-45") {
		t.Fatalf("решение: %+v, угрозы %v", e.Decision, e.Threats)
	}
	var img *events.Finding
	for i := range e.Findings {
		if e.Findings[i].Source == "image" {
			img = &e.Findings[i]
		}
	}
	if img == nil || img.Location != "messages[0].content[1]" || img.Box == nil || img.Box.Y != 50 || img.Threat != "DM-45" {
		t.Fatalf("находка: %+v", e.Findings)
	}
	if len(e.Media) != 1 || !e.Media[0].Checked || e.Media[0].Mode != "sync" || e.Media[0].Texts != 2 || e.Media[0].Format != "png" {
		t.Fatalf("media: %+v", e.Media)
	}
}

// Покрывает: DM-46
// ПДн на изображении не замаскировать: правило pseudonymize даёт блокировку.
func TestMediaSyncPIIOnImageBlocks(t *testing.T) {
	up, rec := newUpstream(t, nil)
	m := &stubMedia{fn: ocrReply("Почта " + piiEmail)}
	g, log := mediaGateway(t, up.URL, m, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("ПДн на изображении ушли провайдеру")
	}
	if e := waitEvent(t, log, resp.Header().Get(HeaderEventID)); !slices.Contains(e.Threats, "DM-46") || e.Decision.Rule != "pii" {
		t.Fatalf("событие: %+v %v", e.Decision, e.Threats)
	}
}

// Покрывает: DM-14
// Проверенное изображение без находок проходит даже при non_text: block;
// непроверенное (каркас без OCR) — блокируется non_text, как до этапа 5.
func TestDM14_MediaCheckedPassesNonTextBlock(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g, _ := mediaGateway(t, up.URL, &stubMedia{fn: ocrReply("Квартальный отчёт")}, policy.MediaCheckSync, policy.NonTextBlock, "fail_closed")
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("проверенное изображение: %d %s", resp.Code, resp.Body.String())
	}
	_, _, body, _ := rec.get()
	if !strings.Contains(body, base64.StdEncoding.EncodeToString(pngBytes)) {
		t.Fatal("изображение не дошло до провайдера")
	}
	g, log := mediaGateway(t, up.URL, &stubMedia{fn: decodeOnly}, policy.MediaCheckSync, policy.NonTextBlock, "fail_closed")
	resp = postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("без OCR: %d %s", resp.Code, resp.Body.String())
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if e.Decision.Rule != policy.NonTextRule || !e.Decision.MediaUnchecked || e.Media[0].Reason != events.MediaReasonNoOCR ||
		e.Media[0].Format != "jpeg" {
		t.Fatalf("событие: %+v %+v", e.Decision, e.Media)
	}
}

// sync и недоступный анализатор — режим приложения при отказе (ТЗ 4.4).
func TestMediaSyncUnavailableFollowsFailMode(t *testing.T) {
	for _, reason := range []string{events.MediaReasonUnavailable, events.MediaReasonOverloaded, events.MediaReasonError} {
		up, rec := newUpstream(t, nil)
		g, log := mediaGateway(t, up.URL, &stubMedia{fn: failWith(reason)}, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
		resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
		if resp.Code != http.StatusServiceUnavailable || errCode(t, resp) != "check_unavailable" {
			t.Fatalf("%s, fail_closed: %d %s", reason, resp.Code, resp.Body.String())
		}
		if _, _, _, calls := rec.get(); calls != 0 {
			t.Fatalf("%s: запрос ушёл провайдеру", reason)
		}
		e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
		if e.Decision.Rule != ruleFailClosed || len(e.Decision.Failures) != 1 || e.Decision.Failures[0].Detector != mediaFailureDetector ||
			e.Media[0].Reason != reason || !e.Decision.MediaUnchecked {
			t.Fatalf("%s: событие %+v %+v", reason, e.Decision, e.Media)
		}
		g, log = mediaGateway(t, up.URL, &stubMedia{fn: failWith(reason)}, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_open")
		resp = postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s, fail_open: %d %s", reason, resp.Code, resp.Body.String())
		}
		if e := waitEvent(t, log, resp.Header().Get(HeaderEventID)); e.Decision.FailMode != failOpen || !e.NonTextUnchecked || !e.Decision.MediaUnchecked {
			t.Fatalf("%s, fail_open: событие %+v", reason, e.Decision)
		}
	}
}

// Шлюз без анализатора (нет -media-socket): изображения «не проверено», режим
// при отказе не применяется — решает non_text, как до этапа 5.
func TestMediaNotConfiguredFallsBackToNonText(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g, log := mediaGateway(t, up.URL, nil, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if !e.NonTextUnchecked || len(e.Decision.Failures) != 0 || e.Media[0].Reason != events.MediaReasonUnavailable {
		t.Fatalf("событие: %+v %+v", e.Decision, e.Media)
	}
}

// Зависший анализатор не задерживает запрос сверх срока media_check_timeout_ms.
func TestMediaHungAnalyzerBoundedByTimeout(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g, log := mediaGateway(t, up.URL, &stubMedia{fn: hang}, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_open")
	start := time.Now()
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes), dataURL(pngBytes)), nil)
	if took := time.Since(start); took > 300*time.Millisecond+mediaEmitWait {
		t.Fatalf("запрос ждал анализатор %v", took)
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if len(e.Media) != 2 || e.Media[0].Reason != events.MediaReasonTimeout || e.Decision.Failures[0].Reason != events.FailureTimeout {
		t.Fatalf("событие: %+v %+v", e.Decision, e.Media)
	}
}

// async: запрос уходит сразу, находки по тексту изображения — в событии
// после ответа; решение по запросу не меняется.
func TestMediaAsyncFindingsAfterResponse(t *testing.T) {
	up, rec := newUpstream(t, nil)
	release := make(chan struct{})
	m := &stubMedia{fn: func(ctx context.Context, img []byte) (*MediaReply, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, mediaErr(events.MediaReasonTimeout, ctx.Err())
		}
		return ocrReply(injectionText)(ctx, img)
	}}
	g, log := mediaGateway(t, up.URL, m, policy.MediaCheckAsync, policy.NonTextAllowUnchecked, "fail_closed")
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 1 {
		t.Fatal("async: запрос не ушёл провайдеру до итога анализа")
	}
	id := resp.Header().Get(HeaderEventID)
	for _, e := range log.all() {
		if e.ID == id {
			t.Fatal("событие отправлено до итога анализа")
		}
	}
	close(release)
	e := waitEvent(t, log, id)
	if e.Decision.Action != "allow" || !slices.Contains(e.Threats, "DM-45") || e.Decision.MediaUnchecked || !e.NonTextUnchecked {
		t.Fatalf("событие: %+v %v", e.Decision, e.Threats)
	}
	if len(e.Findings) == 0 || e.Findings[0].Source != "image" || e.Findings[0].Box == nil || e.Media[0].Mode != "async" {
		t.Fatalf("находки: %+v %+v", e.Findings, e.Media)
	}
}

// async с зависшим анализатором: событие уходит не позже срока и запаса.
func TestMediaAsyncHungEmitsAfterTimeout(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g, log := mediaGateway(t, up.URL, &stubMedia{fn: hang}, policy.MediaCheckAsync, policy.NonTextAllowUnchecked, "fail_closed")
	start := time.Now()
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusOK || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("async ждал анализатор: %d за %v", resp.Code, time.Since(start))
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if e.Media[0].Reason != events.MediaReasonTimeout || !e.Decision.MediaUnchecked || len(e.Decision.Failures) != 0 {
		t.Fatalf("событие: %+v %+v", e.Decision, e.Media)
	}
}

// Ссылку https:// шлюз не загружает (ЗИ.2); off — анализатор не вызывается;
// изображение больше предела анализатора не отправляется.
func TestMediaURLOffAndTooLarge(t *testing.T) {
	up, _ := newUpstream(t, nil)
	m := &stubMedia{fn: ocrReply("текст"), max: 16}
	g, log := mediaGateway(t, up.URL, m, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	resp := postChat(t, g, imageChat(t, "https://img.example.test/a.png", dataURL(pngBytes)), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if e.Media[0].Reason != events.MediaReasonURL || e.Media[1].Reason != events.MediaReasonTooLarge || m.calls.Load() != 0 {
		t.Fatalf("media: %+v, вызовов %d", e.Media, m.calls.Load())
	}
	m = &stubMedia{fn: ocrReply("текст")}
	g, log = mediaGateway(t, up.URL, m, policy.MediaCheckOff, policy.NonTextAllowUnchecked, "fail_closed")
	resp = postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	e = waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if resp.Code != http.StatusOK || e.Media[0].Reason != events.MediaReasonOff || e.Media[0].Mode != "off" || m.calls.Load() != 0 {
		t.Fatalf("off: %d %+v", resp.Code, e.Media)
	}
	// non_text: allow_inline — ссылка блокируется независимо от media_check.
	g, _ = mediaGateway(t, up.URL, &stubMedia{fn: ocrReply("текст")}, policy.MediaCheckSync, policy.NonTextAllowInline, "fail_closed")
	if resp := postChat(t, g, imageChat(t, "https://img.example.test/a.png"), nil); resp.Code != http.StatusBadRequest {
		t.Fatalf("ссылка при allow_inline: %d", resp.Code)
	}
}

// Изображений больше предела проверки: остальные — «не проверено» (limit).
func TestMediaImagesOverLimit(t *testing.T) {
	up, _ := newUpstream(t, nil)
	m := &stubMedia{fn: decodeOnly}
	g, log := mediaGateway(t, up.URL, m, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	urls := make([]string, maxMediaImages+2)
	for i := range urls {
		urls[i] = dataURL(pngBytes)
	}
	resp := postChat(t, g, imageChat(t, urls...), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if int(m.calls.Load()) != maxMediaImages || e.Media[maxMediaImages].Reason != events.MediaReasonLimit {
		t.Fatalf("вызовов %d, media %+v", m.calls.Load(), e.Media[maxMediaImages])
	}
}

// Check API принимает изображения: проверка всегда синхронная (async
// выполняется как sync), находка — с местом images[i] и рамкой.
func TestCheckAcceptsImages(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g, log := mediaGateway(t, up.URL, &stubMedia{fn: ocrReply(injectionText)}, policy.MediaCheckAsync, policy.NonTextAllowUnchecked, "fail_closed")
	resp := postCheck(t, g, `{"direction":"input","images":["`+dataURL(pngBytes)+`"]}`)
	r := decodeCheck(t, resp)
	if resp.Code != http.StatusOK || !r.Blocked || len(r.Findings) == 0 || r.Findings[0].Location != "images[0]" || r.Findings[0].Box == nil ||
		len(r.Media) != 1 || !r.Media[0].Checked || r.MediaUnchecked || r.Text != nil || r.Messages != nil {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "password") {
		t.Fatal("в ответе текст изображения")
	}
	if e := lastCheckEvent(t, log, resp); e.Media[0].Mode != "sync" || !slices.Contains(e.Threats, "DM-45") {
		t.Fatalf("событие: %+v %v", e.Media, e.Threats)
	}
	// Текст и изображение вместе; ссылка — «не проверено».
	g, _ = mediaGateway(t, up.URL, &stubMedia{fn: decodeOnly}, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	resp = postCheck(t, g, `{"direction":"input","text":"Привет","images":["`+dataURL(pngBytes)+`","https://img.example.test/b.png"]}`)
	r = decodeCheck(t, resp)
	if resp.Code != http.StatusOK || r.Blocked || r.Text == nil || *r.Text != "Привет" || !r.MediaUnchecked ||
		r.Media[0].Reason != events.MediaReasonNoOCR || r.Media[1].Reason != events.MediaReasonURL {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("Check API обратился к провайдеру")
	}
}

func TestCheckRejectsBadImages(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g, log := mediaGateway(t, up.URL, &stubMedia{fn: decodeOnly}, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	many := strings.Repeat(`"`+dataURL(pngBytes)+`",`, maxMediaImages) + `"` + dataURL(pngBytes) + `"`
	cases := map[string]string{
		"на выходе":           `{"direction":"output","images":["` + dataURL(pngBytes) + `"]}`,
		"http":                `{"direction":"input","images":["http://img.example.test/a.png"]}`,
		"не base64":           `{"direction":"input","images":["data:image/png;base64,!!!"]}`,
		"не base64-адрес":     `{"direction":"input","images":["data:image/png,abc"]}`,
		"пустая строка":       `{"direction":"input","images":[""]}`,
		"больше предела":      `{"direction":"input","images":[` + many + `]}`,
		"не строка":           `{"direction":"input","images":[5]}`,
		"source image":        `{"direction":"input","source":"image","images":["` + dataURL(pngBytes) + `"]}`,
		"ссылка с пробелом":   `{"direction":"input","images":["https://img.example.test/a b.png"]}`,
		"нет текста и данных": `{"direction":"input","images":[]}`,
	}
	for name, body := range cases {
		if resp := postCheck(t, g, body); resp.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, resp.Code, resp.Body.String())
		}
	}
	if n := len(log.all()); n != 0 {
		t.Errorf("ошибки разбора создали события: %d", n)
	}
}

// Ответы анализатора переводятся в причины события без потерь.
func TestApplyReplyReasons(t *testing.T) {
	cases := []struct {
		res    wire.Result
		reason string
	}{
		{wire.Result{Status: wire.StatusUnsupported, Checks: []wire.Check{}}, events.MediaReasonUnsupported},
		{wire.Result{Status: wire.StatusRejected, Reason: wire.ReasonTooManyPixels, Checks: []wire.Check{}}, events.MediaReasonPixels},
		{wire.Result{Status: wire.StatusRejected, Reason: wire.ReasonTooManyFrames, Checks: []wire.Check{}}, events.MediaReasonFrames},
		{wire.Result{Status: wire.StatusRejected, Reason: wire.ReasonTooManyScans, Checks: []wire.Check{}}, events.MediaReasonScans},
		{wire.Result{Status: wire.StatusRejected, Reason: wire.ReasonTooLarge, Checks: []wire.Check{}}, events.MediaReasonTooLarge},
		{wire.Result{Status: wire.StatusRejected, Reason: wire.ReasonMalformed, Checks: []wire.Check{}}, events.MediaReasonMalformed},
	}
	for _, c := range cases {
		o := mediaOutcome{check: events.MediaCheck{Location: "images[0]", Mode: "sync"}}
		applyReply(&o, &MediaReply{Result: c.res})
		if o.check.Checked || o.check.Reason != c.reason {
			t.Fatalf("%+v → %+v", c.res, o.check)
		}
		if err := (&events.Event{ID: "e", Time: time.Now(), Type: events.TypeCheck, App: "a", PolicyMode: "enforce",
			Decision: &events.Decision{Action: "allow"}, Media: []events.MediaCheck{o.check}}).Validate(); err != nil {
			t.Fatalf("%s: событие не проходит проверку: %v", c.reason, err)
		}
	}
	if !errors.Is(mediaErr(events.MediaReasonTimeout, context.DeadlineExceeded), context.DeadlineExceeded) {
		t.Fatal("MediaError не раскрывает причину")
	}
}

// metaReply — анализатор без OCR (задача 5.43): текст метаданных и QR.
func metaReply(meta, code string) func(context.Context, []byte) (*MediaReply, error) {
	return func(context.Context, []byte) (*MediaReply, error) {
		return &MediaReply{Result: wire.Result{Status: wire.StatusOK, Format: wire.FormatJPEG, Width: 640, Height: 480, Frames: 1,
			Checks: []wire.Check{wire.CheckDecode, wire.CheckMetadata, wire.CheckQR}},
			Texts: []MediaText{{Text: meta, Origin: "metadata"}, {Text: code, Origin: "qr", Box: &events.Box{X: 100, Y: 100, W: 120, H: 120}}}}, nil
	}
}

// Покрывает: DM-47
// Текст метаданных и QR проверяется детекторами и без OCR: инструкция в
// EXIF блокирует запрос, находка — строка DM-47, у QR — с рамкой.
// Изображение без OCR остаётся «не проверено» (no_ocr) для non_text.
func TestMediaMetadataAndQRTextWithoutOCR(t *testing.T) {
	up, rec := newUpstream(t, nil)
	m := &stubMedia{fn: metaReply("SynthCam", injectionText)}
	g, log := mediaGateway(t, up.URL, m, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("инструкция в QR ушла провайдеру")
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if !slices.Contains(e.Threats, "DM-47") || slices.Contains(e.Threats, "DM-45") {
		t.Fatalf("угрозы %v", e.Threats)
	}
	var img *events.Finding
	for i := range e.Findings {
		if e.Findings[i].Source == "image" {
			img = &e.Findings[i]
		}
	}
	if img == nil || img.Threat != "DM-47" || img.Box == nil || img.Box.X != 100 || img.Location != "messages[0].content[1]" {
		t.Fatalf("находка: %+v", e.Findings)
	}
	if len(e.Media) != 1 || e.Media[0].Checked || e.Media[0].Reason != events.MediaReasonNoOCR || e.Media[0].Texts != 2 {
		t.Fatalf("media: %+v", e.Media)
	}
	// Чистые метаданные: запрос проходит, изображение по-прежнему не
	// проверено — при non_text: block его блокирует non_text.
	g, _ = mediaGateway(t, up.URL, &stubMedia{fn: metaReply("SynthCam", "https://menu.example.test/")}, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	if resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil); resp.Code != http.StatusOK {
		t.Fatalf("чистые метаданные: %d %s", resp.Code, resp.Body.String())
	}
	g, _ = mediaGateway(t, up.URL, &stubMedia{fn: metaReply("SynthCam", "https://menu.example.test/")}, policy.MediaCheckSync, policy.NonTextBlock, "fail_closed")
	if resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil); resp.Code != http.StatusBadRequest {
		t.Fatalf("non_text: block без OCR: %d", resp.Code)
	}
}

// Покрывает: DM-50
// Очередь анализатора заполнена (overloaded) или срок истёк: изображение
// «не проверено», событие — media_unavailable (по нему правило
// frequency.media_unavailable); sync — режим приложения при отказе, а не
// пропуск; async — запрос не ждёт, признак — в событии. Отказ по свойству
// изображения и шлюз без анализатора признака не ставят.
func TestDM50_QueueOverflowUnchecked(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g, log := mediaGateway(t, up.URL, &stubMedia{fn: failWith(events.MediaReasonOverloaded)}, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("sync, fail_closed: %d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("непроверенное изображение ушло провайдеру")
	}
	if e := waitEvent(t, log, resp.Header().Get(HeaderEventID)); !e.Decision.MediaUnchecked || !e.Decision.MediaUnavailable || e.Media[0].Reason != events.MediaReasonOverloaded {
		t.Fatalf("sync: %+v %+v", e.Decision, e.Media)
	}
	g, log = mediaGateway(t, up.URL, &stubMedia{fn: hang}, policy.MediaCheckAsync, policy.NonTextAllowUnchecked, "fail_closed")
	resp = postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("async: %d", resp.Code)
	}
	if e := waitEvent(t, log, resp.Header().Get(HeaderEventID)); !e.Decision.MediaUnavailable || e.Media[0].Reason != events.MediaReasonTimeout {
		t.Fatalf("async, срок: %+v %+v", e.Decision, e.Media)
	}
	for name, m := range map[string]MediaAnalyzer{"too_large": &stubMedia{fn: failWith(events.MediaReasonTooLarge)}, "без анализатора": nil} {
		g, log = mediaGateway(t, up.URL, m, policy.MediaCheckSync, policy.NonTextAllowUnchecked, "fail_closed")
		resp = postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
		if e := waitEvent(t, log, resp.Header().Get(HeaderEventID)); !e.Decision.MediaUnchecked || e.Decision.MediaUnavailable {
			t.Fatalf("%s: %+v %+v", name, e.Decision, e.Media)
		}
	}
}
