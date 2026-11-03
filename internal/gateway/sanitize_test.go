package gateway

import (
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Очистка изображений перед отправкой провайдеру (media_sanitize, задача
// 5.45). Анализатор подменяется заглушкой: сама очистка — internal/media
// (sanitize_test.go), протокол — mediaclient_test.go.

// stubSanitizer — анализатор с очисткой.
type stubSanitizer struct {
	stubMedia
	san func(ctx context.Context, img []byte) ([]byte, wire.Format, error)
}

func (s *stubSanitizer) Sanitize(ctx context.Context, img []byte) ([]byte, wire.Format, error) {
	return s.san(ctx, img)
}

var cleanPNG = []byte("\x89PNG\r\n\x1a\nочищено")

func sanitizeTo(b []byte, f wire.Format) func(context.Context, []byte) ([]byte, wire.Format, error) {
	return func(context.Context, []byte) ([]byte, wire.Format, error) { return b, f, nil }
}

func sanitizeFail(reason string) func(context.Context, []byte) ([]byte, wire.Format, error) {
	return func(context.Context, []byte) ([]byte, wire.Format, error) { return nil, "", mediaErr(reason, nil) }
}

func newSanitizer(san func(context.Context, []byte) ([]byte, wire.Format, error)) *stubSanitizer {
	return &stubSanitizer{stubMedia: stubMedia{fn: decodeOnly}, san: san}
}

// sanitizeGateway — шлюз с media_sanitize: true; mode — режим политики
// приложения, failMode — режим при отказе.
func sanitizeGateway(t *testing.T, up string, m MediaAnalyzer, check policy.MediaCheck, mode, failMode string) (http.Handler, *eventLog) {
	t.Helper()
	var log *eventLog
	g := newGateway(t, up, func(o *gwOpts) {
		mediaPolicy(check, policy.NonTextAllowUnchecked)(o)
		o.specs[0].MediaSanitize = true
		o.app = func(a *config.Application) { a.Policy, a.PolicyMode, a.FailMode = "media", mode, failMode }
		if m != nil {
			o.media = m
		}
		log = o.events
	})
	return g, log
}

// Покрывает: DM-47
// Провайдер получает очищенные байты вместо исходных: PNG — data:image/png,
// JPEG — data:image/jpeg; в событии изображение отмечено sanitized.
// Очистка не зависит от media_check (здесь off).
func TestDM47_SanitizeReplacesImage(t *testing.T) {
	cleanJPEG := []byte("\xff\xd8\xffочищено")
	for _, c := range []struct {
		out  []byte
		f    wire.Format
		mime string
	}{{cleanPNG, wire.FormatPNG, "image/png"}, {cleanJPEG, wire.FormatJPEG, "image/jpeg"}} {
		up, rec := newUpstream(t, nil)
		g, log := sanitizeGateway(t, up.URL, newSanitizer(sanitizeTo(c.out, c.f)), policy.MediaCheckOff, "enforce", "fail_closed")
		resp := postChat(t, g, imageChat(t, dataURL(pngBytes), dataURL(pngBytes)), nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", c.f, resp.Code, resp.Body.String())
		}
		_, _, body, _ := rec.get()
		want := "data:" + c.mime + ";base64," + base64.StdEncoding.EncodeToString(c.out)
		if strings.Count(body, want) != 2 || strings.Contains(body, base64.StdEncoding.EncodeToString(pngBytes)) {
			t.Fatalf("%s: провайдер получил не очищенное изображение: %s", c.f, body)
		}
		e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
		if len(e.Media) != 2 || !e.Media[0].Sanitized || !e.Media[1].Sanitized || e.Media[0].Reason != events.MediaReasonOff {
			t.Fatalf("%s: media %+v", c.f, e.Media)
		}
		if _, ok := e.LatencyMS["media_sanitize"]; !ok || e.Decision.Action != "allow" {
			t.Fatalf("%s: событие %+v %v", c.f, e.Decision, e.LatencyMS)
		}
	}
}

// Без media_sanitize изображение уходит как есть, очистка не вызывается.
func TestSanitizeOffKeepsImage(t *testing.T) {
	up, rec := newUpstream(t, nil)
	called := false
	m := newSanitizer(func(context.Context, []byte) ([]byte, wire.Format, error) {
		called = true
		return cleanPNG, wire.FormatPNG, nil
	})
	g, log := mediaGateway(t, up.URL, m, policy.MediaCheckOff, policy.NonTextAllowUnchecked, "fail_closed")
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusOK || called {
		t.Fatalf("%d, очистка вызвана: %v", resp.Code, called)
	}
	if _, _, body, _ := rec.get(); !strings.Contains(body, base64.StdEncoding.EncodeToString(pngBytes)) {
		t.Fatal("исходное изображение не дошло до провайдера")
	}
	if e := waitEvent(t, log, resp.Header().Get(HeaderEventID)); e.Media[0].Sanitized {
		t.Fatalf("media: %+v", e.Media)
	}
}

// Покрывает: DM-47
// Изображение, которое не удалось очистить, провайдеру не уходит: свойство
// изображения — 400, сбой анализатора — 503; в любом режиме политики и при
// fail_open. Решение — block правилом media_sanitize, угроза DM-47.
func TestDM47_SanitizeFailureBlocks(t *testing.T) {
	many := make([]string, maxMediaImages+1)
	for i := range many {
		many[i] = dataURL(pngBytes)
	}
	cases := []struct {
		name   string
		m      MediaAnalyzer
		urls   []string
		status int
		code   string
		reason string
	}{
		{"отказ анализатора", newSanitizer(sanitizeFail(mediaReasonRejected)), []string{dataURL(pngBytes)}, 400, "media_sanitize_rejected", mediaReasonRejected},
		{"больше предела", newSanitizer(sanitizeFail(events.MediaReasonTooLarge)), []string{dataURL(pngBytes)}, 400, "media_sanitize_rejected", events.MediaReasonTooLarge},
		{"ссылка https", newSanitizer(sanitizeTo(cleanPNG, wire.FormatPNG)), []string{dataURL(pngBytes), "https://example.test/a.png"}, 400, "media_sanitize_rejected", events.MediaReasonURL},
		{"base64 не разобран", newSanitizer(sanitizeTo(cleanPNG, wire.FormatPNG)), []string{"data:image/png;base64,QR=="}, 400, "media_sanitize_rejected", events.MediaReasonMalformed},
		{"изображений больше предела", newSanitizer(sanitizeTo(cleanPNG, wire.FormatPNG)), many, 400, "media_sanitize_rejected", events.MediaReasonLimit},
		{"анализатор недоступен", newSanitizer(sanitizeFail(events.MediaReasonUnavailable)), []string{dataURL(pngBytes)}, 503, "media_sanitize_unavailable", events.MediaReasonUnavailable},
		{"очередь заполнена", newSanitizer(sanitizeFail(events.MediaReasonOverloaded)), []string{dataURL(pngBytes)}, 503, "media_sanitize_unavailable", events.MediaReasonOverloaded},
		{"сбой анализатора", newSanitizer(sanitizeFail(events.MediaReasonError)), []string{dataURL(pngBytes)}, 503, "media_sanitize_unavailable", events.MediaReasonError},
		{"неверный формат итога", newSanitizer(sanitizeTo(cleanPNG, wire.FormatGIF)), []string{dataURL(pngBytes)}, 503, "media_sanitize_unavailable", events.MediaReasonError},
		{"паника", newSanitizer(func(context.Context, []byte) ([]byte, wire.Format, error) { panic("сбой") }), []string{dataURL(pngBytes)}, 503, "media_sanitize_unavailable", events.MediaReasonError},
		{"анализатор без очистки", &stubMedia{fn: decodeOnly}, []string{dataURL(pngBytes)}, 503, "media_sanitize_unavailable", events.MediaReasonUnavailable},
		{"анализатор не установлен", nil, []string{dataURL(pngBytes)}, 503, "media_sanitize_unavailable", events.MediaReasonUnavailable},
	}
	for _, c := range cases {
		for _, mode := range [][2]string{{"enforce", "fail_closed"}, {"monitor", "fail_open"}} {
			up, rec := newUpstream(t, nil)
			g, log := sanitizeGateway(t, up.URL, c.m, policy.MediaCheckOff, mode[0], mode[1])
			resp := postChat(t, g, imageChat(t, c.urls...), nil)
			if resp.Code != c.status || errCode(t, resp) != c.code || resp.Header().Get(HeaderDecision) != "block" {
				t.Fatalf("%s, %v: %d %s", c.name, mode, resp.Code, resp.Body.String())
			}
			if _, _, _, calls := rec.get(); calls != 0 {
				t.Fatalf("%s, %v: запрос ушёл провайдеру", c.name, mode)
			}
			e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
			d := e.Decision
			if d.Action != "block" || d.Rule != ruleMediaSanitize || d.Applied[0] != "block" || !slices.Contains(e.Threats, "DM-47") {
				t.Fatalf("%s, %v: решение %+v, угрозы %v", c.name, mode, d, e.Threats)
			}
			last := d.Trace[len(d.Trace)-1]
			if last.Rule != ruleMediaSanitize || !strings.Contains(last.Note, "("+c.reason+")") {
				t.Fatalf("%s, %v: трассировка %+v", c.name, mode, d.Trace)
			}
			if slices.ContainsFunc(e.Media, func(m events.MediaCheck) bool { return m.Sanitized }) {
				t.Fatalf("%s, %v: media %+v", c.name, mode, e.Media)
			}
		}
	}
}

// Зависшая очистка не задерживает запрос сверх срока media_check_timeout_ms:
// изображение не уходит, ответ — 503.
func TestSanitizeHungBoundedByTimeout(t *testing.T) {
	up, rec := newUpstream(t, nil)
	hung := newSanitizer(func(ctx context.Context, _ []byte) ([]byte, wire.Format, error) {
		<-ctx.Done()
		return nil, "", mediaErr(events.MediaReasonTimeout, ctx.Err())
	})
	g, _ := sanitizeGateway(t, up.URL, hung, policy.MediaCheckOff, "enforce", "fail_open")
	start := time.Now()
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes), dataURL(pngBytes)), nil)
	if took := time.Since(start); took > 300*time.Millisecond+mediaEmitWait {
		t.Fatalf("запрос ждал очистку %v", took)
	}
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос ушёл провайдеру")
	}
}

// Запрос без изображений с media_sanitize проходит, анализатор не нужен.
func TestSanitizeNoImages(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g, _ := sanitizeGateway(t, up.URL, nil, policy.MediaCheckOff, "enforce", "fail_closed")
	resp := postChat(t, g, `{"model":"m","messages":[{"role":"user","content":"Привет"}]}`, nil)
	if _, _, _, calls := rec.get(); resp.Code != http.StatusOK || calls != 1 {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
}
