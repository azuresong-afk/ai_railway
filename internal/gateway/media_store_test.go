package gateway

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Изображения запроса в содержимом события full (задача 6.13, ADR-0039).

// storeGateway — шлюз с проверкой изображений sync; storage — режим
// хранения приложения, store и sanitize — media_store и media_sanitize.
func storeGateway(t *testing.T, up string, m MediaAnalyzer, storage string, store, sanitize bool) (http.Handler, *eventLog) {
	t.Helper()
	var log *eventLog
	g := newGateway(t, up, func(o *gwOpts) {
		mediaPolicy(policy.MediaCheckSync, policy.NonTextAllowUnchecked)(o)
		o.specs[0].MediaStore, o.specs[0].MediaSanitize = store, sanitize
		o.maxBody = 16 << 20
		o.app = func(a *config.Application) {
			a.Policy, a.PolicyMode, a.FailMode, a.Storage = "media", "enforce", "fail_closed", storage
		}
		o.media = m
		log = o.events
	})
	return g, log
}

// Хранение выключено (нет media_store или режим не full) — изображения в
// событии нет и отметок о хранении тоже.
func TestMediaStoreOffNotStored(t *testing.T) {
	for _, c := range []struct {
		storage string
		store   bool
	}{{events.StorageFull, false}, {events.StorageMasked, true}, {events.StorageNone, true}} {
		up, _ := newUpstream(t, nil)
		g, log := storeGateway(t, up.URL, &stubMedia{fn: ocrReply("Счёт № 12")}, c.storage, c.store, false)
		resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("%+v: %d %s", c, resp.Code, resp.Body.String())
		}
		e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
		if e.ImageBytes() != 0 || e.Media[0].Stored || e.Media[0].StoreSkipped != "" {
			t.Fatalf("%+v: изображение сохранено: %+v", c, e.Media)
		}
	}
}

// full и media_store: исходные байты изображения — в содержимом события
// вместе с текстом; ссылка и неразобранное изображение отмечены причиной.
func TestMediaStoreFullKeepsImage(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g, log := storeGateway(t, up.URL, &stubMedia{fn: ocrReply("Счёт № 12")}, events.StorageFull, true, false)
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes), "https://img.example.test/a.png"), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if e.Content == nil || len(e.Content.Images) != 1 || !strings.Contains(e.Content.Request, "Что на картинке?") {
		t.Fatalf("содержимое: %+v", e.Content)
	}
	img := e.Content.Images[0]
	if img.Location != "messages[0].content[1]" || img.Format != "png" || img.Sanitized || !bytes.Equal(img.Data, pngBytes) {
		t.Fatalf("изображение: %+v", img)
	}
	if !e.Media[0].Stored || e.Media[1].Stored || e.Media[1].StoreSkipped != events.StoreSkipURL {
		t.Fatalf("media: %+v", e.Media)
	}
	// Анализатор не разобрал заголовок — не хранится.
	g, log = storeGateway(t, up.URL, &stubMedia{fn: failWith(events.MediaReasonUnavailable)}, events.StorageFull, true, false)
	resp = postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	e = waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if e.ImageBytes() != 0 || e.Media[0].StoreSkipped != events.StoreSkipNotParsed {
		t.Fatalf("неразобранное изображение: %+v", e.Media)
	}
}

// Заблокированный запрос (ПДн на изображении) — тоже с изображением: ради
// него хранение и включают (S12).
func TestMediaStoreBlockedRequest(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g, log := storeGateway(t, up.URL, &stubMedia{fn: ocrReply(injectionText)}, events.StorageFull, true, false)
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if e.Decision.Action != "block" || e.ImageBytes() != len(pngBytes) || !e.Media[0].Stored {
		t.Fatalf("событие: %+v %+v", e.Decision, e.Media)
	}
}

// Пределы: изображение больше 3 МиБ не хранится (too_large), сумма по
// событию — не больше 4 МиБ (event_limit); событие при этом проходит
// проверку схемы.
func TestMediaStoreLimits(t *testing.T) {
	big := append(bytes.Clone(pngBytes), bytes.Repeat([]byte{1}, events.MaxStoredImageBytes)...)
	two := append(bytes.Clone(pngBytes), bytes.Repeat([]byte{2}, 2<<20)...)
	up, _ := newUpstream(t, nil)
	m := &stubMedia{max: 8 << 20, fn: ocrReply("Счёт")}
	g, log := storeGateway(t, up.URL, m, events.StorageFull, true, false)
	resp := postChat(t, g, imageChat(t, dataURL(big), dataURL(two), dataURL(two), dataURL(pngBytes)), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	want := []string{events.StoreSkipTooLarge, "", events.StoreSkipEventLimit, ""}
	for i, m := range e.Media {
		if m.StoreSkipped != want[i] || m.Stored != (want[i] == "") {
			t.Fatalf("media[%d]: %+v", i, m)
		}
	}
	if n := e.ImageBytes(); n != len(two)+len(pngBytes) || n > events.MaxEventImageBytes {
		t.Fatalf("байтов изображений %d", n)
	}
}

// media_sanitize: хранится очищенное изображение — то, что ушло
// провайдеру; у заблокированного до очистки запроса — очищенное для
// хранения после ответа. Не очистилось — не хранится.
func TestMediaStoreSanitized(t *testing.T) {
	up, _ := newUpstream(t, nil)
	s := newSanitizer(sanitizeTo(cleanPNG, wire.FormatPNG))
	s.fn = ocrReply("Счёт № 12")
	g, log := storeGateway(t, up.URL, s, events.StorageFull, true, true)
	resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if len(e.Content.Images) != 1 || !e.Content.Images[0].Sanitized || !bytes.Equal(e.Content.Images[0].Data, cleanPNG) ||
		!e.Media[0].Sanitized {
		t.Fatalf("очищенное: %+v %+v", e.Content.Images, e.Media)
	}

	calls := 0
	blocked := newSanitizer(func(context.Context, []byte) ([]byte, wire.Format, error) {
		calls++
		return []byte("\xff\xd8\xffочищено для хранения"), wire.FormatJPEG, nil
	})
	blocked.fn = ocrReply(injectionText)
	g, log = storeGateway(t, up.URL, blocked, events.StorageFull, true, true)
	resp = postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e = waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if len(e.Content.Images) != 1 || e.Content.Images[0].Format != "jpeg" || !e.Content.Images[0].Sanitized || calls != 1 {
		t.Fatalf("очищенное для хранения: %+v, вызовов %d", e.Content.Images, calls)
	}

	failing := newSanitizer(sanitizeFail(events.MediaReasonUnavailable))
	failing.fn = ocrReply(injectionText)
	g, log = storeGateway(t, up.URL, failing, events.StorageFull, true, true)
	resp = postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
	e = waitEvent(t, log, resp.Header().Get(HeaderEventID))
	if e.ImageBytes() != 0 || e.Media[0].StoreSkipped != events.StoreSkipNotSanitized {
		t.Fatalf("неочищенное сохранено: %+v", e.Media)
	}
}

// Check API: изображения тоже хранятся по тем же правилам.
func TestMediaStoreCheckAPI(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g, log := storeGateway(t, up.URL, &stubMedia{fn: ocrReply("Счёт")}, events.StorageFull, true, false)
	resp := postCheck(t, g, `{"direction":"input","images":["`+dataURL(pngBytes)+`"]}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "stored") {
		t.Fatal("в ответе Check API отметка хранения")
	}
	e := lastCheckEvent(t, log, resp)
	if len(e.Content.Images) != 1 || e.Content.Images[0].Location != "images[0]" || !e.Media[0].Stored {
		t.Fatalf("событие: %+v", e.Media)
	}
}
