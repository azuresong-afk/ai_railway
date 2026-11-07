package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
	"github.com/azuresong-afk/ai_railway/internal/mockllm"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Изображения для GigaChat и YandexGPT (задача 6.10 этапа 6). Шлюз
// проверяет изображения (media_check, media_sanitize, «не проверено»,
// пределы) до адаптера провайдера — так же, как для OpenAI-совместимого;
// адаптер переводит уже проверенные байты в формат провайдера. Провайдер —
// mock-llm в режимах GigaChat и YandexGPT, анализатор — заглушка.

var imageVendors = []string{"gigachat", "yandexgpt"}

// vendorMock — mock-llm с записью последнего запроса.
func vendorMock(t *testing.T) (*mockllm.Server, *httptest.Server) {
	t.Helper()
	m := mockllm.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Configure(mockllm.Options{RecordLast: true}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	t.Cleanup(srv.Close)
	return m, srv
}

func vendorLast(t *testing.T, srv *httptest.Server) mockllm.LastRequest {
	t.Helper()
	resp, err := http.Get(srv.URL + mockllm.LastRequestPath) //nolint:gosec,noctx // G107: адрес тестового сервера
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // тестовый ответ
	var lr mockllm.LastRequest
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatal(err)
	}
	return lr
}

// vendorGateway — шлюз с политикой изображений и провайдером vendor.
func vendorGateway(t *testing.T, vendor, up string, m MediaAnalyzer, check policy.MediaCheck, sanitize bool) (http.Handler, *eventLog) {
	t.Helper()
	var log *eventLog
	g := newGateway(t, up, func(o *gwOpts) {
		mediaPolicy(check, policy.NonTextAllowUnchecked)(o)
		o.specs[0].MediaSanitize = sanitize
		o.app = func(a *config.Application) { a.Policy, a.PolicyMode, a.FailMode = "media", "enforce", "fail_closed" }
		o.media = m
		o.vendor = vendor
		o.maxBody = 1 << 20
		log = o.events
	})
	return g, log
}

// Покрывает: DM-46
// ПДн текстом на изображении блокируют запрос до провайдера в формате
// GigaChat и YandexGPT; чистое изображение проходит той же проверкой и
// доходит до провайдера в его формате (файл GigaChat удалён после ответа).
func TestMediaVendorsPIIOnImageBlocks(t *testing.T) {
	for _, vendor := range imageVendors {
		mock, srv := vendorMock(t)
		m := &stubMedia{fn: ocrReply("Почта " + piiEmail)}
		g, log := vendorGateway(t, vendor, srv.URL, m, policy.MediaCheckSync, false)
		resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
		if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" {
			t.Fatalf("%s: %d %s", vendor, resp.Code, resp.Body.String())
		}
		if lr := vendorLast(t, srv); lr.Received || mock.GigaChatFiles() != 0 || m.calls.Load() != 1 {
			t.Fatalf("%s: ПДн на изображении ушли провайдеру: %+v", vendor, lr)
		}
		if e := waitEvent(t, log, resp.Header().Get(HeaderEventID)); !slices.Contains(e.Threats, "DM-46") || e.Decision.Rule != "pii" {
			t.Fatalf("%s: событие %+v %v", vendor, e.Decision, e.Threats)
		}

		m = &stubMedia{fn: ocrReply("Квартальный отчёт")}
		g, log = vendorGateway(t, vendor, srv.URL, m, policy.MediaCheckSync, false)
		resp = postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s: чистое изображение: %d %s", vendor, resp.Code, resp.Body.String())
		}
		lr := vendorLast(t, srv)
		if len(lr.Images) != 1 || lr.Images[0] != (mockllm.LastImage{Format: "png", Bytes: len(pngBytes)}) || mock.GigaChatFiles() != 0 {
			t.Fatalf("%s: провайдер получил %+v, файлов %d", vendor, lr.Images, mock.GigaChatFiles())
		}
		if e := waitEvent(t, log, resp.Header().Get(HeaderEventID)); len(e.Media) != 1 || !e.Media[0].Checked {
			t.Fatalf("%s: media %+v", vendor, e.Media)
		}
	}
}

// Сверх пределов провайдера (GigaChat — одно изображение в сообщении,
// YandexGPT — PNG и JPEG) — отказ 400 unsupported_parameter, провайдер
// запроса не получает, в хранилище GigaChat ничего не загружено.
func TestMediaVendorsLimits(t *testing.T) {
	gif := "data:image/gif;base64,R0lGODlhAQABAAAAACw="
	for _, c := range []struct {
		vendor string
		body   string
	}{
		{"gigachat", imageChat(t, dataURL(pngBytes), dataURL(pngBytes))},
		{"gigachat", imageChat(t, gif)},
		{"gigachat", imageChat(t, "https://img.example/a.png")},
		{"yandexgpt", imageChat(t, gif)},
		{"yandexgpt", imageChat(t, "https://img.example/a.png")},
	} {
		mock, srv := vendorMock(t)
		g, _ := vendorGateway(t, c.vendor, srv.URL, &stubMedia{fn: ocrReply("текст")}, policy.MediaCheckOff, false)
		resp := postChat(t, g, c.body, nil)
		if resp.Code != http.StatusBadRequest || errCode(t, resp) != "unsupported_parameter" {
			t.Fatalf("%s: %d %s", c.vendor, resp.Code, resp.Body.String())
		}
		if lr := vendorLast(t, srv); lr.Received || mock.GigaChatFiles() != 0 {
			t.Fatalf("%s: запрос сверх пределов дошёл до провайдера: %+v", c.vendor, lr)
		}
	}
}

// Покрывает: DM-47
// media_sanitize: провайдер в своём формате получает очищенные байты
// (здесь — JPEG вместо исходного PNG), а не исходные.
func TestMediaVendorsSanitizeReplacesImage(t *testing.T) {
	cleanJPEG := []byte("\xff\xd8\xffочищено")
	for _, vendor := range imageVendors {
		mock, srv := vendorMock(t)
		g, log := vendorGateway(t, vendor, srv.URL, newSanitizer(sanitizeTo(cleanJPEG, wire.FormatJPEG)), policy.MediaCheckOff, true)
		resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", vendor, resp.Code, resp.Body.String())
		}
		lr := vendorLast(t, srv)
		if len(lr.Images) != 1 || lr.Images[0] != (mockllm.LastImage{Format: "jpeg", Bytes: len(cleanJPEG)}) || mock.GigaChatFiles() != 0 {
			t.Fatalf("%s: провайдер получил %+v, файлов %d", vendor, lr.Images, mock.GigaChatFiles())
		}
		if e := waitEvent(t, log, resp.Header().Get(HeaderEventID)); len(e.Media) != 1 || !e.Media[0].Sanitized {
			t.Fatalf("%s: media %+v", vendor, e.Media)
		}
	}
}
