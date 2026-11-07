package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/mockllm"
)

// Изображения GigaChat и YandexGPT (задача 6.10): адаптеры против
// mock-llm в режимах этих провайдеров.

var (
	testPNG  = []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("\x00", 24))
	testJPEG = []byte("\xff\xd8\xff\xe0" + strings.Repeat("\x01", 28))
	testGIF  = []byte("GIF89a" + strings.Repeat("\x00", 20))
)

func dataURLOf(mime string, b []byte) string {
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(b)
}

// imageRequest — запрос с текстом и изображениями в одном сообщении пользователя.
func imageRequest(t *testing.T, model string, stream bool, urls ...string) *chat.Request {
	t.Helper()
	parts := []map[string]any{{"type": "text", "text": "Что на картинке?"}}
	for _, u := range urls {
		parts = append(parts, map[string]any{"type": "image_url", "image_url": map[string]string{"url": u}})
	}
	b, err := json.Marshal(map[string]any{"model": model, "stream": stream, "messages": []map[string]any{
		{"role": "system", "content": "Отвечай кратко."}, {"role": "user", "content": parts}}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := chat.Parse(b, chat.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func mockServer(t *testing.T) (*mockllm.Server, *httptest.Server) {
	t.Helper()
	m := mockllm.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Configure(mockllm.Options{RecordLast: true}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	t.Cleanup(srv.Close)
	return m, srv
}

func testRandom(t *testing.T) aisecCrypto.Random {
	t.Helper()
	cp, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := cp.Random()
	if err != nil {
		t.Fatal(err)
	}
	return rnd
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mockGigaChat(t *testing.T, srv *httptest.Server) *GigaChat {
	t.Helper()
	p, err := NewGigaChat(GigaChatConfig{
		BaseConfig: BaseConfig{ID: "giga", External: true, Transport: &http.Transport{Proxy: nil}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		BaseURL:    mustURL(t, srv.URL+"/api/v1"), AuthURL: mustURL(t, srv.URL+"/api/v2/oauth"), AuthKey: gcKey, Scope: "GIGACHAT_API_CORP",
		Random: testRandom(t)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func lastRequest(t *testing.T, srv *httptest.Server) mockllm.LastRequest {
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

// GigaChat: изображение загружается в хранилище, сообщение ссылается на
// него attachments, после ответа (целиком и потоком) файл удалён.
func TestGigaChatImageUploadAndCleanup(t *testing.T) {
	m, srv := mockServer(t)
	p := mockGigaChat(t, srv)
	ctx := context.Background()
	resp, _, err := p.Chat(ctx, imageRequest(t, "GigaChat-Max", false, dataURLOf("image/png", testPNG)))
	if err != nil {
		t.Fatal(err)
	}
	if got := *resp.Choices[0].Message.Content; !strings.Contains(got, "[изображения: png 32 байт]") || !strings.HasPrefix(got, "Что на картинке?") {
		t.Fatalf("ответ: %q", got)
	}
	lr := lastRequest(t, srv)
	var body struct {
		Messages []struct {
			Role        string   `json:"role"`
			Content     string   `json:"content"`
			Attachments []string `json:"attachments"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(lr.Body), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Messages) != 2 || len(body.Messages[1].Attachments) != 1 || body.Messages[1].Content != "Что на картинке?" ||
		strings.Contains(lr.Body, "base64") || len(body.Messages[0].Attachments) != 0 {
		t.Fatalf("тело запроса GigaChat: %s", lr.Body)
	}
	if n := m.GigaChatFiles(); n != 0 {
		t.Fatalf("файлов в хранилище после ответа: %d", n)
	}
	// Поток: файл удаляется при закрытии потока.
	st, _, err := p.Stream(ctx, imageRequest(t, "GigaChat-Max", true, dataURLOf("image/jpeg", testJPEG)))
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	for {
		c, err := st.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range c.Choices {
			if ch.Delta.Content != nil {
				text.WriteString(*ch.Delta.Content)
			}
		}
	}
	if m.GigaChatFiles() != 1 {
		t.Fatal("файл удалён до закрытия потока")
	}
	if _, ok := st.(Holder); !ok {
		t.Fatal("поток с изображением потерял приостановку срока простоя (Holder)")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "jpeg 32 байт") || m.GigaChatFiles() != 0 {
		t.Fatalf("поток: %q, файлов %d", text.String(), m.GigaChatFiles())
	}
	// Ошибка провайдера после загрузки — файл всё равно удалён.
	if _, _, err := p.Chat(ctx, imageRequest(t, "mock-error-500", false, dataURLOf("image/png", testPNG))); err == nil {
		t.Fatal("ошибка провайдера не передана")
	}
	if n := m.GigaChatFiles(); n != 0 {
		t.Fatalf("после ошибки в хранилище файлов: %d", n)
	}
}

// GigaChat: пределы документации проверяются до загрузки — отказ 400, в
// хранилище ничего не попадает.
func TestGigaChatImageLimits(t *testing.T) {
	m, srv := mockServer(t)
	p := mockGigaChat(t, srv)
	png := dataURLOf("image/png", testPNG)
	big := dataURLOf("image/png", append(append([]byte{}, testPNG...), make([]byte, gigaChatImages.maxBytes)...))
	multi := func(n int) *chat.Request {
		msgs := []map[string]any{}
		for range n {
			msgs = append(msgs, map[string]any{"role": "user", "content": []map[string]any{{"type": "image_url", "image_url": map[string]string{"url": png}}}})
		}
		b, err := json.Marshal(map[string]any{"model": "m", "messages": msgs})
		if err != nil {
			t.Fatal(err)
		}
		req, err := chat.Parse(b, chat.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	for name, req := range map[string]*chat.Request{
		"два в сообщении":   imageRequest(t, "m", false, png, png),
		"одиннадцать":       multi(11),
		"больше 15 МБ":      imageRequest(t, "m", false, big),
		"GIF":               imageRequest(t, "m", false, dataURLOf("image/gif", testGIF)),
		"ссылка":            imageRequest(t, "m", false, "https://img.example/a.png"),
		"не base64":         imageRequest(t, "m", false, "data:image/png;base64,iV=BORw0K"),
		"параметр без пары": mustParse(t, `{"model":"m","stop":"END","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"`+png+`"}}]}]}`),
	} {
		_, _, err := p.Chat(context.Background(), req)
		var pe *Error
		if !errors.As(err, &pe) || pe.Status != http.StatusBadRequest || pe.Code != "unsupported_parameter" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if lr := lastRequest(t, srv); lr.Received || m.GigaChatFiles() != 0 {
		t.Fatalf("запрос сверх пределов дошёл до провайдера: %+v, файлов %d", lr, m.GigaChatFiles())
	}
	// Десять изображений в разных сообщениях — допустимо.
	if _, _, err := p.Chat(context.Background(), multi(10)); err != nil {
		t.Fatalf("десять изображений: %v", err)
	}
	if lr := lastRequest(t, srv); len(lr.Images) != 10 || m.GigaChatFiles() != 0 {
		t.Fatalf("десять изображений: %+v, файлов %d", lr.Images, m.GigaChatFiles())
	}
}

func mustParse(t *testing.T, s string) *chat.Request {
	t.Helper()
	req, err := chat.Parse([]byte(s), chat.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func mockYandex(t *testing.T, base string) *YandexGPT {
	t.Helper()
	p, err := NewYandexGPT(YandexGPTConfig{ //nolint:gosec // G101: выдуманный ключ для mock-llm
		BaseConfig: BaseConfig{ID: "yc", External: true, Transport: &http.Transport{Proxy: nil}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		BaseURL:    mustURL(t, base), APIKey: "AQVN-fixture-api-key-0000", FolderID: "b1gfolder", Random: testRandom(t)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// YandexGPT: текст — методом completion, изображения — OpenAI-совместимым
// методом того же узла с моделью gpt://каталог/модель, Api-Key и
// OpenAI-Project; изображение уходит заново собранным data:-адресом.
func TestYandexGPTImagesViaOpenAICompatible(t *testing.T) {
	_, srv := mockServer(t)
	p := mockYandex(t, srv.URL+"/foundationModels/v1")
	ctx := context.Background()
	text := mustParse(t, `{"model":"yandexgpt","messages":[{"role":"user","content":"Привет"}]}`)
	if resp, _, err := p.Chat(ctx, text); err != nil || *resp.Choices[0].Message.Content != "Привет" {
		t.Fatalf("текст методом completion: %+v %v", resp, err)
	}
	if lr := lastRequest(t, srv); !strings.Contains(lr.Body, `"modelUri":"gpt://b1gfolder/yandexgpt"`) {
		t.Fatalf("текст ушёл не в completion: %s", lr.Body)
	}
	// URL-алфавит base64 без выравнивания — провайдеру уходит стандартный.
	raw := "data:image/png;base64," + base64.RawURLEncoding.EncodeToString(testPNG)
	resp, _, err := p.Chat(ctx, imageRequest(t, "qwen2.5-vl", false, raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := *resp.Choices[0].Message.Content; !strings.Contains(got, "[изображения: png 32 байт]") || resp.Model != "qwen2.5-vl" {
		t.Fatalf("ответ: %q %s", got, resp.Model)
	}
	lr := lastRequest(t, srv)
	if lr.Model != "qwen2.5-vl" || len(lr.Images) != 1 || !strings.Contains(lr.Body, `"model":"gpt://b1gfolder/qwen2.5-vl"`) ||
		!strings.Contains(lr.Body, dataURLOf("image/png", testPNG)) {
		t.Fatalf("запрос с изображением: %+v", lr)
	}
	st, _, err := p.Stream(ctx, imageRequest(t, "qwen2.5-vl", true, dataURLOf("image/jpeg", testJPEG)))
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for {
		c, err := st.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range c.Choices {
			if ch.Delta.Content != nil {
				out.WriteString(*ch.Delta.Content)
			}
		}
		if c.Model != "qwen2.5-vl" {
			t.Fatalf("модель в части потока: %s", c.Model)
		}
	}
	if err := st.Close(); err != nil || !strings.Contains(out.String(), "jpeg 32 байт") {
		t.Fatalf("поток: %q %v", out.String(), err)
	}
	// Пределы: GIF, ссылка, параметр без аналога — 400 без запроса.
	before := lastRequest(t, srv).Count
	for name, req := range map[string]*chat.Request{
		"GIF":    imageRequest(t, "m", false, dataURLOf("image/gif", testGIF)),
		"ссылка": imageRequest(t, "m", false, "https://img.example/a.png"),
		"top_p":  mustParse(t, `{"model":"m","top_p":0.5,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"`+dataURLOf("image/png", testPNG)+`"}}]}]}`),
	} {
		var pe *Error
		if _, _, err := p.Chat(ctx, req); !errors.As(err, &pe) || pe.Status != http.StatusBadRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	if lastRequest(t, srv).Count != before {
		t.Fatal("отклонённый запрос дошёл до провайдера")
	}
	// base_url другого вида — адрес метода не угадывается, изображения — отказ.
	other := mockYandex(t, srv.URL+"/proxy/llm")
	var pe *Error
	if _, _, err := other.Chat(ctx, imageRequest(t, "m", false, dataURLOf("image/png", testPNG))); !errors.As(err, &pe) || pe.Status != 400 {
		t.Fatalf("неизвестный вид base_url: %v", err)
	}
}

func TestVisionURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://llm.api.cloud.yandex.net/foundationModels/v1":   "https://llm.api.cloud.yandex.net/v1/chat/completions",
		"https://llm.api.cloud.yandex.net/foundationModels/v1/":  "https://llm.api.cloud.yandex.net/v1/chat/completions",
		"https://gw.local:8443/yc/foundationModels/v1?x=1#f":     "https://gw.local:8443/yc/v1/chat/completions",
		"https://llm.api.cloud.yandex.net/v1":                    "",
		"https://llm.api.cloud.yandex.net/foundationModels/v1/x": "",
	} {
		if got := visionURL(mustURL(t, in)); got != want {
			t.Errorf("%s: %q, ждали %q", in, got, want)
		}
	}
}

func TestImageFormatAndDataURL(t *testing.T) {
	for b, want := range map[string]string{string(testPNG): imagePNG, string(testJPEG): imageJPEG, "II*\x00abcd": imageTIFF, "MM\x00*abcd": imageTIFF,
		"BM" + strings.Repeat("\x00", 30): imageBMP, "RIFF\x00\x00\x00\x00WEBPVP8 ": imageWEBP, string(testGIF): imageGIF, "BM": "", "": "", "<svg": ""} {
		if got := imageFormat([]byte(b)); got != want {
			t.Errorf("%q: %q, ждали %q", b, got, want)
		}
	}
	if _, err := dataURLBytes("data:image/png;base64,"+base64.StdEncoding.EncodeToString(make([]byte, 101)), 100); !errors.Is(err, errImageTooLarge) {
		t.Fatalf("предел до раскодирования: %v", err)
	}
	for _, u := range []string{"https://a/b.png", "data:image/png,abc", "data:image/png;base64,", "data:image/png;base64,QQ=x", "data:;base64,QR=="} {
		if _, err := dataURLBytes(u, 100); err == nil {
			t.Errorf("%q принят", u)
		}
	}
	if b, err := dataURLBytes("DATA:image/png;BASE64,QUJD", 100); err != nil || string(b) != "ABC" {
		t.Fatalf("регистр схемы: %q %v", b, err)
	}
}

// FuzzDataURLBytes — разбор data:-адреса изображения: без паники, предел
// соблюдается, результат непустой.
func FuzzDataURLBytes(f *testing.F) {
	for _, s := range []string{dataURLOf("image/png", testPNG), "data:image/png;base64,QQ", "data:,", "data:x;base64,-_-_", "https://a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := dataURLBytes(s, 64)
		if err == nil && (len(b) == 0 || len(b) > 64) {
			t.Fatalf("%q: %d байт", s, len(b))
		}
		_ = imageFormat(b)
	})
}
