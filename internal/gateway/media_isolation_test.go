package gateway

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Изоляция aisec-media со стороны шлюза (задача 5.47, критерий ТЗ 14):
// настоящий клиент MediaClient и обработчик чата против поддельного сокета,
// который зависает, обрывает соединение посреди запроса, отвечает мусором
// или исчезает (процесс завершён). Ответ шлюза — не позже срока
// media_check_timeout_ms (300 мс в политике теста) с запасом, шлюз не
// падает и продолжает обслуживать запросы. С настоящим процессом — тесты
// test/isolation.

// mediaFault — поведение поддельного анализатора на кадр analyze или
// sanitize.
type mediaFault func(release <-chan struct{}) func(wire.Header, []byte) (wire.FrameType, any)

var mediaFaults = map[string]mediaFault{
	// Процесс завис: соединение живо, ответа нет.
	"зависание": func(release <-chan struct{}) func(wire.Header, []byte) (wire.FrameType, any) {
		return func(wire.Header, []byte) (wire.FrameType, any) {
			<-release
			return 0, nil
		}
	},
	// Процесс упал посреди запроса: соединение закрыто без ответа.
	"обрыв": func(<-chan struct{}) func(wire.Header, []byte) (wire.FrameType, any) {
		return func(wire.Header, []byte) (wire.FrameType, any) { return 0, nil }
	},
	// Повреждённый ответ: тело не JSON и не изображение.
	"мусор": func(<-chan struct{}) func(wire.Header, []byte) (wire.FrameType, any) {
		return func(h wire.Header, _ []byte) (wire.FrameType, any) {
			if h.Type == wire.TypeSanitize {
				return wire.TypeSanitized, []byte("\x00\x01мусор")
			}
			return wire.TypeResult, []byte("\xff\xfe мусор")
		}
	},
}

// isolationGateway — шлюз с настоящим клиентом aisec-media на сокете sock.
func isolationGateway(t *testing.T, up, sock string, check policy.MediaCheck, sanitize bool, failMode string) (http.Handler, *eventLog) {
	t.Helper()
	c := newMediaClient(t, sock, nil)
	if !sanitize {
		return mediaGateway(t, up, c, check, policy.NonTextAllowUnchecked, failMode)
	}
	return sanitizeGateway(t, up, c, check, "enforce", failMode)
}

// budget — предел ответа шлюза: срок анализа, запас ожидания итога и
// запас на медленную среду (-race).
const isolationBudget = 300*time.Millisecond + mediaEmitWait + 700*time.Millisecond

func TestMediaFaultsDoNotDelayGateway(t *testing.T) {
	for name, fault := range mediaFaults {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			hello := defaultHello()
			hello.Sanitize = true
			f := &fakeMedia{hello: hello, analyze: fault(release), sanitize: fault(release)}
			sock := f.start(t)
			up, rec := newUpstream(t, nil)
			cases := []struct {
				mode     string
				check    policy.MediaCheck
				sanitize bool
				failMode string
				status   int
			}{
				// sync и fail_open: запрос уходит без проверки изображения.
				{"sync, fail_open", policy.MediaCheckSync, false, "fail_open", http.StatusOK},
				// sync и fail_closed: запрос не уходит, ответ 503.
				{"sync, fail_closed", policy.MediaCheckSync, false, "fail_closed", http.StatusServiceUnavailable},
				// async: ответ не ждёт анализатора вовсе.
				{"async", policy.MediaCheckAsync, false, "fail_closed", http.StatusOK},
				// media_sanitize: неочищенное изображение не уходит.
				{"media_sanitize", policy.MediaCheckOff, true, "fail_open", http.StatusServiceUnavailable},
			}
			for _, c := range cases {
				g, log := isolationGateway(t, up.URL, sock, c.check, c.sanitize, c.failMode)
				_, _, _, before := rec.get()
				start := time.Now()
				resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
				took := time.Since(start)
				if resp.Code != c.status || took > isolationBudget {
					t.Fatalf("%s: %d за %v (предел %v): %s", c.mode, resp.Code, took, isolationBudget, resp.Body.String())
				}
				if _, _, _, after := rec.get(); (after > before) != (c.status == http.StatusOK) {
					t.Fatalf("%s: вызовов провайдера %d → %d", c.mode, before, after)
				}
				waitEvent(t, log, resp.Header().Get(HeaderEventID))
				// Шлюз продолжает работать: запрос без изображений проходит.
				if resp := postChat(t, g, `{"model":"m","messages":[{"role":"user","content":"Привет"}]}`, nil); resp.Code != http.StatusOK {
					t.Fatalf("%s: после сбоя анализатора: %d %s", c.mode, resp.Code, resp.Body.String())
				}
			}
		})
	}
}

// Процесс aisec-media завершён: сокета нет. Ответ — сразу, без ожидания
// срока; при media_sanitize запрос не уходит.
func TestMediaSocketGoneDoesNotDelayGateway(t *testing.T) {
	f := &fakeMedia{hello: defaultHello()}
	sock := f.start(t)
	up, _ := newUpstream(t, nil)
	g, _ := isolationGateway(t, up.URL, sock, policy.MediaCheckSync, false, "fail_open")
	if resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil); resp.Code != http.StatusOK {
		t.Fatalf("до остановки: %d %s", resp.Code, resp.Body.String())
	}
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	for _, sanitize := range []bool{false, true} {
		g, _ := isolationGateway(t, up.URL, sock, policy.MediaCheckSync, sanitize, "fail_open")
		start := time.Now()
		resp := postChat(t, g, imageChat(t, dataURL(pngBytes)), nil)
		want := http.StatusOK
		if sanitize {
			want = http.StatusServiceUnavailable
		}
		if took := time.Since(start); resp.Code != want || took > 300*time.Millisecond {
			t.Fatalf("sanitize=%v: %d за %v: %s", sanitize, resp.Code, took, resp.Body.String())
		}
	}
}
