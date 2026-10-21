package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Приём событий (задача 2.15) без TLS: субъект подставляет asGateway.
// Сквозная проверка на mTLS — internal/gateway/eventsink_test.go.

// eventsNow — «сейчас» сервера в этих тестах.
var eventsNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

const testGatewayID = "01900000-0000-7000-8000-0000000000e1"

// testEventID — UUIDv7 со временем eventsNow и номером n.
func testEventID(n int) string {
	ms := eventsNow.UnixMilli()
	return fmt.Sprintf("%08x-%04x-7000-8000-%012x", ms>>16, ms&0xffff, n)
}

func testEvent(n int, content string) events.Event {
	return events.Event{
		ID: testEventID(n), Time: eventsNow, Type: events.TypeGatewayRequest, App: "support-bot", Env: "prod",
		PolicyMode: events.ModeMonitor, Storage: events.StorageFull,
		Decision: &events.Decision{Action: "allow", Applied: []string{}},
		Content:  &events.Content{Request: content},
	}
}

type failStore struct{ err error }

func (f failStore) Insert(context.Context, events.Ingest) (int, int, error) { return 0, 0, f.err }

func newEventsHandler(t testing.TB, st events.Store, logger *slog.Logger) http.Handler {
	t.Helper()
	svc, _ := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: logger, Hasher: testHasher(t), Gateways: svc,
		Authorizer: asGateway(testGatewayID), Events: st, Now: func() time.Time { return eventsNow },
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func batchBody(t testing.TB, evs ...events.Event) string {
	t.Helper()
	b, err := json.Marshal(events.Batch{Events: evs, Stats: &events.SenderStats{StartedAt: eventsNow.Add(-time.Hour), Dropped: 2}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEventsBatchAccepts(t *testing.T) {
	var logs bytes.Buffer
	mem := events.NewMemory()
	h := newEventsHandler(t, mem, slog.New(slog.NewJSONHandler(&logs, nil)))
	promptText := "Паспорт 4510 123456 — секрет содержимого"
	bad := testEvent(3, promptText)
	bad.Time = eventsNow.Add(-8 * 24 * time.Hour)
	body := batchBody(t, testEvent(1, promptText), testEvent(2, promptText), bad)
	w := do(h, http.MethodPost, "/internal/v1/events:batch", body, "Content-Type", "application/json")
	if w.Code != http.StatusOK {
		t.Fatalf("код %d: %s", w.Code, w.Body)
	}
	var res events.BatchResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Accepted != 2 || res.Duplicates != 0 || len(res.Rejected) != 1 || res.Rejected[0] != (events.Rejection{Index: 2, Code: events.RejectTime}) {
		t.Fatalf("итог %+v", res)
	}
	got, ok := mem.Get(testEventID(1))
	if !ok || got.GatewayID != testGatewayID {
		t.Fatalf("событие не привязано к шлюзу из сертификата: %+v", got)
	}
	if st, ok := mem.Stats(testGatewayID); !ok || st.Dropped != 2 {
		t.Fatalf("счётчики шлюза: %+v", st)
	}
	// Повтор пакета — дубли не записываются.
	w = do(h, http.MethodPost, "/internal/v1/events:batch", body, "Content-Type", "application/json")
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || res.Accepted != 0 || res.Duplicates != 2 {
		t.Fatalf("повтор: %+v %v", res, err)
	}
	// Содержимое событий в технический журнал не попадает.
	if strings.Contains(logs.String(), "4510") || !strings.Contains(logs.String(), "события пакета отклонены") {
		t.Fatalf("журнал: %s", logs.String())
	}
}

func TestEventsBatchErrors(t *testing.T) {
	ok := batchBody(t, testEvent(1, "x"))
	h := newEventsHandler(t, events.NewMemory(), quiet())
	cases := map[string]struct {
		body, ctype string
		status      int
		code        string
	}{
		"не JSON":          {`{"events":`, "application/json", http.StatusBadRequest, CodeInvalidRequest},
		"тип тела":         {ok, "text/plain", http.StatusUnsupportedMediaType, CodeUnsupportedMedia},
		"пустой пакет":     {`{"events":[]}`, "application/json", http.StatusBadRequest, CodeInvalidRequest},
		"шлюз в теле":      {strings.Replace(ok, `{"events"`, `{"gateway_id":"x","events"`, 1), "application/json", http.StatusBadRequest, CodeInvalidRequest},
		"запуск в будущем": {strings.Replace(ok, eventsNow.Add(-time.Hour).Format(time.RFC3339), eventsNow.Add(time.Hour).Format(time.RFC3339), 1), "application/json", http.StatusBadRequest, CodeInvalidRequest},
		"больше 8 МиБ":     {`{"events":[{"id":"` + strings.Repeat("a", events.MaxBatchBytes) + `"}]}`, "application/json", http.StatusRequestEntityTooLarge, CodePayloadTooLarge},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := do(h, http.MethodPost, "/internal/v1/events:batch", c.body, "Content-Type", c.ctype)
			mustProblem(t, w, c.status, c.code)
		})
	}
	t.Run("хранилище недоступно", func(t *testing.T) {
		h := newEventsHandler(t, failStore{err: errors.New("нет соединения")}, quiet())
		w := do(h, http.MethodPost, "/internal/v1/events:batch", ok, "Content-Type", "application/json")
		mustProblem(t, w, http.StatusServiceUnavailable, CodeUnavailable)
		if w.Header().Get("Retry-After") == "" {
			t.Fatal("нет Retry-After")
		}
	})
	t.Run("хранилище отвергло данные", func(t *testing.T) {
		h := newEventsHandler(t, failStore{err: fmt.Errorf("%w: x", events.ErrRejectedByDB)}, quiet())
		w := do(h, http.MethodPost, "/internal/v1/events:batch", ok, "Content-Type", "application/json")
		mustProblem(t, w, http.StatusUnprocessableEntity, CodeUnprocessable)
	})
	t.Run("без сертификата шлюза", func(t *testing.T) {
		svc, _ := newGatewayEnv(t)
		h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Events: events.NewMemory()})
		if err != nil {
			t.Fatal(err)
		}
		w := do(h, http.MethodPost, "/internal/v1/events:batch", ok, "Content-Type", "application/json")
		mustProblem(t, w, http.StatusUnauthorized, CodeUnauthorized)
	})
	t.Run("право не шлюза", func(t *testing.T) {
		svc, _ := newGatewayEnv(t)
		h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Events: events.NewMemory(),
			Authorizer: allowPerm{"users.read": true}})
		if err != nil {
			t.Fatal(err)
		}
		w := do(h, http.MethodPost, "/internal/v1/events:batch", ok, "Content-Type", "application/json")
		mustProblem(t, w, http.StatusForbidden, CodeForbidden)
	})
}

// FuzzEventsBatchRequest: любое тело пакета — 200 или ошибка клиента в
// формате Problem Details, без паники и 500.
func FuzzEventsBatchRequest(f *testing.F) {
	h := newEventsHandler(f, events.NewMemory(), quiet())
	f.Add(batchBody(f, testEvent(1, "x")), "application/json")
	f.Add(`{"events":[{}]}`, "application/json")
	f.Add(`{"events":[{"id":"`+testEventID(2)+`","time":"2026-10-21T12:00:00Z","type":"auth_failure","auth_failure":{"reason":"\u0000"}}]}`, "application/json")
	f.Add(`{"events":[]}`, "text/plain")
	f.Fuzz(func(t *testing.T, body, ctype string) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/internal/v1/events:batch", strings.NewReader(body))
		req.Header.Set("Content-Type", ctype)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		switch w.Code {
		case http.StatusOK, http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		default:
			t.Fatalf("код %d: %s", w.Code, w.Body)
		}
		if w.Code != http.StatusOK && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
			t.Fatalf("ошибка не в формате Problem Details: %q", w.Header().Get("Content-Type"))
		}
	})
}
