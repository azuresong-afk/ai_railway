package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Отправка событий на сервер (задача 2.15): по mTLS, событие привязывается
// к шлюзу из сертификата, повтор не дублирует, сбой — повтор позже.

func newEvent(t *testing.T) events.Event {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	u, err := ids.NewGenerator(r).New()
	if err != nil {
		t.Fatal(err)
	}
	return events.Event{
		ID: u.String(), Time: time.Now().UTC(), Type: events.TypeGatewayRequest, App: "support-bot", Env: "prod",
		PolicyMode: events.ModeEnforce, Storage: events.StorageFull,
		Decision: &events.Decision{Action: "allow", Applied: []string{}},
		Content:  &events.Content{Request: "messages[0]: Привет", Response: "choices[0]: Здравствуйте"},
	}
}

func TestServerSinkOverMTLS(t *testing.T) {
	e := newMTLSEnv(t)
	reg := e.registerGateway(t, "gw-1")
	c := e.client(t, reg.CertPEM, reg.KeyPEM)
	sink, err := gateway.NewServerSink(gateway.ServerSinkConfig{Client: c, Server: e.internal, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	sink.CountDropped(func() uint64 { return 7 })
	ev1, ev2 := newEvent(t), newEvent(t)
	bad := newEvent(t)
	bad.ID = strings.ToUpper(bad.ID)
	if err := sink.Send(context.Background(), []events.Event{ev1, ev2, bad}); err != nil {
		t.Fatal(err)
	}
	got, ok := e.events.Get(ev1.ID)
	if !ok || got.GatewayID != reg.GatewayID || got.Event.Content.Request != ev1.Content.Request {
		t.Fatalf("событие не записано или привязано не к шлюзу из сертификата: %+v", got)
	}
	if e.events.Len() != 2 || sink.Rejected() != 1 {
		t.Fatalf("записано %d, отклонено %d", e.events.Len(), sink.Rejected())
	}
	st, ok := e.events.Stats(reg.GatewayID)
	if !ok || st.Dropped != 7 {
		t.Fatalf("счётчики шлюза: %+v", st)
	}
	// Повтор того же пакета (после обрыва ответа) не дублирует события.
	if err := sink.Send(context.Background(), []events.Event{ev1, ev2}); err != nil {
		t.Fatal(err)
	}
	if e.events.Len() != 2 {
		t.Fatalf("повтор продублировал события: %d", e.events.Len())
	}
	// Отозванный шлюз: 401, пакет ждёт повтора, а не теряется молча.
	if _, err := e.svc.Revoke(context.Background(), "gw-1", audit.Actor{Type: audit.ActorCLI, ID: "uid:0"}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Send(context.Background(), []events.Event{newEvent(t)}); !errors.Is(err, events.ErrRetryLater) {
		t.Fatalf("отозванный шлюз: %v", err)
	}
}

// Шлюз не может выдать события за другой шлюз: поля шлюза в теле нет, а
// неизвестное поле — 400.
func TestEventsBatchRejectsGatewayInBody(t *testing.T) {
	e := newMTLSEnv(t)
	reg := e.registerGateway(t, "gw-1")
	c := e.client(t, reg.CertPEM, reg.KeyPEM)
	ev := newEvent(t)
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"events":[` + strings.Replace(string(b), `{"id"`, `{"gateway_id":"00000000-0000-7000-8000-000000000001","id"`, 1) + `]}`
	resp, err := post(t, c, e.internal, "/internal/v1/events:batch", body)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("поле шлюза в событии: %v %v", resp, err)
	}
	resp, err = post(t, c, e.internal, "/internal/v1/events:batch", `{"gateway_id":"x","events":[`+string(b)+`]}`)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("поле шлюза в пакете: %v %v", resp, err)
	}
	if e.events.Len() != 0 {
		t.Fatal("событие записано")
	}
	// Без клиентского сертификата TLS не устанавливается.
	if _, err := post(t, e.client(t, nil, nil), e.internal, "/internal/v1/events:batch", `{"events":[`+string(b)+`]}`); err == nil {
		t.Fatal("приём событий без сертификата")
	}
}

// Ответы сервера и повторы внутри Send.
func TestServerSinkRetries(t *testing.T) {
	var mu sync.Mutex
	var statuses []int
	retryAfter := ""
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		_, _ = io.Copy(io.Discard, r.Body) //nolint:gosec // G104: тело тестового запроса не нужно
		st := http.StatusOK
		if len(statuses) > 0 {
			st, statuses = statuses[0], statuses[1:]
		}
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_, _ = io.WriteString(w, `{"accepted":1,"duplicates":0,"rejected":[]}`) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	sink, err := gateway.NewServerSink(gateway.ServerSinkConfig{Client: srv.Client(), Server: u, Logger: quiet(),
		Sleep: func(_ context.Context, d time.Duration) bool { waits = append(waits, d); return true }})
	if err != nil {
		t.Fatal(err)
	}
	reset := func(st []int, ra string) {
		mu.Lock()
		statuses, retryAfter, calls, waits = st, ra, 0, nil
		mu.Unlock()
	}
	batch := []events.Event{newEvent(t)}

	reset([]int{503, 502}, "")
	if err := sink.Send(context.Background(), batch); err != nil || calls != 3 {
		t.Fatalf("503, 502, 200: %v, вызовов %d", err, calls)
	}
	if len(waits) != 2 || waits[0] != time.Second || waits[1] != 2*time.Second {
		t.Fatalf("паузы %v", waits)
	}

	reset([]int{503, 503, 503}, "")
	if err := sink.Send(context.Background(), batch); !errors.Is(err, events.ErrRetryLater) || calls != 3 {
		t.Fatalf("сервер недоступен: %v, вызовов %d", err, calls)
	}

	reset([]int{400}, "")
	if err := sink.Send(context.Background(), batch); err == nil || errors.Is(err, events.ErrRetryLater) || calls != 1 {
		t.Fatalf("400 не повторяется: %v, вызовов %d", err, calls)
	}
	reset([]int{422}, "")
	if err := sink.Send(context.Background(), batch); err == nil || errors.Is(err, events.ErrRetryLater) || calls != 1 {
		t.Fatalf("422 не повторяется: %v, вызовов %d", err, calls)
	}

	reset([]int{429}, "3")
	if err := sink.Send(context.Background(), batch); err != nil || len(waits) != 1 || waits[0] != 3*time.Second {
		t.Fatalf("429 с Retry-After 3: %v, паузы %v", err, waits)
	}
	reset([]int{503}, "30")
	if err := sink.Send(context.Background(), batch); !errors.Is(err, events.ErrRetryLater) || calls != 1 {
		t.Fatalf("долгий Retry-After — сразу в очередь: %v, вызовов %d", err, calls)
	}
}

// Пакет больше предела делится на части.
func TestServerSinkSplitsLargeBatch(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b events.Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		sizes = append(sizes, len(b.Events))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accepted":0,"duplicates":0,"rejected":[]}`) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := gateway.NewServerSink(gateway.ServerSinkConfig{Client: srv.Client(), Server: u, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	batch := make([]events.Event, 200)
	for i := range batch {
		batch[i] = newEvent(t)
		batch[i].Content.Request = strings.Repeat("я", 32<<10) // 64 КиБ
	}
	if err := sink.Send(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range sizes {
		total += n
	}
	if total != 200 || len(sizes) < 2 {
		t.Fatalf("части %v", sizes)
	}
}

// Отказ сервера в отдельном событии (storage) и обрезка содержимого не
// делают пакет ошибкой: шлюз считает отказ и пишет число обрезанных в
// журнал без содержимого (В10 ревью 2.r3a).
func TestServerSinkStorageRejectAndTruncated(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) //nolint:gosec // G104: тело тестового запроса не нужно
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accepted":1,"duplicates":0,"rejected":[{"index":1,"code":"storage"}],"truncated":1}`) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	sink, err := gateway.NewServerSink(gateway.ServerSinkConfig{Client: srv.Client(), Server: u,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Send(context.Background(), []events.Event{newEvent(t), newEvent(t)}); err != nil {
		t.Fatal(err)
	}
	if sink.Rejected() != 1 || !strings.Contains(logs.String(), "обрезал содержимое") || !strings.Contains(logs.String(), `"storage":1`) {
		t.Fatalf("отклонено %d, журнал: %s", sink.Rejected(), logs.String())
	}
}
