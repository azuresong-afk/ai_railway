package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/api"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/policy/toolrate"
)

// Сквозная проверка ИАФ.10 на настоящем TLS: регистрация на порту консоли
// по токену, heartbeat на внутренний порт по mTLS, отказ без сертификата,
// с сертификатом чужого УЦ и после отзыва.

type nopAuditor struct{}

func (nopAuditor) Record(context.Context, audit.Entry) error { return nil }

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type mtlsEnv struct {
	tp       aisecCrypto.TLSProvider
	ca       *aisecCrypto.CA
	mem      *gwregistry.Memory
	svc      *gwregistry.Service
	events   *events.Memory
	console  *url.URL
	internal *url.URL
}

func newMTLSEnv(t *testing.T) *mtlsEnv {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := aisecCrypto.NewCA("AISec test CA", 400*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	e := &mtlsEnv{tp: tp, ca: ca, mem: gwregistry.NewMemory(), events: events.NewMemory()}
	// Сертификат шлюза на 12 часов: heartbeat требует перевыпуск (истекает
	// раньше 30 суток), а сертификат не истекает вместе с УЦ (3В5 ревью 3.r1).
	e.svc, err = gwregistry.New(gwregistry.Options{Store: e.mem, Provider: p, CA: ca, Audit: nopAuditor{}, Logger: quiet(),
		CertValidity: 12 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	consoleH, _, err := api.New(api.Options{Logger: quiet(), Hasher: h, Gateways: e.svc})
	if err != nil {
		t.Fatal(err)
	}
	internalH, _, err := api.NewInternal(api.InternalOptions{Logger: quiet(), Hasher: h, Gateways: e.svc, Events: e.events})
	if err != nil {
		t.Fatal(err)
	}
	consoleTLS, err := tp.ServerConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	internalTLS, err := tp.MutualServerConfig(certPEM, keyPEM, ca.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	start := func(hd http.Handler, mutual bool) *url.URL {
		s := httptest.NewUnstartedServer(hd)
		s.TLS = consoleTLS
		if mutual {
			s.TLS = internalTLS
		}
		s.Config.ErrorLog = slog.NewLogLogger(quiet().Handler(), slog.LevelError)
		s.StartTLS()
		t.Cleanup(s.Close)
		u, err := url.Parse(s.URL)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	e.console = start(consoleH, false)
	e.internal = start(internalH, true)
	return e
}

func (e *mtlsEnv) client(t *testing.T, certPEM, keyPEM []byte) *http.Client {
	t.Helper()
	tr, err := gateway.ControlTransport(e.tp, e.ca.CertPEM(), certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func (e *mtlsEnv) registerGateway(t *testing.T, name string) gateway.Registration {
	t.Helper()
	tok, _, err := e.svc.IssueToken(context.Background(), gwregistry.TokenInput{Name: name, Actor: audit.Actor{Type: audit.ActorCLI, ID: "uid:0"}})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := gateway.Register(context.Background(), e.client(t, nil, nil), e.console, tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// reply — то, что тестам нужно от ответа; тело читается и закрывается в post.
type reply struct {
	StatusCode int
	Header     http.Header
}

func post(t *testing.T, c *http.Client, u *url.URL, path, body string) (reply, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, u.JoinPath(path).String(), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104: тело прочитано, ошибка закрытия тесту не важна
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return reply{}, err
	}
	return reply{StatusCode: resp.StatusCode, Header: resp.Header}, nil
}

func TestRegisterAndHeartbeatOverMTLS(t *testing.T) {
	e := newMTLSEnv(t)
	reg := e.registerGateway(t, "gw-1")
	if !bytes.Contains(reg.KeyPEM, []byte("PRIVATE KEY")) || reg.GatewayID == "" || reg.Name != "gw-1" {
		t.Fatalf("регистрация: %+v", reg.GatewayID)
	}
	if !bytes.Equal(reg.CAPEM, e.ca.CertPEM()) {
		t.Fatal("в ответе не корень внутреннего УЦ")
	}
	// Закрытый ключ шлюза сервер не видел: в реестре только серийный номер.
	c := e.client(t, reg.CertPEM, reg.KeyPEM)
	var stopped bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gateway.RunHeartbeat(ctx, gateway.HeartbeatConfig{
		Client: c, Server: e.internal, Version: "2.0.0", Logger: quiet(),
		Sleep: func(context.Context, time.Duration) bool { stopped = true; return false },
	})
	if !stopped {
		t.Fatal("цикл heartbeat не дошёл до паузы")
	}
	list, err := e.svc.List(context.Background())
	if err != nil || len(list) != 1 || list[0].Version != "2.0.0" || list[0].LastSeenAt.IsZero() {
		t.Fatalf("heartbeat не записан: %+v %v", list, err)
	}
	// Сразу второй heartbeat — 429 с Retry-After.
	resp, err := post(t, c, e.internal, "/internal/v1/heartbeat", `{"version":"2.0.0"}`)
	if err != nil || resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("частый heartbeat: %v %v", resp, err)
	}
}

func TestInternalAPIRejectsClients(t *testing.T) {
	e := newMTLSEnv(t)
	reg := e.registerGateway(t, "gw-1")

	t.Run("без сертификата", func(t *testing.T) {
		if _, err := post(t, e.client(t, nil, nil), e.internal, "/internal/v1/heartbeat", `{"version":"1"}`); err == nil {
			t.Fatal("внутренний API принял клиента без сертификата")
		}
	})
	t.Run("сертификат чужого УЦ", func(t *testing.T) {
		foreign, err := aisecCrypto.NewCA("Foreign CA", time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		key, csr, err := aisecCrypto.NewClientCSR("x")
		if err != nil {
			t.Fatal(err)
		}
		// Тот же CN, что у настоящего шлюза: имя не помогает без нашего УЦ.
		cert, _, err := foreign.IssueClient(csr, reg.GatewayID, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := post(t, e.client(t, cert, key), e.internal, "/internal/v1/heartbeat", `{"version":"1"}`); err == nil {
			t.Fatal("внутренний API принял сертификат чужого УЦ")
		}
	})
	t.Run("регистрация не на внутреннем порту", func(t *testing.T) {
		resp, err := post(t, e.client(t, reg.CertPEM, reg.KeyPEM), e.internal, "/api/v1/gateways/register", `{}`)
		if err != nil || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("маршрут консоли на внутреннем порту: %v %v", resp, err)
		}
	})
	t.Run("внутренний API не на порту консоли", func(t *testing.T) {
		resp, err := post(t, e.client(t, nil, nil), e.console, "/internal/v1/heartbeat", `{"version":"1"}`)
		if err != nil || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("heartbeat на порту консоли: %v %v", resp, err)
		}
	})
	t.Run("неверное тело", func(t *testing.T) {
		c := e.client(t, reg.CertPEM, reg.KeyPEM)
		for body, want := range map[string]int{
			`{"version":"1","extra":1}`: http.StatusBadRequest,
			`{"version":""}`:            http.StatusBadRequest,
			`{"version":"1 2"}`:         http.StatusBadRequest,
			`[]`:                        http.StatusBadRequest,
			`{"version":"` + strings.Repeat("1", 1<<20) + `"}`:                 http.StatusRequestEntityTooLarge,
			`{"version":"1","bundle_etag":"` + "é" + `"}`:                      http.StatusBadRequest,
			`{"version":"1"} {"version":"2"}`:                                  http.StatusBadRequest,
			`{"version":"1","bundle_etag":"` + strings.Repeat("a", 129) + `"}`: http.StatusBadRequest,
		} {
			resp, err := post(t, c, e.internal, "/internal/v1/heartbeat", body)
			if err != nil || resp.StatusCode != want {
				t.Errorf("%.40s: %v %v, ожидается %d", body, resp, err, want)
			}
		}
	})
	t.Run("после отзыва", func(t *testing.T) {
		if _, err := e.svc.Revoke(context.Background(), "gw-1", audit.Actor{Type: audit.ActorCLI, ID: "uid:0"}); err != nil {
			t.Fatal(err)
		}
		resp, err := post(t, e.client(t, reg.CertPEM, reg.KeyPEM), e.internal, "/internal/v1/heartbeat", `{"version":"1"}`)
		if err != nil || resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("отозванный шлюз: %v %v", resp, err)
		}
	})
}

func TestRegisterRejected(t *testing.T) {
	e := newMTLSEnv(t)
	bad := gwregistry.TokenPrefix + strings.Repeat("A", gwregistry.TokenLen-len(gwregistry.TokenPrefix))
	_, err := gateway.Register(context.Background(), e.client(t, nil, nil), e.console, bad, nil)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("неверный токен: %v", err)
	}
	if strings.Contains(err.Error(), bad) {
		t.Fatal("токен в тексте ошибки")
	}
	// Тело регистрации ограничено.
	resp, err := post(t, e.client(t, nil, nil), e.console, "/api/v1/gateways/register",
		`{"token":"x","csr":"`+strings.Repeat("a", 17<<10)+`"}`)
	if err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("большое тело регистрации: %v %v", resp, err)
	}
	resp, err = post(t, e.client(t, nil, nil), e.console, "/api/v1/gateways/register", `{"token":"x","csr":"не CSR"}`)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("неверный CSR: %v %v", resp, err)
	}
}

// Регистрация без подключённого УЦ — 503.
func TestRegisterUnavailable(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	hd, _, err := api.New(api.Options{Logger: quiet(), Hasher: h})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/gateways/register", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	hd.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("код %d", rec.Code)
	}
}

// Реакция цикла heartbeat на ответы сервера: интервал, 401, Retry-After, сбой сети.
func TestHeartbeatBackoff(t *testing.T) {
	var mu sync.Mutex
	status, retry := http.StatusOK, ""
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now().Add(-time.Hour), "interval_seconds": 1}) //nolint:gosec // G104: ответ тестового сервера; обрыв увидит клиент
		} else {
			_, _ = io.WriteString(w, `{"detail":"нет"}`) //nolint:gosec // G104: ответ тестового сервера; обрыв увидит клиент
		}
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	steps := []func(){
		func() { status, retry = http.StatusUnauthorized, "" },
		func() { status, retry = http.StatusTooManyRequests, "120" },
		func() { srv.Close() },
	}
	gateway.RunHeartbeat(context.Background(), gateway.HeartbeatConfig{
		Client: srv.Client(), Server: u, Version: "1", Logger: quiet(),
		Sleep: func(_ context.Context, d time.Duration) bool {
			waits = append(waits, d)
			if len(waits) > len(steps) {
				return false
			}
			mu.Lock()
			steps[len(waits)-1]()
			mu.Unlock()
			return true
		},
	})
	// 200 с интервалом 1 с — не чаще 10 с; 401 — пауза 5 минут; 429 —
	// не меньше Retry-After; сбой сети — растущая пауза.
	want := []time.Duration{10 * time.Second, 5 * time.Minute, 120 * time.Second, 40 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("паузы %v", waits)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("пауза %d: %v, ожидается %v (все: %v)", i, waits[i], want[i], waits)
		}
	}
}

// Н38 ревью 2.r4: запрос проверки из консоли выполняется один раз, итог
// уходит со следующим heartbeat вместе с временем запроса.
func TestHeartbeatVerifyRequest(t *testing.T) {
	requested := time.Date(2026, 10, 22, 12, 0, 0, 123456000, time.UTC)
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b) //nolint:gosec // G104: тело проверяет тест
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now(), "interval_seconds": 60, "verify_requested_at": requested}) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	reports := &gateway.Reports{}
	verifies := 0
	var waits []time.Duration
	gateway.RunHeartbeat(context.Background(), gateway.HeartbeatConfig{
		Client: srv.Client(), Server: u, Version: "1", Logger: quiet(), Reports: reports,
		Verify: func(context.Context) {
			verifies++
			reports.SetIntegrity(false, time.Now(), "files_mismatch", 1, gateway.Manifest{})
		},
		Sleep: func(_ context.Context, d time.Duration) bool {
			waits = append(waits, d)
			return len(waits) < 3
		},
	})
	if verifies != 1 {
		t.Fatalf("проверок по одному запросу: %d", verifies)
	}
	// После проверки — следующий heartbeat через минимальную паузу, дальше — обычный период.
	if len(waits) != 3 || waits[0] != 10*time.Second || waits[1] != time.Minute {
		t.Fatalf("паузы %v", waits)
	}
	if _, ok := bodies[0]["verify_request"]; ok {
		t.Fatal("ответ на запрос до проверки")
	}
	got, _ := bodies[1]["verify_request"].(string)
	in, _ := bodies[1]["integrity"].(map[string]any)
	if at, err := time.Parse(time.RFC3339Nano, got); err != nil || !at.Equal(requested) || in["reason"] != "files_mismatch" {
		t.Fatalf("итог по запросу: %v", bodies[1])
	}
}

func TestControlTransportErrors(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.ControlTransport(tp, nil, nil, nil); err == nil {
		t.Fatal("транспорт без корня")
	}
	ca, err := aisecCrypto.NewCA("CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.ControlTransport(tp, ca.CertPEM(), []byte("x"), []byte("y")); err == nil {
		t.Fatal("транспорт с неверным сертификатом")
	}
	if !gateway.ValidVersion("2.0.0-rc.1+abc") || gateway.ValidVersion("") || gateway.ValidVersion("1 0") {
		t.Fatal("ValidVersion")
	}
}

// Время запуска уходит в каждом heartbeat, после отмены — heartbeat
// остановки с тем же временем (В27 ревью 2.r5, РСБ.2).
func TestHeartbeatStartedAndStopping(t *testing.T) {
	started := time.Date(2026, 10, 22, 9, 30, 0, 123456789, time.UTC)
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b) //nolint:gosec // G104: тело проверяет тест
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now(), "interval_seconds": 60}) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	gateway.RunHeartbeat(ctx, gateway.HeartbeatConfig{
		Client: srv.Client(), Server: u, Version: "1", Logger: quiet(), StartedAt: started,
		Sleep: func(context.Context, time.Duration) bool {
			cancel()
			return false
		},
	})
	if len(bodies) != 2 {
		t.Fatalf("heartbeat: %v", bodies)
	}
	for i, b := range bodies {
		got, _ := b["started_at"].(string)
		if at, err := time.Parse(time.RFC3339Nano, got); err != nil || !at.Equal(started) {
			t.Fatalf("started_at в heartbeat %d: %v", i, b)
		}
	}
	if _, ok := bodies[0]["stopping"]; ok || bodies[1]["stopping"] != true {
		t.Fatalf("stopping: %v", bodies)
	}
	// Без времени запуска (прежний режим) heartbeat остановки не уходит.
	bodies = nil
	gateway.RunHeartbeat(context.Background(), gateway.HeartbeatConfig{
		Client: srv.Client(), Server: u, Version: "1", Logger: quiet(),
		Sleep: func(context.Context, time.Duration) bool { return false },
	})
	if len(bodies) != 1 || bodies[0]["started_at"] != nil {
		t.Fatalf("без времени запуска: %v", bodies)
	}
}

// 3Н40 ревью 3.r3: время сервера из ответа heartbeat — в часах сроков
// исключений.
func TestHeartbeatObservesServerTime(t *testing.T) {
	ahead := time.Now().Add(5 * 24 * time.Hour)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"server_time": ahead, "interval_seconds": 60}) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	sc := &gateway.ServerClock{}
	if d := time.Until(sc.Now()); d > time.Minute {
		t.Fatalf("без heartbeat: %v", d)
	}
	gateway.RunHeartbeat(context.Background(), gateway.HeartbeatConfig{
		Client: srv.Client(), Server: u, Version: "1", Logger: quiet(), ServerTime: sc,
		Sleep: func(context.Context, time.Duration) bool { return false },
	})
	if got := sc.Now(); got.Before(ahead) || got.After(ahead.Add(time.Minute)) {
		t.Fatalf("часы сроков исключений: %v, сервер %v", got, ahead)
	}
}

// 3Н40, 3Н43 ревью 3.r3: heartbeat несёт часы шлюза и отпечаток
// действующего сертификата адреса приложений (пусто — сертификат шлюза),
// но только после ответа сервера с clock_tls: сервер прежней версии
// отклоняет неизвестные поля, а шлюзы обновляют раньше сервера. Без
// источника отпечатка поле не уходит.
func TestHeartbeatClockAndTLSFingerprint(t *testing.T) {
	var bodies []map[string]any
	clockTLS := true
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b) //nolint:gosec // G104: тело проверяет тест
		bodies = append(bodies, b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now(), "interval_seconds": 60, "clock_tls": clockTLS}) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC)
	fp := strings.Repeat("ab", 32)
	run := func(src func() string) {
		n := 0
		gateway.RunHeartbeat(context.Background(), gateway.HeartbeatConfig{
			Client: srv.Client(), Server: u, Version: "1", Logger: quiet(), Clock: func() time.Time { return at }, TLSFingerprint: src,
			Sleep: func(context.Context, time.Duration) bool { n++; return n < 2 },
		})
	}
	run(func() string { return fp })
	run(func() string { return "" })
	run(nil)
	clockTLS = false
	run(func() string { return fp })
	if len(bodies) != 8 {
		t.Fatalf("heartbeat: %v", bodies)
	}
	// Первый heartbeat каждого запуска — без полей: сервер ещё не ответил.
	for i := 0; i < 8; i += 2 {
		if _, ok := bodies[i]["time"]; ok || bodies[i]["tls_fingerprint"] != nil {
			t.Fatalf("первый heartbeat %d с новыми полями: %v", i, bodies[i])
		}
	}
	for i, want := range map[int]any{1: fp, 3: "", 5: nil} {
		got, _ := bodies[i]["time"].(string)
		if ts, err := time.Parse(time.RFC3339Nano, got); err != nil || !ts.Equal(at) || bodies[i]["tls_fingerprint"] != want {
			t.Fatalf("heartbeat %d: %v", i, bodies[i])
		}
	}
	// Сервер прежней версии: полей нет и во втором heartbeat.
	if _, ok := bodies[7]["time"]; ok || bodies[7]["tls_fingerprint"] != nil {
		t.Fatalf("сервер без clock_tls: %v", bodies[7])
	}
}

// Задача 5.9 этапа 5 (4Н11, 4Н13): heartbeat несёт заполнение и
// вытеснения счётчиков лимитов вызовов и сессий session.risk, но только
// после ответа сервера с limits — сервер прежней версии отклоняет
// неизвестные поля.
func TestHeartbeatLimits(t *testing.T) {
	var bodies []map[string]any
	limits := true
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b) //nolint:gosec // G104: тело проверяет тест
		bodies = append(bodies, b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now(), "interval_seconds": 60, "limits": limits}) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rates := toolrate.New(2)
	now := time.Now()
	for _, k := range []string{"a", "b", "c"} {
		rates.Hit(k, time.Minute, 10, now)
	}
	report := func() *gateway.LimitsReport { return gateway.NewLimitsReport(rates, nil) }
	run := func() {
		n := 0
		gateway.RunHeartbeat(context.Background(), gateway.HeartbeatConfig{
			Client: srv.Client(), Server: u, Version: "1", Logger: quiet(), Limits: report,
			Sleep: func(context.Context, time.Duration) bool { n++; return n < 2 },
		})
	}
	run()
	limits = false
	run()
	if len(bodies) != 4 {
		t.Fatalf("heartbeat: %v", bodies)
	}
	if _, ok := bodies[0]["limits"]; ok {
		t.Fatalf("первый heartbeat с limits: %v", bodies[0])
	}
	got, _ := bodies[1]["limits"].(map[string]any)
	tr, _ := got["tool_rate"].(map[string]any)
	if tr["keys"] != 2.0 || tr["max_keys"] != 2.0 || tr["evictions"] != 1.0 {
		t.Fatalf("limits: %v", bodies[1])
	}
	if _, ok := got["sessions"]; ok {
		t.Fatalf("сессий нет, а раздел передан: %v", got)
	}
	if _, ok := bodies[3]["limits"]; ok {
		t.Fatalf("сервер без limits: %v", bodies[3])
	}
}

// 5Н4 ревью 5.r1 этапа 5: сервер откатили на выпуск без limits — строгий
// разбор отвечает 400 на heartbeat с этим полем. Шлюз сбрасывает признаки
// возможностей и сразу повторяет heartbeat без необязательных полей, а не
// выглядит недоступным до перезапуска.
func TestHeartbeatRetriesWithoutOptionalFieldsOn400(t *testing.T) {
	var bodies []map[string]any
	strict := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b) //nolint:gosec // G104: тело проверяет тест
		bodies = append(bodies, b)
		w.Header().Set("Content-Type", "application/json")
		if _, ok := b["limits"]; ok && strict {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"invalid_request"}`)) //nolint:gosec // G104: ответ тестового сервера
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now(), "interval_seconds": 60, "limits": !strict, //nolint:gosec // G104: ответ тестового сервера
			"clock_tls": !strict})
		strict = true
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rates := toolrate.New(2)
	report := func() *gateway.LimitsReport { return gateway.NewLimitsReport(rates, nil) }
	var waits []time.Duration
	n := 0
	gateway.RunHeartbeat(context.Background(), gateway.HeartbeatConfig{
		Client: srv.Client(), Server: u, Version: "1", Logger: quiet(), Limits: report,
		Sleep: func(_ context.Context, d time.Duration) bool { waits = append(waits, d); n++; return n < 3 },
	})
	// 1 — без признаков; 2 — с limits и time, 400; 3 — сразу без них; 4 — без них.
	if len(bodies) != 4 {
		t.Fatalf("heartbeat: %d %v", len(bodies), bodies)
	}
	if _, ok := bodies[1]["limits"]; !ok {
		t.Fatalf("второй heartbeat без limits: %v", bodies[1])
	}
	for _, i := range []int{2, 3} {
		if _, ok := bodies[i]["limits"]; ok {
			t.Fatalf("heartbeat %d после 400 с limits: %v", i+1, bodies[i])
		}
		if _, ok := bodies[i]["time"]; ok {
			t.Fatalf("heartbeat %d после 400 с time: %v", i+1, bodies[i])
		}
	}
	if waits[1] != time.Minute {
		t.Fatalf("после повтора — отсрочка, а не интервал сервера: %v", waits)
	}
}
