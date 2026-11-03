package redteam

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect/canary"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/mockllm"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

const (
	testAppID  = "01900000-0000-7000-8000-0000000000a1"
	testTarget = "http://bot.example.test:8080/v1/chat/completions"
)

var admin = By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000b1", Name: "secadmin"},
	IP: netip.MustParseAddr("192.0.2.10"), Confirm: func(context.Context) error { return nil }}

// fakeApps — приложение testAppID с моделью m и провайдер-оценщик judge.
type fakeApps struct{}

func (fakeApps) Application(_ context.Context, id, _ string) (apps.Application, error) {
	if id != testAppID {
		return apps.Application{}, apps.ErrNotFound
	}
	return apps.Application{ID: testAppID, Slug: "crm-bot", Models: []string{"m"}}, nil
}

func (fakeApps) Providers(context.Context) ([]apps.Provider, error) {
	return []apps.Provider{{ID: "p1", Slug: "local-llm", Type: "openai", OnPremise: true}, {ID: "p2", Slug: "cloud", Type: "openai"}}, nil
}

func (fakeApps) OpenCredential(context.Context, string) ([]byte, error) { return nil, nil }

type env struct {
	t     *testing.T
	s     *Service
	mem   *Memory
	p     aisecCrypto.Provider
	mock  *httptest.Server
	llm   *mockllm.Server
	ctx   context.Context
	stop  context.CancelFunc
	conns atomic.Int32
	// addrs — проверенные адреса, с которыми исполнитель соединялся.
	mu    sync.Mutex
	addrs []string
	ips   []netip.Addr
}

func newEnv(t *testing.T, mod func(*Options)) *env {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, p: p, mem: NewMemory(), ips: []netip.Addr{netip.MustParseAddr("10.0.0.5")}}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	key, err := aisecCrypto.RandomBytes(rnd, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	box, err := keyring.NewStaticKey(p, "01900000-0000-7000-8000-0000000000d1", key)
	if err != nil {
		t.Fatal(err)
	}
	e.llm = mockllm.New(quiet())
	e.mock = httptest.NewServer(e.llm.Handler())
	t.Cleanup(e.mock.Close)
	o := Options{Store: e.mem, ServiceDBs: servicedb.NewMemory(), Provider: p, Box: box, Apps: fakeApps{}, Logger: quiet(),
		KeyWait: 2 * time.Second, KeyPoll: 20 * time.Millisecond, Lookup: e.lookup}
	if mod != nil {
		mod(&o)
	}
	if e.s, err = New(o); err != nil {
		t.Fatal(err)
	}
	e.s.connect = e.connect(e.mock.Listener.Addr().String())
	data, err := os.ReadFile("../../testdata/redteam/scenarios-test.aisecdb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.DB().Upload(context.Background(), servicedb.By{Actor: admin.Actor}, data); err != nil {
		t.Fatal(err)
	}
	e.ctx, e.stop = context.WithCancel(context.Background())
	t.Cleanup(func() {
		e.stop()
		e.s.Wait()
	})
	if err := e.s.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	return e
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

func (e *env) lookup(_ context.Context, _, host string) ([]netip.Addr, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if host != "bot.example.test" {
		return nil, errors.New("нет такого имени")
	}
	return slices.Clone(e.ips), nil
}

func (e *env) setIPs(ips ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ips = nil
	for _, s := range ips {
		e.ips = append(e.ips, netip.MustParseAddr(s))
	}
}

// connect — соединение с проверенным адресом уходит на мок.
func (e *env) connect(real string) Connect {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		e.mu.Lock()
		e.addrs = append(e.addrs, addr)
		e.mu.Unlock()
		e.conns.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, real)
	}
}

func endpointInput(mod func(*TargetInput)) TargetInput {
	in := TargetInput{Name: "Чат-бот заказчика", Kind: KindEndpoint, URL: testTarget,
		RequestTemplate: `{"model": "m", "messages": "{{messages}}", "temperature": 0}`, ResponsePath: "choices.0.message.content",
		AuthorizationNote: "Договор о пилоте № 17 от 01.11.2026, письмо владельца адреса", Storage: StorageMasked,
		Headers: []Header{{Name: "X-Test", Value: "redteam"}}, Limits: &Limits{RatePerMinute: MaxRate, Concurrency: 2}}
	if mod != nil {
		mod(&in)
	}
	return in
}

func (e *env) target(mod func(*TargetInput)) Target {
	e.t.Helper()
	tg, err := e.s.CreateTarget(context.Background(), admin, endpointInput(mod))
	if err != nil {
		e.t.Fatal(err)
	}
	return tg
}

// rawTarget — цель в хранилище в обход проверки (пределы ниже допустимых
// для быстрых тестов сроков).
func (e *env) rawTarget(t Target) Target {
	e.t.Helper()
	t.ID, t.OrgID, t.CreatedAt, t.UpdatedAt, t.CreatedBy, t.UpdatedBy = "01900000-0000-7000-8000-0000000000c9", e.s.o.OrgID, time.Now(),
		time.Now(), "test", "test"
	if err := e.mem.CreateTarget(context.Background(), t, audit.Entry{}); err != nil {
		e.t.Fatal(err)
	}
	return t
}

func (e *env) start(in StartInput) Run {
	e.t.Helper()
	r, err := e.s.StartRun(context.Background(), admin, in)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *env) wait(id string) (Run, map[string]Result) {
	e.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r, res, err := e.s.Run(context.Background(), id)
		if err != nil {
			e.t.Fatal(err)
		}
		if r.Status != RunRunning && r.Status != RunQueued {
			// Запуск записан; исполнитель освобождает слот сразу после.
			for range 100 {
				e.s.mu.Lock()
				_, busy := e.s.active[id]
				e.s.mu.Unlock()
				if !busy {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			out := map[string]Result{}
			for _, x := range res {
				out[x.ScenarioID] = x
			}
			return r, out
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatal("запуск не завершился")
	return Run{}, nil
}

func (e *env) actions() []string {
	var out []string
	for _, r := range e.mem.Audit() {
		out = append(out, r.Action)
	}
	return out
}

// Канарейка (DM-08) в ответе цели даёт итог succeeded.
// Цель по адресу на mock-llm: маркер (contains), двухшаговый сценарий,
// канарейка (детектор canary, DM-08), judge без оценщика — unchecked;
// выдержка — только у succeeded в режиме masked; аудит начала и конца.
func TestRunEndpointMockLLM(t *testing.T) {
	e := newEnv(t, nil)
	rnd, err := e.p.Random()
	if err != nil {
		t.Fatal(err)
	}
	marker, err := canary.Generate(rnd)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.llm.Configure(mockllm.Options{Canary: marker}); err != nil {
		t.Fatal(err)
	}
	tg := e.target(nil)
	r := e.start(StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM01-001", "RT-DM06-001", "RT-DM08-001", "RT-DM19-001"}})
	if r.Status != RunRunning || r.Scenarios != 4 || r.KeyPrefix != "" {
		t.Fatalf("запуск: %+v", r)
	}
	done, res := e.wait(r.ID)
	if done.Status != RunDone || done.Counts[VerdictSucceeded] != 3 || done.Counts[VerdictUnchecked] != 1 {
		t.Fatalf("итог запуска: %+v", done)
	}
	if x := res["RT-DM01-001"]; x.Verdict != VerdictSucceeded || !slices.Equal(x.Matched, []string{MatchContains}) || x.Step != 1 ||
		x.HTTPStatus != 200 || x.Example == nil {
		t.Fatalf("DM-01: %+v", x)
	}
	if x := res["RT-DM06-001"]; x.Verdict != VerdictSucceeded || x.Step != 2 {
		t.Fatalf("DM-06 (два шага): %+v", x)
	}
	dm08 := res["RT-DM08-001"]
	if dm08.Verdict != VerdictSucceeded || !slices.Contains(dm08.Matched, MatchCanary) ||
		!slices.Contains(dm08.Findings, Finding{Detector: canary.ID, Category: canary.CatLeak, Threat: "DM-08"}) {
		t.Fatalf("DM-08: %+v", dm08)
	}
	if x := res["RT-DM19-001"]; x.Verdict != VerdictUnchecked || x.Judge != string(judge.ReasonUnavailable) {
		t.Fatalf("DM-19 без оценщика: %+v", x)
	}
	for _, x := range res {
		if x.Verdict != VerdictSucceeded && x.Example != nil {
			t.Fatalf("выдержка не у succeeded: %+v", x)
		}
	}
	if acts := e.actions(); !slices.Equal(acts, []string{ActionTargetCreated, ActionRunStarted, ActionRunFinished}) {
		t.Fatalf("аудит: %v", acts)
	}
	// Все соединения — на проверенный адрес цели.
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, a := range e.addrs {
		if a != "10.0.0.5:8080" {
			t.Fatalf("соединение не с адресом цели: %s", a)
		}
	}
}

// Секрет (DM-10) в ответе цели даёт итог succeeded по
// условию findings; в выдержке masked секрет заменён категорией.
func TestRunFindingsMasked(t *testing.T) {
	// Синтетическая строка подключения собирается при выполнении.
	secret := "postgres://app:" + "Q3a19q5o0m07!" + "@db.internal:5432/app"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		b, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "Вот: " + secret + " — пользуйтесь."}}}}) //nolint:gosec // G104: кодирование значений теста без ошибок
		_, _ = w.Write(b)                                                                                                                                  //nolint:gosec // G104: ответ мока, ошибка записи в тесте не важна
	}))
	defer srv.Close()
	e := newEnv(t, nil)
	e.s.connect = e.connect(srv.Listener.Addr().String())
	tg := e.target(nil)
	_, res := e.wait(e.start(StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM10-001"}}).ID)
	x := res["RT-DM10-001"]
	if x.Verdict != VerdictSucceeded || !slices.Equal(x.Matched, []string{MatchFindings}) ||
		!slices.Contains(x.Findings, Finding{Detector: "secrets", Category: "secret.connection_string", Threat: "DM-10"}) {
		t.Fatalf("DM-10: %+v", x)
	}
	// Выдержка хранится запечатанной (5В3 ревью 5.r3): в хранилище — ни
	// открытого текста, ни секрета; распечатка — только Service.Examples.
	if x.Example == nil || bytes.Contains(x.Example.Data, []byte("Вот:")) || bytes.Contains(x.Example.Data, []byte("Q3a19q5o0m07")) {
		t.Fatalf("выдержка в хранилище: %+v", x.Example)
	}
	ex, err := e.s.Examples(context.Background(), x.RunID)
	if err != nil || !strings.Contains(ex["RT-DM10-001"], "[secret.connection_string]") || strings.Contains(ex["RT-DM10-001"], "Q3a19q5o0m07") {
		t.Fatalf("выдержка: %q %v", ex, err)
	}
}

// Режим none — без выдержки; находки без условия сценария — defended;
// выдержка режима masked — до MaxExample байт по границе символа.
func TestExampleMaskedAndNone(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.target(func(in *TargetInput) { in.Storage = StorageNone })
	done, res := e.wait(e.start(StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM01-001", "RT-DM10-001"}}).ID)
	if done.Counts[VerdictSucceeded] != 1 || res["RT-DM01-001"].Example != nil {
		t.Fatalf("режим none: %+v %+v", done, res)
	}
	// Без канарейки в ответе секрета нет: условие findings не выполнено.
	if x := res["RT-DM10-001"]; x.Verdict != VerdictDefended || len(x.Matched) != 0 {
		t.Fatalf("DM-10 без секрета: %+v", x)
	}
	long := strings.Repeat("я", MaxExample)
	if ex := maskedExample(long, nil); len(ex) > MaxExample+len("…") || !strings.HasSuffix(ex, "…") {
		t.Fatalf("длина выдержки: %d", len(ex))
	}
}

// Оценщик judge.llm (ADR-0030) через стенд: нарушение — succeeded с
// условием judge; провайдер не «у заказчика» — без оценщика.
func TestRunJudge(t *testing.T) {
	var asked atomic.Int32
	e := newEnv(t, func(o *Options) {
		o.Judges = func(_ context.Context, slug string) (judge.Client, error) {
			asked.Add(1)
			if slug != "local-llm" {
				return nil, nil
			}
			return judge.Stand{Markers: map[string]string{judgeRule: "возврат"}}, nil
		}
	})
	tg := e.target(func(in *TargetInput) { in.JudgeProvider, in.JudgeModel = "local-llm", "qwen" })
	_, res := e.wait(e.start(StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM19-001"}}).ID)
	if x := res["RT-DM19-001"]; x.Verdict != VerdictSucceeded || x.Judge != JudgeViolated || !slices.Equal(x.Matched, []string{MatchJudge}) {
		t.Fatalf("оценщик: %+v", x)
	}
	if asked.Load() != 1 {
		t.Fatal("оценщик не запрошен")
	}
	if _, err := e.s.CreateTarget(context.Background(), admin, endpointInput(func(in *TargetInput) {
		in.JudgeProvider, in.JudgeModel = "cloud", "gpt"
	})); !isInput(err) {
		t.Fatalf("оценщик не «у заказчика» принят: %v", err)
	}
}

func isInput(err error) bool {
	var ie *InputError
	return errors.As(err, &ie)
}

// Защита от SSRF (ADR-0031, раздел 3): литерал запрещённого адреса и
// localhost — отказ при сохранении; имя, которое разрешается в loopback,
// адрес метаданных или набор с хотя бы одним запрещённым адресом, — отказ
// соединения (blocked_address) без обращения; проверка — при каждом
// соединении: после смены ответа DNS (rebinding) следующий запуск получает
// отказ.
func TestEndpointSSRF(t *testing.T) {
	e := newEnv(t, nil)
	for _, bad := range []string{"http://127.0.0.1:8080/x", "http://localhost:80/x", "http://169.254.169.254:80/latest",
		"http://[::1]:80/", "http://[fd00:ec2::254]:80/", "http://100.100.100.200:80/", "http://[::ffff:127.0.0.1]:80/",
		"http://0.0.0.0:80/", "http://bot.example.test/no-port", "ftp://bot.example.test:21/", "http://u:p@bot.example.test:80/"} {
		if _, err := e.s.CreateTarget(context.Background(), admin, endpointInput(func(in *TargetInput) { in.URL = bad })); !isInput(err) {
			t.Errorf("%s: адрес принят (%v)", bad, err)
		}
	}
	tg := e.target(nil)
	in := StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM01-001"}}
	if _, res := e.wait(e.start(in).ID); res["RT-DM01-001"].Verdict != VerdictSucceeded {
		t.Fatalf("разрешённый адрес: %+v", res)
	}
	before := e.conns.Load()
	for _, ips := range [][]string{{"127.0.0.1"}, {"169.254.169.254"}, {"10.0.0.5", "127.0.0.2"}, {"fd00:ec2::254"},
		{"64:ff9b::7f00:1"}, {"::"}} {
		e.setIPs(ips...)
		_, res := e.wait(e.start(in).ID)
		if x := res["RT-DM01-001"]; x.Verdict != VerdictError || x.ErrorCode != ErrCodeBlockedAddr {
			t.Fatalf("%v: %+v", ips, x)
		}
	}
	if e.conns.Load() != before {
		t.Fatal("соединение с запрещённым адресом")
	}
}

// Перенаправление не выполняется: 3xx — ошибка шага redirect, адрес из
// Location не запрашивается.
func TestEndpointRedirect(t *testing.T) {
	var hit atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Add(1) }))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}))
	defer redir.Close()
	e := newEnv(t, nil)
	e.s.connect = e.connect(redir.Listener.Addr().String())
	tg := e.target(nil)
	_, res := e.wait(e.start(StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM01-001"}}).ID)
	if x := res["RT-DM01-001"]; x.Verdict != VerdictError || x.ErrorCode != ErrCodeRedirect || x.HTTPStatus != http.StatusFound {
		t.Fatalf("перенаправление: %+v", x)
	}
	if hit.Load() != 0 {
		t.Fatal("исполнитель перешёл по перенаправлению")
	}
}

// Пределы: срок запроса, размер ответа, частота, параллельность.
func TestEndpointLimits(t *testing.T) {
	var cur, peak atomic.Int32
	var mu sync.Mutex
	var times []time.Time
	slowSize := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := cur.Add(1)
		defer cur.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		mu.Lock()
		times = append(times, time.Now())
		size := slowSize
		mu.Unlock()
		body, _ := io.ReadAll(r.Body) //nolint:gosec // G104: тело запроса к моку; неполное тело проверяет утверждение ниже
		switch {
		case strings.Contains(string(body), "ПРОБОЙ") && size < 0:
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-r.Context().Done():
			}
			return
		case size > 0:
			_, _ = w.Write([]byte(`{"answer":"` + strings.Repeat("a", size) + `"}`)) //nolint:gosec // G104: ответ мока, ошибка записи в тесте не важна
			return
		}
		time.Sleep(30 * time.Millisecond)
		_, _ = w.Write([]byte(`{"answer":"нет"}`)) //nolint:gosec // G104: ответ мока, ошибка записи в тесте не важна
	}))
	defer srv.Close()
	e := newEnv(t, nil)
	e.s.connect = e.connect(srv.Listener.Addr().String())
	base := Target{Name: "Быстрая", Kind: KindEndpoint, URL: testTarget, RequestTemplate: `{"q":"{{prompt}}"}`, ResponsePath: "answer",
		AuthorizationNote: "основание для теста", Storage: StorageNone, Headers: []Header{},
		Limits: Limits{RatePerMinute: 600, Concurrency: 1, RequestTimeoutSec: 1, RunTimeoutMin: 1}}
	tg := e.rawTarget(base)

	// Срок запроса: 1 с при ответе через 1,5 с.
	mu.Lock()
	slowSize = -1
	mu.Unlock()
	_, res := e.wait(e.start(StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM01-001"}}).ID)
	if x := res["RT-DM01-001"]; x.Verdict != VerdictError || x.ErrorCode != ErrCodeTimeout {
		t.Fatalf("срок запроса: %+v", x)
	}
	// Ответ больше MaxResponse.
	mu.Lock()
	slowSize = MaxResponse + 10
	mu.Unlock()
	_, res = e.wait(e.start(StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM01-001"}}).ID)
	if x := res["RT-DM01-001"]; x.Verdict != VerdictError || x.ErrorCode != ErrCodeTooLarge {
		t.Fatalf("размер ответа: %+v", x)
	}
	// Частота 600 в минуту (100 мс) и параллельность 1: шесть запросов
	// пяти сценариев — не быстрее 0,5 с, одновременно — не больше одного.
	mu.Lock()
	slowSize, times = 0, nil
	mu.Unlock()
	peak.Store(0)
	done, _ := e.wait(e.start(StartInput{TargetID: tg.ID}).ID)
	mu.Lock()
	n, span := len(times), times[len(times)-1].Sub(times[0])
	mu.Unlock()
	if done.Status != RunDone || n != 6 || span < 450*time.Millisecond || peak.Load() != 1 {
		t.Fatalf("частота и параллельность: %+v, запросов %d за %v, одновременно %d", done, n, span, peak.Load())
	}
	// Параллельность 2: одновременно — не больше двух.
	base.Limits.Concurrency = 2
	base.Name = "Две"
	e.mem.mu.Lock()
	base.ID, base.OrgID = "01900000-0000-7000-8000-0000000000ca", e.s.o.OrgID
	e.mem.targets[base.ID] = base
	e.mem.mu.Unlock()
	peak.Store(0)
	e.wait(e.start(StartInput{TargetID: base.ID}).ID)
	if p := peak.Load(); p < 1 || p > 2 {
		t.Fatalf("параллельность 2: одновременно %d", p)
	}
}

// Срок запуска и отмена: оставшиеся сценарии — skipped; отмена — запись
// аудита redteam.run_cancelled от пользователя; второй запуск той же цели
// во время первого — ErrBusy.
func TestRunDeadlineCancelBusy(t *testing.T) {
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(hang)
	e := newEnv(t, nil)
	e.s.connect = e.connect(srv.Listener.Addr().String())
	tg := e.rawTarget(Target{Name: "Зависает", Kind: KindEndpoint, URL: testTarget, RequestTemplate: `{"q":"{{prompt}}"}`,
		ResponsePath: "a", AuthorizationNote: "основание для теста", Headers: []Header{},
		Limits: Limits{RatePerMinute: 600, Concurrency: 1, RequestTimeoutSec: 60, RunTimeoutMin: 1}})
	e.s.runTimeout = 300 * time.Millisecond
	done, res := e.wait(e.start(StartInput{TargetID: tg.ID}).ID)
	if done.Status != RunFailed || done.Reason != ReasonDeadline || done.Counts[VerdictSkipped] != 5 || len(res) != 5 {
		t.Fatalf("срок запуска: %+v", done)
	}
	e.s.runTimeout = time.Minute
	r := e.start(StartInput{TargetID: tg.ID})
	if _, err := e.s.StartRun(context.Background(), admin, StartInput{TargetID: tg.ID}); !errors.Is(err, ErrBusy) {
		t.Fatalf("второй запуск цели: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := e.s.Cancel(context.Background(), admin, r.ID); err != nil {
		t.Fatal(err)
	}
	done, _ = e.wait(r.ID)
	if done.Status != RunCancelled || done.Counts[VerdictSkipped] != 5 {
		t.Fatalf("отмена: %+v", done)
	}
	if err := e.s.Cancel(context.Background(), admin, r.ID); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("повторная отмена: %v", err)
	}
	recs := e.mem.Audit()
	last := recs[len(recs)-1]
	if last.Action != ActionRunCancelled || last.Actor.ID != admin.Actor.ID {
		t.Fatalf("аудит отмены: %+v", last)
	}
}

// fakeGateway — шлюз: ключи запусков из TestKeys (как в пакете),
// /v1/models — 401, пока «пакет не дошёл» (delay запросов), блокировка
// запроса с ПРОБОЙ, остальное — mock-llm.
type fakeGateway struct {
	t      *testing.T
	s      *Service
	h      aisecCrypto.Hasher
	llm    http.Handler
	delay  atomic.Int32
	never  bool
	events atomic.Int32
}

func (g *fakeGateway) authorized(r *http.Request) bool {
	keys, err := g.s.TestKeys(r.Context(), time.Now())
	if err != nil {
		return false
	}
	var recs []auth.KeyRecord
	for app, ks := range keys {
		for _, k := range ks {
			if !k.Test {
				g.t.Error("ключ запуска без признака test")
			}
			recs = append(recs, auth.KeyRecord{AppID: app, Prefix: k.Prefix, SHA256: k.SHA256, Expires: k.ExpiresAt, Test: k.Test})
		}
	}
	a, err := auth.NewAuthenticator(g.h, recs)
	if err != nil {
		return false
	}
	id, fail := a.Authenticate(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), netip.MustParseAddr("127.0.0.1"), time.Now())
	return fail == nil && id.AppID == testAppID && id.Test
}

func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/models" {
		if g.never || g.delay.Add(-1) >= 0 || !g.authorized(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`)) //nolint:gosec // G104: ответ мока, ошибка записи в тесте не важна
		return
	}
	if !g.authorized(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	g.events.Add(1)
	w.Header().Set(headerEventID, "01900000-0000-7000-8000-00000000e00"+string(rune('0'+g.events.Load()%10)))
	body, _ := io.ReadAll(r.Body) //nolint:gosec // G104: тело запроса к фальшивому шлюзу; пустое тело даёт отказ проверки
	if strings.Contains(string(body), "ПРОБОЙ") {
		w.Header().Set(headerDecision, decisionBlock)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"запрос заблокирован политикой"}}`)) //nolint:gosec // G104: ответ мока, ошибка записи в тесте не важна
		return
	}
	w.Header().Set(headerDecision, "allow")
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	g.llm.ServeHTTP(w, r)
}

// Цель «приложение через шлюз»: ключ запуска выпускается на время запуска
// и доходит до шлюза через пакет (TestKeys, признак test), исполнитель
// ждёт его на /v1/models; блокировка шлюзом — blocked; ID событий шлюза —
// в результатах; после запуска ключа в пакете нет.
func TestRunGatewayTarget(t *testing.T) {
	g := &fakeGateway{t: t}
	gw := httptest.NewServer(g)
	defer gw.Close()
	e := newEnv(t, func(o *Options) { o.GatewayURL = gw.URL })
	g.s, g.llm = e.s, e.llm.Handler()
	h, err := e.p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	g.h = h
	g.delay.Store(3)
	tg, err := e.s.CreateTarget(context.Background(), By{Actor: admin.Actor}, TargetInput{Name: "CRM-бот", Kind: KindGateway, AppID: testAppID, Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	r := e.start(StartInput{TargetID: tg.ID, Lang: LangRU})
	if r.KeyPrefix == "" || len(r.KeyHash) == 0 || r.AppID != testAppID {
		t.Fatalf("ключ запуска: %+v", r)
	}
	keys, err := e.s.TestKeys(context.Background(), time.Now())
	if err != nil || len(keys[testAppID]) != 1 || keys[testAppID][0].Prefix != r.KeyPrefix ||
		keys[testAppID][0].SHA256 != hex.EncodeToString(r.KeyHash) || !keys[testAppID][0].ExpiresAt.After(r.Deadline) {
		t.Fatalf("ключи пакета: %+v %v", keys, err)
	}
	done, res := e.wait(r.ID)
	if done.Status != RunDone || done.Scenarios != 3 {
		t.Fatalf("запуск: %+v", done)
	}
	if x := res["RT-DM01-001"]; x.Verdict != VerdictBlocked || len(x.EventIDs) != 1 || x.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("блокировка шлюзом: %+v", x)
	}
	if x := res["RT-DM10-001"]; x.Verdict != VerdictDefended || len(x.EventIDs) != 1 || x.Example != nil {
		t.Fatalf("защищено: %+v", x)
	}
	if keys, err := e.s.TestKeys(context.Background(), time.Now()); err != nil || len(keys) != 0 {
		t.Fatalf("ключ после запуска: %+v %v", keys, err)
	}
	// Ключ, который не дошёл до шлюза.
	g.never = true
	done, _ = e.wait(e.start(StartInput{TargetID: tg.ID}).ID)
	if done.Status != RunFailed || done.Reason != ReasonKeyNotDelivered || done.Counts[VerdictSkipped] != 5 {
		t.Fatalf("ключ не дошёл: %+v", done)
	}
}

// Без адреса шлюза цели gateway не запускаются; цель — только приложение
// продукта с разрешённой моделью.
func TestGatewayTargetChecks(t *testing.T) {
	e := newEnv(t, nil)
	for _, in := range []TargetInput{
		{Name: "a", Kind: KindGateway, AppID: "01900000-0000-7000-8000-0000000000ff", Model: "m"},
		{Name: "a", Kind: KindGateway, AppID: testAppID, Model: "other"},
		{Name: "a", Kind: KindGateway, AppID: testAppID, Model: "m", URL: testTarget},
	} {
		if _, err := e.s.CreateTarget(context.Background(), admin, in); !isInput(err) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	tg, err := e.s.CreateTarget(context.Background(), admin, TargetInput{Name: "CRM", Kind: KindGateway, AppID: testAppID, Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.StartRun(context.Background(), admin, StartInput{TargetID: tg.ID}); !errors.Is(err, ErrGatewayNotConfigured) {
		t.Fatalf("без адреса шлюза: %v", err)
	}
	if _, err := New(Options{Store: e.mem, ServiceDBs: servicedb.NewMemory(), Provider: e.p, Apps: fakeApps{},
		GatewayURL: "https://gw.example.test:8443"}); err == nil {
		t.Fatal("адрес шлюза https без корневого сертификата принят")
	}
}

// Цель endpoint: добавление, смена адреса и включение выдержек — с
// повторной проверкой; смена имени — без неё; без проверки (токен) — отказ; вид не меняется.
func TestTargetConfirm(t *testing.T) {
	e := newEnv(t, nil)
	noConfirm := By{Actor: admin.Actor}
	if _, err := e.s.CreateTarget(context.Background(), noConfirm, endpointInput(nil)); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("без повторной проверки: %v", err)
	}
	failed := By{Actor: admin.Actor, Confirm: func(context.Context) error { return errors.New("неверный пароль") }}
	if _, err := e.s.CreateTarget(context.Background(), failed, endpointInput(nil)); err == nil {
		t.Fatal("неверная повторная проверка принята")
	}
	tg := e.target(nil)
	if _, err := e.s.UpdateTarget(context.Background(), noConfirm, tg.ID, endpointInput(func(in *TargetInput) { in.Name = "Новое имя" })); err != nil {
		t.Fatalf("смена имени: %v", err)
	}
	if _, err := e.s.UpdateTarget(context.Background(), noConfirm, tg.ID, endpointInput(func(in *TargetInput) {
		in.URL = "http://other.example.test:8080/"
	})); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("смена адреса без проверки: %v", err)
	}
	// Включение хранения выдержек (none → masked) — с повторной проверкой,
	// отключение (masked → none) — без неё (5Н22 ревью 5.r3).
	none := endpointInput(func(in *TargetInput) { in.Name, in.Storage = "Новое имя", StorageNone })
	if _, err := e.s.UpdateTarget(context.Background(), noConfirm, tg.ID, none); err != nil {
		t.Fatalf("отключение выдержек: %v", err)
	}
	masked := endpointInput(func(in *TargetInput) { in.Name = "Новое имя" })
	if _, err := e.s.UpdateTarget(context.Background(), noConfirm, tg.ID, masked); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("включение выдержек без проверки: %v", err)
	}
	if got, err := e.s.UpdateTarget(context.Background(), admin, tg.ID, masked); err != nil || got.Storage != StorageMasked {
		t.Fatalf("включение выдержек с проверкой: %+v %v", got, err)
	}
	if _, err := e.s.UpdateTarget(context.Background(), admin, tg.ID, TargetInput{Name: "x", Kind: KindGateway, AppID: testAppID, Model: "m"}); !isInput(err) {
		t.Fatalf("смена вида: %v", err)
	}
	if err := e.s.DeleteTarget(context.Background(), admin, tg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Target(context.Background(), tg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("удалённая цель: %v", err)
	}
	// В аудите — адрес и основание, без значений заголовков.
	for _, r := range e.mem.Audit() {
		b, _ := json.Marshal(r.Details) //nolint:gosec // G104: кодирование значений теста без ошибок
		if strings.Contains(string(b), `"redteam"`) {
			t.Fatalf("значение заголовка в аудите: %s", b)
		}
	}
}

// Запуск: неизвестная цель, неверный фильтр, секретный заголовок.
func TestStartRunInput(t *testing.T) {
	e := newEnv(t, nil)
	tg := e.target(func(in *TargetInput) { in.AuthHeader = "Authorization" })
	for _, in := range []StartInput{
		{TargetID: "01900000-0000-7000-8000-0000000000ee"},
		{TargetID: tg.ID, Scenarios: []string{"RT-NONE-001"}, AuthValue: "Bearer x"},
		{TargetID: tg.ID, Threats: []string{"DM-1"}, AuthValue: "Bearer x"},
		{TargetID: tg.ID, Lang: "de", AuthValue: "Bearer x"},
		{TargetID: tg.ID},
		{TargetID: tg.ID, AuthValue: "a\nb"},
	} {
		if _, err := e.s.StartRun(context.Background(), admin, in); !isInput(err) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	if _, err := e.s.StartRun(context.Background(), admin, StartInput{TargetID: tg.ID, Threats: []string{"DM-33"}, AuthValue: "Bearer x"}); !errors.Is(err, ErrNoScenarios) {
		t.Fatalf("пустой выбор: %v", err)
	}
	// Значение секретного заголовка уходит цели и не попадает в хранилище.
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization") + "|" + r.Header.Get("X-Test") + "|" + r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"нет"}}]}`)) //nolint:gosec // G104: ответ мока, ошибка записи в тесте не важна
	}))
	defer srv.Close()
	e.s.connect = e.connect(srv.Listener.Addr().String())
	e.wait(e.start(StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM10-001"}, AuthValue: "Bearer s3cr3t-value"}).ID)
	if got.Load() != "Bearer s3cr3t-value|redteam|aisec-redteam" {
		t.Fatalf("заголовки запроса: %v", got.Load())
	}
	b, _ := json.Marshal(e.mem) //nolint:gosec // G104: кодирование значений теста без ошибок
	for _, r := range e.mem.Audit() {
		d, _ := json.Marshal(r.Details) //nolint:gosec // G104: кодирование значений теста без ошибок
		b = append(b, d...)
	}
	if strings.Contains(string(b), "s3cr3t") {
		t.Fatal("значение секретного заголовка сохранено")
	}
}

// Незавершённые запуски прошлого процесса — failed (interrupted) с аудитом.
func TestInterruptOnStart(t *testing.T) {
	e := newEnv(t, nil)
	run := Run{ID: "01900000-0000-7000-8000-0000000000d1", OrgID: e.s.o.OrgID, TargetName: "x", TargetKind: KindEndpoint,
		Status: RunRunning, Counts: Counts{}, StartedAt: time.Now(), Deadline: time.Now().Add(time.Hour)}
	if err := e.mem.CreateRun(context.Background(), run, audit.Entry{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := e.s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	r, _, err := e.s.Run(context.Background(), run.ID)
	if err != nil || r.Status != RunFailed || r.Reason != ReasonInterrupted || r.FinishedAt == nil {
		t.Fatalf("прерванный запуск: %+v %v", r, err)
	}
}
