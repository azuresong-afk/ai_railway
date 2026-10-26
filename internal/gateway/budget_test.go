package gateway

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Учёт расхода и жёсткие бюджеты (задача 3.18).

// budgetClock — подменяемые часы теста.
type budgetClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *budgetClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *budgetClock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

// newTestBudget — пояс Москвы, цена модели m провайдера up: 5 ₽ за 1 000
// токенов входа и выхода — 50 000 единиц 1e-7 ₽ за токен; бюджеты hard.
func newTestBudget(t *testing.T, clock *budgetClock, hard ...bundle.HardBudget) *Budget {
	t.Helper()
	b := NewBudget(clock.now)
	err := b.Reconfigure(&bundle.Budgets{Timezone: "Europe/Moscow",
		Prices: []bundle.ModelPrice{{Provider: "up", Model: "m", Input: 50_000, Output: 50_000}}, Hard: hard})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Покрывает: DM-15
func TestDM15_HardBudgetBlocks(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	// Ответ провайдера — 1 токен входа и 1 выхода: 100 000 единиц, 1 копейка.
	// Бюджет — 2 копейки: второй запрос доводит расход ровно до 100 %.
	budget := newTestBudget(t, clock, bundle.HardBudget{App: "app", Limit: 200_000})
	up, rec := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.budget = budget; log = o.events })
	for i := range 2 {
		if resp := postChat(t, g, chatBody, nil); resp.Code != http.StatusOK {
			t.Fatalf("запрос %d в пределах бюджета: %d %s", i+1, resp.Code, resp.Body.String())
		}
	}
	resp := postChat(t, g, chatBody, nil)
	if resp.Code != http.StatusTooManyRequests || errCode(t, resp) != "budget_exceeded" {
		t.Fatalf("ровно 100 %% бюджета: %d %s", resp.Code, resp.Body.String())
	}
	// До начала ноября по Москве (2026-10-31T21:00Z).
	want := time.Date(2026, 10, 31, 21, 0, 0, 0, time.UTC).Sub(clock.now())
	if got := resp.Header().Get("Retry-After"); got != strconv.FormatInt(int64(want/time.Second), 10) {
		t.Fatalf("Retry-After: %q, ожидается %v", got, want)
	}
	if resp.Header().Get(HeaderDecision) != "block" {
		t.Fatalf("X-AISec-Decision: %q", resp.Header().Get(HeaderDecision))
	}
	if _, _, _, calls := rec.get(); calls != 2 {
		t.Fatalf("сверх бюджета до провайдера дошло: %d запросов из 3", calls)
	}
	e := lastEvent(t, log, resp)
	if e.Decision.Rule != ruleBudget || e.Decision.Action != "block" || !slices.Equal(e.Threats, []string{"DM-15"}) {
		t.Fatalf("событие: %+v %v", e.Decision, e.Threats)
	}
	// Эмбеддинги того же приложения тоже отклоняются; Check API модель не
	// вызывает и бюджет не тратит.
	eup, _ := embUpstream(t)
	ge := newGateway(t, eup.URL, func(o *gwOpts) { o.budget = budget })
	if resp := postEmb(t, ge, `{"model":"m","input":"x"}`); resp.Code != http.StatusTooManyRequests || errCode(t, resp) != "budget_exceeded" {
		t.Fatalf("эмбеддинги: %d %s", resp.Code, resp.Body.String())
	}
	if resp := postCheck(t, g, `{"direction":"input","text":"раз"}`); resp.Code != http.StatusOK {
		t.Fatalf("Check API: %d %s", resp.Code, resp.Body.String())
	}
	// Отказ не тратит бюджет: расход — два запроса.
	rep := budget.report()
	if len(rep.Months) != 1 || len(rep.Months[0].Apps) != 1 {
		t.Fatalf("отчёт: %+v", rep)
	}
	if u := rep.Months[0].Apps[0]; u.Cost != 200_000 || u.Requests != 2 || u.PricedTokens != 4 || u.UnpricedRequests != 0 {
		t.Fatalf("счётчики: %+v", u)
	}
	// Повышение бюджета в новом пакете снимает отказ.
	if err := budget.Reconfigure(&bundle.Budgets{Timezone: "Europe/Moscow",
		Prices: []bundle.ModelPrice{{Provider: "up", Model: "m", Input: 50_000, Output: 50_000}},
		Hard:   []bundle.HardBudget{{App: "app", Limit: 300_000}}}); err != nil {
		t.Fatal(err)
	}
	if resp := postChat(t, g, chatBody, nil); resp.Code != http.StatusOK {
		t.Fatalf("после повышения бюджета: %d %s", resp.Code, resp.Body.String())
	}
}

// Месяц расхода — в часовом поясе установки: последняя секунда октября по
// Москве — ещё октябрь, следующая — ноябрь, и бюджет снова доступен.
func TestBudgetMonthRolloverInTimezone(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 31, 20, 59, 59, 0, time.UTC)}
	b := newTestBudget(t, clock, bundle.HardBudget{App: "app", Limit: 100_000})
	b.Record("app", "up", "m", 1, 1)
	out, wait := b.Exhausted("app")
	if !out || wait != time.Second {
		t.Fatalf("23:59:59 по Москве: %v %v", out, wait)
	}
	clock.set(time.Date(2026, 10, 31, 21, 0, 0, 0, time.UTC))
	if out, _ := b.Exhausted("app"); out {
		t.Fatal("в новом месяце бюджет исчерпан")
	}
	b.Record("app", "up", "m", 1, 0)
	rep := b.report()
	if len(rep.Months) != 2 || rep.Months[0].Month != "2026-10" || rep.Months[1].Month != "2026-11" {
		t.Fatalf("месяцы: %+v", rep.Months)
	}
	if rep.Months[1].Apps[0].Cost != 50_000 {
		t.Fatalf("ноябрь: %+v", rep.Months[1].Apps)
	}
	// Сервер принял отчёт: октябрь больше не отправляется.
	b.apply(rep, &budgetState{Month: "2026-11"})
	if rep := b.report(); len(rep.Months) != 1 || rep.Months[0].Month != "2026-11" {
		t.Fatalf("после подтверждения: %+v", rep.Months)
	}
	// Хранятся только текущий и прошлый месяц.
	clock.set(time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC))
	b.Record("app", "up", "m", 1, 0)
	if rep := b.report(); len(rep.Months) != 2 || rep.Months[1].Month != "2027-01" {
		t.Fatalf("старые месяцы: %+v", rep.Months)
	}
}

// Расход остальных процессов и шлюзов из ответа heartbeat складывается со
// своим; ответ за другой месяц не учитывается.
func TestBudgetOthersFromServer(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b := newTestBudget(t, clock, bundle.HardBudget{App: "app", Limit: 1_000_000}, bundle.HardBudget{App: "other", Limit: 1})
	b.Record("app", "up", "m", 5, 4) // 450 000
	rep := b.report()
	b.apply(rep, &budgetState{Month: "2026-09", Others: map[string]int64{"app": 600_000}})
	if out, _ := b.Exhausted("app"); out {
		t.Fatal("учтён расход другого месяца")
	}
	b.apply(rep, &budgetState{Month: "2026-10", Others: map[string]int64{"app": 549_999, "x": -5}})
	if out, _ := b.Exhausted("app"); out {
		t.Fatal("999 999 из 1 000 000 — исчерпан")
	}
	b.apply(rep, &budgetState{Month: "2026-10", Others: map[string]int64{"app": 550_000}})
	if out, _ := b.Exhausted("app"); !out {
		t.Fatal("ровно бюджет вместе с чужим расходом — не исчерпан")
	}
	// Приложение без жёсткого бюджета и неизвестное не отклоняются.
	if out, _ := b.Exhausted("free"); out {
		t.Fatal("приложение без бюджета")
	}
	// Ответ без раздела budget или неверный месяц ничего не меняют.
	b.apply(rep, nil)
	b.apply(rep, &budgetState{Month: "2026-13"})
	if out, _ := b.Exhausted("app"); !out {
		t.Fatal("неверный ответ сбросил чужой расход")
	}
}

// Модель без цены: стоимость не определена, запрос не отклоняется, токены
// и запросы считаются отдельно.
func TestBudgetUnpricedModel(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b := newTestBudget(t, clock, bundle.HardBudget{App: "app", Limit: 1})
	b.Record("app", "up", "unknown-model", 100, 50)
	b.Record("app", "other-provider", "m", 1, 1)
	if out, _ := b.Exhausted("app"); out {
		t.Fatal("расход без цены исчерпал бюджет")
	}
	u := b.report().Months[0].Apps[0]
	if u.Cost != 0 || u.UnpricedRequests != 2 || u.UnpricedTokens != 152 || u.Requests != 2 || u.PricedTokens != 0 {
		t.Fatalf("счётчики: %+v", u)
	}
}

// Переполнение: огромные токены и цены дают насыщение, а не отрицательный
// расход; в heartbeat счётчики не больше 2^62.
func TestBudgetOverflowSaturates(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b := NewBudget(clock.now)
	if err := b.Reconfigure(&bundle.Budgets{Timezone: "UTC",
		Prices: []bundle.ModelPrice{{Provider: "up", Model: "m", Input: bundle.MaxPrice, Output: bundle.MaxPrice}},
		Hard:   []bundle.HardBudget{{App: "app", Limit: bundle.MaxBudget}}}); err != nil {
		t.Fatal(err)
	}
	b.Record("app", "up", "m", math.MaxInt64, math.MaxInt64)
	b.Record("app", "up", "m", math.MaxInt64, -1)
	if out, _ := b.Exhausted("app"); !out {
		t.Fatal("насыщенный расход не исчерпал бюджет")
	}
	u := b.report().Months[0].Apps[0]
	if u.Cost != maxBudgetCounter || u.PricedTokens != maxBudgetCounter || u.Requests != 2 {
		t.Fatalf("счётчики в отчёте: %+v", u)
	}
}

// Без раздела budgets расход не считается и запросы не отклоняются; неверный
// часовой пояс — пакет отклоняется, прежние бюджеты действуют.
func TestBudgetReconfigure(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b := newTestBudget(t, clock, bundle.HardBudget{App: "app", Limit: 1})
	b.Record("app", "up", "m", 1, 0)
	if err := b.Reconfigure(&bundle.Budgets{Timezone: "Mars/Olympus"}); err == nil {
		t.Fatal("неизвестный часовой пояс принят")
	}
	if out, _ := b.Exhausted("app"); !out {
		t.Fatal("неудачная смена пакета сбросила бюджеты")
	}
	if err := b.Reconfigure(nil); err != nil {
		t.Fatal(err)
	}
	b.Record("app", "up", "m", 1, 0)
	if out, _ := b.Exhausted("app"); out || b.report() != nil {
		t.Fatal("без раздела budgets бюджет применяется или счётчики уходят на сервер")
	}
	// Счётчики процесса нарастающие: возврат раздела их не обнуляет.
	b = newTestBudget(t, clock)
	b.Record("app", "up", "m", 1, 0)
	if err := b.Reconfigure(nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Reconfigure(&bundle.Budgets{Timezone: "Europe/Moscow"}); err != nil {
		t.Fatal(err)
	}
	if u := b.report().Months[0].Apps[0]; u.Cost != 50_000 {
		t.Fatalf("счётчики после возврата раздела: %+v", u)
	}
}

// Heartbeat передаёт счётчики процесса и принимает расход остальных
// процессов; при остановке счётчики тоже уходят.
func TestHeartbeatBudget(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b := newTestBudget(t, clock, bundle.HardBudget{App: "app", Limit: 1_000_000})
	b.Record("app", "up", "m", 1, 1)
	var mu sync.Mutex
	var bodies []heartbeatBody
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var hb heartbeatBody
		if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
			t.Error(err)
		}
		mu.Lock()
		bodies = append(bodies, hb)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G104: ответ тестового сервера
		_ = json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now(), "interval_seconds": 30,
			"budget": map[string]any{"month": "2026-10", "others": map[string]int64{"app": 900_000}}})
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	RunHeartbeat(ctx, HeartbeatConfig{Client: srv.Client(), Server: u, Version: "1", Logger: quiet(), Budget: b,
		StartedAt: clock.now(), Sleep: func(context.Context, time.Duration) bool { cancel(); return false }})
	if len(bodies) != 2 {
		t.Fatalf("heartbeat: %d", len(bodies))
	}
	for i, hb := range bodies {
		if hb.Budget == nil || len(hb.Budget.Months) != 1 || hb.Budget.Months[0].Month != "2026-10" ||
			len(hb.Budget.Months[0].Apps) != 1 || hb.Budget.Months[0].Apps[0].Cost != 100_000 {
			t.Fatalf("heartbeat %d: %+v", i, hb.Budget)
		}
	}
	if out, _ := b.Exhausted("app"); !out {
		t.Fatal("расход остальных процессов из ответа не учтён")
	}
}

// Эмбеддинги: usage только с total_tokens — расход по нему; ошибка
// провайдера — запроса и расхода нет.
func TestBudgetEmbeddingsAndProviderError(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	budget := newTestBudget(t, clock)
	up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G104: ответ тестового провайдера
		_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.5]}],"model":"m","usage":{"prompt_tokens":0,"total_tokens":4}}`))
	})
	g := newGateway(t, up.URL, func(o *gwOpts) { o.budget = budget })
	if resp := postEmb(t, g, `{"model":"m","input":"x"}`); resp.Code != http.StatusOK {
		t.Fatalf("эмбеддинги: %d %s", resp.Code, resp.Body.String())
	}
	if u := budget.report().Months[0].Apps[0]; u.Cost != 200_000 || u.Requests != 1 {
		t.Fatalf("расход эмбеддингов: %+v", u)
	}
	bad, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	g = newGateway(t, bad.URL, func(o *gwOpts) { o.budget = budget })
	if resp := postChat(t, g, chatBody, nil); resp.Code == http.StatusOK {
		t.Fatal("ошибка провайдера не передана")
	}
	if u := budget.report().Months[0].Apps[0]; u.Requests != 1 {
		t.Fatalf("неудачный запрос посчитан: %+v", u)
	}
}

// 3В22 ревью 3.r3: запрос, ушедший провайдеру, с неизвестным исходом
// (клиент прервал запрос, таймаут провайдера, обрыв потока до заголовков)
// списывает оценку сверху — вход и max_tokens — и в бюджет, и в квоту
// токенов; явный отказ провайдера со статусом — без списания.
//
// Покрывает: DM-15, DM-36
func TestDM15_CanceledRequestCharged(t *testing.T) {
	const maxOut = 300
	text := strings.Repeat("а", 300) // 600 байт — 200 токенов по оценке
	in := int64(estimateTokens(len(text)))
	body := func(stream bool) string {
		return `{"model":"m","max_tokens":` + strconv.Itoa(maxOut) + `,"stream":` + strconv.FormatBool(stream) +
			`,"messages":[{"role":"user","content":"` + text + `"}]}`
	}
	for _, tc := range []struct {
		name    string
		stream  bool
		cancel  bool // клиент рвёт соединение, когда провайдер получил запрос
		refuse  bool // провайдер отвечает 400
		charged bool
	}{
		{name: "клиент прервал запрос", cancel: true, charged: true},
		{name: "клиент прервал поток до заголовков", stream: true, cancel: true, charged: true},
		{name: "таймаут провайдера", charged: true},
		{name: "таймаут потока до заголовков", stream: true, charged: true},
		{name: "явный отказ провайдера", refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &budgetClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
			budget := newTestBudget(t, clock, bundle.HardBudget{App: "app", Limit: 1 << 40})
			got := make(chan struct{}, 1)
			release := make(chan struct{})
			defer close(release)
			up, _ := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				select {
				case got <- struct{}{}:
				default:
				}
				if tc.refuse {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"error":{"message":"bad","type":"invalid_request_error","code":"bad_request"}}`)) //nolint:errcheck,gosec // G104: ответ тестового провайдера
					return
				}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			})
			g := newGateway(t, up.URL, func(o *gwOpts) {
				o.budget = budget
				o.quotas = config.Quotas{TokensPerMinute: int(in) + maxOut + 10}
				o.transport = &http.Transport{Proxy: nil, ResponseHeaderTimeout: 200 * time.Millisecond}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				go func() {
					<-got
					cancel()
				}()
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(body(tc.stream)))
			req.Header.Set("Content-Type", "application/json")
			g.ServeHTTP(httptest.NewRecorder(), req)
			rep := budget.report()
			var u budgetUsage
			if len(rep.Months) == 1 && len(rep.Months[0].Apps) == 1 {
				u = rep.Months[0].Apps[0]
			}
			// Второй запрос: при списанном резерве квота токенов исчерпана.
			second := postChat(t, g, `{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`, nil)
			if !tc.charged {
				if u.Requests != 0 || u.Cost != 0 {
					t.Fatalf("явный отказ списан: %+v", u)
				}
				if second.Code == http.StatusTooManyRequests {
					t.Fatalf("после явного отказа квота не возвращена: %s", second.Body.String())
				}
				return
			}
			if want := (in + maxOut) * 50_000; u.Requests != 1 || u.Cost < want {
				t.Fatalf("расход: %+v, ожидается Requests 1 и Cost >= %d", u, want)
			}
			if second.Code != http.StatusTooManyRequests || errCode(t, second) != "quota_exceeded" {
				t.Fatalf("резерв квоты возвращён: %d %s", second.Code, second.Body.String())
			}
		})
	}
}

// 3В23 ревью 3.r3: часы шлюза назад через границу месяца не стирают счётчик
// текущего месяца — расход «будущего» месяца переносится в текущий, отчёт
// заканчивается текущим, apply его не удаляет; бюджет срабатывает.
//
// Покрывает: DM-15
func TestBudgetClockBackAcrossMonth(t *testing.T) {
	// 1 ноября 01:00 по Москве: часы шлюза ушли вперёд.
	clock := &budgetClock{t: time.Date(2026, 10, 31, 22, 0, 0, 0, time.UTC)}
	b := newTestBudget(t, clock, bundle.HardBudget{App: "app", Limit: 300_000})
	b.Record("app", "up", "m", 1, 1) // 100 000
	rep := b.report()
	b.apply(rep, &budgetState{Month: rep.Months[len(rep.Months)-1].Month})
	// NTP вернул часы: 31 октября 23:00 по Москве.
	clock.set(time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC))
	b.Record("app", "up", "m", 1, 1)
	for range 2 {
		rep := b.report()
		if last := rep.Months[len(rep.Months)-1].Month; last != "2026-10" {
			t.Fatalf("последний месяц отчёта: %s, %+v", last, rep.Months)
		}
		// Сервер отвечает последним месяцем отчёта.
		b.apply(rep, &budgetState{Month: rep.Months[len(rep.Months)-1].Month})
	}
	rep = b.report()
	if len(rep.Months) != 1 || rep.Months[0].Month != "2026-10" || rep.Months[0].Apps[0].Cost != 200_000 || rep.Months[0].Apps[0].Requests != 2 {
		t.Fatalf("счётчики после переноса: %+v", rep.Months)
	}
	b.Record("app", "up", "m", 1, 1)
	if out, _ := b.Exhausted("app"); !out {
		t.Fatal("бюджет не сработал после возврата часов")
	}
	// Сервер ответил «будущим» месяцем (его часы впереди): текущий месяц
	// шлюза всё равно не удаляется.
	b.apply(b.report(), &budgetState{Month: "2026-11"})
	if out, _ := b.Exhausted("app"); !out {
		t.Fatal("ответ сервера будущим месяцем стёр текущий")
	}
}

// Смена пояса установки у границы месяца: Москва → UTC 1 ноября в 01:00 по
// Москве (31 октября по UTC) — ноябрьский расход переходит в октябрь UTC.
//
// Покрывает: DM-15
func TestBudgetTimezoneChangeAcrossMonth(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 31, 22, 0, 0, 0, time.UTC)}
	b := newTestBudget(t, clock, bundle.HardBudget{App: "app", Limit: 200_000})
	b.Record("app", "up", "m", 1, 1)
	if err := b.Reconfigure(&bundle.Budgets{Timezone: "UTC",
		Prices: []bundle.ModelPrice{{Provider: "up", Model: "m", Input: 50_000, Output: 50_000}},
		Hard:   []bundle.HardBudget{{App: "app", Limit: 200_000}}}); err != nil {
		t.Fatal(err)
	}
	b.Record("app", "up", "m", 1, 1)
	rep := b.report()
	b.apply(rep, &budgetState{Month: rep.Months[len(rep.Months)-1].Month})
	if out, _ := b.Exhausted("app"); !out {
		t.Fatalf("расход до смены пояса потерян: %+v", b.report().Months)
	}
}

// При переполнении месяца вытесняются счётчики приложений вне пакета, а не
// расход нового приложения.
func TestBudgetEvictsAppsOutsideBundle(t *testing.T) {
	clock := &budgetClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b := newTestBudget(t, clock)
	for i := range maxBudgetApps {
		b.Record("old-"+strconv.Itoa(i), "up", "m", 1, 0)
	}
	b.Record("new", "up", "m", 1, 0)
	if rep := b.report(); slices.ContainsFunc(rep.Months[0].Apps, func(u budgetUsage) bool { return u.App == "new" }) {
		t.Fatal("пакет неизвестен — вытеснено чужое приложение")
	}
	if err := b.Reconfigure(&bundle.Budgets{Timezone: "Europe/Moscow"}, "new"); err != nil {
		t.Fatal(err)
	}
	b.Record("new", "up", "m", 1, 0)
	rep := b.report()
	if len(rep.Months[0].Apps) != maxBudgetApps || !slices.ContainsFunc(rep.Months[0].Apps, func(u budgetUsage) bool { return u.App == "new" }) {
		t.Fatalf("приложение пакета не учтено: %d", len(rep.Months[0].Apps))
	}
}
