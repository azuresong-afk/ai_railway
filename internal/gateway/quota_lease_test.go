package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/quotalease"
)

// Аренда квот (задача 4.29, ADR-0021): шлюзы против сервера-заглушки.
// Заглушка разбирает запрос строгим разборщиком сервера (quotalease.Parse)
// и, как сервер, учитывает выданное сразу при выдаче; окна времени она не
// ведёт — их проверяют PG-тесты internal/quotalease.

type leaseKeyT struct{ app, quota string }

type fakeLeaseServer struct {
	t  *testing.T
	mu sync.Mutex
	// limits — лимит квоты; charged — учтено (выдано по неотчитанным,
	// израсходовано по отчитанным, автономный расход).
	limits   map[leaseKeyT]int64
	charged  map[leaseKeyT]int64
	leases   map[string]*fakeLease
	byReq    map[string]quotalease.Grant
	requests []quotalease.Request
	gateways int
	// down — сервер недоступен (503); failAfterCommit — выдать, но
	// ответить 500 (ответ потерян).
	down, failAfterCommit bool
	seq                   int
}

type fakeLease struct {
	key      leaseKeyT
	granted  int64
	reported bool
}

func newFakeLeaseServer(t *testing.T, limits map[leaseKeyT]int64) (*fakeLeaseServer, *url.URL) {
	t.Helper()
	f := &fakeLeaseServer{t: t, limits: limits, charged: map[leaseKeyT]int64{}, leases: map[string]*fakeLease{},
		byReq: map[string]quotalease.Grant{}, gateways: 2}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return f, u
}

func (f *fakeLeaseServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != leasePath || f.down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	req, err := quotalease.Parse(body)
	if err != nil {
		f.t.Errorf("запрос шлюза не проходит разбор сервера: %v: %s", err, body)
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	f.requests = append(f.requests, req)
	resp := quotalease.Response{ServerTime: time.Now(), Gateways: f.gateways}
	for _, a := range req.Apps {
		ar := quotalease.AppResponse{App: a.App}
		for _, q := range a.Quotas {
			k := leaseKeyT{a.App, q.Quota}
			if g, ok := f.byReq[q.RequestID]; ok {
				// Повтор: та же выдача, автономный расход не учитывается.
				ar.Quotas = append(ar.Quotas, g)
				continue
			}
			for _, rep := range q.Reports {
				l := f.leases[rep.Lease]
				if l == nil || l.key != k || rep.Used > l.granted || l.reported {
					f.t.Errorf("неверный отчёт: %+v", rep)
					continue
				}
				l.reported = true
				f.charged[k] -= l.granted - rep.Used
			}
			f.charged[k] += q.Offline
			limit, ok := f.limits[k]
			g := quotalease.Grant{Quota: q.Quota, RequestID: q.RequestID, Limit: limit, Unlimited: !ok}
			if ok && q.Want > 0 {
				free := max(limit-f.charged[k], 0)
				g.Granted = min(max(q.Want, (limit+int64(f.gateways)-1)/int64(f.gateways)/2), free)
				g.Remaining = free - g.Granted
				if g.Granted > 0 {
					f.seq++
					g.Lease = fmt.Sprintf("0192a000-0000-7000-8000-%012x", f.seq)
					g.TTLMS = leaseTTL(q.Quota).Milliseconds()
					f.leases[g.Lease] = &fakeLease{key: k, granted: g.Granted}
					f.charged[k] += g.Granted
				}
				if g.Granted < q.Want {
					g.RetryAfterMS = 30000
				}
			}
			f.byReq[q.RequestID] = g
			if q.Want > 0 {
				ar.Quotas = append(ar.Quotas, g)
			}
		}
		if len(ar.Quotas) > 0 {
			resp.Apps = append(resp.Apps, ar)
		}
	}
	if f.failAfterCommit {
		f.failAfterCommit = false
		http.Error(w, "lost", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp) //nolint:gosec // G104: тестовая заглушка
}

func (f *fakeLeaseServer) set(fn func(f *fakeLeaseServer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeLeaseServer) get(k leaseKeyT) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.charged[k]
}

// syncClock — часы для шлюза и фонового цикла аренды.
type syncClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *syncClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *syncClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type leaseGW struct {
	lim   *Limiter
	bud   *Budget
	lease *LeaseClient
}

// newLeaseGW — шлюз в режиме leased: приложения crm (fail_open) и erp
// (fail_closed) с квотами q.
func newLeaseGW(t *testing.T, srv *url.URL, clock *syncClock, q config.Quotas) *leaseGW {
	t.Helper()
	lc := newTestLeaseClient(t, srv, clock)
	lim := newLimiter(nil, clock.now)
	lim.SetLeases(lc)
	lim.Reconfigure([]config.Application{{ID: "crm", FailMode: failOpen, Quotas: q}, {ID: "erp", FailMode: "fail_closed", Quotas: q}})
	bud := NewBudget(clock.now)
	bud.SetLeases(lc)
	return &leaseGW{lim: lim, bud: bud, lease: lc}
}

// newTestLeaseClient — включённый клиент аренды с фоновым циклом.
func newTestLeaseClient(t *testing.T, srv *url.URL, clock *syncClock) *LeaseClient {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	lc, err := NewLeaseClient(LeaseConfig{Client: http.DefaultClient, Server: srv, IDs: ids.NewGenerator(r), Logger: quietLogger(),
		Now: clock.now})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go lc.Run(ctx)
	lc.SetEnabled(true)
	return lc
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func admitN(t *testing.T, gws []*leaseGW, app string, n int) (ok int, last error) {
	t.Helper()
	for i := range n {
		rs, err := gws[i%len(gws)].lim.AdmitCtx(context.Background(), QuotaRequest{App: app})
		if err != nil {
			last = err
			continue
		}
		rs.Settle(0)
		ok++
	}
	return ok, last
}

// Несколько шлюзов против одного сервера: вместе они пропускают не больше
// requests_per_minute приложения; сверх — 429 quota_exceeded с Retry-After.
func TestDM36_LeasedQuotaGatewaysShareLimit(t *testing.T) {
	f, u := newFakeLeaseServer(t, map[leaseKeyT]int64{{"crm", QuotaRequestsPerMinute}: 10})
	clock := &syncClock{t: time.Unix(1_800_000_000, 0)}
	q := config.Quotas{RequestsPerMinute: 10}
	gws := []*leaseGW{newLeaseGW(t, u, clock, q), newLeaseGW(t, u, clock, q), newLeaseGW(t, u, clock, q)}
	ok, err := admitN(t, gws, "crm", 30)
	if ok != 10 {
		t.Fatalf("пропущено %d при лимите 10 на три шлюза", ok)
	}
	ex := exceeded(t, err, QuotaRequestsPerMinute, "DM-36")
	if ex.RetryAfter <= 0 {
		t.Fatalf("без Retry-After: %+v", ex)
	}
	if c := f.get(leaseKeyT{"crm", QuotaRequestsPerMinute}); c != 10 {
		t.Fatalf("учтено на сервере %d", c)
	}
	// Локальный режим: каждый шлюз считает сам.
	for _, g := range gws {
		g.lease.SetEnabled(false)
	}
	if ok, err := admitN(t, gws, "crm", 30); ok != 30 {
		t.Fatalf("режим local: %d, %v", ok, err)
	}
}

// Остаток аренды возвращается отчётом после её срока; повтор запроса после
// потерянного ответа идёт с тем же request_id и не выдаёт единицы дважды.
func TestDM36_LeaseReturnAndIdempotentRetry(t *testing.T) {
	k := leaseKeyT{"crm", QuotaTPM}
	f, u := newFakeLeaseServer(t, map[leaseKeyT]int64{k: 1000})
	clock := &syncClock{t: time.Unix(1_800_000_000, 0)}
	g := newLeaseGW(t, u, clock, config.Quotas{TokensPerMinute: 1000})
	rs, err := g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "crm", Tokens: 100})
	if err != nil {
		t.Fatal(err)
	}
	rs.Settle(40)
	charged := f.get(k)
	if charged < 100 {
		t.Fatalf("выдано %d", charged)
	}
	// Срок аренды прошёл: отчёт возвращает неизрасходованное.
	clock.advance(leaseMinuteTTL + time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for f.get(k) != 40 {
		if time.Now().After(deadline) {
			t.Fatalf("остаток не возвращён: учтено %d", f.get(k))
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Ответ потерян после выдачи: повтор с тем же ID получает ту же аренду.
	f.set(func(f *fakeLeaseServer) { f.failAfterCommit = true })
	_, err = g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "crm", Tokens: 10})
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(2 * time.Second)
	deadline = time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		seen := map[string]int{}
		for _, r := range f.requests {
			for _, a := range r.Apps {
				for _, q := range a.Quotas {
					seen[q.RequestID]++
				}
			}
		}
		repeated := 0
		for _, n := range seen {
			if n > 1 {
				repeated++
			}
		}
		f.mu.Unlock()
		if repeated > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("потерянный ответ не повторён с тем же request_id")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(f.leases); n != 2 {
		t.Fatalf("выдач после повтора: %d %+v", n, f.requests)
	}
}

// Сервер недоступен: fail_open — автономная доля (лимит на число шлюзов из
// последнего ответа), событие помечается quota_degraded, heartbeat
// сообщает quota_autonomous; fail_closed — та же доля в льготный срок,
// затем ErrQuotaUnavailable (503 quota_unavailable).
func TestDM36_LeaseServerDownFailOpenAndClosed(t *testing.T) {
	f, u := newFakeLeaseServer(t, map[leaseKeyT]int64{{"crm", QuotaRequestsPerMinute}: 10, {"erp", QuotaRequestsPerMinute}: 10})
	clock := &syncClock{t: time.Unix(1_800_000_000, 0)}
	g := newLeaseGW(t, u, clock, config.Quotas{RequestsPerMinute: 10})
	for _, app := range []string{"crm", "erp"} {
		if ok, err := admitN(t, []*leaseGW{g}, app, 1); ok != 1 {
			t.Fatalf("%s: аренда не получена: %v", app, err)
		}
	}
	f.set(func(f *fakeLeaseServer) { f.down = true })
	clock.advance(leaseMinuteTTL + time.Second)
	// fail_open: доля ⌈10/2⌉ = 5 в скользящую минуту, из неё один запрос
	// уже прошёл по аренде.
	ok, err := admitN(t, []*leaseGW{g}, "crm", 8)
	if ok != 4 {
		t.Fatalf("автономная доля: %d, %v", ok, err)
	}
	exceeded(t, err, QuotaRequestsPerMinute, "DM-36")
	rs, err := g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "erp"})
	if err != nil || !rs.Degraded() {
		t.Fatalf("льготный срок fail_closed: %v", err)
	}
	if !g.lease.Autonomous() {
		t.Fatal("heartbeat не сообщит автономную долю")
	}
	// Льготный срок (ещё один срок аренды) истёк — 503.
	clock.advance(leaseMinuteTTL)
	if _, err := g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "erp"}); !errors.Is(err, ErrQuotaUnavailable) {
		t.Fatalf("fail_closed после льготного срока: %v", err)
	}
	// fail_open не отказывает 503 и после льготного срока.
	clock.advance(time.Minute)
	if _, err := g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "crm"}); err != nil {
		t.Fatalf("fail_open после минуты: %v", err)
	}
	// Сервер вернулся — снова аренда.
	f.set(func(f *fakeLeaseServer) { f.down = false })
	deadline := time.Now().Add(15 * time.Second)
	for {
		rs, err := g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "erp"})
		if err == nil && !rs.Degraded() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("после восстановления: %v", err)
		}
		clock.advance(time.Second)
		time.Sleep(50 * time.Millisecond)
	}
}

// Шлюз целиком, сервер управления недоступен с запуска: приложение с
// fail_closed после льготного срока получает 503 quota_unavailable и событие
// отказа, запрос до провайдера не доходит; с fail_open — ответ провайдера и
// событие с флагом quota_degraded.
func TestDM36_LeaseUnavailableThroughHandler(t *testing.T) {
	f, u := newFakeLeaseServer(t, nil)
	f.set(func(f *fakeLeaseServer) { f.down = true })
	for _, mode := range []string{"fail_closed", failOpen} {
		t.Run(mode, func(t *testing.T) {
			clock := &syncClock{t: time.Unix(1_800_000_000, 0)}
			lc := newTestLeaseClient(t, u, clock)
			clock.advance(time.Minute)
			up, rec := newUpstream(t, nil)
			var log *eventLog
			g := newGateway(t, up.URL, func(o *gwOpts) {
				o.quotas = config.Quotas{RequestsPerMinute: 10}
				o.app = func(a *config.Application) { a.FailMode = mode }
				o.leases, log = lc, o.events
			})
			resp := postChat(t, g, chatBody, nil)
			_, _, _, calls := rec.get()
			e := lastEvent(t, log, resp)
			if mode == failOpen {
				if resp.Code != http.StatusOK || calls != 1 || !e.Decision.QuotaDegraded {
					t.Fatalf("fail_open: %d %s, вызовов %d, событие %+v", resp.Code, resp.Body.String(), calls, e.Decision)
				}
				return
			}
			if resp.Code != http.StatusServiceUnavailable || errCode(t, resp) != "quota_unavailable" || resp.Header().Get("Retry-After") == "" {
				t.Fatalf("fail_closed: %d %s", resp.Code, resp.Body.String())
			}
			if calls != 0 {
				t.Fatal("запрос без проверки квоты дошёл до провайдера")
			}
			if e.Decision.Rule != "quota.unavailable" || e.Decision.Action != "block" || !slices.Equal(e.Threats, []string{"DM-36"}) {
				t.Fatalf("событие: %+v %v", e.Decision, e.Threats)
			}
		})
	}
}

// Автономная доля минутной квоты включает расход шлюза по арендам за ту же
// минуту, а автономный расход после восстановления связи занимает первую
// выдачу: вместе с арендами он не превышает лимит минуты.
func TestDM36_LeaseAutonomousMinuteCountsLeasedUse(t *testing.T) {
	k := leaseKeyT{"crm", QuotaRequestsPerMinute}
	f, u := newFakeLeaseServer(t, map[leaseKeyT]int64{k: 10})
	clock := &syncClock{t: time.Unix(1_800_000_000, 0)}
	g := newLeaseGW(t, u, clock, config.Quotas{RequestsPerMinute: 10})
	if ok, err := admitN(t, []*leaseGW{g}, "crm", 4); ok != 4 {
		t.Fatalf("по аренде: %d, %v", ok, err)
	}
	f.set(func(f *fakeLeaseServer) { f.down = true })
	clock.advance(leaseMinuteTTL + time.Second)
	// Доля ⌈10/2⌉ = 5, четыре уже израсходованы по арендам.
	ok, err := admitN(t, []*leaseGW{g}, "crm", 3)
	if ok != 1 {
		t.Fatalf("автономная доля: %d, %v", ok, err)
	}
	exceeded(t, err, QuotaRequestsPerMinute, "DM-36")
	f.set(func(f *fakeLeaseServer) { f.down = false })
	deadline := time.Now().Add(15 * time.Second)
	for {
		rs, err := g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "crm"})
		if err == nil && !rs.Degraded() {
			rs.Settle(0)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("после восстановления: %v", err)
		}
		clock.advance(time.Second)
		time.Sleep(50 * time.Millisecond)
	}
	g.lease.mu.Lock()
	st := g.lease.states[leaseKey{"crm", QuotaRequestsPerMinute}]
	debt, used := st.autoDebt, int64(0)
	for _, r := range st.leases {
		used += r.used
	}
	g.lease.mu.Unlock()
	// Автономный запрос и запрос после восстановления — в аренде.
	if debt != 0 || used < 2 {
		t.Fatalf("автономный расход не засчитан в аренду: долг %d, израсходовано %d", debt, used)
	}
}

// Пустой вход без предела ответа (оценка 0 токенов) — нулевой резерв в
// аренде, расход ответа списывается; квота, которой у приложения на
// сервере нет, считается локально и снова запрашивается у сервера после
// срока признака.
func TestDM36_LeaseZeroTokensAndUnlimited(t *testing.T) {
	kTPM, kTPD := leaseKeyT{"crm", QuotaTPM}, leaseKeyT{"crm", QuotaTPD}
	f, u := newFakeLeaseServer(t, map[leaseKeyT]int64{kTPM: 1000})
	clock := &syncClock{t: time.Unix(1_800_000_000, 0)}
	g := newLeaseGW(t, u, clock, config.Quotas{TokensPerMinute: 1000, TokensPerDay: 100})
	rs, err := g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "crm"})
	if err != nil || rs.tpm == nil {
		t.Fatalf("нулевой резерв: %v %+v", err, rs)
	}
	rs.Settle(30)
	g.lease.mu.Lock()
	used := int64(0)
	for _, r := range g.lease.states[leaseKey{"crm", QuotaTPM}].leases {
		used += r.used
	}
	g.lease.mu.Unlock()
	if used != 30 {
		t.Fatalf("расход ответа не списан: %d", used)
	}
	// tokens_per_day на сервере нет — локальный счётчик (30 уже учтено).
	if _, err := g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "crm", Tokens: 80}); err == nil {
		t.Fatal("локальная суточная квота не проверена")
	} else {
		exceeded(t, err, QuotaTPD, "DM-36")
	}
	// Лимит вернули на сервере: после срока признака шлюз снова спрашивает.
	f.set(func(f *fakeLeaseServer) { f.limits[kTPD] = 100 })
	clock.advance(leaseLongTTL + time.Second)
	rs, err = g.lim.AdmitCtx(context.Background(), QuotaRequest{App: "crm", Tokens: 10})
	if err != nil || rs.tpd == nil || f.get(kTPD) == 0 {
		t.Fatalf("после возврата лимита: %v, учтено %d", err, f.get(kTPD))
	}
}

// Жёсткий бюджет при двух шлюзах (ADR-0021, п. 4): резерв оценки до вызова
// провайдера, уточнение фактом после; вместе шлюзы не превышают бюджет,
// сверх — 429 budget_exceeded (budget.hard, DM-15).
func TestDM15_LeasedBudgetTwoGateways(t *testing.T) {
	k := leaseKeyT{"crm", quotaBudget}
	// Бюджет 1 ₽ = 10 000 000 единиц; цена — 100 единиц за токен входа и
	// выхода: оценка запроса 500 000, факт 300 000.
	f, u := newFakeLeaseServer(t, map[leaseKeyT]int64{k: 10_000_000})
	clock := &syncClock{t: time.Unix(1_800_000_000, 0)}
	sec := &bundle.Budgets{Timezone: "Europe/Moscow",
		Prices: []bundle.ModelPrice{{Provider: "p", Model: "m", Input: 100, Output: 100}},
		Hard:   []bundle.HardBudget{{App: "crm", Limit: 10_000_000}}}
	gws := []*leaseGW{newLeaseGW(t, u, clock, config.Quotas{}), newLeaseGW(t, u, clock, config.Quotas{})}
	for _, g := range gws {
		if err := g.bud.Reconfigure(sec, "crm"); err != nil {
			t.Fatal(err)
		}
		if !g.bud.Leased("crm") {
			t.Fatal("бюджет не в аренде")
		}
	}
	var spent int64
	var last error
	for i := range 200 {
		g := gws[i%2]
		hold, err := g.bud.Reserve(context.Background(), "crm", "p", "m", 2000, 3000)
		if err != nil {
			last = err
			break
		}
		cost := g.bud.Record("crm", "p", "m", 2000, 1000)
		hold.Settle(cost)
		spent += cost
	}
	var ex *Exceeded
	if !errors.As(last, &ex) || ex.Rule != ruleBudget || ex.Threat != "DM-15" {
		t.Fatalf("исчерпание бюджета: %v", last)
	}
	if spent > 10_000_000 || f.get(k) > 10_000_000 {
		t.Fatalf("бюджет превышен: израсходовано %d, учтено %d", spent, f.get(k))
	}
	// Модель без цены — стоимость не определена, запрос не отклоняется.
	if h, err := gws[0].bud.Reserve(context.Background(), "crm", "p", "unpriced", 10, 10); h != nil || err != nil {
		t.Fatalf("без цены: %v %v", h, err)
	}
}

// Запрос аренды шлюза проходит строгий разбор сервера и укладывается в его
// пределы (64 КиБ) при множестве приложений и отчётов.
func TestLeaseRequestFitsServerLimits(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("https://server.invalid")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewLeaseClient(LeaseConfig{Client: http.DefaultClient, Server: u, IDs: ids.NewGenerator(r), Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := range bundle.MaxApplications {
		for qi, q := range []string{QuotaRequestsPerMinute, QuotaTPM, QuotaTPD, quotaBudget} {
			st := c.state(fmt.Sprintf("app-%04d", i), q, 100, now)
			st.want = 1 << 62
			for j := range leaseMaxReports {
				st.leases = append(st.leases, &leaseRec{id: fmt.Sprintf("0192a000-0000-7000-8000-%08x%02x%02x", i, qi, j), granted: 1 << 62,
					expires: now.Add(-time.Hour)})
			}
			st.offline = 1 << 62
		}
	}
	req, refs := c.build(now)
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) == 0 || len(body) > quotalease.MaxBody {
		t.Fatalf("квот %d, тело %d байт", len(refs), len(body))
	}
	if _, err := quotalease.Parse(body); err != nil {
		t.Fatal(err)
	}
}
