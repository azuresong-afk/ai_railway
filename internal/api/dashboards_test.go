package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// fakeDash — подмена агрегатов: запоминает условия последнего чтения и
// отдаёт заданные данные.
type fakeDash struct {
	mu    sync.Mutex
	last  events.DashQuery
	apps  []string
	notOK bool
	total events.DashTotals
	err   error
	reads int
	// block — Totals ждёт закрытия канала; cur и peak — текущие и наибольшие
	// одновременные вычисления (3В28).
	block     chan struct{}
	cur, peak int
}

func (f *fakeDash) note(q events.DashQuery) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last, f.reads = q, f.reads+1
	f.apps = append(f.apps, q.App)
}

func (f *fakeDash) lastQuery() events.DashQuery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func (f *fakeDash) Totals(_ context.Context, q events.DashQuery) (events.DashTotals, error) {
	f.note(q)
	f.mu.Lock()
	block := f.block
	f.cur++
	f.peak = max(f.peak, f.cur)
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	f.mu.Lock()
	f.cur--
	f.mu.Unlock()
	return f.total, f.err
}

func (f *fakeDash) Latency(_ context.Context, q events.DashQuery) (events.DashLatency, error) {
	f.note(q)
	return events.DashLatency{Bounds: []int{5, events.DashLatencyOverflow}, Counts: []int64{3, 1}, P95: events.DashLatencyOverflow, Total: 4}, nil
}

func (f *fakeDash) DecisionSeries(_ context.Context, q events.DashQuery) ([]events.DashPoint, error) {
	f.note(q)
	return []events.DashPoint{{Bucket: q.From, Key: "blocked", Value: 2}}, nil
}

func (f *fakeDash) FindingSeries(_ context.Context, q events.DashQuery, _, _ string, _ []string) ([]events.DashPoint, error) {
	f.note(q)
	return []events.DashPoint{{Bucket: q.From, Key: "DM-01", Value: 2}, {Bucket: q.From, Key: "DM-99", Value: 5}}, nil
}

func (f *fakeDash) TopFindings(_ context.Context, q events.DashQuery, _, _ string, _ int) ([]events.DashTop, error) {
	f.note(q)
	return []events.DashTop{{Key: "DM-01", Value: 2}}, nil
}

func (f *fakeDash) PIIBreakdown(_ context.Context, q events.DashQuery) ([]events.DashPIIRow, error) {
	f.note(q)
	return []events.DashPIIRow{{Category: "pii.snils", App: "crm", Action: "redact", Findings: 4}}, nil
}

func (f *fakeDash) Heatmap(_ context.Context, q events.DashQuery) ([]events.DashCell, error) {
	f.note(q)
	return []events.DashCell{{Weekday: 1, Hour: 10, Findings: 2}}, nil
}

func (f *fakeDash) RequestsBy(_ context.Context, q events.DashQuery, dim string, _ int) ([]events.DashRequestRow, error) {
	f.note(q)
	return []events.DashRequestRow{{Key: dim, Requests: 7, Cost: 1_234_000}}, nil
}

func (f *fakeDash) UsageSeries(_ context.Context, q events.DashQuery) ([]events.DashUsagePoint, error) {
	f.note(q)
	return []events.DashUsagePoint{{Bucket: q.From, Requests: 7, Tokens: 100, Cost: 1_234_000}}, nil
}

func (f *fakeDash) Feed(_ context.Context, _ time.Time, app string, all bool, _ int) ([]events.DashFeedItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.apps = append(f.apps, "feed:"+app)
	if all {
		f.apps = append(f.apps, "feed-all")
	}
	return []events.DashFeedItem{{ID: "01900000-0000-7000-8000-000000000001", Time: time.Now().UTC(), App: app, Action: "block", Threats: []string{"DM-01"}}}, nil
}

func (f *fakeDash) Ready(context.Context) (bool, error) { return !f.notOK, nil }

// Дашборды: чтение — dashboards.read (аналитик, аудитор, администраторы);
// владелец приложения видит только «Приложение» своих приложений, чужое —
// 404 (УПД.8); без права и без входа — отказ.
func TestDashboardsViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	prov := e.provider(t, sys, "openai-main")
	mine := e.application(t, sys, "mine", prov.ID, tOwnerID)
	other := e.application(t, sys, "other", prov.ID, tOwner2ID)
	e.dash.total = events.DashTotals{Requests: 10, Cost: 4_600_000, NonTextUnchecked: 2}

	full := []string{"overview", "threats", "pii", "consumption"}
	for _, login := range []string{"admin", "sysadm", "analyst", "auditor"} {
		s := e.mustLogin(t, login)
		for _, name := range full {
			w := e.call(s, "GET", "/api/v1/dashboards/"+name, "", false)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"period":{"name":"24h"`) || strings.Contains(w.Body.String(), "null") {
				t.Fatalf("%s %s: %d %s", login, name, w.Code, w.Body)
			}
		}
		if w := e.call(s, "GET", "/api/v1/dashboards/app/"+mine.ID, "", false); w.Code != http.StatusOK {
			t.Fatalf("%s: дашборд приложения: %d %s", login, w.Code, w.Body)
		}
	}
	owner := e.mustLogin(t, "owner")
	for _, name := range full {
		mustProblem(t, e.call(owner, "GET", "/api/v1/dashboards/"+name, "", false), 403, CodeForbidden)
	}
	mustProblem(t, e.call(owner, "GET", "/api/v1/dashboards/stream?dashboard=overview", "", false), 403, CodeForbidden)
	w := e.call(owner, "GET", "/api/v1/dashboards/app/"+mine.ID+"?period=7d", "", false)
	if w.Code != http.StatusOK || e.dash.lastQuery().App != "mine" {
		t.Fatalf("владелец, своё приложение: %d %s %+v", w.Code, w.Body, e.dash.lastQuery())
	}
	mustProblem(t, e.call(owner, "GET", "/api/v1/dashboards/app/"+other.ID, "", false), 404, CodeNotFound)
	mustProblem(t, e.call(owner, "GET", "/api/v1/dashboards/app/not-a-uuid", "", false), 404, CodeNotFound)
	// Роль без права: 403 везде; без входа — 401.
	keymgr := e.mustLogin(t, "keymgr")
	for _, path := range []string{"overview", "app/" + mine.ID} {
		mustProblem(t, e.call(keymgr, "GET", "/api/v1/dashboards/"+path, "", false), 403, CodeForbidden)
		mustProblem(t, e.call(session{}, "GET", "/api/v1/dashboards/"+path, "", false), 401, CodeUnauthorized)
	}
	mustProblem(t, e.call(session{}, "GET", "/api/v1/dashboards/stream?dashboard=overview", "", false), 401, CodeUnauthorized)
	if _, n := lastDenied(t, e.mem); n == 0 {
		t.Fatal("отказы не записаны в аудит (УПД.6)")
	}
}

// Периоды: именованные и произвольные, шаг рядов, ошибки ввода.
func TestDashboardPeriods(t *testing.T) {
	e := newAppsEnv(t)
	an := e.mustLogin(t, "analyst")
	read := func(q string) (OverviewView, int) {
		w := e.call(an, "GET", "/api/v1/dashboards/overview"+q, "", false)
		var v OverviewView
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
		}
		return v, w.Code
	}
	for q, unit := range map[string]string{"?period=15m": "minute", "?period=1h": "minute", "?period=24h": "hour", "?period=7d": "hour",
		"?period=30d": "hour", "": "hour"} {
		v, code := read(q)
		if code != 200 || v.Period.Unit != unit {
			t.Fatalf("%q: %d %+v", q, code, v.Period)
		}
	}
	now := time.Now().UTC()
	f := func(d time.Time) string { return d.Format(time.RFC3339) }
	// Произвольный период: до 31 суток — по часам, длиннее — по суткам.
	v, code := read("?from=" + f(now.Add(-10*24*time.Hour)) + "&to=" + f(now.Add(-time.Hour)))
	if code != 200 || v.Period.Unit != "hour" || v.Period.Name != "custom" || !v.Period.From.Equal(v.Period.From.Truncate(time.Hour)) {
		t.Fatalf("произвольный период: %d %+v", code, v.Period)
	}
	if v, code = read("?from=" + f(now.Add(-40*24*time.Hour)) + "&to=" + f(now)); code != 200 || v.Period.Unit != "day" {
		t.Fatalf("период больше 31 суток: %d %+v", code, v.Period)
	}
	for _, q := range []string{"?period=2h", "?period=24h&from=" + f(now), "?from=" + f(now.Add(time.Hour)), "?from=вчера&to=" + f(now),
		"?from=" + f(now) + "&to=" + f(now.Add(-time.Hour)), "?from=" + f(now.Add(-400*24*time.Hour)) + "&to=" + f(now),
		"?period=24h&period=7d", "?feed=none", "?x=1"} {
		mustProblem(t, e.call(an, "GET", "/api/v1/dashboards/overview"+q, "", false), 400, CodeInvalidRequest)
	}
	// Пустой период — нули и пустые массивы, не null.
	e.dash.total = events.DashTotals{}
	w := e.call(an, "GET", "/api/v1/dashboards/consumption?period=1h", "", false)
	var c ConsumptionView
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || w.Code != 200 || c.Totals.Requests != 0 || c.Forecast.Enough || c.Totals.Cost != "0.0000000" {
		t.Fatalf("пустой период: %d %s %v", w.Code, w.Body, err)
	}
	// Агрегаты не досчитаны — признак в ответе.
	e.dash.notOK = true
	if v, _ := read("?period=30d&feed=all"); v.Period.AggregatesReady {
		t.Fatal("досчёт не закончен, а признак готовности стоит")
	}
	e.dash.notOK = false
	// Сбой чтения — 500 без подробностей.
	e.dash.err = context.DeadlineExceeded
	mustProblem(t, e.call(an, "GET", "/api/v1/dashboards/overview?period=15m&feed=all", "", false), 503, CodeUnavailable)
	e.dash.err = nil
	// feed=all доходит до ленты.
	e.dash.mu.Lock()
	e.dash.apps = nil
	e.dash.mu.Unlock()
	e.call(an, "GET", "/api/v1/dashboards/overview?feed=all&period=15m", "", false)
	e.dash.mu.Lock()
	got := strings.Join(e.dash.apps, ",")
	e.dash.mu.Unlock()
	if !strings.Contains(got, "feed-all") {
		t.Fatalf("лента не получила feed=all: %s", got)
	}
}

// Прогноз до конца месяца: линейный по прошедшей части; меньше суток — без прогноза.
func TestDashboardForecast(t *testing.T) {
	loc := time.UTC
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, loc)
	end := start.AddDate(0, 1, 0)
	f := forecast(1_000_000, start, end, start.Add(12*time.Hour), "2026-10")
	if f.Enough || f.Projected != f.Spent {
		t.Fatalf("меньше суток: %+v", f)
	}
	f = forecast(0, start, end, start.Add(10*24*time.Hour), "2026-10")
	if f.Enough {
		t.Fatalf("нулевой расход: %+v", f)
	}
	// Прошло 10 суток из 31: прогноз = расход × 3,1.
	f = forecast(1_000_000, start, end, start.Add(10*24*time.Hour), "2026-10")
	if !f.Enough || f.Projected != "0.3100000" {
		t.Fatalf("прогноз: %+v", f)
	}
	f = forecast(1<<62, start, end, start.Add(24*time.Hour), "2026-10")
	if !f.Enough || f.Projected == "" {
		t.Fatalf("переполнение: %+v", f)
	}
}

// SSE: снимок при подключении, пинг при неизменных данных, предел потоков на
// пользователя, закрытие при выходе.
func TestDashboardStream(t *testing.T) {
	old := dashStreamEvery
	dashStreamEvery = 30 * time.Millisecond
	t.Cleanup(func() { dashStreamEvery = old })
	e := newAppsEnv(t)
	an := e.mustLogin(t, "analyst")
	srv := httptest.NewServer(e.h)
	t.Cleanup(srv.Close)
	open := func(s session, query string) (*http.Response, context.CancelFunc) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/dashboards/stream"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range s.cookies {
			req.AddCookie(c)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		return resp, cancel
	}
	resp, cancel := open(an, "?dashboard=overview&period=24h")
	defer cancel()
	defer func() {
		_ = resp.Body.Close() //nolint:gosec // G104: закрытие тестового ответа
	}()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("поток: %d %v", resp.StatusCode, resp.Header)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	var snapshots, pings int
	for sc.Scan() && (snapshots < 1 || pings < 2) {
		line := sc.Text()
		switch {
		case line == "event: snapshot":
			snapshots++
		case line == ": ping":
			pings++
		case strings.HasPrefix(line, "data: "):
			var v OverviewView
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &v); err != nil || v.Period.Unit != "hour" {
				t.Fatalf("снимок: %v %+v", err, v.Period)
			}
		}
	}
	if snapshots != 1 || pings < 2 {
		t.Fatalf("снимков %d, пингов %d: %v", snapshots, pings, sc.Err())
	}
	// Предел потоков на пользователя: четвёртый — 429.
	open3 := []context.CancelFunc{}
	for range dashStreamsPerSubject - 1 {
		r, c := open(an, "?dashboard=threats")
		open3 = append(open3, c)
		code := r.StatusCode
		_ = r.Body.Close() //nolint:gosec // G104: закрытие тестового ответа
		if code != 200 {
			t.Fatalf("поток в пределах лимита: %d", code)
		}
	}
	r4, c4 := open(an, "?dashboard=pii")
	defer c4()
	defer func() {
		_ = r4.Body.Close() //nolint:gosec // G104: закрытие тестового ответа
	}()
	if r4.StatusCode != http.StatusTooManyRequests || r4.Header.Get("Retry-After") == "" {
		t.Fatalf("поток сверх предела: %d", r4.StatusCode)
	}
	for _, c := range open3 {
		c()
	}
	// Неверные параметры потока.
	for _, q := range []string{"", "?dashboard=x", "?dashboard=app", "?dashboard=overview&app_id=" + "01900000-0000-7000-8000-000000000001", "?dashboard=overview&period=2h"} {
		r, c := open(e.mustLogin(t, "auditor"), q)
		c()
		code := r.StatusCode
		_ = r.Body.Close() //nolint:gosec // G104: закрытие тестового ответа
		if code != http.StatusBadRequest {
			t.Fatalf("%q: %d", q, code)
		}
	}
	// Выход закрывает поток.
	if w := e.call(an, "POST", "/api/v1/auth/logout", "", true); w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("выход: %d %s", w.Code, w.Body)
	}
	done := make(chan struct{})
	go func() {
		for sc.Scan() {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("поток не закрылся после выхода")
	}
}

// Параллельные запросы с одинаковыми условиями читают агрегаты один раз за TTL.
func TestDashboardCacheShared(t *testing.T) {
	e := newAppsEnv(t)
	an, au := e.mustLogin(t, "analyst"), e.mustLogin(t, "auditor")
	e.call(an, "GET", "/api/v1/dashboards/pii?period=24h", "", false)
	before := e.dash.reads
	if w := e.call(au, "GET", "/api/v1/dashboards/pii?period=24h", "", false); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	if e.dash.reads != before {
		t.Fatalf("повторный запрос в пределах TTL читал агрегаты: %d → %d", before, e.dash.reads)
	}
	// Права проверяются до кэша: владелец снимок не получает.
	mustProblem(t, e.call(e.mustLogin(t, "owner"), "GET", "/api/v1/dashboards/pii?period=24h", "", false), 403, CodeForbidden)
}

// FuzzParseDashParams — разбор периода дашбордов: любые параметры либо отвергаются, либо дают
// корректный период (начало раньше конца, не длиннее 366 суток).
func FuzzParseDashParams(f *testing.F) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	f.Add("24h", "", "", "")
	f.Add("", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", "all")
	f.Add("", "2026-10-02T00:00:00Z", "2026-10-01T00:00:00Z", "")
	f.Add("x", "не время", "", "actions")
	f.Fuzz(func(t *testing.T, period, from, to, feed string) {
		q := url.Values{}
		for k, v := range map[string]string{"period": period, "from": from, "to": to, "feed": feed} {
			if v != "" {
				q.Set(k, v)
			}
		}
		p, prob := parseDashParams(q, now)
		if prob != nil {
			return
		}
		if !p.from.Before(p.to) || p.to.Sub(p.from) > events.DashMaxRange || p.to.After(now) {
			t.Fatalf("период вне границ: %v — %v", p.from, p.to)
		}
	})
}

// 3В27 ревью 3.r3 (УПД.2, решение владельца 26.10.2026): «Лента решений» —
// метаданные каждого события — только с events.read на все объекты.
// Администратор системы получает «Обзор» с пустой лентой и feed_hidden,
// аналитик — с лентой; кэш не переносит ленту между ними; владелец
// приложения на «Приложении» ленты не видит.
func TestDashboardFeedRequiresEventsRead(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	prov := e.provider(t, sys, "openai-main")
	mine := e.application(t, sys, "mine", prov.ID, tOwnerID)
	type view struct {
		Feed       []events.DashFeedItem `json:"feed"`
		FeedHidden bool                  `json:"feed_hidden"`
	}
	get := func(s session, path string) view {
		t.Helper()
		w := e.call(s, "GET", path, "", false)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		var v view
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	an := e.mustLogin(t, "analyst")
	// Аналитик первым: снимок с лентой в кэше не должен достаться администратору системы.
	for _, path := range []string{"/api/v1/dashboards/overview", "/api/v1/dashboards/app/" + mine.ID} {
		if v := get(an, path); len(v.Feed) == 0 || v.FeedHidden {
			t.Fatalf("аналитик %s: %+v", path, v)
		}
		if v := get(sys, path); len(v.Feed) != 0 || !v.FeedHidden {
			t.Fatalf("администратор системы %s: %+v", path, v)
		}
	}
	if v := get(e.mustLogin(t, "owner"), "/api/v1/dashboards/app/"+mine.ID); len(v.Feed) != 0 || !v.FeedHidden {
		t.Fatalf("владелец приложения: %+v", v)
	}
}

// 3В28 ревью 3.r3: вычисления снимков ограничены MaxDashComputes на сервер,
// сверх — 503 с Retry-After; одинаковые запросы ждут одно вычисление.
func TestDashboardComputeLimit(t *testing.T) {
	e := newAppsEnv(t)
	an := e.mustLogin(t, "analyst")
	block := make(chan struct{})
	e.dash.mu.Lock()
	e.dash.block = block
	e.dash.mu.Unlock()
	now := time.Now().UTC()
	type res struct {
		code  int
		retry string
	}
	out := make(chan res, 16)
	var wg sync.WaitGroup
	get := func(days int) {
		wg.Go(func() {
			from := now.Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)
			w := e.call(an, "GET", "/api/v1/dashboards/threats?from="+url.QueryEscape(from), "", false)
			out <- res{w.Code, w.Header().Get("Retry-After")}
		})
	}
	running := func() int {
		e.dash.mu.Lock()
		defer e.dash.mu.Unlock()
		return e.dash.cur
	}
	// Заняты все места вычислений.
	for i := range MaxDashComputes {
		get(i + 2)
	}
	for deadline := time.Now().Add(5 * time.Second); running() < MaxDashComputes; {
		if time.Now().After(deadline) {
			t.Fatalf("вычислений: %d", running())
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Другие периоды — 503 с Retry-After сразу.
	for i := range 4 {
		get(i + 10)
	}
	for range 4 {
		if r := <-out; r.code != http.StatusServiceUnavailable || r.retry == "" {
			t.Fatalf("сверх предела: %d, Retry-After %q", r.code, r.retry)
		}
	}
	// Тот же запрос, что уже считается, не занимает новое место: ждёт итог.
	get(2)
	time.Sleep(50 * time.Millisecond)
	close(block)
	wg.Wait()
	close(out)
	ok := 0
	for r := range out {
		if r.code == http.StatusOK {
			ok++
		}
	}
	e.dash.mu.Lock()
	peak := e.dash.peak
	e.dash.mu.Unlock()
	if peak > MaxDashComputes || ok != MaxDashComputes+1 {
		t.Fatalf("одновременных вычислений: %d, успешных ответов: %d", peak, ok)
	}
}

// Шаг потока и срок снимка растут с длиной периода.
func TestDashTick(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		d    time.Duration
		want time.Duration
	}{{24 * time.Hour, dashStreamEvery}, {7 * 24 * time.Hour, 20 * dashStreamEvery}, {90 * 24 * time.Hour, 100 * dashStreamEvery}} {
		if got := dashTick(dashParams{from: now.Add(-tc.d), to: now}); got != tc.want {
			t.Errorf("%v: %v, ожидается %v", tc.d, got, tc.want)
		}
	}
}

// stalledWriter — клиент потока, переставший читать: первая запись проходит,
// следующие ждут срока записи (SetWriteDeadline) и завершаются ошибкой, без
// срока — висят до release.
type stalledWriter struct {
	hdr      http.Header
	mu       sync.Mutex
	deadline time.Time
	writes   int
	release  chan struct{}
}

func (s *stalledWriter) Header() http.Header { return s.hdr }
func (s *stalledWriter) WriteHeader(int)     {}
func (s *stalledWriter) FlushError() error   { return nil }

func (s *stalledWriter) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
	return nil
}

func (s *stalledWriter) Write(b []byte) (int, error) {
	s.mu.Lock()
	s.writes++
	n, dl := s.writes, s.deadline
	s.mu.Unlock()
	if n == 1 {
		return len(b), nil
	}
	if dl.IsZero() {
		<-s.release
		return 0, os.ErrClosed
	}
	select {
	case <-time.After(time.Until(dl)):
	case <-s.release:
	}
	return 0, os.ErrDeadlineExceeded
}

// 3Н44 ревью 3.r3: поток SSE не держит место в пределе потоков вечно —
// у записи есть срок, у потока — предельный срок жизни, остановка сервера
// закрывает потоки сразу.
func TestDashboardStreamBounded(t *testing.T) {
	oldEvery, oldWrite, oldAge := dashStreamEvery, dashStreamWriteTimeout, dashStreamMaxAge
	dashStreamEvery, dashStreamWriteTimeout = 20*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { dashStreamEvery, dashStreamWriteTimeout, dashStreamMaxAge = oldEvery, oldWrite, oldAge })
	e := newAppsEnv(t)
	an := e.mustLogin(t, "analyst")

	// Клиент перестал читать: обработчик выходит по сроку записи.
	sw := &stalledWriter{hdr: http.Header{}, release: make(chan struct{})}
	t.Cleanup(func() { close(sw.release) })
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboards/stream?dashboard=overview&period=24h", nil)
	for _, c := range an.cookies {
		req.AddCookie(c)
	}
	done := make(chan struct{})
	go func() {
		e.h.ServeHTTP(sw, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("поток с непрочитанными данными не закрыт по сроку записи")
	}

	srv := httptest.NewServer(e.h)
	t.Cleanup(srv.Close)
	// waitEOF открывает поток по настоящему TCP и ждёт, пока сервер его закроет.
	waitEOF := func(after func()) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/dashboards/stream?dashboard=overview&period=24h", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range an.cookies {
			req.AddCookie(c)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = resp.Body.Close() //nolint:gosec // G104: закрытие тестового ответа
		}()
		if resp.StatusCode != 200 {
			t.Fatalf("поток: %d", resp.StatusCode)
		}
		if after != nil {
			after()
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatalf("поток не закрыт сервером: %v", err)
		}
	}
	// Предельный срок жизни.
	dashStreamMaxAge = 200 * time.Millisecond
	waitEOF(nil)
	// Остановка сервера.
	dashStreamMaxAge = time.Hour
	waitEOF(func() { close(e.stopping) })

	// Все места возвращены: пользователь снова открывает три потока (после
	// остановки каждый тут же закрывается, но место занимает и отдаёт).
	for range dashStreamsPerSubject {
		waitEOF(nil)
	}
}
