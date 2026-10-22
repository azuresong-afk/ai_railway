package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Дашборды (ТЗ 5.8, 6.4; задача 3.19 этапа 3): агрегаты событий без
// содержимого запросов и ответов. Чтение — dashboards.read; владелец
// приложения (ScopeOwn) видит только дашборд «Приложение» своих
// приложений, остальные дашборды требуют права на все объекты (УПД.8).
// Режим реального времени — SSE: тот же снимок каждые dashStreamEvery.

// Параметры дашбордов и потока.
const (
	dashReadTimeout = 15 * time.Second
	// dashStreamsPerSubject и dashStreamsTotal — одновременных потоков на
	// пользователя или токен и на сервер.
	dashStreamsPerSubject = 3
	dashStreamsTotal      = 100
	// dashCacheTTL — снимок общий для запросов с одинаковыми условиями.
	dashCacheTTL     = 2 * time.Second
	dashCacheEntries = 256
	dashTopN         = 10
)

// dashStreamEvery — период снимков потока: задержка не больше 5 с.
var dashStreamEvery = 3 * time.Second

// Именованные периоды ТЗ 5.8.
var dashPeriods = map[string]time.Duration{
	"15m": 15 * time.Minute, "1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
}

// DashboardReader — чтение агрегатов (*events.DashStore).
type DashboardReader interface {
	Totals(ctx context.Context, q events.DashQuery) (events.DashTotals, error)
	Latency(ctx context.Context, q events.DashQuery) (events.DashLatency, error)
	DecisionSeries(ctx context.Context, q events.DashQuery) ([]events.DashPoint, error)
	FindingSeries(ctx context.Context, q events.DashQuery, dim, prefix string) ([]events.DashPoint, error)
	TopFindings(ctx context.Context, q events.DashQuery, dim, prefix string, limit int) ([]events.DashTop, error)
	PIIBreakdown(ctx context.Context, q events.DashQuery) ([]events.DashPIIRow, error)
	Heatmap(ctx context.Context, q events.DashQuery) ([]events.DashCell, error)
	RequestsBy(ctx context.Context, q events.DashQuery, dim string, limit int) ([]events.DashRequestRow, error)
	UsageSeries(ctx context.Context, q events.DashQuery) ([]events.DashUsagePoint, error)
	Feed(ctx context.Context, to time.Time, app string, all bool, limit int) ([]events.DashFeedItem, error)
	Ready(ctx context.Context) (bool, error)
}

func dashboardRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/dashboards/overview", Permission: auth.PermDashboardsRead, Handler: needDash(d, d.dashHandler("overview"))},
		{Method: http.MethodGet, Path: "/api/v1/dashboards/threats", Permission: auth.PermDashboardsRead, Handler: needDash(d, d.dashHandler("threats"))},
		{Method: http.MethodGet, Path: "/api/v1/dashboards/pii", Permission: auth.PermDashboardsRead, Handler: needDash(d, d.dashHandler("pii"))},
		{Method: http.MethodGet, Path: "/api/v1/dashboards/consumption", Permission: auth.PermDashboardsRead, Handler: needDash(d, d.dashHandler("consumption"))},
		{Method: http.MethodGet, Path: "/api/v1/dashboards/app/{id}", Permission: auth.PermDashboardsRead, Scoped: true, Handler: needDash(d, d.dashHandler("app"))},
		{Method: http.MethodGet, Path: "/api/v1/dashboards/stream", Permission: auth.PermDashboardsRead, Scoped: true, Handler: needDash(d, d.dashStream)},
	}
}

func needDash(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Dashboards == nil || d.Auth == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Дашборды не подключены на сервере."))
			return
		}
		h(w, r)
	}
}

// dashPeriod — период ответа и состояние агрегатов.
type dashPeriod struct {
	// Name — именованный период (15m, 1h, 24h, 7d, 30d) или custom.
	Name string `json:"name"`
	// From и To — фактический период: для почасовых данных начало
	// округляется до часа вниз.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Unit — шаг рядов: minute, hour или day (период длиннее 31 суток).
	Unit     string `json:"unit"`
	Timezone string `json:"timezone"`
	// AggregatesReady — досчёт прошлых периодов закончен: цифры полные.
	AggregatesReady bool `json:"aggregates_ready"`
}

type dashHolder struct {
	Period dashPeriod `json:"period"`
}

func (h *dashHolder) period() *dashPeriod { return &h.Period }

type dashView interface{ period() *dashPeriod }

// DashTotalsView — итоги периода; стоимость — рубли десятичной строкой.
type DashTotalsView struct {
	events.DashTotals
	Cost string `json:"cost"`
}

func totalsView(t events.DashTotals) DashTotalsView {
	return DashTotalsView{DashTotals: t, Cost: apps.FormatMoney(t.Cost, 7)}
}

// DashLatencyView — задержка шлюза: p95 в мс; overflow — больше 5 с.
type DashLatencyView struct {
	P95Ms    int   `json:"p95_ms"`
	Overflow bool  `json:"overflow"`
	Requests int64 `json:"requests"`
}

func latencyView(l events.DashLatency) DashLatencyView {
	if l.P95 == events.DashLatencyOverflow {
		return DashLatencyView{P95Ms: events.DashLatencyBounds[len(events.DashLatencyBounds)-1], Overflow: true, Requests: l.Total}
	}
	return DashLatencyView{P95Ms: l.P95, Requests: l.Total}
}

// DashRequestRowView — запросы по ключу; стоимость — рубли.
type DashRequestRowView struct {
	events.DashRequestRow
	Cost string `json:"cost"`
}

func rowsView(rows []events.DashRequestRow) []DashRequestRowView {
	out := make([]DashRequestRowView, 0, len(rows))
	for _, r := range rows {
		out = append(out, DashRequestRowView{DashRequestRow: r, Cost: apps.FormatMoney(r.Cost, 7)})
	}
	return out
}

// OverviewView — дашборд «Обзор» (ТЗ 6.4, п. 3). Открытые инциденты,
// оповещения и состояние шлюзов консоль берёт из их API.
type OverviewView struct {
	dashHolder
	Totals       DashTotalsView        `json:"totals"`
	Latency      DashLatencyView       `json:"latency"`
	Decisions    []events.DashPoint    `json:"decisions"`
	TopDetectors []events.DashTop      `json:"top_detectors"`
	Apps         []DashRequestRowView  `json:"apps"`
	Feed         []events.DashFeedItem `json:"feed"`
}

// ThreatsView — дашборд «Угрозы»: находки по строкам матрицы обнаружения,
// категориям и детекторам во времени, тепловая карта день недели × час.
type ThreatsView struct {
	dashHolder
	Totals DashTotalsView `json:"totals"`
	// NonTextUncheckedShare — доля запросов с непроверенным нетекстовым содержимым, 0..1.
	NonTextUncheckedShare float64            `json:"non_text_unchecked_share"`
	TopThreats            []events.DashTop   `json:"top_threats"`
	TopCategories         []events.DashTop   `json:"top_categories"`
	TopDetectors          []events.DashTop   `json:"top_detectors"`
	ByThreat              []events.DashPoint `json:"by_threat"`
	ByCategory            []events.DashPoint `json:"by_category"`
	ByDetector            []events.DashPoint `json:"by_detector"`
	Heatmap               []events.DashCell  `json:"heatmap"`
}

// PIIView — дашборд «ПДн»: типы, приложения, действия.
type PIIView struct {
	dashHolder
	Findings int64               `json:"findings"`
	Types    []events.DashTop    `json:"types"`
	Rows     []events.DashPIIRow `json:"rows"`
	Series   []events.DashPoint  `json:"series"`
}

// AppDashboardView — дашборд «Приложение».
type AppDashboardView struct {
	dashHolder
	Application  DashAppRef            `json:"application"`
	Totals       DashTotalsView        `json:"totals"`
	Latency      DashLatencyView       `json:"latency"`
	Decisions    []events.DashPoint    `json:"decisions"`
	TopDetectors []events.DashTop      `json:"top_detectors"`
	Models       []DashRequestRowView  `json:"models"`
	Feed         []events.DashFeedItem `json:"feed"`
}

// DashAppRef — приложение дашборда.
type DashAppRef struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// DashUsagePointView — расход по шагу ряда; стоимость — рубли.
type DashUsagePointView struct {
	Bucket   time.Time `json:"bucket"`
	Requests int64     `json:"requests"`
	Tokens   int64     `json:"tokens"`
	Cost     string    `json:"cost"`
}

// DashForecast — прогноз расхода до конца месяца (линейный по прошедшей
// части месяца); без данных за сутки прогноза нет.
type DashForecast struct {
	Month     string `json:"month"`
	Spent     string `json:"spent"`
	Projected string `json:"projected"`
	// Enough — данных достаточно для прогноза (прошли сутки месяца и есть расход).
	Enough       bool    `json:"enough"`
	MonthElapsed float64 `json:"month_elapsed"`
}

// ConsumptionView — дашборд «Потребление» (ТЗ 6.4, п. 13).
type ConsumptionView struct {
	dashHolder
	Totals       DashTotalsView       `json:"totals"`
	Series       []DashUsagePointView `json:"series"`
	ByApp        []DashRequestRowView `json:"by_app"`
	ByModel      []DashRequestRowView `json:"by_model"`
	ByProvider   []DashRequestRowView `json:"by_provider"`
	ByDepartment []DashRequestRowView `json:"by_department"`
	ByUser       []DashRequestRowView `json:"by_user"`
	Forecast     DashForecast         `json:"forecast"`
	// Budgets — исполнение бюджетов за текущий месяц; только с budgets.read.
	Budgets []BudgetStatusView `json:"budgets"`
}

// dashParams — разобранные параметры запроса дашборда.
type dashParams struct {
	// name — именованный период или custom.
	name     string
	from, to time.Time
	// rolling — конец периода «сейчас»: каждый снимок считается от текущего момента.
	rolling bool
	feedAll bool
}

var dashKeys = map[string]bool{"period": true, "from": true, "to": true, "feed": true}

// parseDashParams разбирает period или from/to (RFC 3339) и feed.
func parseDashParams(q url.Values, now time.Time, extra ...string) (dashParams, *Problem) {
	var out dashParams
	for k, vs := range q {
		if !dashKeys[k] && !slices.Contains(extra, k) {
			return out, Invalid("Неизвестный параметр запроса.", FieldError{k, "Допустимы period, from, to, feed."})
		}
		if len(vs) != 1 {
			return out, Invalid("Параметры заданы неверно.", FieldError{k, "Параметр указывается один раз."})
		}
	}
	var bad []FieldError
	pt := func(name string) time.Time {
		v := q.Get(name)
		if v == "" {
			return time.Time{}
		}
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			bad = append(bad, FieldError{name, "Укажите время в формате RFC 3339, например 2026-10-21T15:00:00Z."})
		}
		return t.UTC()
	}
	from, to := pt("from"), pt("to")
	name := q.Get("period")
	rolling := true
	switch {
	case name != "" && (!from.IsZero() || !to.IsZero()):
		bad = append(bad, FieldError{"period", "Укажите либо period, либо from и to."})
	case name != "":
		dur, ok := dashPeriods[name]
		if !ok {
			bad = append(bad, FieldError{"period", "Одно из значений: 15m, 1h, 24h, 7d, 30d."})
		}
		to, from = now, now.Add(-dur)
	case from.IsZero() && to.IsZero():
		name, to, from = "24h", now, now.Add(-24*time.Hour)
	default:
		name = "custom"
		if from.IsZero() {
			bad = append(bad, FieldError{"from", "Для произвольного периода нужны from и to."})
		}
		if to.IsZero() || to.After(now) {
			to = now
		} else {
			rolling = false
		}
		if !from.IsZero() && (!from.Before(to) || to.Sub(from) > events.DashMaxRange) {
			bad = append(bad, FieldError{"from", "Начало раньше конца, период не длиннее 366 суток."})
		}
	}
	if f := q.Get("feed"); f != "" && f != "all" && f != "actions" {
		bad = append(bad, FieldError{"feed", "Одно из значений: all, actions."})
	}
	if len(bad) > 0 {
		return out, Invalid("Период задан неверно.", bad...)
	}
	return dashParams{name: name, from: from, to: to, rolling: rolling, feedAll: q.Get("feed") == "all"}, nil
}

// dashScope проверяет права на уровне объектов и возвращает приложение
// для дашборда «Приложение».
func (d Deps) dashScope(r *http.Request, name, appID string) (DashAppRef, *Problem) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		return DashAppRef{}, errForbidden()
	}
	if name != "app" {
		if !p.Grants.Full(auth.PermDashboardsRead) {
			return DashAppRef{}, errForbidden()
		}
		return DashAppRef{}, nil
	}
	if d.Apps == nil {
		return DashAppRef{}, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Приложения не подключены на сервере.")
	}
	owner, _ := ownerScope(r, auth.PermDashboardsRead)
	id, err := store.ParseUUID(appID)
	if err != nil {
		return DashAppRef{}, NewProblem(http.StatusNotFound, CodeNotFound, appNotFound)
	}
	a, err := d.Apps.Application(r.Context(), string(id), owner)
	if err != nil {
		return DashAppRef{}, appsProblem(d.Logger, err, appNotFound)
	}
	return DashAppRef{ID: a.ID, Slug: a.Slug, Name: a.Name}, nil
}

func (d Deps) dashHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID := ""
		if name == "app" {
			appID = r.PathValue("id")
		}
		now := time.Now().UTC()
		params, prob := parseDashParams(r.URL.Query(), now)
		if prob != nil {
			WriteProblem(w, prob)
			return
		}
		app, prob := d.dashScope(r, name, appID)
		if prob != nil {
			WriteProblem(w, prob)
			return
		}
		ctx, cancel := contextTimeout(r, dashReadTimeout)
		defer cancel()
		body, _, err := d.dashSnapshot(ctx, name, params, app, auth.PermBudgetsRead, r)
		if err != nil {
			WriteProblem(w, d.dashProblem(err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body) //nolint:gosec // G104: обрыв соединения клиента не требует действий
	}
}

func (d Deps) dashProblem(err error) *Problem {
	switch {
	case errors.Is(err, events.ErrDashRange), errors.Is(err, events.ErrBadRange):
		return Invalid("Период задан неверно.", FieldError{"from", "Начало раньше конца, период не длиннее 366 суток."})
	case errors.Is(err, events.ErrTooManyRows):
		return Invalid("Слишком много данных за период: сузьте период.")
	case errors.Is(err, context.DeadlineExceeded):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Дашборд не успел посчитаться: сузьте период или повторите позже.")
	}
	d.Logger.Error("дашборд: ошибка чтения агрегатов", "class", "db", "error", err)
	return errInternal()
}

// dashCache — снимки дашбордов с одинаковыми условиями, TTL dashCacheTTL.
type dashCache struct {
	mu sync.Mutex
	m  map[string]dashEntry
}

type dashEntry struct {
	at   time.Time
	body []byte
	data [32]byte
}

func newDashCache() *dashCache { return &dashCache{m: map[string]dashEntry{}} }

func (c *dashCache) get(key string, now time.Time) (dashEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || now.Sub(e.at) >= dashCacheTTL {
		return dashEntry{}, false
	}
	return e, true
}

func (c *dashCache) put(key string, e dashEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= dashCacheEntries {
		for k, v := range c.m {
			if e.at.Sub(v.at) >= dashCacheTTL {
				delete(c.m, k)
			}
		}
		if len(c.m) >= dashCacheEntries {
			clear(c.m)
		}
	}
	c.m[key] = e
}

// dashSnapshot возвращает JSON дашборда и отпечаток данных без периода
// (для потока: неизменный снимок не пересылается). Условия бюджетов
// (budgetPerm) входят в ключ кэша: состав ответа зависит от прав.
func (d Deps) dashSnapshot(ctx context.Context, name string, p dashParams, app DashAppRef, budgetPerm string, r *http.Request) ([]byte, [32]byte, error) {
	pr, _ := PrincipalFrom(r.Context())
	withBudgets := name == "consumption" && pr.Grants.Full(budgetPerm)
	period := p.name
	if p.name == "custom" {
		period = fmt.Sprintf("custom-%d-%v", p.from.Unix(), p.rolling)
		if !p.rolling {
			period = fmt.Sprintf("custom-%d-%d", p.from.Unix(), p.to.Unix())
		}
	}
	key := fmt.Sprintf("%s|%s|%s|%v|%v", name, app.Slug, period, p.feedAll, withBudgets)
	now := time.Now()
	if d.DashCache != nil {
		if e, ok := d.DashCache.get(key, now); ok {
			return e.body, e.data, nil
		}
	}
	cfg, err := d.Auth.InstallSettings(ctx)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if _, err := time.LoadLocation(cfg.Timezone); err != nil {
		return nil, [32]byte{}, fmt.Errorf("часовой пояс установки: %w", err)
	}
	q := events.DashQuery{From: p.from, To: p.to, App: app.Slug, TZ: cfg.Timezone}
	// Скользящий период считается от текущего момента каждого снимка.
	if p.rolling {
		q.To = now.UTC()
		if dur, ok := dashPeriods[p.name]; ok {
			q.From = q.To.Add(-dur)
		}
	}
	ready, err := d.Dashboards.Ready(ctx)
	if err != nil {
		return nil, [32]byte{}, err
	}
	norm := q.Normalize()
	meta := dashPeriod{Name: p.name, From: norm.From, To: norm.To, Unit: norm.Unit(),
		Timezone: cfg.Timezone, AggregatesReady: ready}
	var view dashView
	switch name {
	case "overview":
		view, err = d.buildOverview(ctx, q, p.feedAll)
	case "threats":
		view, err = d.buildThreats(ctx, q)
	case "pii":
		view, err = d.buildPII(ctx, q)
	case "app":
		view, err = d.buildApp(ctx, q, app, p.feedAll)
	case "consumption":
		view, err = d.buildConsumption(ctx, q, withBudgets)
	default:
		err = fmt.Errorf("неизвестный дашборд %q", name)
	}
	if err != nil {
		return nil, [32]byte{}, err
	}
	*view.period() = meta
	body, err := json.Marshal(view)
	if err != nil {
		return nil, [32]byte{}, err
	}
	// Отпечаток данных — без периода: его конец меняется каждую секунду.
	saved := *view.period()
	view.period().From, view.period().To = time.Time{}, time.Time{}
	plain, err := json.Marshal(view)
	*view.period() = saved
	if err != nil {
		return nil, [32]byte{}, err
	}
	e := dashEntry{at: now, body: body, data: sha256.Sum256(plain)}
	if d.DashCache != nil {
		d.DashCache.put(key, e)
	}
	return body, e.data, nil
}

func nz[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (d Deps) buildOverview(ctx context.Context, q events.DashQuery, feedAll bool) (dashView, error) {
	var v OverviewView
	var err error
	t, err := d.Dashboards.Totals(ctx, q)
	if err != nil {
		return nil, err
	}
	lat, err := d.Dashboards.Latency(ctx, q)
	if err != nil {
		return nil, err
	}
	if v.Decisions, err = d.Dashboards.DecisionSeries(ctx, q); err != nil {
		return nil, err
	}
	if v.TopDetectors, err = d.Dashboards.TopFindings(ctx, q, events.DimDetector, "", dashTopN); err != nil {
		return nil, err
	}
	byApp, err := d.Dashboards.RequestsBy(ctx, q, events.DimApp, 20)
	if err != nil {
		return nil, err
	}
	if v.Feed, err = d.Dashboards.Feed(ctx, q.To, "", feedAll, 30); err != nil {
		return nil, err
	}
	v.Totals, v.Latency, v.Apps = totalsView(t), latencyView(lat), rowsView(byApp)
	v.Decisions, v.TopDetectors, v.Feed = nz(v.Decisions), nz(v.TopDetectors), nz(v.Feed)
	return &v, nil
}

// onlyKeys оставляет точки ряда с ключами из top: ряд ограничен самыми
// частыми значениями.
func onlyKeys(points []events.DashPoint, top []events.DashTop) []events.DashPoint {
	keep := make(map[string]bool, len(top))
	for _, t := range top {
		keep[t.Key] = true
	}
	out := make([]events.DashPoint, 0, len(points))
	for _, p := range points {
		if keep[p.Key] {
			out = append(out, p)
		}
	}
	return out
}

func (d Deps) buildThreats(ctx context.Context, q events.DashQuery) (dashView, error) {
	var v ThreatsView
	t, err := d.Dashboards.Totals(ctx, q)
	if err != nil {
		return nil, err
	}
	v.Totals = totalsView(t)
	if t.Requests > 0 {
		v.NonTextUncheckedShare = float64(t.NonTextUnchecked) / float64(t.Requests)
	}
	type dim struct {
		name string
		top  *[]events.DashTop
		ser  *[]events.DashPoint
	}
	for _, x := range []dim{{events.DimThreat, &v.TopThreats, &v.ByThreat}, {events.DimCategory, &v.TopCategories, &v.ByCategory},
		{events.DimDetector, &v.TopDetectors, &v.ByDetector}} {
		if *x.top, err = d.Dashboards.TopFindings(ctx, q, x.name, "", dashTopN); err != nil {
			return nil, err
		}
		series, err := d.Dashboards.FindingSeries(ctx, q, x.name, "")
		if err != nil {
			return nil, err
		}
		*x.ser = onlyKeys(series, *x.top)
		*x.top, *x.ser = nz(*x.top), nz(*x.ser)
	}
	if v.Heatmap, err = d.Dashboards.Heatmap(ctx, q); err != nil {
		return nil, err
	}
	v.Heatmap = nz(v.Heatmap)
	return &v, nil
}

func (d Deps) buildPII(ctx context.Context, q events.DashQuery) (dashView, error) {
	var v PIIView
	var err error
	if v.Types, err = d.Dashboards.TopFindings(ctx, q, events.DimCategory, "pii.", 20); err != nil {
		return nil, err
	}
	if v.Rows, err = d.Dashboards.PIIBreakdown(ctx, q); err != nil {
		return nil, err
	}
	series, err := d.Dashboards.FindingSeries(ctx, q, events.DimCategory, "pii.")
	if err != nil {
		return nil, err
	}
	v.Series = nz(onlyKeys(series, v.Types))
	for _, r := range v.Rows {
		v.Findings += r.Findings
	}
	v.Types, v.Rows = nz(v.Types), nz(v.Rows)
	return &v, nil
}

func (d Deps) buildApp(ctx context.Context, q events.DashQuery, app DashAppRef, feedAll bool) (dashView, error) {
	v := AppDashboardView{Application: app}
	t, err := d.Dashboards.Totals(ctx, q)
	if err != nil {
		return nil, err
	}
	lat, err := d.Dashboards.Latency(ctx, q)
	if err != nil {
		return nil, err
	}
	if v.Decisions, err = d.Dashboards.DecisionSeries(ctx, q); err != nil {
		return nil, err
	}
	if v.TopDetectors, err = d.Dashboards.TopFindings(ctx, q, events.DimDetector, "", dashTopN); err != nil {
		return nil, err
	}
	models, err := d.Dashboards.RequestsBy(ctx, q, events.DimModel, dashTopN)
	if err != nil {
		return nil, err
	}
	if v.Feed, err = d.Dashboards.Feed(ctx, q.To, app.Slug, feedAll, 30); err != nil {
		return nil, err
	}
	v.Totals, v.Latency, v.Models = totalsView(t), latencyView(lat), rowsView(models)
	v.Decisions, v.TopDetectors, v.Feed = nz(v.Decisions), nz(v.TopDetectors), nz(v.Feed)
	return &v, nil
}

// forecast — линейный прогноз расхода месяца: расход на текущий момент,
// поделённый на прошедшую долю месяца. Меньше суток месяца или нулевой
// расход — прогноза нет.
func forecast(spent int64, monthStart, monthEnd, now time.Time, month string) DashForecast {
	f := DashForecast{Month: month, Spent: apps.FormatMoney(spent, 7), Projected: apps.FormatMoney(spent, 7)}
	total, elapsed := monthEnd.Sub(monthStart), now.Sub(monthStart)
	if total <= 0 || elapsed <= 0 {
		return f
	}
	f.MonthElapsed = min(float64(elapsed)/float64(total), 1)
	if elapsed < 24*time.Hour || spent <= 0 {
		return f
	}
	f.Enough = true
	projected := float64(spent) / f.MonthElapsed
	if projected > 4e18 {
		projected = 4e18
	}
	f.Projected = apps.FormatMoney(int64(projected), 7)
	return f
}

func (d Deps) buildConsumption(ctx context.Context, q events.DashQuery, withBudgets bool) (dashView, error) {
	var v ConsumptionView
	t, err := d.Dashboards.Totals(ctx, q)
	if err != nil {
		return nil, err
	}
	v.Totals = totalsView(t)
	series, err := d.Dashboards.UsageSeries(ctx, q)
	if err != nil {
		return nil, err
	}
	v.Series = make([]DashUsagePointView, 0, len(series))
	for _, s := range series {
		v.Series = append(v.Series, DashUsagePointView{Bucket: s.Bucket, Requests: s.Requests, Tokens: s.Tokens, Cost: apps.FormatMoney(s.Cost, 7)})
	}
	for _, x := range []struct {
		dim string
		dst *[]DashRequestRowView
	}{{events.DimApp, &v.ByApp}, {events.DimModel, &v.ByModel}, {events.DimProvider, &v.ByProvider},
		{events.DimDept, &v.ByDepartment}, {events.DimUser, &v.ByUser}} {
		rows, err := d.Dashboards.RequestsBy(ctx, q, x.dim, 20)
		if err != nil {
			return nil, err
		}
		*x.dst = rowsView(rows)
	}
	// Прогноз — по текущему месяцу в поясе установки, независимо от периода.
	loc, err := time.LoadLocation(q.TZ)
	if err != nil {
		return nil, err
	}
	now := q.To.In(loc)
	if time.Since(q.To) > time.Minute {
		now = time.Now().In(loc)
	}
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
	mq := events.DashQuery{From: monthStart.UTC(), To: now.UTC(), App: q.App, TZ: q.TZ}
	var spent int64
	if mq.From.Before(mq.To) {
		mt, err := d.Dashboards.Totals(ctx, mq)
		if err != nil {
			return nil, err
		}
		spent = mt.Cost
	}
	v.Forecast = forecast(spent, monthStart, monthStart.AddDate(0, 1, 0), now, now.Format("2006-01"))
	if withBudgets && d.Apps != nil {
		sts, _, err := d.Apps.BudgetStatuses(ctx, "")
		if err != nil {
			return nil, err
		}
		for _, st := range sts {
			if st.Budget != nil {
				v.Budgets = append(v.Budgets, budgetStatusView(st))
			}
		}
	}
	v.Budgets = nz(v.Budgets)
	return &v, nil
}

// dashStream — SSE: снимок дашборда при подключении и затем при каждом
// изменении данных, проверка прав на каждом шаге (выход, отзыв токена и
// смена роли закрывают поток), пустой комментарий вместо неизменного
// снимка. Параметры — как у GET-дашборда плюс dashboard и app_id.
func (d Deps) dashStream(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name, appID := q.Get("dashboard"), q.Get("app_id")
	if !slices.Contains([]string{"overview", "threats", "pii", "consumption", "app"}, name) {
		WriteProblem(w, Invalid("Дашборд задан неверно.", FieldError{"dashboard", "Одно из значений: overview, threats, pii, consumption, app."}))
		return
	}
	if (name == "app") != (appID != "") {
		WriteProblem(w, Invalid("Дашборд задан неверно.", FieldError{"app_id", "ID приложения нужен только для дашборда app."}))
		return
	}
	now := time.Now().UTC()
	rest := url.Values{}
	for k, vs := range q {
		if k != "dashboard" && k != "app_id" {
			rest[k] = vs
		}
	}
	params, prob := parseDashParams(rest, now)
	if prob != nil {
		WriteProblem(w, prob)
		return
	}
	app, prob := d.dashScope(r, name, appID)
	if prob != nil {
		WriteProblem(w, prob)
		return
	}
	pr, _ := PrincipalFrom(r.Context())
	subject := pr.ID
	if d.DashStreams != nil {
		if !d.DashStreams.Acquire(subject) {
			w.Header().Set("Retry-After", "10")
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited,
				"Открыто слишком много потоков обновления: закройте лишние вкладки и повторите."))
			return
		}
		defer d.DashStreams.Release(subject)
	}
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, "retry: 5000\n\n"); err != nil {
		return
	}
	var last [32]byte
	cur := r
	t := time.NewTicker(dashStreamEvery)
	defer t.Stop()
	for first := true; ; first = false {
		if !first {
			select {
			case <-r.Context().Done():
				return
			case <-t.C:
			}
			// Выход, отзыв токена, деактивация и потеря права закрывают поток.
			p2, dec := d.Reauthorize(r, auth.PermDashboardsRead)
			if dec != Allow {
				return
			}
			cur = r.WithContext(WithPrincipal(r.Context(), p2))
			// Право на приложение могло смениться (владелец, архив).
			var prob *Problem
			if app, prob = d.dashScope(cur, name, appID); prob != nil {
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), dashReadTimeout)
		body, sum, err := d.dashSnapshot(ctx, name, params, app, auth.PermBudgetsRead, cur)
		cancel()
		var out bytes.Buffer
		switch {
		case err != nil:
			if r.Context().Err() != nil {
				return
			}
			d.Logger.Warn("поток дашборда: снимок не получен", "error", err)
			out.WriteString("event: error\ndata: {\"detail\":\"Данные временно недоступны.\"}\n\n")
		case !first && sum == last:
			out.WriteString(": ping\n\n")
		default:
			last = sum
			out.WriteString("event: snapshot\ndata: ")
			out.Write(body)
			out.WriteString("\n\n")
		}
		if _, err := w.Write(out.Bytes()); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}
