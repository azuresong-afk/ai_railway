package events_test

import (
	"fmt"
	"io"
	"log/slog"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// uuidAt — UUIDv7 события с заданным временем (ключ секции) и номером.
func uuidAt(t time.Time, n int) string {
	ms := uint64(t.UnixMilli())
	return fmt.Sprintf("%08x-%04x-7%03x-8%03x-%012x", ms>>16, ms&0xffff, n&0xfff, n&0xfff, uint64(n)) //nolint:gosec // G115: время теста положительно
}

func dashStoreFor(t *testing.T, e *pgEnv) (*events.DashStore, *events.PGStore) {
	t.Helper()
	ds, err := events.NewDashStore(e.app, e.app, audit.DefaultOrgID, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := events.NewPGStore(e.app, e.box, e.log, "", events.WithIngestHook(ds.Hook()))
	if err != nil {
		t.Fatal(err)
	}
	return ds, st
}

// dashDump — содержимое таблиц агрегатов в виде отсортированных строк.
func dashDump(t *testing.T, e *pgEnv) string {
	t.Helper()
	var b strings.Builder
	for _, tab := range []string{"dash_req_hour", "dash_find_hour", "dash_user_hour", "dash_latency_hour"} {
		rows, err := e.owner.Query(pgCtx(t), "SELECT t::text FROM "+tab+" t ORDER BY 1")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(&b, tab)
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&b, s)
		}
		rows.Close()
	}
	return b.String()
}

type dashEvent struct {
	at       time.Time
	n        int
	typ      string
	app      string
	provider string
	model    string
	user     string
	action   string
	mode     string
	tokens   [2]int
	findings []events.Finding
	latency  map[string]int64
}

func (d dashEvent) build() events.Event {
	ev := events.Event{ID: uuidAt(d.at, d.n), Time: d.at, Type: d.typ, App: d.app, Provider: d.provider, Model: d.model, User: d.user,
		PolicyMode: d.mode, Storage: events.StorageNone, Findings: d.findings, LatencyMS: d.latency,
		Decision: &events.Decision{Action: d.action, Applied: []string{d.action}, Severity: "high"}}
	if d.tokens != [2]int{} {
		ev.Tokens = &events.Tokens{Prompt: d.tokens[0], Completion: d.tokens[1]}
	}
	for _, f := range d.findings {
		if f.Threat != "" && !slices.Contains(ev.Threats, f.Threat) {
			ev.Threats = append(ev.Threats, f.Threat)
		}
	}
	return ev
}

func finding(cat, det, threat string) events.Finding {
	return events.Finding{Detector: det, Version: "1", Category: cat, Score: 0.9, Threat: threat, Location: "messages[0]"}
}

// Агрегаты дашбордов на живой БД: прирост хука равен пересчёту по events,
// дубли пакета не удваивают счётчики, граница часа, цены, периоды из events
// и из часовых таблиц, сбой хука не теряет событие и досчитывается.
func TestPGDashboardAggregates(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	ds, st := dashStoreFor(t, e)
	if err := ds.Init(ctx); err != nil {
		t.Fatal(err)
	}
	// Провайдер mock и цена модели m1: 2 ₽ и 4 ₽ за 1 000 токенов (0,0001 ₽).
	if _, err := e.owner.Exec(ctx, `INSERT INTO providers (id, org_id, slug, name, type, base_url, ca_pem, created_at, created_by, updated_at, updated_by)
		VALUES ('01900000-0000-7000-8000-0000000000b1', $1, 'mock', 'Mock', 'openai', 'https://mock.example', 'pem', now(), 't', now(), 't')`, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO model_prices (id, org_id, provider_id, model, input_price, output_price, created_at, created_by, updated_at, updated_by)
		VALUES ('01900000-0000-7000-8000-0000000000b2', $1, '01900000-0000-7000-8000-0000000000b1', 'm1', 20000, 40000, now(), 't', now(), 't')`, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}

	day := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	at := func(h, m, s int) time.Time {
		return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(s)*time.Second)
	}
	ev := []dashEvent{
		{at: at(10, 15, 0), n: 1, typ: events.TypeGatewayRequest, app: "a", provider: "mock", model: "m1", user: "a1b2c3", action: "block", mode: "enforce",
			tokens: [2]int{100, 50}, findings: []events.Finding{finding("pii.snils", "pii", "DM-31")}, latency: map[string]int64{"total": 120, "provider": 100}},
		{at: at(10, 59, 59), n: 2, typ: events.TypeGatewayRequest, app: "a", provider: "mock", model: "m1", user: "a1b2c3", action: "redact", mode: "enforce",
			tokens: [2]int{10, 10}, findings: []events.Finding{finding("pii.phone", "pii", "DM-31"), finding("pii.phone", "pii", "DM-31")},
			latency: map[string]int64{"total": 30}},
		{at: at(11, 0, 0), n: 3, typ: events.TypeGatewayRequest, app: "b", provider: "mock", model: "m2", user: "u1", action: "allow", mode: "enforce",
			tokens: [2]int{7, 3}, latency: map[string]int64{"total": 9, "provider": 5}},
		{at: at(11, 20, 0), n: 4, typ: events.TypeGatewayRequest, app: "b", provider: "mock", model: "m1", user: "u1", action: "block", mode: "monitor",
			findings: []events.Finding{finding("injection.override", "injection", "DM-01")}, latency: map[string]int64{"total": 3}},
		{at: at(12, 0, 0), n: 5, typ: events.TypeCheck, app: "a", action: "allow", mode: "enforce"},
	}
	auth := events.Event{ID: uuidAt(at(12, 5, 0), 6), Time: at(12, 5, 0), Type: events.TypeAuthFailure, PolicyMode: events.ModeEnforce,
		AuthFailure: &events.AuthFailure{RemoteAddr: "192.0.2.1", Reason: "invalid"}, Storage: events.StorageNone}
	var batch1, batch2 []events.Event
	for i, d := range ev {
		if i < 3 {
			batch1 = append(batch1, d.build())
		} else {
			batch2 = append(batch2, d.build())
		}
	}
	batch2 = append(batch2, auth)
	for _, b := range [][]events.Event{batch1, batch2, batch1} {
		if _, err := st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: b}); err != nil {
			t.Fatal(err)
		}
	}
	hookDump := dashDump(t, e)
	if err := ds.Recompute(ctx, day, day.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := dashDump(t, e); got != hookDump {
		t.Fatalf("прирост хука и пересчёт различаются:\n--- хук\n%s\n--- пересчёт\n%s", hookDump, got)
	}

	tz := "Europe/Moscow"
	hourly := events.DashQuery{From: day, To: day.Add(24 * time.Hour), TZ: tz}
	raw := events.DashQuery{From: at(10, 0, 0), To: at(11, 30, 0), TZ: tz}
	if hourly.Raw() || !raw.Raw() {
		t.Fatal("выбор источника периода")
	}
	want := events.DashTotals{Requests: 5, WithFindings: 3, Blocked: 1, WouldBlock: 1, Masked: 1, TokensPrompt: 117, TokensCompletion: 63,
		Cost: 4_600_000, UnpricedRequests: 1}
	if got, err := ds.Totals(ctx, hourly); err != nil || got != want {
		t.Fatalf("итоги по часам: %+v %v", got, err)
	}
	// Тот же период, прочитанный прямо из events, совпадает с таблицами.
	rawWant := want
	rawWant.Requests = 4 // проверка в 12:00 вне периода
	if got, err := ds.Totals(ctx, raw); err != nil || got != rawWant {
		t.Fatalf("итоги из events: %+v %v", got, err)
	}
	if got, err := ds.Totals(ctx, events.DashQuery{From: at(1, 0, 0), To: at(2, 0, 0), TZ: tz}); err != nil || got != (events.DashTotals{}) {
		t.Fatalf("пустой период: %+v %v", got, err)
	}
	if _, err := ds.Totals(ctx, events.DashQuery{From: at(2, 0, 0), To: at(1, 0, 0), TZ: tz}); err == nil {
		t.Fatal("перевёрнутый период принят")
	}
	if _, err := ds.Totals(ctx, events.DashQuery{From: day.AddDate(-2, 0, 0), To: day, TZ: tz}); err == nil {
		t.Fatal("период длиннее 366 суток принят")
	}

	lat, err := ds.Latency(ctx, hourly)
	if err != nil || lat.Total != 4 || lat.P95 != 50 {
		t.Fatalf("задержка: %+v %v", lat, err)
	}
	pts, err := ds.DecisionSeries(ctx, hourly)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, p := range pts {
		got[p.Bucket.Format("15:04")+" "+p.Key] += p.Value
	}
	if !slices.Equal(mapKeys(got), []string{"10:00 blocked", "10:00 masked", "11:00 allowed", "11:00 would_block", "12:00 allowed"}) {
		t.Fatalf("ряд решений: %v", got)
	}
	pii, err := ds.TopFindings(ctx, hourly, events.DimCategory, "pii.", 10)
	if err != nil || len(pii) != 2 || pii[0] != (events.DashTop{Key: "pii.phone", Value: 2}) || pii[1] != (events.DashTop{Key: "pii.snils", Value: 1}) {
		t.Fatalf("ПДн: %+v %v", pii, err)
	}
	if rows, err := ds.PIIBreakdown(ctx, hourly); err != nil || len(rows) != 2 || rows[0].Category != "pii.phone" || rows[0].Action != "redact" {
		t.Fatalf("разбор ПДн: %+v %v", rows, err)
	}
	loc, _ := time.LoadLocation(tz) //nolint:gosec // G104: имя пояса из теста
	cells, err := ds.Heatmap(ctx, hourly)
	if err != nil || len(cells) != 2 || cells[0].Findings != 3 || cells[1].Findings != 1 {
		t.Fatalf("тепловая карта: %+v %v", cells, err)
	}
	first := at(10, 15, 0).In(loc)
	wd := int(first.Weekday())
	if wd == 0 {
		wd = 7
	}
	if cells[0].Weekday != wd {
		t.Fatalf("день недели в поясе установки: %+v ждали %d", cells, wd)
	}
	for _, c := range cells {
		if c.Hour != 13 && c.Hour != 14 {
			t.Fatalf("час в поясе установки: %+v", cells)
		}
	}
	byApp, err := ds.RequestsBy(ctx, hourly, events.DimApp, 10)
	if err != nil || len(byApp) != 2 || byApp[0].Key != "a" || byApp[0].Requests != 3 || byApp[1].Key != "b" || byApp[1].Requests != 2 {
		t.Fatalf("по приложениям: %+v %v", byApp, err)
	}
	byUser, err := ds.RequestsBy(ctx, hourly, events.DimUser, 10)
	if err != nil || len(byUser) != 2 || byUser[0].Requests != 2 || byUser[1].Requests != 2 {
		t.Fatalf("по пользователям: %+v %v", byUser, err)
	}
	if byDept, err := ds.RequestsBy(ctx, hourly, events.DimDept, 10); err != nil || len(byDept) != 1 || byDept[0].Key != "" || byDept[0].Requests != 5 {
		t.Fatalf("по подразделениям: %+v %v", byDept, err)
	}
	if _, err := ds.RequestsBy(ctx, hourly, "x; drop", 10); err == nil {
		t.Fatal("чужое измерение принято")
	}
	hourly.App = "b"
	if got, err := ds.Totals(ctx, hourly); err != nil || got.Requests != 2 || got.Cost != 0 {
		t.Fatalf("итоги приложения: %+v %v", got, err)
	}
	feed, err := ds.Feed(ctx, day.Add(24*time.Hour), "", false, 10)
	if err != nil || len(feed) != 3 || feed[0].Action != "block" || feed[0].PolicyMode != "monitor" || feed[2].Action != "block" {
		t.Fatalf("лента решений: %+v %v", feed, err)
	}
	if feed, err := ds.Feed(ctx, day.Add(24*time.Hour), "", true, 10); err != nil || len(feed) != 5 {
		t.Fatalf("лента, все решения: %d %v", len(feed), err)
	}

	// Суточные корзины для периода длиннее 31 суток.
	long := events.DashQuery{From: day.AddDate(0, 0, -40), To: day.Add(24 * time.Hour), TZ: tz}
	if long.Unit() != events.UnitDay {
		t.Fatalf("корзина длинного периода: %s", long.Unit())
	}
	us, err := ds.UsageSeries(ctx, long)
	if err != nil || len(us) != 1 || us[0].Requests != 5 || us[0].Cost != 4_600_000 {
		t.Fatalf("расход по суткам: %+v %v", us, err)
	}

	// Сбой хука не теряет событие: часы помечаются к досчёту.
	if _, err := e.owner.Exec(ctx, "ALTER TABLE dash_find_hour RENAME TO dash_find_hour_x"); err != nil {
		t.Fatal(err)
	}
	late := dashEvent{at: at(13, 0, 0), n: 7, typ: events.TypeGatewayRequest, app: "a", provider: "mock", model: "m1", user: "a1b2c3", action: "block",
		mode: "enforce", tokens: [2]int{1, 1}, findings: []events.Finding{finding("pii.inn", "pii", "DM-31")}}
	res, err := st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{late.build()}})
	if err != nil || res.Accepted != 1 {
		t.Fatalf("приём при сбое агрегатов: %+v %v", res, err)
	}
	if ready, err := ds.Ready(ctx); err != nil || ready {
		t.Fatalf("после сбоя агрегаты не должны быть полными: %v %v", ready, err)
	}
	if _, err := e.owner.Exec(ctx, "ALTER TABLE dash_find_hour_x RENAME TO dash_find_hour"); err != nil {
		t.Fatal(err)
	}
	stepAll := func() {
		t.Helper()
		for range 64 {
			done, err := ds.BackfillStep(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if done {
				return
			}
		}
		t.Fatal("досчёт не закончился")
	}
	stepAll()
	if ready, err := ds.Ready(ctx); err != nil || !ready {
		t.Fatalf("после досчёта: %v %v", ready, err)
	}
	hourly.App = ""
	if got, err := ds.Totals(ctx, hourly); err != nil || got.Requests != 6 || got.Blocked != 2 {
		t.Fatalf("итоги после досчёта: %+v %v", got, err)
	}
	full := dashDump(t, e)

	// Досчёт с нуля (обновление установки с готовыми событиями) даёт те же строки.
	for _, tab := range []string{"dash_req_hour", "dash_find_hour", "dash_user_hour", "dash_latency_hour"} {
		if _, err := e.owner.Exec(ctx, "TRUNCATE "+tab); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.owner.Exec(ctx, "UPDATE dash_state SET backfill_cursor = NULL, backfill_done = false"); err != nil {
		t.Fatal(err)
	}
	stepAll()
	if got := dashDump(t, e); got != full {
		t.Fatalf("досчёт с нуля отличается:\n--- было\n%s\n--- стало\n%s", full, got)
	}
}

func mapKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Чужие огромные значения токенов и задержки не срывают приём пакета и не
// переполняют агрегаты.
func TestPGDashboardHugeValues(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	ds, st := dashStoreFor(t, e)
	if err := ds.Init(ctx); err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	var evs []events.Event
	for i := 1; i <= 3; i++ {
		d := dashEvent{at: day.Add(time.Duration(i) * time.Minute), n: i, typ: events.TypeGatewayRequest, app: "a", provider: "mock", model: "m1",
			action: "allow", mode: "enforce", tokens: [2]int{math.MaxInt64, math.MaxInt64}, latency: map[string]int64{"total": math.MaxInt64}}
		evs = append(evs, d.build())
	}
	res, err := st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: evs})
	if err != nil || res.Accepted != 3 {
		t.Fatalf("приём огромных значений: %+v %v", res, err)
	}
	if ready, err := ds.Ready(ctx); err != nil || ready {
		t.Fatalf("метка досчёта: %v %v", ready, err)
	}
	got, err := ds.Totals(ctx, events.DashQuery{From: day, To: day.Add(24 * time.Hour), TZ: "UTC"})
	if err != nil || got.Requests != 3 || got.TokensPrompt != 3e12 {
		t.Fatalf("итоги: %+v %v", got, err)
	}
	if lat, err := ds.Latency(ctx, events.DashQuery{From: day, To: day.Add(24 * time.Hour), TZ: "UTC"}); err != nil || lat.P95 != events.DashLatencyOverflow {
		t.Fatalf("задержка: %+v %v", lat, err)
	}
}

// 3В25 ревью 3.r3: пересчёт часа (исключительная блокировка часа у досчёта)
// не задерживает приём событий: пакет за этот час принимается сразу, час
// помечается к досчёту, после досчёта агрегаты равны полному пересчёту;
// пересчёт старого часа не мешает приросту текущего.
func TestPGDashIngestNotBlockedByBackfill(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	ds, st := dashStoreFor(t, e)
	if err := ds.Init(ctx); err != nil {
		t.Fatal(err)
	}
	hour := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	ev := func(at time.Time, n int) events.Event {
		return dashEvent{at: at, n: n, typ: events.TypeGatewayRequest, app: "a", provider: "mock", model: "m1", action: "block", mode: "enforce",
			tokens: [2]int{3, 4}, findings: []events.Finding{finding("pii.inn", "pii", "DM-31")}}.build()
	}
	// «Досчёт» держит исключительную блокировку часа hour.
	lock, err := e.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(ctx) //nolint:errcheck // откат после теста
	if _, err := lock.Exec(ctx, "SELECT pg_advisory_xact_lock($1, $2)", int32(0x6173_6461), int32(hour.Unix()/3600)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if res, err := st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(),
		Events: []events.Event{ev(hour.Add(10*time.Minute), 1), ev(hour.Add(20*time.Minute), 2)}}); err != nil || res.Accepted != 2 {
		t.Fatalf("приём при пересчёте часа: %+v %v", res, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("приём ждал блокировку: %v", d)
	}
	// Соседний час не заблокирован: прирост идёт сразу.
	if res, err := st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(),
		Events: []events.Event{ev(hour.Add(70*time.Minute), 3)}}); err != nil || res.Accepted != 1 {
		t.Fatalf("приём в соседний час: %+v %v", res, err)
	}
	var dirty int
	if err := e.owner.QueryRow(ctx, "SELECT count(DISTINCT bucket) FROM dash_dirty_hours").Scan(&dirty); err != nil || dirty != 1 {
		t.Fatalf("помеченных часов: %d %v", dirty, err)
	}
	if ready, err := ds.Ready(ctx); err != nil || ready {
		t.Fatalf("с помеченным часом агрегаты не полные: %v %v", ready, err)
	}
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for range 64 {
		done, err := ds.BackfillStep(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
	}
	if ready, err := ds.Ready(ctx); err != nil || !ready {
		t.Fatalf("после досчёта: %v %v", ready, err)
	}
	got := dashDump(t, e)
	if err := ds.Recompute(ctx, hour.Add(-time.Hour), hour.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if want := dashDump(t, e); got != want {
		t.Fatalf("после досчёта помеченного часа:\n--- было\n%s\n--- пересчёт\n%s", got, want)
	}
	if got, err := ds.Totals(ctx, events.DashQuery{From: hour, To: hour.Add(2 * time.Hour), TZ: "UTC"}); err != nil || got.Requests != 3 {
		t.Fatalf("итоги: %+v %v", got, err)
	}
}

// 3В28 ревью 3.r3: сумма строк агрегатов, каждая у предела 4e18, при чтении
// не переполняет bigint — все чтения отвечают, значение ограничено пределом.
func TestPGDashboardSumNoOverflow(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	ds, _ := dashStoreFor(t, e)
	day := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	for i, app := range []string{"a", "b", "c"} {
		if _, err := e.owner.Exec(ctx, `INSERT INTO dash_req_hour (org_id, bucket, app, provider, model, action, mode, requests, with_findings,
			non_text_unchecked, tokens_prompt, tokens_completion, cost, unpriced_requests) VALUES ($1, $2, $3, 'p', 'm', 'allow', 'enforce',
			4e18, 4e18, 0, 4e18, 4e18, 4e18, 0)`, audit.DefaultOrgID, day.Add(time.Duration(i)*time.Hour), app); err != nil {
			t.Fatal(err)
		}
		if _, err := e.owner.Exec(ctx, `INSERT INTO dash_find_hour (org_id, bucket, app, detector, category, threat, action, findings)
			VALUES ($1, $2, $3, 'pii', 'pii.inn', 'DM-31', 'allow', 4e18)`, audit.DefaultOrgID, day.Add(time.Duration(i)*time.Hour), app); err != nil {
			t.Fatal(err)
		}
	}
	q := events.DashQuery{From: day, To: day.Add(24 * time.Hour), TZ: "UTC"}
	if got, err := ds.Totals(ctx, q); err != nil || got.Requests != 4e18 || got.Cost != 4e18 {
		t.Fatalf("итоги: %+v %v", got, err)
	}
	if _, err := ds.RequestsBy(ctx, q, events.DimProvider, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.UsageSeries(ctx, events.DashQuery{From: day, To: day.Add(24 * time.Hour), TZ: "UTC"}); err != nil {
		t.Fatal(err)
	}
	if top, err := ds.TopFindings(ctx, q, events.DimDetector, "", 10); err != nil || len(top) != 1 || top[0].Value != 4e18 {
		t.Fatalf("топ: %+v %v", top, err)
	}
	if _, err := ds.Heatmap(ctx, q); err != nil {
		t.Fatal(err)
	}
	// Ряд — только по ключам топа.
	if pts, err := ds.FindingSeries(ctx, q, events.DimApp, "", []string{"b"}); err != nil || len(pts) != 1 || pts[0].Key != "b" {
		t.Fatalf("ряд по ключам: %+v %v", pts, err)
	}
	if pts, err := ds.FindingSeries(ctx, q, events.DimApp, "", []string{}); err != nil || len(pts) != 0 {
		t.Fatalf("ряд по пустому топу: %+v %v", pts, err)
	}
}
